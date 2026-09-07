//! .vgsafe 隐私保险箱：单文件口令容器，管理文件夹树的增量增删、导出与换口令。
//! 容器布局：头(42B) + AES-256-GCM(tar 流) + tag(16B)。
//!   头 = "VGS1"(4) + kid(1) + m(4) + t(4) + p(1) + salt(16) + nonce(12)，AAD = "VGS1"。
//! 打开即解密到临时工作树（GCM 认证通过才可见）；会话关闭/程序退出时覆写擦除。
//! 修改策略：v1 为整箱重写——写临时容器、自校验、原子替换旧箱（旧箱留作回滚，成功后擦除）。

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::crypto::{ct_eq, derive_v3, ArgonParams, Gcm, NONCE_SZ, TAG_SZ};
use crate::paths::{cleanup, mktmpdir, safe_name, uniq};
use crate::tarx;

pub const MAGIC: &[u8; 4] = b"VGS1";
pub const SAFE_EXT: &str = ".vgsafe";
pub const KDF_ARGON2ID: u8 = 0x01;
pub const AAD: &[u8] = b"VGS1";
const HDR_SZ: usize = 4 + 1 + 4 + 4 + 1 + 16 + NONCE_SZ; // 42
const IO_BLOCK: usize = 1 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
}

/// 已打开的保险箱会话。持有明文工作树；Drop 时覆写擦除。
pub struct Session {
    pub path: PathBuf,
    pass: String,
    staged: PathBuf, // 临时目录（含解密后的工作树 tree/）
    tree: PathBuf,   // 工作树根
    pub entries: Vec<Entry>,
}

impl Drop for Session {
    fn drop(&mut self) {
        cleanup(&self.staged);
    }
}

/// 新建空保险箱。文件已存在或口令为空时报错。
pub fn create(path: &Path, pass: &str) -> io::Result<Session> {
    if pass.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "口令不能为空"));
    }
    if path.exists() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "文件已存在"));
    }
    let staged = mktmpdir();
    let tree = staged.join("tree");
    std::fs::create_dir_all(&tree)?;
    let mut s = Session {
        path: path.to_path_buf(),
        pass: pass.to_string(),
        staged,
        tree,
        entries: Vec::new(),
    };
    match s.save(&|_| {}) {
        Ok(()) => Ok(s),
        Err(e) => Err(e),
    }
}

/// 打开保险箱：整箱解密（先认证）到临时工作树。
pub fn open(path: &Path, pass: &str) -> io::Result<Session> {
    if pass.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "口令不能为空"));
    }
    let staged = mktmpdir();
    let tree = staged.join("tree");
    let staged_for_body = staged.clone();
    let result = (|| -> io::Result<Session> {
        {
            let mut tar = File::create(staged_for_body.join("payload.tar"))?;
            read_verify(path, pass, &mut tar, &|_, _| {})?;
        }
        tarx::unpack_file(&staged_for_body.join("payload.tar"), &tree)?;
        let _ = std::fs::remove_file(staged_for_body.join("payload.tar"));
        let mut s = Session {
            path: path.to_path_buf(),
            pass: pass.to_string(),
            staged: staged_for_body,
            tree,
            entries: Vec::new(),
        };
        s.refresh_entries();
        Ok(s)
    })();
    match result {
        Ok(s) => Ok(s),
        Err(e) => {
            cleanup(&staged);
            Err(e)
        }
    }
}

impl Session {
    fn refresh_entries(&mut self) {
        self.entries = walk_entries(&self.tree);
    }

    /// 添加文件/文件夹（复制进箱，原文件不动）。返回成功添加的项数。
    pub fn add_paths(&mut self, srcs: &[PathBuf]) -> io::Result<usize> {
        let mut added = 0usize;
        for src in srcs {
            if !src.exists() {
                continue;
            }
            let raw = src
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "item".to_string());
            let base = safe_name(&raw, 100);
            let dst = uniq(&self.tree.join(&base));
            copy_recursive(src, &dst)?;
            added += 1;
        }
        self.refresh_entries();
        Ok(added)
    }

    /// 移除条目（按名称精确匹配）。返回移除数。
    pub fn remove_entries(&mut self, names: &[String]) -> io::Result<usize> {
        let mut removed = 0usize;
        for name in names {
            if !self.entries.iter().any(|e| &e.name == name) {
                continue;
            }
            let p = self.tree.join(name);
            if p.is_dir() {
                std::fs::remove_dir_all(&p)?;
                removed += 1;
            } else if p.is_file() {
                std::fs::remove_file(&p)?;
                removed += 1;
            }
        }
        self.refresh_entries();
        Ok(removed)
    }

    /// 重命名条目（顶层或嵌套均可，只改名字不改所在目录）。保存由调用方另行触发。
    pub fn rename_entry(&mut self, from: &str, to: &str) -> io::Result<()> {
        if !valid_rel_path(from) || !valid_rel_path(to) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "路径不合法（不能为空/含 .. 或反斜杠）",
            ));
        }
        if from == to {
            return Ok(());
        }
        let src = self.tree.join(from);
        if !src.exists() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "条目不存在"));
        }
        let dst = self.tree.join(to);
        if dst.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "目标名称已存在",
            ));
        }
        if let Some(parent) = dst.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "目标目录不存在（移动请用「移动」操作）",
                ));
            }
        }
        std::fs::rename(&src, &dst)?;
        self.refresh_entries();
        Ok(())
    }

    /// 移动条目到目录前缀（空串 = 移到根目录；目标目录不存在自动创建）。
    /// 目标重名自动加 _2/_3 后缀。保存由调用方另行触发。
    pub fn move_entry(&mut self, name: &str, dest_dir: &str) -> io::Result<()> {
        if !valid_rel_path(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "路径不合法",
            ));
        }
        let clean = dest_dir.trim().trim_matches('/').to_string();
        if !clean.is_empty() && !valid_rel_path(&clean) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "目标目录不合法",
            ));
        }
        let base = name.rsplit('/').next().unwrap_or(name).to_string();
        let target_plain = if clean.is_empty() {
            base.clone()
        } else {
            format!("{}/{}", clean, base)
        };
        if target_plain == name {
            return Ok(()); // 原地移动 = 无操作
        }
        if target_plain.starts_with(&format!("{}/", name)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "不能移动到自身子目录",
            ));
        }
        if !clean.is_empty() {
            std::fs::create_dir_all(self.tree.join(&clean))?;
        }
        let mut target = target_plain;
        let mut i = 2;
        while self.tree.join(&target).exists() {
            let (stem, ext) = split_ext(&base);
            target = if clean.is_empty() {
                format!("{}_{}{}", stem, i, ext)
            } else {
                format!("{}/{}_{}{}", clean, stem, i, ext)
            };
            i += 1;
        }
        std::fs::rename(self.tree.join(name), self.tree.join(&target))?;
        self.refresh_entries();
        Ok(())
    }

    /// 保存：工作树整箱重加密 -> 写临时容器 -> 自校验 -> 原子替换旧箱。
    pub fn save(&mut self, prog: &dyn Fn(u8)) -> io::Result<()> {
        let tmp_c = self.path.with_extension("vgsafe.tmp");
        let total = tree_size(&self.tree);
        let salt = rand_bytes::<16>();
        let nonce = rand_bytes::<NONCE_SZ>();
        let prm = ArgonParams::default();
        let key = derive_v3(self.pass.as_bytes(), &salt, prm)?;
        let mut done: u64 = 0;
        let mut last: u8 = 0;
        let r = (|| -> io::Result<()> {
            let mut f = File::create(&tmp_c)?;
            f.write_all(MAGIC)?;
            f.write_all(&[KDF_ARGON2ID])?;
            f.write_all(&prm.m_kib.to_be_bytes())?;
            f.write_all(&prm.t.to_be_bytes())?;
            f.write_all(&[prm.p as u8])?;
            f.write_all(&salt)?;
            f.write_all(&nonce)?;
            let mut g = Gcm::new(&key, &nonce, AAD);
            {
                let mut writer = EncW {
                    f: &mut f,
                    g: &mut g,
                    done: &mut done,
                    total,
                    last: &mut last,
                    prog,
                };
                tarx::pack_dir(&self.tree, &mut writer)?;
            }
            let tag = g.finish_tag();
            f.write_all(&tag)?;
            f.sync_all()?;
            Ok(())
        })();
        match r {
            Ok(()) => {}
            Err(e) => {
                cleanup(&tmp_c);
                return Err(e);
            }
        }
        // 自校验：完整解密一次确认认证通过，再替换旧箱
        if let Err(e) = {
            let mut sink = io::sink();
            read_verify(&tmp_c, &self.pass, &mut sink, &|_, _| {})
        } {
            cleanup(&tmp_c);
            return Err(e);
        }
        let bak = self.path.with_extension("vgsafe.bak");
        let _ = std::fs::remove_file(&bak);
        if self.path.exists() {
            std::fs::rename(&self.path, &bak)?;
        }
        if let Err(e) = std::fs::rename(&tmp_c, &self.path) {
            if !self.path.exists() && bak.exists() {
                let _ = std::fs::rename(&bak, &self.path);
            }
            cleanup(&tmp_c);
            return Err(e);
        }
        if bak.exists() {
            cleanup(&bak);
        }
        self.refresh_entries();
        Ok(())
    }

    /// 导出全部条目到 out_root（单顶层直落，否则归并为目录）。
    pub fn export(&self, out_root: &Path, prog: &dyn Fn(u64, u64)) -> io::Result<(PathBuf, usize)> {
        let tmp = mktmpdir();
        let result = (|| -> io::Result<(PathBuf, usize)> {
            let tp = tmp.join("payload.tar");
            {
                let mut f = File::create(&tp)?;
                read_verify(&self.path, &self.pass, &mut f, prog)?;
            }
            tarx::place(&tmp, "vgsafe", out_root)
        })();
        cleanup(&tmp);
        result
    }

    /// 选择性导出指定条目到 out_root（复制，不影响箱内）。
    pub fn export_selective(&self, names: &[String], out_root: &Path) -> io::Result<usize> {
        std::fs::create_dir_all(out_root)?;
        let mut n = 0usize;
        for name in names {
            let src = self.tree.join(name);
            if !src.exists() {
                continue;
            }
            let dst = uniq(&out_root.join(safe_name(name, 100)));
            if src.is_dir() {
                std::fs::create_dir_all(&dst)?;
                copy_recursive(&src, &dst)?;
            } else {
                std::fs::copy(&src, &dst)?;
            }
            n += 1;
        }
        Ok(n)
    }

    /// 更换口令：内存中替换后整箱重加密保存。
    pub fn change_password(&mut self, new_pass: &str) -> io::Result<()> {
        if new_pass.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "口令不能为空"));
        }
        self.pass = new_pass.to_string();
        self.save(&|_| {})
    }
}

/// 解密整箱到 out（写明文流），并校验认证标记。返回明文字节数。
pub fn read_verify(
    container: &Path,
    pass: &str,
    out: &mut dyn Write,
    prog: &dyn Fn(u64, u64),
) -> io::Result<u64> {
    let mut f = File::open(container)?;
    let file_len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if file_len < HDR_SZ as u64 + TAG_SZ as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "不是有效的 VaultGuard 保险箱文件",
        ));
    }
    let mut hdr = [0u8; HDR_SZ];
    f.read_exact(&mut hdr)?;
    if &hdr[..4] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "不是 VaultGuard 保险箱文件",
        ));
    }
    if hdr[4] != KDF_ARGON2ID {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "未知的密钥派生类型",
        ));
    }
    let m = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]);
    let t = u32::from_be_bytes([hdr[9], hdr[10], hdr[11], hdr[12]]);
    let p = hdr[13] as u32;
    if m == 0 || t == 0 || p == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "保险箱文件头参数无效",
        ));
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&hdr[14..30]);
    let mut nonce = [0u8; NONCE_SZ];
    nonce.copy_from_slice(&hdr[30..30 + NONCE_SZ]);
    let key = derive_v3(
        pass.as_bytes(),
        &salt,
        ArgonParams {
            m_kib: m,
            t,
            p,
        },
    )?;
    let ct_len = file_len - HDR_SZ as u64 - TAG_SZ as u64;
    let mut g = Gcm::new(&key, &nonce, AAD);
    let mut buf = vec![0u8; IO_BLOCK];
    let mut left = ct_len;
    let mut done: u64 = 0;
    while left > 0 {
        let want = (IO_BLOCK as u64).min(left) as usize;
        let n = f.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "文件被截断"));
        }
        g.ghash_data(&buf[..n]);
        g.crypt_in_place(&mut buf[..n]);
        out.write_all(&buf[..n])?;
        left -= n as u64;
        done += n as u64;
        prog(done, ct_len);
    }
    let mut tag = [0u8; TAG_SZ];
    f.read_exact(&mut tag)?;
    if !ct_eq(&g.finish_tag(), &tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "认证失败：口令错误，或数据已被改动",
        ));
    }
    Ok(ct_len)
}

/// 加密写入器：tar 产出的每块明文 -> GHASH 累计 -> CTR 加密 -> 写容器。
struct EncW<'a> {
    f: &'a mut File,
    g: &'a mut Gcm,
    done: &'a mut u64,
    total: u64,
    last: &'a mut u8,
    prog: &'a dyn Fn(u8),
}

impl Write for EncW<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // 顺序必须是：先加密，GHASH 累计密文（与 engine::enc_streaming 一致）
        let mut b = buf.to_vec();
        self.g.crypt_in_place(&mut b);
        self.g.ghash_data(&b);
        self.f.write_all(&b)?;
        *self.done += b.len() as u64;
        let pct = if self.total == 0 {
            0
        } else {
            ((*self.done).min(self.total) * 100 / self.total).min(99) as u8
        };
        if pct != *self.last {
            *self.last = pct;
            (self.prog)(pct);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.f.flush()
    }
}

// ── 内部工具 ──────────────────────────────────────────────────────

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut b);
    b
}

fn walk_entries(tree: &Path) -> Vec<Entry> {
    fn rec(dir: &Path, prefix: &str, out: &mut Vec<Entry>) {
        let rd = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => return,
        };
        let mut subs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        subs.sort();
        for p in subs {
            let name = p
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", prefix, name)
            };
            let is_dir = p.is_dir();
            let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            out.push(Entry {
                name: rel.clone(),
                size,
                is_dir,
            });
            if is_dir {
                rec(&p, &rel, out);
            }
        }
    }
    let mut out = Vec::new();
    rec(tree, "", &mut out);
    out
}

fn tree_size(tree: &Path) -> u64 {
    fn rec(dir: &Path) -> u64 {
        let mut sum = 0u64;
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    sum += rec(&p);
                } else {
                    sum += e.metadata().map(|m| m.len()).unwrap_or(0);
                }
            }
        }
        sum
    }
    rec(tree)
}

fn copy_recursive(src: &Path, dst: &Path) -> io::Result<()> {
    let md = std::fs::symlink_metadata(src)?;
    if md.is_dir() {
        std::fs::create_dir_all(dst)?;
        for e in std::fs::read_dir(src)?.flatten() {
            copy_recursive(&e.path(), &dst.join(e.file_name()))?;
        }
        Ok(())
    } else if md.is_file() {
        std::fs::copy(src, dst).map(|_| ())
    } else {
        Ok(()) // 符号链接等跳过
    }
}

fn split_ext(name: &str) -> (String, String) {
    match name.rfind('.') {
        Some(i) if i > 0 => (name[..i].to_string(), name[i..].to_string()),
        _ => (name.to_string(), String::new()),
    }
}

/// 保险箱内相对路径合法性：非空、无头尾斜杠、无空段 / . / .. / 反斜杠。
fn valid_rel_path(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.ends_with('/')
        && !p.contains('\\')
        && p.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

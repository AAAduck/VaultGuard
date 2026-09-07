//! 高层流程：流式加密（tar 流直通加密，明文不落盘）/ 流式解密状态机 / do_enc / do_dec。
//! 加密侧：tar 打包直接写入加密管道（有界通道 + 后台线程），全程无明文临时文件。
//! 解密侧：先认证后落位——明文 tar 暂存临时目录，GCM 标记验证通过才解包；用后擦除。

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::sync_channel;

use crate::crypto::{
    aad_for, ct_eq, derive_v1, derive_v2, derive_v3, ArgonParams, Gcm, FMT_V1, FMT_V2, FMT_V3,
    KDF_ARGON2ID, NONCE_SZ, TAG_SZ,
};
use crate::crypto::{ARGON_SALT_SZ, SALT_SZ};
use crate::paths::{cleanup, mktmpdir, random_out_name, safe_name, uniq};
use crate::shells::{self, Ev as EncEv, Sink};
use crate::tarx;

pub const BLOCK: usize = 1 << 20; // 1 MiB

/// 加密密钥来源：
/// Builtin    —— VG\x02，内置密钥 + HKDF（防随手翻看，不防知道本工具的人）；
/// Passphrase —— VG\x03，Argon2id 口令派生（防拿到程序/源码的攻击者）。
#[derive(Clone)]
pub enum KeySource {
    Builtin,
    Passphrase(String),
}

/// 进度回调：done/total（字节）。加密=明文 tar 字节；解密≈容器内已消费密文字节。
pub type ProgressFn<'a> = dyn Fn(u64, u64) + 'a;

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    let mut rng = rand::thread_rng();
    rand::RngCore::fill_bytes(&mut rng, &mut b);
    b
}

/// 外壳名 -> 字节标识
pub fn shell_byte(shell: &str) -> u8 {
    match shell {
        "jpg" => crate::crypto::SHELL_JPG,
        "docx" => crate::crypto::SHELL_DOCX,
        _ => crate::crypto::SHELL_PNG,
    }
}

pub fn shell_ext(shell: &str) -> &'static str {
    match shell {
        "jpg" => ".jpg",
        "docx" => ".docx",
        _ => ".png",
    }
}

fn report_progress(on: Option<&ProgressFn<'_>>, done: u64, total: u64, last: &mut u8) {
    if let Some(f) = on {
        let pct = if total == 0 {
            0
        } else {
            ((done.min(total)) * 100 / total).min(99) as u8
        };
        if pct != *last {
            *last = pct;
            f(done, total);
        }
    }
}

/// 把明文读源流式加密为事件序列，返回明文字节数。
/// key_src 决定容器版本：内置密钥（VG\x02）或用户口令（VG\x03）。
pub fn enc_streaming<R: Read>(
    mut r: R,
    key_src: &KeySource,
    shell_byte: u8,
    sink: &mut dyn Sink,
    total: Option<u64>,
    on_progress: Option<&ProgressFn<'_>>,
) -> io::Result<u64> {
    let (head, key, nonce, fmt): (Vec<u8>, [u8; 32], [u8; NONCE_SZ], &'static [u8; 3]) =
        match key_src {
            KeySource::Builtin => {
                let salt = rand_bytes::<SALT_SZ>();
                let nonce = rand_bytes::<NONCE_SZ>();
                let key = derive_v2(&salt);
                let mut head = Vec::with_capacity(3 + SALT_SZ + NONCE_SZ);
                head.extend_from_slice(FMT_V2);
                head.extend_from_slice(&salt);
                head.extend_from_slice(&nonce);
                (head, key, nonce, FMT_V2)
            }
            KeySource::Passphrase(pass) => {
                let prm = ArgonParams::default();
                let salt = rand_bytes::<ARGON_SALT_SZ>();
                let nonce = rand_bytes::<NONCE_SZ>();
                let key = derive_v3(pass.as_bytes(), &salt, prm)?;
                let mut head =
                    Vec::with_capacity(3 + 1 + 4 + 4 + 1 + ARGON_SALT_SZ + NONCE_SZ);
                head.extend_from_slice(FMT_V3);
                head.push(KDF_ARGON2ID);
                head.extend_from_slice(&prm.m_kib.to_be_bytes());
                head.extend_from_slice(&prm.t.to_be_bytes());
                head.push(prm.p as u8);
                head.extend_from_slice(&salt);
                head.extend_from_slice(&nonce);
                (head, key, nonce, FMT_V3)
            }
        };
    let mut g = Gcm::new(&key, &nonce, &aad_for(fmt, shell_byte));

    sink.emit(&EncEv::H(head))?;
    let mut plain: u64 = 0;
    let mut last_pct = 0u8;
    let mut buf = vec![0u8; BLOCK];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        plain += n as u64;
        let page = &mut buf[..n];
        g.crypt_in_place(page); // 密文写回同一缓冲
        sink.emit(&EncEv::D(page.to_vec()))?;
        g.ghash_data(page);
        if let Some(total) = total {
            report_progress(on_progress, plain, total, &mut last_pct);
        }
    }
    let tag = g.finish_tag();
    sink.emit(&EncEv::T(tag.to_vec()))?;
    if total.is_some() {
        if let Some(f) = on_progress {
            f(plain.max(total.unwrap_or(plain)), plain.max(total.unwrap_or(plain)));
        }
    }
    Ok(plain)
}

/// 消费事件序列，认证解密并写明文 tar。返回明文总字节。
/// pass 供 VG\x03（口令格式）使用；v1/v2 忽略。
pub fn stream_decrypt(
    shell: &str,
    path: &Path,
    tp: &Path,
    pass: Option<&str>,
    on_progress: Option<&ProgressFn<'_>>,
) -> io::Result<u64> {
    let mut dec: Option<Gcm> = None;
    let mut fmt: &'static [u8; 3] = FMT_V2;
    let mut saw_head = false;
    let mut size: u64 = 0;
    let mut out = File::create(tp)?;
    let container_len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let mut consumed: u64 = 0;
    let mut last_pct = 0u8;

    let mut handle = |ev: EncEv| -> io::Result<()> {
        match ev {
            EncEv::H(pl) => {
                saw_head = true;
                if pl.len() < 3 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "标记不符, 不是本工具产物",
                    ));
                }
                let v: &'static [u8; 3] = match &pl[..3] {
                    x if x == FMT_V3 => FMT_V3,
                    x if x == FMT_V2 => FMT_V2,
                    x if x == FMT_V1 => FMT_V1,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "标记不符, 不是本工具产物",
                        ))
                    }
                };
                fmt = v;
                if v == FMT_V3 {
                    // VG\x03 头：fmt(3) kid(1) m(4) t(4) p(1) salt(16) nonce(12)
                    const H3: usize = 3 + 1 + 4 + 4 + 1 + ARGON_SALT_SZ + NONCE_SZ;
                    if pl.len() < H3 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "口令加密文件头损坏",
                        ));
                    }
                    if pl[3] != KDF_ARGON2ID {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "未知的密钥派生类型",
                        ));
                    }
                    let m = u32::from_be_bytes([pl[4], pl[5], pl[6], pl[7]]);
                    let t = u32::from_be_bytes([pl[8], pl[9], pl[10], pl[11]]);
                    let p = pl[12] as u32;
                    if m == 0 || t == 0 || p == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "口令加密文件头参数无效",
                        ));
                    }
                    let salt = &pl[13..13 + ARGON_SALT_SZ];
                    let nonce: &[u8; NONCE_SZ] = pl[13 + ARGON_SALT_SZ..H3].try_into().unwrap();
                    let pass = pass.filter(|s| !s.is_empty()).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "此文件使用口令加密：请先输入口令（图形界面在左栏「口令」框填写，命令行加 --password）",
                        )
                    })?;
                    let key = derive_v3(pass.as_bytes(), salt, ArgonParams { m_kib: m, t, p })?;
                    dec = Some(Gcm::new(&key, nonce, &aad_for(FMT_V3, shell_byte(shell))));
                } else {
                    if pl.len() < 3 + SALT_SZ + NONCE_SZ {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "加密文件头损坏",
                        ));
                    }
                    let salt = &pl[3..3 + SALT_SZ];
                    let nonce: &[u8; NONCE_SZ] = pl[3 + SALT_SZ..3 + SALT_SZ + NONCE_SZ]
                        .try_into()
                        .unwrap();
                    let (key, aad) = if v == FMT_V1 {
                        (derive_v1(salt), crate::crypto::AAD_V1.to_vec())
                    } else {
                        (derive_v2(salt), aad_for(FMT_V2, shell_byte(shell)))
                    };
                    dec = Some(Gcm::new(&key, nonce, &aad));
                }
            }
            EncEv::D(c) => {
                let g = dec
                    .as_mut()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "数据顺序异常"))?;
                let n = c.len() as u64;
                g.ghash_data(&c);
                let mut p = c;
                g.crypt_in_place(&mut p);
                out.write_all(&p)?;
                size += n;
                consumed += n;
                if container_len > 0 {
                    report_progress(on_progress, consumed, container_len, &mut last_pct);
                }
            }
            EncEv::T(t) => {
                let g = dec
                    .take()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "缺认证标记"))?;
                if t.len() < TAG_SZ {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "缺认证标记"));
                }
                let tag = g.finish_tag();
                if !ct_eq(&tag, &t[..TAG_SZ]) {
                    let msg = if fmt == FMT_V3 {
                        "认证失败：口令错误，或数据已被改动"
                    } else {
                        "认证失败: 数据可能被改动或密钥不匹配"
                    };
                    return Err(io::Error::new(io::ErrorKind::InvalidData, msg));
                }
                if let Some(f) = on_progress {
                    f(size, size);
                }
            }
        }
        Ok(())
    };

    match shell {
        "png" => shells::evs_png(path, &mut handle)?,
        "jpg" => shells::evs_jpg(path, &mut handle)?,
        _ => shells::evs_docx(path, &mut handle)?,
    }
    if !saw_head {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "容器内无加密数据",
        ));
    }
    if dec.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "容器内缺少认证标记",
        ));
    }
    Ok(size)
}

/// 加密选项：密钥来源、输出命名、自定义封面。
pub struct EncOptions {
    pub key_src: KeySource,
    /// false = 输出随机文件名（不泄露原文件名）
    pub keep_name: bool,
    /// 自定义封面文件（须与所选外壳同类型）；None = 内置随机封面
    pub cover: Option<PathBuf>,
}

/// 高层加密。返回 (输出路径, 打包项数, 明文 tar 字节数)。
/// 加密全程无明文临时文件（tar 流直通加密管道）。
pub fn do_enc(
    paths: &[PathBuf],
    shell: &str,
    out_root: &Path,
    opts: &EncOptions,
    on_progress: Option<&ProgressFn<'_>>,
) -> Result<(PathBuf, usize, u64), String> {
    let mut valid: Vec<PathBuf> = Vec::new();
    for p in paths {
        if p.exists() {
            valid.push(p.clone());
        }
    }
    if valid.is_empty() {
        return Err("没有可加密的文件/文件夹".to_string());
    }
    if let KeySource::Passphrase(p) = &opts.key_src {
        if p.trim().is_empty() {
            return Err("口令不能为空（不设口令请使用内置密钥模式）".to_string());
        }
    }
    let shell = if matches!(shell, "png" | "jpg" | "docx") {
        shell
    } else {
        "png"
    };
    let sb = shell_byte(shell);
    let count = valid.len();
    let total: u64 = valid
        .iter()
        .map(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
        .sum();
    let first = valid[0]
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let plain_len = AtomicU64::new(0);

    // tar 打包线程：产物流入有界通道（背压限内存），读端直接进加密器
    let (tx, rx) = sync_channel::<io::Result<Vec<u8>>>(8);
    let valid_for_pack = valid.clone();
    let packer = std::thread::spawn(move || {
        if let Err(e) = tarx::pack_to_writer(&valid_for_pack, TarSender { tx: tx.clone() }) {
            let _ = tx.send(Err(e)); // 读端把打包失败当作 I/O 错误传播
        }
    });

    // 输出名：默认随机化（隐私——文件名不泄露原内容），可按需保留原名
    let base = if opts.keep_name {
        let raw = safe_name(&first, 110);
        let stem = match raw.rfind('.') {
            Some(i) if i > 0 => raw[..i].to_string(),
            _ => raw.clone(),
        };
        format!("{}{}", stem, shell_ext(shell))
    } else {
        random_out_name(shell_ext(shell))
    };
    let out = uniq(&out_root.join(&base));
    std::fs::create_dir_all(out_root).map_err(|e| e.to_string())?;

    // 自定义封面：随选项携带（须与外壳同类型），读取失败直接报错不产生半成品
    let cover: Option<Vec<u8>> = match &opts.cover {
        Some(p) => Some(std::fs::read(p).map_err(|e| format!("读取自定义封面失败: {e}"))?),
        None => None,
    };

    let gen = |sink: &mut dyn Sink| -> io::Result<()> {
        let reader = ChanReader {
            rx,
            buf: Vec::new(),
            pos: 0,
        };
        let n = enc_streaming(reader, &opts.key_src, sb, sink, Some(total), on_progress)?;
        plain_len.store(n, Ordering::Relaxed);
        Ok(())
    };
    let r = match shell {
        "jpg" => shells::enc_jpg(cover.as_deref(), &out, gen).map_err(|e| e.to_string()),
        "docx" => shells::enc_docx(cover.as_deref(), &out, gen).map_err(|e| e.to_string()),
        _ => shells::enc_png(cover.as_deref(), &out, gen).map_err(|e| e.to_string()),
    };
    let _ = packer.join();
    match r {
        Ok(()) => Ok((out, count, plain_len.load(Ordering::Relaxed))),
        Err(e) => {
            // 中途失败不残留半个产物
            let _ = std::fs::remove_file(&out);
            Err(e)
        }
    }
}

/// 还原结果：目标路径、条目数、明文总字节、内容清单（认证通过后的 tar 条目）、各文件 SHA-256。
#[derive(Debug)]
pub struct DecResult {
    pub dst: PathBuf,
    pub entries: usize,
    pub plain_bytes: u64,
    /// 内容清单：(名称, 字节, 是否目录)——来自认证通过的 tar 头
    pub manifest: Vec<(String, u64, bool)>,
    pub hashes: Vec<(String, String)>, // (相对路径, sha256 hex)
}

/// 还原预览：解密完成、认证通过后的临时状态，供选择性落位使用。
/// 持有临时目录（含 payload.tar）；调用方用完必须交给 do_dec_place 落位或显式丢弃（Drop 清理）。
pub struct DecPreview {
    pub tmp_dir: PathBuf,
    pub tar_path: PathBuf,
    pub base: String,
    pub manifest: Vec<(String, u64, bool)>,
    pub plain_bytes: u64,
}

impl Drop for DecPreview {
    fn drop(&mut self) {
        // 保险：未被 do_dec_place 消费时，Drop 擦除临时明文
        cleanup(&self.tmp_dir);
    }
}

/// 提取顶层条目清单（从完整 manifest 中取第一层路径，去重保序）。
pub fn top_entries(manifest: &[(String, u64, bool)]) -> Vec<(String, u64, bool)> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (name, sz, is_dir) in manifest {
        let top = name.split('/').next().unwrap_or("").to_string();
        if top.is_empty() || !seen.insert(top.clone()) {
            continue;
        }
        if name == &top {
            // 条目本身就是顶层
            out.push((top, *sz, *is_dir));
        } else {
            // 子条目，顶层是目录（tar 保证目录条目在子文件之前，但兜底处理）
            out.push((top, 0, true));
        }
    }
    out
}

/// 第一阶段：解密 + 认证 + 列清单，不落位。返回 DecPreview 供选择性落位。
/// pass 供 VG\x03 口令格式使用；v1/v2 传 None。
pub fn do_dec_preview(
    path: &Path,
    pass: Option<&str>,
    on_progress: Option<&ProgressFn<'_>>,
) -> Result<DecPreview, String> {
    if !path.is_file() {
        return Err("不是文件".to_string());
    }
    let shell = shells::probe_vault(path);
    let shell = match shell {
        Some(s) => s,
        None => return Err("无法识别, 不是 VaultGuard 加密产物".to_string()),
    };
    let tmp = mktmpdir();
    let tp = tmp.join("payload.tar");
    let result = (|| -> Result<DecPreview, String> {
        let size = stream_decrypt(shell, path, &tp, pass, on_progress).map_err(|e| e.to_string())?;
        let base = safe_name(
            &path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default(),
            110,
        );
        let manifest = tarx::list_file(&tp).unwrap_or_default();
        Ok(DecPreview {
            tmp_dir: tmp.clone(),
            tar_path: tp,
            base,
            manifest,
            plain_bytes: size,
        })
    })();
    if result.is_err() {
        cleanup(&tmp);
    }
    // 成功时 tmp 由 DecPreview 持有；失败时已 cleanup
    result
}

/// 第二阶段：从预览落位到 out_root。
/// filter=None 全量落位；filter=Some 只落位选中的顶层条目。
/// 消费 preview（内部清理临时目录）。
pub fn do_dec_place(
    mut preview: DecPreview,
    out_root: &Path,
    filter: Option<&[String]>,
) -> Result<DecResult, String> {
    let result = (|| -> Result<DecResult, String> {
        let (dst, n) = match filter {
            None => tarx::place(&preview.tmp_dir, &preview.base, out_root),
            Some(sel) => tarx::place_filtered(&preview.tmp_dir, &preview.base, out_root, sel),
        }
        .map_err(|e| e.to_string())?;
        let manifest = std::mem::take(&mut preview.manifest);
        let mut hashes = Vec::new();
        collect_hashes(&dst, &mut hashes, 0);
        Ok(DecResult {
            dst,
            entries: n,
            plain_bytes: preview.plain_bytes,
            manifest,
            hashes,
        })
    })();
    // 无论成功失败，临时目录都已由 place/place_filtered 内部清理 staged；
    // 但 tmp_dir 本身（含可能的残留 payload.tar）仍需擦除
    cleanup(&preview.tmp_dir);
    // 阻止 DecPreview::drop 重复 cleanup（tmp_dir 已删，cleanup 是幂等的 best-effort）
    result
}

/// 高层还原（全量，向后兼容）。pass 供 VG\x03 口令格式使用；v1/v2 传 None。
pub fn do_dec(
    path: &Path,
    out_root: &Path,
    pass: Option<&str>,
    on_progress: Option<&ProgressFn<'_>>,
) -> Result<DecResult, String> {
    let preview = do_dec_preview(path, pass, on_progress)?;
    do_dec_place(preview, out_root, None)
}

const HASH_LIMIT: usize = 32; // 最多记录 32 个文件的哈希，防止超大目录刷屏

fn collect_hashes(dir: &Path, out: &mut Vec<(String, String)>, depth: usize) {
    if out.len() >= HASH_LIMIT || depth > 16 {
        return;
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                collect_hashes(&p, out, depth + 1);
            } else if let Ok(data) = std::fs::read(&p) {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(&data);
                let hex: String = h
                    .finalize()
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                let rel = p.strip_prefix(dir).unwrap_or(&p).to_string_lossy().to_string();
                out.push((rel, hex));
                if out.len() >= HASH_LIMIT {
                    return;
                }
            }
        }
    }
}

// ── 加密管道：tar 打包(写端) -> 有界通道 -> 加密器(读端) ─────────────

struct TarSender {
    tx: std::sync::mpsc::SyncSender<io::Result<Vec<u8>>>,
}

impl Write for TarSender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx
            .send(Ok(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "加密管道已关闭"))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ChanReader {
    rx: std::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    buf: Vec<u8>,
    pos: usize,
}

impl Read for ChanReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos >= self.buf.len() {
            match self.rx.recv() {
                Ok(Ok(v)) => {
                    self.buf = v;
                    self.pos = 0;
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => return Ok(0), // 打包完成，EOF
            }
        }
        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// 供 tarx::place 使用的简化名（避免私有访问链过深）
#[allow(dead_code)]
pub fn vault_stem(base: &str) -> String {
    crate::paths::strip_vault_ext(base)
}

//! tar（USTAR/GNU/PAX）打包与还原，与 Python `tarfile` 产物理互操作。
//! Python 侧 tarfile.open('w') 为 GNU 格式；Rust 读写均兼容。
//! Rust 写侧：长文件名自动 GNU 扩展头，Python 可读；Rust 读侧拒绝路径穿越。

use std::fs::File;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use crate::paths::{safe_name, uniq};

/// 把 srcs 打包为 tar 流写入任意 Write（加密直通管道用，明文不落盘）。
pub fn pack_to_writer<W: Write>(srcs: &[PathBuf], w: W) -> io::Result<()> {
    let mut b = tar::Builder::new(w);
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();

    for src in srcs {
        let src = std::fs::canonicalize(src).unwrap_or_else(|_| src.clone());
        let raw = src
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "item".to_string());
        let base = safe_name(&raw, 110);
        let mut nm = base.clone();
        let mut i = 2;
        while used.contains(&nm) {
            let (stem, ext) = split_ext(&base);
            nm = format!("{}_{}{}", stem, i, ext);
            i += 1;
        }
        used.insert(nm.clone());
        append_recursive(&mut b, &src, &nm)?;
    }
    b.finish()?;
    Ok(())
}

fn split_ext(name: &str) -> (String, String) {
    match name.rfind('.') {
        Some(i) if i > 0 => (name[..i].to_string(), name[i..].to_string()),
        _ => (name.to_string(), String::new()),
    }
}

fn append_recursive<W: Write>(b: &mut tar::Builder<W>, abs: &Path, arc: &str) -> io::Result<()> {
    let md = std::fs::symlink_metadata(abs)?;
    let ft = md.file_type();
    if ft.is_file() {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::file());
        header.set_size(md.len());
        header.set_mode(0o644);
        if let Ok(t) = md.modified() {
            if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
                header.set_mtime(d.as_secs());
            }
        }
        let f = File::open(abs)?;
        b.append_data(&mut header, arc, f)?;
        Ok(())
    } else if ft.is_dir() {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
        if let Ok(t) = md.modified() {
            if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
                header.set_mtime(d.as_secs());
            }
        }
        b.append_data(&mut header, arc, io::empty())?;
        let rd = std::fs::read_dir(abs)?;
        let mut subs: Vec<PathBuf> = Vec::new();
        for e in rd.flatten() {
            subs.push(e.path());
        }
        subs.sort();
        for sub in subs {
            let child = sub
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let child_arc = if arc.is_empty() {
                child.clone()
            } else {
                format!("{}/{}", arc, child)
            };
            append_recursive(b, &sub, &child_arc)?;
        }
        Ok(())
    } else {
        // symlink / hardlink 等跳过（对应 Python 实现 filter=_no_link）
        Ok(())
    }
}

/// 在 dst 下解包 tar。返回 (顶层组件列表, 条目数)。
fn unpack(tp: &Path, dst: &Path) -> io::Result<(Vec<String>, usize)> {
    std::fs::create_dir_all(dst)?;
    let f = File::open(tp)?;
    let mut ar = tar::Archive::new(f);
    let mut tops: Vec<String> = Vec::new();
    let mut count = 0usize;
    for entry in ar.entries()? {
        let mut e = entry?;
        let raw = e.path()?.to_string_lossy().to_string();
        let name = raw.trim_matches('/').to_string();
        if name.is_empty() || name == "." {
            continue;
        }
        count += 1;
        let head = name.split('/').next().unwrap_or("").to_string();
        if !tops.contains(&head) {
            tops.push(head);
        }
        let rel = sanitize_rel(&name)?;
        if rel.as_os_str().is_empty() {
            continue;
        }
        let out_path = dst.join(&rel);
        if let Some(p) = out_path.parent() {
            std::fs::create_dir_all(p)?;
        }
        if e.header().entry_type().is_dir() {
            std::fs::create_dir_all(&out_path)?;
        } else if e.header().entry_type().is_file() {
            let mut f = std::fs::File::create(&out_path)?;
            std::io::copy(&mut e, &mut f)?;
        }
        // 其余类型（链接等）忽略
    }
    Ok((tops, count))
}

/// 归一化 tar 条目相对路径；拒绝 Root/ParentDir（..）逃逸。
fn sanitize_rel(name: &str) -> io::Result<PathBuf> {
    let p = Path::new(name);
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(x) => {
                if !x.is_empty() {
                    out.push(x);
                }
            }
            Component::CurDir => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "非法路径: 路径穿越被拒绝",
                ))
            }
        }
    }
    Ok(out)
}

/// 把目录内容（不含目录本身这层名）打包为 tar 流。保险箱重打包用。
pub fn pack_dir<W: Write>(dir: &Path, w: W) -> io::Result<()> {
    let mut b = tar::Builder::new(w);
    let rd = std::fs::read_dir(dir)?;
    let mut subs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    subs.sort();
    for sub in subs {
        let name = sub
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        append_recursive(&mut b, &sub, &name)?;
    }
    b.finish()?;
    Ok(())
}

/// 解包 tar 文件到 dst。返回条目数。
pub fn unpack_file(tp: &Path, dst: &Path) -> io::Result<usize> {
    let (_, n) = unpack(tp, dst)?;
    Ok(n)
}

/// 列出 tar 文件条目（名称, 大小, 是否目录），不解包。
pub fn list_file(tp: &Path) -> io::Result<Vec<(String, u64, bool)>> {
    let f = File::open(tp)?;
    let mut ar = tar::Archive::new(f);
    let mut out = Vec::new();
    for entry in ar.entries()? {
        let e = entry?;
        let raw = e.path()?.to_string_lossy().to_string();
        let name = raw.trim_matches('/').to_string();
        if name.is_empty() || name == "." {
            continue;
        }
        out.push((
            name,
            e.header().size().unwrap_or(0),
            e.header().entry_type().is_dir(),
        ));
    }
    Ok(out)
}

/// 跨盘安全移动（rename 失败回退 拷贝+删除）。保险箱导出/落位用。
pub fn move_path(src: &Path, dst: &Path) -> io::Result<()> {
    force_move(src, dst)
}

/// 跨盘安全移动：rename 失败（源/目标在不同磁盘）时回退为 拷贝+删除。
fn force_move(src: &Path, dst: &Path) -> io::Result<()> {
    match std::fs::rename(src, dst) {
        Ok(()) => return Ok(()),
        Err(e) => {
            if e.kind() != std::io::ErrorKind::CrossesDevices {
                return Err(e);
            }
        }
    }
    let md = std::fs::metadata(src)?;
    if md.is_dir() {
        std::fs::create_dir_all(dst)?;
        for en in std::fs::read_dir(src)? {
            let en = en?;
            let s = en.path();
            let d = dst.join(en.file_name());
            if en.file_type()?.is_dir() {
                force_move(&s, &d)?;
            } else {
                std::fs::copy(&s, &d)?;
                let _ = std::fs::remove_file(&s);
            }
        }
        let _ = std::fs::remove_dir_all(src);
    } else {
        std::fs::copy(src, dst)?;
        let _ = std::fs::remove_file(src);
    }
    Ok(())
}

/// 解包并把内容落位到 out 根：单顶层直落，否则归并为 还原_<原名>。
/// 返回 (目标路径, 条目数)。
pub fn place(
    tmp: &Path,
    vault_base: &str,
    out: &Path,
) -> io::Result<(PathBuf, usize)> {
    let staged = tmp.join("x");
    let tp = tmp.join("payload.tar");
    let (tops, count) = unpack(&tp, &staged)?;
    std::fs::create_dir_all(out)?;
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&staged)?
        .flatten()
        .map(|e| e.path())
        .collect();
    // 若 tar 顶层是空目录，read_dir 后目录也已存在
    if tops.len() == 1 {
        let dst = uniq(&out.join(&tops[0]));
        let src = staged.join(&tops[0]);
        match force_move(&src, &dst) {
            Ok(_) => {
                let _ = std::fs::remove_dir_all(&staged);
                return Ok((dst, count));
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&staged);
                return Err(e);
            }
        }
    }
    let name = format!(
        "还原_{}",
        safe_name(&crate::paths::strip_vault_ext(vault_base), 80)
    );
    let dst = uniq(&out.join(&name));
    std::fs::create_dir_all(&dst)?;
    if entries.is_empty() {
        // read_dir 过早（或顶层仅空目录已被创建）
        entries = std::fs::read_dir(&staged)?.flatten().map(|e| e.path()).collect();
    }
    for en in entries {
        let bn = en
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let _ = force_move(&en, &dst.join(&bn));
    }
    let _ = std::fs::remove_dir_all(&staged);
    Ok((dst, count))
}

#[allow(dead_code)]
fn _noop(_: &Path) {}

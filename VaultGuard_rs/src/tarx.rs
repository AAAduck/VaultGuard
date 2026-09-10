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
        append_one(b, abs, arc, false)?;
        Ok(())
    } else if ft.is_dir() {
        append_one(b, abs, arc, true)?;
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

/// 将已经展开的文件树条目按指定归档路径写入 tar。
/// VGS2 保存使用它：只打包本次新增的 staged 条目，避免读取旧数据段。
pub fn pack_entries_to_writer<W: Write>(items: &[(PathBuf, String, bool)], w: W) -> io::Result<()> {
    let mut b = tar::Builder::new(w);
    for (src, arc, is_dir) in items {
        append_one(&mut b, src, arc, *is_dir)?;
    }
    b.finish()?;
    Ok(())
}

/// 把多个根条目（含目录递归）打包进一个 tar。VGS2 批量暂存用：add 时把本次
/// 新增的所有文件合并成单个 tar，保存时作为一段加密，避免逐文件小读写。
pub fn pack_recursive_entries<W: Write>(items: &[(PathBuf, String)], w: W) -> io::Result<()> {
    let mut b = tar::Builder::new(w);
    for (src, arc) in items {
        append_recursive(&mut b, src, arc)?;
    }
    b.finish()?;
    Ok(())
}

/// 统计路径的纯文件数据字节（目录递归求和）。供分批打包估算段大小。
fn path_data_bytes(p: &Path) -> u64 {
    let md = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(_) => return 0,
    };
    if md.is_dir() {
        let mut sum = 0u64;
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                sum += path_data_bytes(&e.path());
            }
        }
        sum
    } else if md.is_file() {
        md.len()
    } else {
        0
    }
}

/// 把多个根条目按纯文件字节分批打包成多个 tar（每批 ≤ `target` 字节，
/// 单个条目超过上限时独占一批）。返回 (tar 路径, 该 tar 包含的条目下标)。
/// VGS2 批量暂存用：add 时按段大小拆分，保存时各批并行加密为独立数据段。
/// `tag` 用于区分同一次会话中的多批 add（同目录下避免互相覆盖）。
pub fn pack_split_tars(
    items: &[(PathBuf, String)],
    target: u64,
    dir: &Path,
    tag: u64,
) -> io::Result<Vec<(PathBuf, Vec<usize>)>> {
    std::fs::create_dir_all(dir)?;
    let mut out: Vec<(PathBuf, Vec<usize>)> = Vec::new();
    let mut cur_path: Option<PathBuf> = None;
    let mut cur: Option<tar::Builder<std::fs::File>> = None;
    let mut cur_items: Vec<usize> = Vec::new();
    let mut cur_bytes: u64 = 0;
    let mut file_idx: u64 = 0;
    for (i, (src, arc)) in items.iter().enumerate() {
        let sz = path_data_bytes(src);
        if cur.is_some() && cur_bytes > 0 && cur_bytes.saturating_add(sz) > target {
            // 封尾当前 tar
            cur.take().expect("cur").finish()?;
            out.push((cur_path.take().expect("path"), std::mem::take(&mut cur_items)));
            cur_bytes = 0;
        }
        if cur.is_none() {
            let p = dir.join(format!("{tag:08x}-{file_idx:08x}.tar"));
            file_idx += 1;
            cur_path = Some(p.clone());
            cur = Some(tar::Builder::new(std::fs::File::create(&p)?));
        }
        append_recursive(cur.as_mut().expect("cur"), src, arc)?;
        cur_items.push(i);
        cur_bytes = cur_bytes.saturating_add(sz);
    }
    if let Some(mut b) = cur.take() {
        b.finish()?;
        out.push((cur_path.take().expect("path"), std::mem::take(&mut cur_items)));
    }
    Ok(out)
}

fn append_one<W: Write>(b: &mut tar::Builder<W>, abs: &Path, arc: &str, is_dir: bool) -> io::Result<()> {
    let md = std::fs::symlink_metadata(abs)?;
    if is_dir != md.is_dir() || (!is_dir && !md.is_file()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "暂存条目类型已变化"));
    }
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(if is_dir { tar::EntryType::Directory } else { tar::EntryType::file() });
    header.set_size(if is_dir { 0 } else { md.len() });
    header.set_mode(if is_dir { 0o755 } else { 0o644 });
    if let Ok(t) = md.modified() {
        if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
            header.set_mtime(d.as_secs());
        }
    }
    if is_dir {
        b.append_data(&mut header, arc, io::empty())?;
    } else {
        // BufReader：tar crate 内部用 8 KiB 小片 io::copy 读源文件，
        // 包一层大缓冲避免每 8 KiB 一次系统调用（大文件打包的吞吐瓶颈）。
        let f = std::io::BufReader::with_capacity(1 << 20, File::open(abs)?);
        b.append_data(&mut header, arc, f)?;
    }
    Ok(())
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

/// 从一个已认证的临时 tar 提取指定文件。目标路径由调用者从已认证 manifest
/// 生成；tar 内未匹配条目一律忽略，避免整段物化。
pub fn extract_files(tp: &Path, wanted: &[(String, PathBuf)]) -> io::Result<usize> {
    let mut want = std::collections::BTreeMap::new();
    for (tar_path, dst) in wanted {
        want.insert(tar_path.as_str(), dst);
    }
    let f = File::open(tp)?;
    // tar crate 的条目读取用 8 KiB 小片，包 BufReader 避免逐片系统调用。
    let mut ar = tar::Archive::new(std::io::BufReader::with_capacity(1 << 20, f));
    let mut n = 0usize;
    for entry in ar.entries()? {
        let mut e = entry?;
        let raw = e.path()?.to_string_lossy().to_string();
        let name = raw.trim_matches('/').to_string();
        let Some(dst) = want.get(name.as_str()) else { continue };
        // 即使匹配，也校验 tar 的原始路径，防止解析器在后续改动时绕过路径边界。
        let _ = sanitize_rel(&name)?;
        if !e.header().entry_type().is_file() {
            continue;
        }
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = std::io::BufWriter::with_capacity(1 << 20, File::create(dst)?);
        std::io::copy(&mut e, &mut out)?;
        out.flush()?;
        n += 1;
    }
    Ok(n)
}

/// 转发批的明文载体：小批驻留内存（供并行加密），超大批落盘（调用方流式串行处理）。
#[derive(Debug)]
pub enum BatchPlain {
    Mem(Vec<u8>),
    Disk(PathBuf),
}

/// 一批转发结果：明文载体 + 该批包含的转发后路径（供调用方建立 arc→段 映射）。
#[derive(Debug)]
pub struct RelayBatch {
    pub plain: BatchPlain,
    pub arcs: Vec<String>,
}

impl BatchPlain {
    /// 该批明文字节数（用于调用方的内存预算）。
    pub fn len(&self) -> u64 {
        match self {
            BatchPlain::Mem(v) => v.len() as u64,
            BatchPlain::Disk(p) => std::fs::metadata(p).map(|m| m.len()).unwrap_or(0),
        }
    }
}

/// 封一个内存批：补 tar 尾部并交给回调。
fn seal_mem<F>(cur: &mut Option<(tar::Builder<Vec<u8>>, Vec<String>)>, on_batch: &mut F) -> io::Result<()>
where
    F: FnMut(RelayBatch) -> io::Result<()>,
{
    if let Some((b, arcs)) = cur.take() {
        let buf = b.into_inner()?; // 写入 tar 尾部并取回缓冲
        on_batch(RelayBatch { plain: BatchPlain::Mem(buf), arcs })?;
    }
    Ok(())
}

/// 从已认证的临时 tar 把存活条目转发成多个大小受控的明文批。
///
/// 批在内存中累积：`target` 为封批目标（≈ 段大小），`mem_cap` 为单批内存上限。
/// 单个条目本身就超过 `mem_cap` 时该条目独占一批并落盘到 `spill_dir`，由调用方
/// 流式串行处理 —— 既保住「整段进内存」的内存有界性，又不为常规条目多写一份
/// 明文临时文件（明文临时文件意味着额外一次写 + 一次覆写擦除）。
/// 每批就绪即回调 `on_batch`；返回转发条目数。
pub fn relay_files_batched<F>(
    tp: &Path,
    wanted: &[(String, String)],
    target: u64,
    mem_cap: u64,
    spill_dir: &Path,
    on_batch: &mut F,
) -> io::Result<usize>
where
    F: FnMut(RelayBatch) -> io::Result<()>,
{
    let mut map = std::collections::BTreeMap::new();
    for (from, to) in wanted {
        map.insert(from.as_str(), to.as_str());
    }
    let f = File::open(tp)?;
    let mut ar = tar::Archive::new(std::io::BufReader::with_capacity(1 << 20, f));
    let mut cur: Option<(tar::Builder<Vec<u8>>, Vec<String>)> = None;
    let mut spill_idx = 0u64;
    let mut n = 0usize;
    for entry in ar.entries()? {
        let e = entry?;
        let raw = e.path()?.to_string_lossy().to_string();
        let name = raw.trim_matches('/').to_string();
        let Some(to) = map.get(name.as_str()).copied() else { continue };
        let _ = sanitize_rel(&name)?;
        if !e.header().entry_type().is_file() {
            continue;
        }
        // 该条目在段内的近似字节数（头 512B + 数据按 512 对齐）
        let entry_bytes = 512 + e.header().size().unwrap_or(0).div_ceil(512) * 512;
        // 1) 单个条目超过内存上限：独占一批并落盘（调用方流式处理）
        if entry_bytes > mem_cap {
            seal_mem(&mut cur, on_batch)?;
            std::fs::create_dir_all(spill_dir)?;
            let p = spill_dir.join(format!("spill-{spill_idx:05}.tar"));
            spill_idx += 1;
            let mut b = tar::Builder::new(File::create(&p)?);
            let mut header = e.header().clone();
            b.append_data(&mut header, to, e)?;
            b.finish()?;
            on_batch(RelayBatch { plain: BatchPlain::Disk(p), arcs: vec![to.to_string()] })?;
            n += 1;
            continue;
        }
        // 2) 当前内存批装不下 → 先封批
        let over = cur.as_ref().map(|(b, _)| b.get_ref().len() as u64 + entry_bytes > mem_cap).unwrap_or(false);
        if over {
            seal_mem(&mut cur, on_batch)?;
        }
        // 3) 追加到内存批
        if cur.is_none() {
            cur = Some((tar::Builder::new(Vec::with_capacity(1 << 20)), Vec::new()));
        }
        let (b, arcs) = cur.as_mut().expect("cur");
        let mut header = e.header().clone();
        b.append_data(&mut header, to, e)?;
        arcs.push(to.to_string());
        n += 1;
        // 4) 达到封批目标 → 交批
        if b.get_ref().len() as u64 >= target {
            seal_mem(&mut cur, on_batch)?;
        }
    }
    seal_mem(&mut cur, on_batch)?;
    Ok(n)
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
    place_inner(tmp, vault_base, out, None)
}

/// 把已经按原始相对路径物化的目录落位。与 `place` 保持同一单顶层/多顶层语义，
/// 供 VGS2 按需解密后的临时树使用。
pub fn place_tree(tree: &Path, vault_base: &str, out: &Path) -> io::Result<(PathBuf, usize)> {
    std::fs::create_dir_all(out)?;
    let mut tops: Vec<PathBuf> = std::fs::read_dir(tree)?.flatten().map(|e| e.path()).collect();
    tops.sort();
    if tops.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "没有匹配的条目可落位"));
    }
    let total = count_tree_entries(tree);
    if tops.len() == 1 {
        let name = tops[0].file_name().unwrap_or_default();
        let dst = uniq(&out.join(name));
        force_move(&tops[0], &dst)?;
        return Ok((dst, total));
    }
    let name = format!(
        "还原_{}",
        safe_name(&crate::paths::strip_vault_ext(vault_base), 80)
    );
    let dst = uniq(&out.join(name));
    std::fs::create_dir_all(&dst)?;
    for top in tops {
        let name = top.file_name().unwrap_or_default().to_owned();
        force_move(&top, &dst.join(name))?;
    }
    Ok((dst, total))
}

fn count_tree_entries(dir: &Path) -> usize {
    let mut n = 0usize;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            n += 1;
            let p = e.path();
            if p.is_dir() {
                n += count_tree_entries(&p);
            }
        }
    }
    n
}

/// 选择性落位：只把 selected 中列出的顶层条目从 tar 落位到 out。
/// 落位策略与 place 一致：单顶层直落，否则归并到 还原_<原名>/ 下。
/// 返回 (目标路径, 实际落位条目数)。
pub fn place_filtered(
    tmp: &Path,
    vault_base: &str,
    out: &Path,
    selected: &[String],
) -> io::Result<(PathBuf, usize)> {
    place_inner(tmp, vault_base, out, Some(selected))
}

fn place_inner(
    tmp: &Path,
    vault_base: &str,
    out: &Path,
    filter: Option<&[String]>,
) -> io::Result<(PathBuf, usize)> {
    let staged = tmp.join("x");
    let tp = tmp.join("payload.tar");
    let (tops, total) = unpack(&tp, &staged)?;
    std::fs::create_dir_all(out)?;

    // 选中的顶层条目；filter=None 表示全选
    let sel_tops: Vec<String> = match filter {
        None => tops.clone(),
        Some(sel) => tops
            .iter()
            .filter(|t| sel.contains(*t))
            .cloned()
            .collect(),
    };
    if sel_tops.is_empty() {
        let _ = std::fs::remove_dir_all(&staged);
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "没有匹配的条目可落位",
        ));
    }

    let mut moved = 0usize;
    // 单顶层（且未过滤或过滤后仍为 1）→ 直接落位到 out/原名
    if sel_tops.len() == 1 {
        let dst = uniq(&out.join(&sel_tops[0]));
        let src = staged.join(&sel_tops[0]);
        match force_move(&src, &dst) {
            Ok(_) => {
                let _ = std::fs::remove_dir_all(&staged);
                // 无过滤时保持旧语义：返回 tar 总条目数；过滤时返回实际落位顶层条目数
                return Ok((dst, if filter.is_none() { total } else { 1 }));
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&staged);
                return Err(e);
            }
        }
    }

    // 多顶层 → 归并到 还原_<原名>/ 下
    let name = format!(
        "还原_{}",
        safe_name(&crate::paths::strip_vault_ext(vault_base), 80)
    );
    let dst = uniq(&out.join(&name));
    std::fs::create_dir_all(&dst)?;
    for top in &sel_tops {
        let src = staged.join(top);
        if !src.exists() {
            continue;
        }
        let _ = force_move(&src, &dst.join(top));
        moved += 1;
    }
    let _ = std::fs::remove_dir_all(&staged);
    // 无过滤时保持旧语义：返回 tar 总条目数；过滤时返回实际落位顶层条目数
    Ok((dst, if filter.is_none() { total } else { moved }))
}

#[allow(dead_code)]
fn _noop(_: &Path) {}

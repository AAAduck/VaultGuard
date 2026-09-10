//! .vgsafe 隐私保险箱。
//!
//! VGS1 是历史整箱 GCM(tar) 格式，仍可打开；VGS2 使用已认证的独立 manifest 和
//! 追加式数据段。打开 VGS2 只读取 manifest，数据仅在导出或压缩时按需、流式解密。

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::crypto::{ct_eq, derive_v3, ArgonParams, Gcm, NONCE_SZ, TAG_SZ};
use crate::paths::{cleanup, mktmpdir, safe_name, uniq};
use crate::profile;
use crate::{tarx, vgs2};

/// 历史 VGS1 格式常量，保留给还原路径和兼容性测试。
pub const MAGIC: &[u8; 4] = b"VGS1";
pub const SAFE_EXT: &str = ".vgsafe";
pub const KDF_ARGON2ID: u8 = 0x01;
pub const AAD: &[u8] = b"VGS1";
const V1_HDR_SZ: usize = 4 + 1 + 4 + 4 + 1 + 16 + NONCE_SZ;
const IO_BLOCK: usize = 1 << 20;
const AUTO_GC_MIN_BYTES: u64 = 256 * 1024 * 1024;
const AUTO_GC_MANIFESTS: usize = 32;
/// 数据段大小目标（并行加密的分批粒度；单个超大文件可独占一段）。
const SEG_TARGET: u64 = 64 * 1024 * 1024;
/// 超过该字节的段退回流式串行加密（避免整段明文进内存）。
const PARALLEL_MEM_CAP: u64 = 128 * 1024 * 1024;
/// 并行加密时同时驻留内存的明文总量上限（一批 ≈ [`SEG_TARGET`]，8 worker 恰好用满）。
const PARALLEL_BUF_BUDGET: u64 = 512 * 1024 * 1024;

/// 并行 worker 数：物理核封顶 8（SMT 上超线程对加密提升有限）。
fn worker_count() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(8)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
}

#[derive(Clone)]
enum Source {
    /// 已落盘的 VGS2 数据段，tar_path 是段内的原始归档路径。
    Existing { seg: u64, tar_path: String },
    /// 本次会话暂存的批量 tar（add 时把整批新增打包成一个文件）；
    /// arc 是该条目在暂存 tar 内的路径。保存时整段加密，避免逐文件小读写。
    StagedTar { tar: PathBuf, arc: String },
    /// VGS1 打开时的临时工作树。第一次保存会全量升级到 VGS2。
    Legacy(PathBuf),
    /// 目录不占数据段；manifest 本身保留其存在与层级。
    Dir,
}

#[derive(Clone)]
struct Node {
    size: u64,
    is_dir: bool,
    mtime: i64,
    source: Source,
}

enum Storage {
    New,
    LegacyV1,
    V2 {
        key: [u8; 32],
        /// 只保留最后一个已认证 manifest 为止的段；其后的断电残留下次保存会截掉。
        segments: Vec<vgs2::SegmentMeta>,
        manifest_count: usize,
    },
}

/// 打开的保险箱。VGS2 会话不含旧内容的明文工作树，`staged` 仅保存尚未入箱的新副本。
pub struct Session {
    pub path: PathBuf,
    pass: String,
    staged: PathBuf,
    /// VGS1 会话保留解密出的明文 tar（升级保存时整段转发，避免逐文件重打包）。
    legacy_tar: Option<PathBuf>,
    nodes: BTreeMap<String, Node>,
    pub entries: Vec<Entry>,
    storage: Storage,
    dirty: bool,
    next_stage: u64,
}

impl Drop for Session {
    fn drop(&mut self) {
        cleanup(&self.staged);
    }
}

/// 新建空 VGS2 保险箱。
pub fn create(path: &Path, pass: &str) -> io::Result<Session> {
    if pass.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "口令不能为空"));
    }
    if path.exists() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "文件已存在"));
    }
    let staged = mktmpdir();
    std::fs::create_dir_all(staged.join("adds"))?;
    let mut s = Session {
        path: path.to_path_buf(),
        pass: pass.to_string(),
        staged,
        legacy_tar: None,
        nodes: BTreeMap::new(),
        entries: Vec::new(),
        storage: Storage::New,
        dirty: true,
        next_stage: 1,
    };
    if let Err(e) = s.save(&|_| {}) {
        return Err(e);
    }
    Ok(s)
}

/// 按文件头分派打开 VGS1 / VGS2。
pub fn open(path: &Path, pass: &str) -> io::Result<Session> {
    if pass.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "口令不能为空"));
    }
    let mut f = File::open(path)?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)?;
    if &magic == vgs2::MAGIC {
        open_v2(path, pass)
    } else if &magic == MAGIC {
        open_v1(path, pass)
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, "不是 VaultGuard 保险箱文件"))
    }
}

fn open_v2(path: &Path, pass: &str) -> io::Result<Session> {
    let mut f = File::open(path)?;
    let mut hdr = [0u8; vgs2::HDR_SZ];
    f.read_exact(&mut hdr)?;
    let (_, m, t, p, salt, _) = vgs2::decode_header(&hdr)?;
    let key = profile::phase("kdf", || derive_v3(pass.as_bytes(), &salt, ArgonParams { m_kib: m, t, p }))?;
    let all_segments = profile::phase("scan", || vgs2::scan_segments(&mut f))?;

    // manifest 可能已完整写头、但未写完 tag 或被损坏。由后向前尝试已结构化的
    // manifest，认证失败时回退到上一份；错误口令则所有 manifest 都会失败。
    let mut last_err: Option<io::Error> = None;
    let opened = profile::phase("manifest-open", || {
        for i in (0..all_segments.len()).rev() {
            let seg = all_segments[i];
            if seg.head.seg_type != vgs2::SEG_MANIFEST {
                continue;
            }
            match vgs2::read_manifest_segment(&mut f, seg, &key)
                .and_then(|b| vgs2::decode_manifest(&b))
                .and_then(|m| nodes_from_manifest(m, &all_segments[..=i]))
            {
                Ok(nodes) => return Ok::<_, io::Error>((nodes, i)),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "未找到有效 manifest")))
    });
    let (nodes, manifest_i) = opened?;
    let staged = mktmpdir();
    std::fs::create_dir_all(staged.join("adds"))?;
    let mut s = Session {
        path: path.to_path_buf(),
        pass: pass.to_string(),
        staged,
        legacy_tar: None,
        nodes,
        entries: Vec::new(),
        storage: Storage::V2 {
            key,
            segments: all_segments[..=manifest_i].to_vec(),
            manifest_count: all_segments[..=manifest_i]
                .iter()
                .filter(|x| x.head.seg_type == vgs2::SEG_MANIFEST)
                .count(),
        },
        dirty: false,
        next_stage: 1,
    };
    s.refresh_entries();
    Ok(s)
}

/// VGS1 兼容打开。旧格式没有独立索引，必须解密一次；保存时自动升级到 VGS2。
fn open_v1(path: &Path, pass: &str) -> io::Result<Session> {
    let staged = mktmpdir();
    let staged_for_session = staged.clone();
    std::fs::create_dir_all(staged_for_session.join("adds"))?;
    let result = (|| -> io::Result<Session> {
        let tar = staged_for_session.join("legacy_payload.tar");
        {
            let mut out = File::create(&tar)?;
            read_verify_v1(path, pass, &mut out, &|_, _| {})?;
        }
        let tree = staged_for_session.join("legacy_tree");
        tarx::unpack_file(&tar, &tree)?;
        // 保留明文 tar：升级保存时整段转发为数据段，避免对工作树逐文件重打包
        let nodes = collect_legacy_nodes(&tree)?;
        let mut s = Session {
            path: path.to_path_buf(),
            pass: pass.to_string(),
            staged: staged_for_session,
            legacy_tar: Some(tar),
            nodes,
            entries: Vec::new(),
            storage: Storage::LegacyV1,
            dirty: false,
            next_stage: 1,
        };
        s.refresh_entries();
        Ok(s)
    })();
    if result.is_err() {
        cleanup(&staged);
    }
    result
}

impl Session {
    fn refresh_entries(&mut self) {
        self.entries = self
            .nodes
            .iter()
            .map(|(name, n)| Entry {
                name: name.clone(),
                size: n.size,
                is_dir: n.is_dir,
            })
            .collect();
    }

    /// 刷新活跃标记（GUI 每 30 秒调用）。
    pub fn touch(&self) -> io::Result<()> {
        crate::paths::touch_active(&self.staged)
    }

    /// GUI 用于在旧格式第一次会改变容器前请求明确确认。
    pub fn is_legacy_v1(&self) -> bool {
        matches!(self.storage, Storage::LegacyV1)
    }

    pub fn add_paths(&mut self, srcs: &[PathBuf]) -> io::Result<usize> {
        self.add_paths_impl(srcs, false)
    }

    pub fn add_paths_organized(&mut self, srcs: &[PathBuf]) -> io::Result<usize> {
        self.add_paths_impl(srcs, true)
    }

    fn add_paths_impl(&mut self, srcs: &[PathBuf], organize: bool) -> io::Result<usize> {
        let mut added = 0usize;
        let mut pack_items: Vec<(PathBuf, String)> = Vec::new();
        // (name, is_dir, size, mtime, arc, item_idx)：item_idx 定位该条目所属的暂存 tar
        let mut entry_infos: Vec<(String, bool, u64, i64, String, usize)> = Vec::new();
        // 本批次已占用的名字（节点要打包后才插入，重名去重需要提前记账；
        // 除顶层名外还含目录源的子条目名，防止「文件夹 A 的 x.txt」与
        // 单独拖入的 A/x.txt 在本批次内撞名）。
        let mut pending: BTreeSet<String> = BTreeSet::new();
        for src in srcs {
            if !src.exists() {
                continue;
            }
            let item_idx = pack_items.len();
            let raw = src
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "item".to_string());
            let base = safe_name(&raw, 100);
            let mut parent = if organize && src.is_file() {
                category_of(&raw).to_string()
            } else {
                String::new()
            };
            if !parent.is_empty()
                && self.nodes.get(&parent).is_some_and(|n| !n.is_dir)
            {
                parent = self.unique_path(&parent);
            }
            if !parent.is_empty() {
                self.ensure_dirs(&parent)?;
            }
            let wanted = if parent.is_empty() { base } else { format!("{parent}/{base}") };
            let target = self.unique_path_pending(&wanted, &pending);
            pending.insert(target.clone());
            self.ensure_parent_dirs(&target)?;
            pack_items.push((src.clone(), target.clone()));
            let start = entry_infos.len();
            collect_src_entries(src, &target, &mut entry_infos, item_idx)?;
            for (name, ..) in &entry_infos[start..] {
                pending.insert(name.clone());
            }
            added += 1;
        }
        if added > 0 {
            // 整批新增按段大小拆成多个暂存 tar：保存时各批并行加密为独立数据段，
            // 既避免逐文件小读写（1 万文件档实测可差一个数量级），又让加密可并行。
            // tag 递增保证同一会话多次 add 不会互相覆盖暂存 tar。
            let tag = self.next_stage;
            self.next_stage = self.next_stage.wrapping_add(1).max(1);
            let adds_dir = self.staged.join("adds");
            let tars = profile::phase("stage-pack", || {
                tarx::pack_split_tars(&pack_items, SEG_TARGET, &adds_dir, tag)
            })?;
            // item_idx -> 所属 tar
            let mut item_to_tar: Vec<Option<PathBuf>> = vec![None; pack_items.len()];
            for (tar, idxs) in &tars {
                for &i in idxs {
                    item_to_tar[i] = Some(tar.clone());
                }
            }
            for (name, is_dir, size, mtime, arc, item_idx) in entry_infos {
                let source = if is_dir {
                    Source::Dir
                } else {
                    let tar = item_to_tar[item_idx].clone().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "暂存条目缺少所属 tar")
                    })?;
                    Source::StagedTar { tar, arc }
                };
                self.nodes.insert(name, Node { size, is_dir, mtime, source });
            }
            self.dirty = true;
            self.refresh_entries();
        }
        Ok(added)
    }

    /// 移除条目及其子项；删除在 VGS2 中先从 manifest 隐藏，物理数据由压缩回收。
    pub fn remove_entries(&mut self, names: &[String]) -> io::Result<usize> {
        let mut removed = 0usize;
        for name in names {
            if !self.nodes.contains_key(name) {
                continue;
            }
            let prefix = format!("{name}/");
            let keys: Vec<String> = self
                .nodes
                .keys()
                .filter(|n| *n == name || n.starts_with(&prefix))
                .cloned()
                .collect();
            for key in keys {
                self.nodes.remove(&key);
            }
            removed += 1;
        }
        if removed > 0 {
            self.dirty = true;
            self.refresh_entries();
        }
        Ok(removed)
    }

    pub fn rename_entry(&mut self, from: &str, to: &str) -> io::Result<()> {
        if !valid_rel_path(from) || !valid_rel_path(to) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "路径不合法（不能为空/含 .. 或反斜杠）"));
        }
        if from == to {
            return Ok(());
        }
        if !self.nodes.contains_key(from) {
            return Err(io::Error::new(io::ErrorKind::NotFound, "条目不存在"));
        }
        if self.nodes.get(from).is_some_and(|n| n.is_dir) && to.starts_with(&format!("{from}/")) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "不能移动到自身子目录"));
        }
        let parent = parent_name(to);
        if !parent.is_empty() && !self.nodes.get(parent).is_some_and(|n| n.is_dir) {
            return Err(io::Error::new(io::ErrorKind::NotFound, "目标目录不存在（移动请用「移动」操作）"));
        }
        self.rename_nodes(from, to)?;
        self.dirty = true;
        self.refresh_entries();
        Ok(())
    }

    pub fn move_entry(&mut self, name: &str, dest_dir: &str) -> io::Result<()> {
        if !valid_rel_path(name) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "路径不合法"));
        }
        if !self.nodes.contains_key(name) {
            return Err(io::Error::new(io::ErrorKind::NotFound, "条目不存在"));
        }
        let clean = dest_dir.trim().trim_matches('/');
        if !clean.is_empty() && !valid_rel_path(clean) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "目标目录不合法"));
        }
        if self.nodes.get(name).is_some_and(|n| n.is_dir) && !clean.is_empty() && clean.starts_with(&format!("{name}/")) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "不能移动到自身子目录"));
        }
        if !clean.is_empty() {
            if self.nodes.get(clean).is_some_and(|n| !n.is_dir) {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "目标目录位置已被文件占用"));
            }
            self.ensure_dirs(clean)?;
        }
        let base = name.rsplit('/').next().unwrap_or(name);
        let plain = if clean.is_empty() { base.to_string() } else { format!("{clean}/{base}") };
        if plain == name {
            return Ok(());
        }
        let target = self.unique_path(&plain);
        self.rename_nodes(name, &target)?;
        self.dirty = true;
        self.refresh_entries();
        Ok(())
    }

    /// 写入本次变更。VGS2 增量保存只追加新的数据段和一份 manifest；旧格式/新口令
    /// 则走原子全量重写，且不把整个旧保险箱常驻物化到会话中。
    pub fn save(&mut self, prog: &dyn Fn(u8)) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        match self.storage {
            Storage::V2 { .. } => self.append_save(prog),
            Storage::New | Storage::LegacyV1 => self.rewrite_all_v2(prog),
        }
    }

    /// 手动「压缩」：仅保留当前可见条目，原子重写并回收删除/旧 manifest 的物理空间。
    pub fn compact(&mut self, prog: &dyn Fn(u8)) -> io::Result<()> {
        self.rewrite_all_v2(prog)
    }

    pub fn export(&self, out_root: &Path, prog: &dyn Fn(u64, u64)) -> io::Result<(PathBuf, usize)> {
        let tmp = mktmpdir();
        let result = (|| -> io::Result<(PathBuf, usize)> {
            let tree = tmp.join("tree");
            self.materialize(&self.nodes.keys().cloned().collect(), &tree, prog)?;
            let base = self.path.file_name().and_then(|x| x.to_str()).unwrap_or("vgsafe");
            tarx::place_tree(&tree, base, out_root)
        })();
        cleanup(&tmp);
        result
    }

    pub fn export_selective(&self, names: &[String], out_root: &Path) -> io::Result<usize> {
        std::fs::create_dir_all(out_root)?;
        let mut selected = BTreeSet::new();
        for name in names {
            if self.nodes.contains_key(name) {
                let prefix = format!("{name}/");
                for child in self.nodes.keys() {
                    if child == name || child.starts_with(&prefix) {
                        selected.insert(child.clone());
                    }
                }
            }
        }
        if selected.is_empty() {
            return Ok(0);
        }
        let tmp = mktmpdir();
        let result = (|| -> io::Result<usize> {
            let tree = tmp.join("tree");
            self.materialize(&selected, &tree, &|_, _| {})?;
            let mut n = 0usize;
            for name in names {
                let src = tree.join(name);
                if !src.exists() {
                    continue;
                }
                let dst = uniq(&out_root.join(rel_safe(name)));
                copy_recursive(&src, &dst)?;
                n += 1;
            }
            Ok(n)
        })();
        cleanup(&tmp);
        result
    }

    /// 更换口令必定原子全量重写，以新 Argon2 salt 与新主密钥加密全部存活数据。
    pub fn change_password(&mut self, new_pass: &str) -> io::Result<()> {
        if new_pass.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "口令不能为空"));
        }
        let old = std::mem::replace(&mut self.pass, new_pass.to_string());
        let result = self.rewrite_all_v2(&|_| {});
        if result.is_err() {
            self.pass = old;
        }
        result
    }

    fn append_save(&mut self, prog: &dyn Fn(u8)) -> io::Result<()> {
        let (key, prior, count) = match &self.storage {
            Storage::V2 { key, segments, manifest_count } => (*key, segments.clone(), *manifest_count),
            _ => unreachable!(),
        };
        let mut f = OpenOptions::new().read(true).write(true).open(&self.path)?;
        let end = logical_end(&prior)?;
        // 上次崩溃的半段不属于已提交版本，可安全截掉；旧 manifest 仍在 end 之前。
        profile::phase("truncate", || f.set_len(end))?;
        let mut segments = prior;
        let mut next = segments.last().map(|s| s.head.seq + 1).unwrap_or(1);
        // 暂存条目按「暂存 tar」分组 —— 每个暂存 tar 直接作为一个数据段（其内容
        // 即该批文件的 tar 流），攒够 worker 个后并行加密、按序号顺序写回。
        let mut staged_tars: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();
        for node in self.nodes.values() {
            if let Source::StagedTar { tar, arc } = &node.source {
                staged_tars.entry(tar.clone()).or_default().push(arc.clone());
            }
        }
        // 先在副本上准备本次提交后的索引。只有新 manifest 已完整写入并同步后，
        // 才将它换入会话；这样数据段成功、manifest 失败时，下次保存仍会从暂存
        // 文件重新追加数据，而不会引用稍后被截掉的半次提交。
        let mut committed_nodes = self.nodes.clone();
        if !staged_tars.is_empty() {
            let total: u64 = self
                .nodes
                .values()
                .filter(|n| matches!(n.source, Source::StagedTar { .. }))
                .map(|n| n.size)
                .sum();
            let mut done = 0u64;
            let mut last = 0u8;
            let workers = worker_count();
            let (arc_to_seg, metas, next_after) = profile::phase("data-write", || {
                let mut sink = SegSink::new(&mut f, key, next, self.staged.join("batches"), workers);
                // 暂存 tar 内容已是「该段明文」，直接进并行加密队列；
                // 超过 PARALLEL_MEM_CAP 的段（单个超大文件）走流式串行，避免整段进内存。
                for (tar, arcs) in &staged_tars {
                    let sz = std::fs::metadata(tar).map(|m| m.len()).unwrap_or(0);
                    if sz <= PARALLEL_MEM_CAP {
                        // 暂存 tar 内容已是「该段明文」，读入内存后进并行加密队列
                        let data = std::fs::read(tar)?;
                        sink.push(tarx::BatchPlain::Mem(data), arcs.clone())?;
                    } else {
                        sink.stream_file(tar, arcs)?;
                    }
                    done = done.saturating_add(sz);
                    report_pct(prog, &mut last, done, total);
                }
                sink.finish()?;
                Ok::<_, io::Error>((sink.arc_to_seg, sink.segs, sink.next))
            })?;
            next = next_after;
            for node in committed_nodes.values_mut() {
                if let Source::StagedTar { arc, .. } = &node.source {
                    let seg = arc_to_seg.get(arc).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "暂存条目缺少对应数据段"))?;
                    node.source = if node.is_dir {
                        Source::Dir
                    } else {
                        Source::Existing { seg: *seg, tar_path: arc.clone() }
                    };
                }
            }
            segments.extend(metas);
        }
        let manifest = make_manifest_for(&committed_nodes)?;
        if manifest.len() as u64 > vgs2::MAX_MANIFEST_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "manifest 超出打开安全上限"));
        }
        let manifest_seg = profile::phase("manifest-write", || {
            vgs2::append_stream_segment(
                &mut f,
                vgs2::SEG_MANIFEST,
                next,
                &key,
                random_bytes::<NONCE_SZ>(),
                |w| w.write_all(&manifest),
            )
        })?;
        segments.push(manifest_seg);
        profile::phase("fsync", || f.sync_all())?;
        self.nodes = committed_nodes;
        self.storage = Storage::V2 { key, segments, manifest_count: count + 1 };
        self.dirty = false;
        self.clear_staged_adds();
        self.refresh_entries();
        prog(100);
        if self.gc_needed()? {
            self.rewrite_all_v2(prog)?;
        }
        Ok(())
    }

    fn rewrite_all_v2(&mut self, prog: &dyn Fn(u8)) -> io::Result<()> {
        let tmp = self.path.with_extension("vgsafe.tmp");
        cleanup(&tmp);
        let work = mktmpdir();
        let result = (|| -> io::Result<([u8; 32], Vec<vgs2::SegmentMeta>, BTreeMap<String, Node>)> {
            // 分组：已落盘条目按数据段归类（转发）；暂存条目按暂存 tar 归类（整段直用）；
            // 旧格式条目由保留的明文 tar 整段转发。不再物化整棵明文树 ——
            // 压缩/升级只读存活条目，省去树写、树读与树擦除。
            let mut seg_groups: BTreeMap<u64, Vec<(String, String)>> = BTreeMap::new();
            let mut staged_arcs: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();
            // 旧格式条目：(明文 tar 内原路径 → 转发后路径 = 当前可见名)。
            // 升级前可能已重命名/移动，源路径取节点工作树相对路径。
            let mut legacy_wanted: Vec<(String, String)> = Vec::new();
            let legacy_root = self.staged.join("legacy_tree");
            for (name, node) in &self.nodes {
                match &node.source {
                    Source::Existing { seg, tar_path } => {
                        // 段内条目路径与可见名相互独立：转发时保持 tar_path 不变
                        seg_groups.entry(*seg).or_default().push((tar_path.clone(), tar_path.clone()));
                    }
                    Source::StagedTar { tar, arc } => {
                        staged_arcs.entry(tar.clone()).or_default().push(arc.clone());
                    }
                    Source::Legacy(p) => {
                        let rel = p.strip_prefix(&legacy_root).unwrap_or(p).to_string_lossy().replace('\\', "/");
                        legacy_wanted.push((rel, name.clone()));
                    }
                    Source::Dir => {}
                }
            }
            let legacy_tar = self.legacy_tar.clone();
            let old_key = self.v2_key();
            let seg_map = self.segment_map();
            let container = self.path.clone();
            let salt = random_bytes::<16>();
            let reserve_nonce = random_bytes::<NONCE_SZ>();
            let prm = ArgonParams::default();
            let key = profile::phase("kdf", || derive_v3(self.pass.as_bytes(), &salt, prm))?;
            let mut f = File::create(&tmp)?;
            f.write_all(&vgs2::encode_header(vgs2::KID_ARGON2ID, prm.m_kib, prm.t, prm.p, &salt, &reserve_nonce)?)?;
            let file_count: usize = seg_groups.values().map(|v| v.len()).sum::<usize>()
                + staged_arcs.values().map(|v| v.len()).sum::<usize>()
                + legacy_wanted.len();
            let mut segs: Vec<vgs2::SegmentMeta> = Vec::new();
            let mut new_nodes = self.nodes.clone();
            let mut next = 1u64;
            let workers = worker_count();
            if file_count > 0 {
                let mut done = 0u64;
                let mut last = 0u8;
                let total: u64 = self.nodes.values().filter(|n| !n.is_dir).map(|n| n.size).sum();
                let (arc_to_seg, metas, next_after) = profile::phase("data-write", || {
                    let mut sink = SegSink::new(&mut f, key, 1, work.join("batches"), workers);
                    // 1) 旧数据段：按 worker 波浪「并行解密 → 分批转发」。一波的明文
                    //    只驻留到该波转发结束，避免整箱明文同时落盘。
                    let seg_list: Vec<(u64, Vec<(String, String)>)> = seg_groups.into_iter().collect();
                    for chunk in seg_list.chunks(workers.max(1)) {
                        let payloads = decrypt_wave(chunk, &seg_map, old_key, &work, &container)?;
                        for (_, payload, wanted) in &payloads {
                            let n = sink.relay(payload, wanted)?;
                            done = done.saturating_add(n as u64);
                            report_pct(prog, &mut last, done, total);
                            cleanup(payload);
                        }
                    }
                    // 2) 旧格式明文 tar 整段转发（源路径 → 当前可见名）
                    if !legacy_wanted.is_empty() {
                        let lt = legacy_tar.clone().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "旧格式会话缺少明文 tar"))?;
                        let n = sink.relay(&lt, &legacy_wanted)?;
                        if n != legacy_wanted.len() {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "旧格式 tar 缺少所列条目"));
                        }
                        done = done.saturating_add(n as u64);
                        report_pct(prog, &mut last, done, total);
                    }
                    // 3) 暂存 tar：内容即该段明文，直接攒批并行加密
                    for (tar, arcs) in staged_arcs {
                        let sz = std::fs::metadata(&tar).map(|m| m.len()).unwrap_or(0);
                        if sz <= PARALLEL_MEM_CAP {
                            let data = std::fs::read(&tar)?;
                            sink.push(tarx::BatchPlain::Mem(data), arcs)?;
                        } else {
                            sink.stream_file(&tar, &arcs)?;
                        }
                        done = done.saturating_add(sz);
                        report_pct(prog, &mut last, done, total);
                    }
                    sink.finish()?;
                    Ok::<_, io::Error>((sink.arc_to_seg, sink.segs, sink.next))
                })?;
                segs = metas;
                next = next_after;
                for (name, node) in &mut new_nodes {
                    if !node.is_dir {
                        let arc = match &node.source {
                            Source::Existing { tar_path, .. } => tar_path.clone(),
                            Source::StagedTar { arc, .. } => arc.clone(),
                            Source::Legacy(_) => name.clone(),
                            Source::Dir => unreachable!(),
                        };
                        let seg = arc_to_seg.get(&arc).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "条目缺少对应数据段"))?;
                        node.source = Source::Existing { seg: *seg, tar_path: arc };
                    }
                }
            }
            for node in new_nodes.values_mut() {
                if node.is_dir {
                    node.source = Source::Dir;
                }
            }
            let manifest = make_manifest_for(&new_nodes)?;
            let ms = profile::phase("manifest-write", || {
                vgs2::append_stream_segment(
                    &mut f,
                    vgs2::SEG_MANIFEST,
                    next,
                    &key,
                    random_bytes::<NONCE_SZ>(),
                    |w| w.write_all(&manifest),
                )
            })?;
            segs.push(ms);
            profile::phase("fsync", || f.sync_all())?;
            profile::phase("verify", || verify_v2_container(&tmp, &key))?;
            Ok((key, segs, new_nodes))
        })();
        profile::phase("cleanup", || cleanup(&work));
        let (key, segments, nodes) = match result {
            Ok(x) => x,
            Err(e) => {
                cleanup(&tmp);
                return Err(e);
            }
        };
        profile::phase("replace", || replace_container(&tmp, &self.path))?;
        self.nodes = nodes;
        self.storage = Storage::V2 { key, segments, manifest_count: 1 };
        self.dirty = false;
        self.clear_staged_adds();
        self.refresh_entries();
        prog(100);
        Ok(())
    }

    /// 将所选条目按逻辑路径物化到一个短暂目录。最终落位永远发生在所有数据段认证后。
    fn materialize(
        &self,
        selected: &BTreeSet<String>,
        tree: &Path,
        prog: &dyn Fn(u64, u64),
    ) -> io::Result<()> {
        std::fs::create_dir_all(tree)?;
        let mut groups: BTreeMap<u64, Vec<(String, PathBuf)>> = BTreeMap::new();
        let mut tar_groups: BTreeMap<PathBuf, Vec<(String, PathBuf)>> = BTreeMap::new();
        let mut total = 0u64;
        for name in selected {
            let Some(node) = self.nodes.get(name) else { continue };
            let dst = tree.join(name);
            if node.is_dir {
                std::fs::create_dir_all(&dst)?;
                continue;
            }
            total = total.saturating_add(node.size);
            match &node.source {
                Source::Existing { seg, tar_path } => groups.entry(*seg).or_default().push((tar_path.clone(), dst)),
                Source::StagedTar { tar, arc } => tar_groups.entry(tar.clone()).or_default().push((arc.clone(), dst)),
                Source::Legacy(src) => {
                    if let Some(parent) = dst.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    copy_file_buffered(src, &dst)?;
                }
                Source::Dir => return Err(io::Error::new(io::ErrorKind::InvalidData, "文件缺少数据来源")),
            }
        }
        for (tar, wanted) in tar_groups {
            let n = tarx::extract_files(&tar, &wanted)?;
            if n != wanted.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "暂存 tar 缺少所列条目"));
            }
        }
        let seg_map = self.segment_map();
        let key = self.v2_key().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "旧格式数据段状态无效"))?;
        let container = self.path.clone();
        let tmp = tree.parent().unwrap_or(tree).join("segments");
        std::fs::create_dir_all(&tmp)?;
        let mut done = 0u64;
        let workers = worker_count();
        // 段间认证链独立：按 worker 波浪并行「解密 → 提取」，各线程写不同的落位路径。
        // 先解出本波全部明文（认证通过才算数），全员成功后再统一提取，避免半认证部分落位。
        let group_list: Vec<(u64, Vec<(String, PathBuf)>)> = groups.into_iter().collect();
        for chunk in group_list.chunks(workers.max(1)) {
            let mut payloads: Vec<(u64, PathBuf)> = Vec::with_capacity(chunk.len());
            std::thread::scope(|scope| -> io::Result<()> {
                let mut handles = Vec::with_capacity(chunk.len());
                for (seq, _) in chunk {
                    let seg = seg_map.get(seq).copied().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "manifest 引用了不存在的数据段")
                    })?;
                    let payload = tmp.join(format!("{seq}.tar"));
                    let container = container.clone();
                    let seq = *seq;
                    handles.push(scope.spawn(move || -> io::Result<(u64, PathBuf)> {
                        let mut out = File::create(&payload)?;
                        vgs2::decrypt_segment_to_file(&mut File::open(&container)?, seg, &key, &mut out)?;
                        drop(out);
                        Ok((seq, payload))
                    }));
                }
                for h in handles {
                    payloads.push(join_result(h)?);
                }
                Ok(())
            })?;
            for (seq, payload) in &payloads {
                let wanted = chunk
                    .iter()
                    .find(|(s, _)| s == seq)
                    .map(|(_, w)| w)
                    .expect("wave 与分组成对");
                let n = tarx::extract_files(payload, wanted)?;
                if n != wanted.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "数据段缺少 manifest 所列条目"));
                }
                done = done.saturating_add(wanted.iter().map(|(_, p)| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)).sum::<u64>());
                prog(done.min(total), total);
                cleanup(payload);
            }
        }
        cleanup(&tmp);
        prog(total, total);
        Ok(())
    }

    fn v2_key(&self) -> Option<[u8; 32]> {
        match &self.storage {
            Storage::V2 { key, .. } => Some(*key),
            _ => None,
        }
    }

    fn segment_map(&self) -> BTreeMap<u64, vgs2::SegmentMeta> {
        match &self.storage {
            Storage::V2 { segments, .. } => segments.iter().map(|s| (s.head.seq, *s)).collect(),
            _ => BTreeMap::new(),
        }
    }

    fn gc_needed(&self) -> io::Result<bool> {
        let Storage::V2 { segments, manifest_count, .. } = &self.storage else { return Ok(false) };
        let total = logical_end(segments)?;
        let live: BTreeSet<u64> = self.nodes.values().filter_map(|n| match n.source {
            Source::Existing { seg, .. } => Some(seg),
            _ => None,
        }).collect();
        let mut live_bytes = vgs2::HDR_SZ as u64;
        for seg in segments {
            if seg.head.seg_type == vgs2::SEG_DATA && live.contains(&seg.head.seq) {
                live_bytes = live_bytes.saturating_add(vgs2::segment_disk_len(*seg)?);
            }
        }
        let garbage_over_30 = total > 0 && total.saturating_sub(live_bytes) * 10 > total * 3;
        Ok((garbage_over_30 && total > AUTO_GC_MIN_BYTES) || *manifest_count >= AUTO_GC_MANIFESTS)
    }

    fn unique_path(&self, wanted: &str) -> String {
        self.unique_path_pending(wanted, &BTreeSet::new())
    }

    /// 同 unique_path，但额外避开 `pending` 中本批次已占用的名字
    /// （暂存条目打包后才写入 nodes，重名去重需要提前记账）。
    fn unique_path_pending(&self, wanted: &str, pending: &BTreeSet<String>) -> String {
        if !self.nodes.contains_key(wanted) && !pending.contains(wanted) {
            return wanted.to_string();
        }
        let (parent, base) = match wanted.rsplit_once('/') {
            Some((p, b)) => (format!("{p}/"), b),
            None => (String::new(), wanted),
        };
        let (stem, ext) = split_ext(base);
        let mut i = 2;
        loop {
            let test = format!("{parent}{stem}_{i}{ext}");
            if !self.nodes.contains_key(&test) && !pending.contains(&test) {
                return test;
            }
            i += 1;
        }
    }

    fn ensure_parent_dirs(&mut self, path: &str) -> io::Result<()> {
        let parent = parent_name(path);
        if parent.is_empty() { Ok(()) } else { self.ensure_dirs(parent) }
    }

    fn ensure_dirs(&mut self, dir: &str) -> io::Result<()> {
        let mut path = String::new();
        for part in dir.split('/') {
            path = if path.is_empty() { part.to_string() } else { format!("{path}/{part}") };
            match self.nodes.get(&path) {
                Some(n) if !n.is_dir => return Err(io::Error::new(io::ErrorKind::AlreadyExists, "目录位置已被文件占用")),
                Some(_) => {}
                None => {
                    self.nodes.insert(path.clone(), Node { size: 0, is_dir: true, mtime: now_secs(), source: Source::Dir });
                }
            }
        }
        Ok(())
    }

    fn rename_nodes(&mut self, from: &str, to: &str) -> io::Result<()> {
        let prefix = format!("{from}/");
        let affected: Vec<(String, Node)> = self
            .nodes
            .iter()
            .filter(|(n, _)| *n == from || n.starts_with(&prefix))
            .map(|(n, node)| (n.clone(), node.clone()))
            .collect();
        if affected.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "条目不存在"));
        }
        let moved: BTreeSet<String> = affected.iter().map(|(n, _)| n.clone()).collect();
        for (old, _) in &affected {
            let suffix = old.strip_prefix(from).unwrap_or("");
            let new = format!("{to}{suffix}");
            if self.nodes.contains_key(&new) && !moved.contains(&new) {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "目标名称已存在"));
            }
        }
        for (old, _) in &affected {
            self.nodes.remove(old);
        }
        for (old, node) in affected {
            let suffix = old.strip_prefix(from).unwrap_or("");
            self.nodes.insert(format!("{to}{suffix}"), node);
        }
        Ok(())
    }

    fn clear_staged_adds(&self) {
        let adds = self.staged.join("adds");
        cleanup(&adds);
        let _ = std::fs::create_dir_all(adds);
        let _ = crate::paths::touch_active(&self.staged);
    }
}

fn make_manifest_for(nodes: &BTreeMap<String, Node>) -> io::Result<Vec<u8>> {
    let entries: Vec<vgs2::MEntry> = nodes
        .iter()
        .map(|(name, node)| {
            let (seg, tar_path) = match &node.source {
                Source::Existing { seg, tar_path } => (*seg, tar_path.clone()),
                Source::Dir => (0, String::new()),
                Source::StagedTar { .. } | Source::Legacy(_) => (0, String::new()),
            };
            vgs2::MEntry { name: name.clone(), is_dir: node.is_dir, size: node.size, mtime: node.mtime, seg, tar_path }
        })
        .collect();
    vgs2::encode_manifest(&entries)
}

fn nodes_from_manifest(entries: Vec<vgs2::MEntry>, segments: &[vgs2::SegmentMeta]) -> io::Result<BTreeMap<String, Node>> {
    let data: BTreeSet<u64> = segments.iter().filter(|s| s.head.seg_type == vgs2::SEG_DATA).map(|s| s.head.seq).collect();
    let mut out = BTreeMap::new();
    for e in entries {
        if !valid_rel_path(&e.name) || out.contains_key(&e.name) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "manifest 条目路径无效或重复"));
        }
        let source = if e.is_dir {
            if e.seg != 0 || !e.tar_path.is_empty() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "目录 manifest 记录无效"));
            }
            Source::Dir
        } else {
            if e.seg == 0 || !data.contains(&e.seg) || !valid_rel_path(&e.tar_path) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "文件 manifest 引用无效"));
            }
            Source::Existing { seg: e.seg, tar_path: e.tar_path }
        };
        out.insert(e.name, Node { size: e.size, is_dir: e.is_dir, mtime: e.mtime, source });
    }
    Ok(out)
}

fn logical_end(segments: &[vgs2::SegmentMeta]) -> io::Result<u64> {
    match segments.last() {
        None => Ok(vgs2::HDR_SZ as u64),
        Some(seg) => seg.body_offset
            .checked_add(seg.head.len)
            .and_then(|n| n.checked_add(vgs2::TAG_SZ as u64))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "段末尾溢出")),
    }
}

fn verify_v2_container(path: &Path, key: &[u8; 32]) -> io::Result<()> {
    let mut f = File::open(path)?;
    let segs = vgs2::scan_segments(&mut f)?;
    if segs.is_empty() || segs.last().is_none_or(|s| s.head.seg_type != vgs2::SEG_MANIFEST) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "新保险箱缺少 manifest"));
    }
    // 每段认证链独立，可并行校验（各线程独立文件句柄）
    vgs2::verify_segments_parallel(path, &segs, key, worker_count())
}

fn replace_container(tmp: &Path, path: &Path) -> io::Result<()> {
    // Windows 上 std::fs::rename 不能覆盖既有目标。不要先把旧箱改名为 .bak，
    // 否则断电窗口内原路径会消失；MoveFileExW 在同一卷完成覆盖替换，失败时旧箱
    // 仍在原位。临时文件与目标总在同一目录，因此不会触发跨卷复制。
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };

        let from: Vec<u16> = tmp.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: both buffers are NUL-terminated UTF-16 paths and remain alive throughout
        // the synchronous Windows API call.
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) } != 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        cleanup(tmp);
        return Err(err);
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(tmp, path)
    }
}

/// 按字节推进百分比回调（并行批处理路径用：粒度到批）。
fn report_pct(prog: &dyn Fn(u8), last: &mut u8, done: u64, total: u64) {
    let pct = if total == 0 {
        0
    } else {
        ((done.min(total) * 100 / total).min(99)) as u8
    };
    if pct != *last {
        *last = pct;
        prog(pct);
    }
}

/// 等待并行任务结果：线程 panic 也转成错误，避免二次崩溃。
fn join_result<T>(h: std::thread::ScopedJoinHandle<'_, io::Result<T>>) -> io::Result<T> {
    match h.join() {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "并行任务异常终止")),
    }
}

/// 并行解密一波数据段到临时明文 tar（每线程独立容器句柄 + 独立输出文件）。
/// 返回 (段序号, 明文 tar 路径, 该段待转发的条目映射)；调用方负责在转发后擦除明文。
fn decrypt_wave(
    chunk: &[(u64, Vec<(String, String)>)],
    seg_map: &BTreeMap<u64, vgs2::SegmentMeta>,
    old_key: Option<[u8; 32]>,
    work: &Path,
    container: &Path,
) -> io::Result<Vec<(u64, PathBuf, Vec<(String, String)>)>> {
    let mut out = Vec::with_capacity(chunk.len());
    std::thread::scope(|scope| -> io::Result<()> {
        let mut handles = Vec::with_capacity(chunk.len());
        for (seq, wanted) in chunk {
            let seg = seg_map.get(seq).copied().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "manifest 引用了不存在的数据段")
            })?;
            let key = old_key.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "旧格式数据段状态无效")
            })?;
            let payload = work.join(format!("relay-{seq}.tar"));
            let seq = *seq;
            let wanted = wanted.clone();
            let container = container.to_path_buf();
            handles.push(scope.spawn(move || -> io::Result<(u64, PathBuf, Vec<(String, String)>)> {
                let mut fout = File::create(&payload)?;
                vgs2::decrypt_segment_to_file(&mut File::open(&container)?, seg, &key, &mut fout)?;
                drop(fout);
                Ok((seq, payload, wanted))
            }));
        }
        for h in handles {
            out.push(join_result(h)?);
        }
        Ok(())
    })?;
    out.sort_by_key(|(seq, _, _)| *seq);
    Ok(out)
}

/// 新容器的数据段写入器：攒批 → 并行加密 → 按序号顺序落盘。
///
/// 每段独立 nonce/AAD（格式本身支持乱序，但段序号必须与文件位置一致），因此
/// 加密可并行、写入必须串行。批大小目标 [`SEG_TARGET`]，超过 [`PARALLEL_MEM_CAP`]
/// 的段（单个超大文件）自动退回流式串行，避免整段明文进内存。
struct SegSink<'a> {
    f: &'a mut File,
    key: [u8; 32],
    next: u64,
    arc_to_seg: BTreeMap<String, u64>,
    segs: Vec<vgs2::SegmentMeta>,
    pending: Vec<tarx::RelayBatch>,
    batch_dir: PathBuf,
    batch_call: u64,
    workers: usize,
    bytes: u64,
    pending_bytes: u64,
}

impl<'a> SegSink<'a> {
    fn new(f: &'a mut File, key: [u8; 32], start_seq: u64, batch_dir: PathBuf, workers: usize) -> Self {
        Self {
            f,
            key,
            next: start_seq,
            arc_to_seg: BTreeMap::new(),
            segs: Vec::new(),
            pending: Vec::new(),
            batch_dir,
            batch_call: 0,
            workers: workers.max(1),
            bytes: 0,
            pending_bytes: 0,
        }
    }

    /// 把已认证临时 tar 的存活条目转发成新数据段（按 [`SEG_TARGET`] 分批）。
    /// 返回转发条目数。
    fn relay(&mut self, tp: &Path, wanted: &[(String, String)]) -> io::Result<usize> {
        // 超大条目（单文件）落盘的溢出目录，每次调用独立，避免覆盖。
        let dir = self.batch_dir.join(format!("b{:04}", self.batch_call));
        self.batch_call = self.batch_call.saturating_add(1);
        tarx::relay_files_batched(tp, wanted, SEG_TARGET, PARALLEL_MEM_CAP, &dir, &mut |batch| {
            self.push(batch.plain, batch.arcs)
        })
    }

    /// 入队一批明文（内存批或超大条目落盘批）；攒够 worker 数或攒够明文预算即并行
    /// 加密写盘（内存占用受 [`PARALLEL_MEM_CAP`] 与 [`PARALLEL_BUF_BUDGET`] 双重约束）。
    fn push(&mut self, plain: tarx::BatchPlain, arcs: Vec<String>) -> io::Result<()> {
        let len = plain.len();
        if self.pending.len() >= self.workers
            || (self.pending_bytes > 0 && self.pending_bytes.saturating_add(len) > PARALLEL_BUF_BUDGET)
        {
            self.flush()?;
        }
        self.pending_bytes = self.pending_bytes.saturating_add(len);
        self.pending.push(tarx::RelayBatch { plain, arcs });
        Ok(())
    }

    /// 把一个超大段流式串行加密写盘（不整段进内存）。
    fn stream_file(&mut self, path: &Path, arcs: &[String]) -> io::Result<()> {
        self.flush()?;
        let data = profile::phase("data-write", || {
            vgs2::append_stream_segment(
                self.f,
                vgs2::SEG_DATA,
                self.next,
                &self.key,
                random_bytes::<NONCE_SZ>(),
                |w| {
                    let mut src = File::open(path)?;
                    let mut buf = vec![0u8; IO_BLOCK];
                    loop {
                        let n = src.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        w.write_all(&buf[..n])?;
                    }
                    Ok(())
                },
            )
        })?;
        for a in arcs {
            self.arc_to_seg.insert(a.clone(), data.head.seq);
        }
        self.segs.push(data);
        self.bytes = self.bytes.saturating_add(data.head.len);
        self.next = self.next.checked_add(1).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "段序号已用尽"))?;
        Ok(())
    }

    /// 写入剩余待落盘批次。
    fn finish(&mut self) -> io::Result<()> {
        self.flush()
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let batches: Vec<tarx::RelayBatch> = self.pending.drain(..).collect();
        self.pending_bytes = 0;
        let mut small: Vec<tarx::RelayBatch> = Vec::new();
        for b in batches {
            match b.plain {
                // 超大条目独占的落盘批：流式串行，避免整段进内存
                tarx::BatchPlain::Disk(path) => {
                    self.flush_plain(&mut small)?;
                    self.stream_file(&path, &b.arcs)?;
                }
                tarx::BatchPlain::Mem(_) => small.push(b),
            }
        }
        self.flush_plain(&mut small)
    }

    /// 并行加密一批明文段并按序号顺序写回。
    fn flush_plain(&mut self, small: &mut Vec<tarx::RelayBatch>) -> io::Result<()> {
        if small.is_empty() {
            return Ok(());
        }
        let batches: Vec<tarx::RelayBatch> = small.drain(..).collect();
        let mut arcs_all: Vec<Vec<String>> = Vec::with_capacity(batches.len());
        let mut plains: Vec<Vec<u8>> = Vec::with_capacity(batches.len());
        for b in batches {
            let data = match b.plain {
                tarx::BatchPlain::Mem(v) => v,
                // 正常路径不会走到（Disk 批在 flush 中已分流），兜底读回
                tarx::BatchPlain::Disk(p) => std::fs::read(&p)?,
            };
            self.bytes = self.bytes.saturating_add(data.len() as u64);
            arcs_all.push(b.arcs);
            plains.push(data);
        }
        let results = profile::phase("parallel-encrypt", || {
            vgs2::encrypt_batches_parallel(&self.key, vgs2::SEG_DATA, self.next, plains, self.workers)
        })?;
        let metas = profile::phase("seg-write", || vgs2::write_segments_sequential(self.f, results))?;
        for (arcs, meta) in arcs_all.iter().zip(metas.iter()) {
            for a in arcs {
                self.arc_to_seg.insert(a.clone(), meta.head.seq);
            }
            self.segs.push(*meta);
        }
        self.next = self
            .next
            .checked_add(metas.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "段序号已用尽"))?;
        Ok(())
    }
}

/// 收集新增源的条目元数据：(节点名, 是否目录, 大小, mtime, 暂存 tar 内路径, 所属条目下标)。
/// 目录递归；文件与目录的 arc 均为「目标名 + 相对路径」（与打包进暂存 tar 的路径一致）。
fn collect_src_entries(
    src: &Path,
    name: &str,
    out: &mut Vec<(String, bool, u64, i64, String, usize)>,
    item_idx: usize,
) -> io::Result<()> {
    let md = std::fs::symlink_metadata(src)?;
    if md.is_dir() {
        out.push((name.to_string(), true, 0, modified_secs(&md), name.to_string(), item_idx));
        let mut kids: Vec<PathBuf> = std::fs::read_dir(src)?.flatten().map(|e| e.path()).collect();
        kids.sort();
        for child in kids {
            let raw = child.file_name().and_then(|x| x.to_str()).unwrap_or("file");
            let child_name = format!("{name}/{}", safe_name(raw, 100));
            collect_src_entries(&child, &child_name, out, item_idx)?;
        }
    } else if md.is_file() {
        out.push((name.to_string(), false, md.len(), modified_secs(&md), name.to_string(), item_idx));
    }
    Ok(())
}

fn collect_legacy_nodes(tree: &Path) -> io::Result<BTreeMap<String, Node>> {
    fn rec(root: &Path, dir: &Path, out: &mut BTreeMap<String, Node>) -> io::Result<()> {
        let mut kids: Vec<PathBuf> = std::fs::read_dir(dir)?.flatten().map(|e| e.path()).collect();
        kids.sort();
        for p in kids {
            let name = p.strip_prefix(root).unwrap_or(&p).to_string_lossy().replace('\\', "/");
            let md = std::fs::symlink_metadata(&p)?;
            if md.is_dir() {
                out.insert(name.clone(), Node { size: 0, is_dir: true, mtime: modified_secs(&md), source: Source::Dir });
                rec(root, &p, out)?;
            } else if md.is_file() {
                out.insert(name, Node { size: md.len(), is_dir: false, mtime: modified_secs(&md), source: Source::Legacy(p) });
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    rec(tree, tree, &mut out)?;
    Ok(out)
}

fn copy_recursive(src: &Path, dst: &Path) -> io::Result<()> {
    let md = std::fs::symlink_metadata(src)?;
    if md.is_dir() {
        std::fs::create_dir_all(dst)?;
        for e in std::fs::read_dir(src)?.flatten() {
            let name = safe_name(&e.file_name().to_string_lossy(), 100);
            copy_recursive(&e.path(), &dst.join(name))?;
        }
        Ok(())
    } else if md.is_file() {
        copy_file_buffered(src, dst)
    } else {
        Ok(())
    }
}

/// 缓冲文件拷贝。Windows 上 `std::fs::copy`（CopyFileW）生成的副本在首次
/// 读取时可能被实时防护扫描拖慢一个数量级（本机实测 1 GiB 冷读 6.5s → 0.6s），
/// 保险箱的暂存/物化等热路径统一走大缓冲手动拷贝。
fn copy_file_buffered(src: &Path, dst: &Path) -> io::Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut r = std::io::BufReader::with_capacity(1 << 20, File::open(src)?);
    let mut w = std::io::BufWriter::with_capacity(1 << 20, File::create(dst)?);
    std::io::copy(&mut r, &mut w)?;
    w.flush()?;
    Ok(())
}

fn modified_secs(md: &std::fs::Metadata) -> i64 {
    md.modified().ok().and_then(|x| x.duration_since(std::time::UNIX_EPOCH).ok()).map(|x| x.as_secs() as i64).unwrap_or(0)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|x| x.as_secs() as i64).unwrap_or(0)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut b);
    b
}

fn parent_name(path: &str) -> &str { path.rsplit_once('/').map(|x| x.0).unwrap_or("") }

fn split_ext(name: &str) -> (String, String) {
    match name.rfind('.') { Some(i) if i > 0 => (name[..i].to_string(), name[i..].to_string()), _ => (name.to_string(), String::new()) }
}

fn rel_safe(name: &str) -> PathBuf {
    let mut p = PathBuf::new();
    for seg in name.split('/') { if !seg.is_empty() { p.push(safe_name(seg, 100)); } }
    if p.as_os_str().is_empty() { p.push("file"); }
    p
}

/// 文件扩展名 -> 分类目录名。
pub fn category_of(name: &str) -> &'static str {
    let low = name.to_lowercase();
    let ext = low.rsplit('.').next().unwrap_or("");
    if ext.len() == low.len() { return "其他"; }
    match ext {
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "svg" | "tif" | "tiff" | "ico" | "heic" | "heif" => "图片",
        "doc" | "docx" | "pdf" | "txt" | "md" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods" | "odp" | "csv" | "rtf" | "epub" | "tex" => "文档",
        "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" | "tgz" | "zst" | "cab" | "iso" => "压缩包",
        "mp3" | "wav" | "flac" | "aac" | "ogg" | "m4a" | "wma" | "opus" | "mid" | "midi" => "音频",
        "mp4" | "avi" | "mkv" | "mov" | "wmv" | "flv" | "webm" | "m4v" | "ts" | "m2ts" => "视频",
        _ => "其他",
    }
}

fn valid_rel_path(p: &str) -> bool {
    !p.is_empty() && !p.starts_with('/') && !p.ends_with('/') && !p.contains('\\') && p.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

/// 保留的 VGS1 流式认证解密 API。VGS2 不应调用它。
pub fn read_verify(container: &Path, pass: &str, out: &mut dyn Write, prog: &dyn Fn(u64, u64)) -> io::Result<u64> {
    read_verify_v1(container, pass, out, prog)
}

fn read_verify_v1(container: &Path, pass: &str, out: &mut dyn Write, prog: &dyn Fn(u64, u64)) -> io::Result<u64> {
    let mut f = File::open(container)?;
    let file_len = f.metadata()?.len();
    if file_len < V1_HDR_SZ as u64 + TAG_SZ as u64 { return Err(io::Error::new(io::ErrorKind::InvalidData, "不是有效的 VaultGuard 保险箱文件")); }
    let mut hdr = [0u8; V1_HDR_SZ];
    f.read_exact(&mut hdr)?;
    if &hdr[..4] != MAGIC || hdr[4] != KDF_ARGON2ID { return Err(io::Error::new(io::ErrorKind::InvalidData, "不是 VGS1 保险箱文件")); }
    let m = u32::from_be_bytes(hdr[5..9].try_into().unwrap());
    let t = u32::from_be_bytes(hdr[9..13].try_into().unwrap());
    let p = hdr[13] as u32;
    if m == 0 || t == 0 || p == 0 { return Err(io::Error::new(io::ErrorKind::InvalidData, "保险箱文件头参数无效")); }
    let salt: [u8; 16] = hdr[14..30].try_into().unwrap();
    let nonce: [u8; NONCE_SZ] = hdr[30..42].try_into().unwrap();
    let key = derive_v3(pass.as_bytes(), &salt, ArgonParams { m_kib: m, t, p })?;
    let ct_len = file_len - V1_HDR_SZ as u64 - TAG_SZ as u64;
    let mut g = Gcm::new(&key, &nonce, AAD);
    let mut buf = vec![0u8; IO_BLOCK];
    let mut left = ct_len;
    let mut done = 0u64;
    while left > 0 {
        let take = left.min(IO_BLOCK as u64) as usize;
        f.read_exact(&mut buf[..take])?;
        g.ghash_data(&buf[..take]);
        g.crypt_in_place(&mut buf[..take]);
        out.write_all(&buf[..take])?;
        left -= take as u64;
        done += take as u64;
        prog(done, ct_len);
    }
    let mut tag = [0u8; TAG_SZ];
    f.read_exact(&mut tag)?;
    if !ct_eq(&g.finish_tag(), &tag) { return Err(io::Error::new(io::ErrorKind::InvalidData, "认证失败：口令错误，或数据已被改动")); }
    Ok(ct_len)
}

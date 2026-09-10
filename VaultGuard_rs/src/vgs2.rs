//! VGS2 保险箱格式（P0 格式与向量；P1--P3 由 `safe` 接管读写、追加保存与压缩）。
//! 设计见项目文档 §九：段链式布局 —— "VGS2" 全局头 + 追加式段链（数据段 0x01 / manifest 段 0x02），
//! 段序号进 AAD 防重排/防拼接；尾部截断会按设计回退至此前已认证的 manifest。

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::crypto::{ct_eq, Gcm};
use crate::profile;

pub const MAGIC: &[u8; 4] = b"VGS2";
pub const HDR_SZ: usize = 4 + 1 + 4 + 4 + 1 + 16 + 12 + 8; // 50
pub const KID_ARGON2ID: u8 = 0x01;

pub const SEG_DATA: u8 = 0x01;
pub const SEG_MANIFEST: u8 = 0x02;
pub const SEG_HDR_SZ: usize = 1 + 8 + 8 + 12 + 4; // 33
pub const NONCE_SZ: usize = 12;
pub const TAG_SZ: usize = 16;
/// 单条名字 / tar 路径的最大字节数（防恶意声明导致超大分配）
pub const MAX_NAME: usize = 4096;
/// manifest 条目数上限
pub const MAX_ENTRIES: usize = 1_000_000;
/// 单段最大长度。段头来自不可信输入，先做上限检查再转换为 usize。
pub const MAX_SEGMENT_LEN: u64 = 1 << 50;
/// manifest 会在打开时一次性认证并解码；与数据段分开限额，绝不按不可信长度
/// 分配大块内存。数据段必须使用 `decrypt_segment_to_file` 流式处理。
pub const MAX_MANIFEST_LEN: u64 = 64 * 1024 * 1024;
const IO_BLOCK: usize = 1 << 20;

// ── 全局头（50B）───────────────────────────────────────────────

/// 编码全局头：MAGIC(4) + kid(1) + m(4) + t(4) + p(1) + salt(16) + nonce(12) + reserve(8)。
pub fn encode_header(
    kid: u8,
    m: u32,
    t: u32,
    p: u32,
    salt: &[u8; 16],
    nonce: &[u8; 12],
) -> io::Result<[u8; HDR_SZ]> {
    if kid != KID_ARGON2ID || m == 0 || t == 0 || p == 0 || p > u8::MAX as u32 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "VGS2 头参数无效"));
    }
    let mut b = [0u8; HDR_SZ];
    b[..4].copy_from_slice(MAGIC);
    b[4] = kid;
    b[5..9].copy_from_slice(&m.to_be_bytes());
    b[9..13].copy_from_slice(&t.to_be_bytes());
    b[13] = p as u8;
    b[14..30].copy_from_slice(salt);
    b[30..42].copy_from_slice(nonce);
    Ok(b)
}

/// 解码全局头 → (kid, m, t, p, salt, nonce)。非 VGS2 / 长度不足拒绝。
pub fn decode_header(b: &[u8]) -> io::Result<(u8, u32, u32, u32, [u8; 16], [u8; 12])> {
    if b.len() < HDR_SZ || &b[..4] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "不是 VGS2 保险箱文件",
        ));
    }
    let kid = b[4];
    if kid != KID_ARGON2ID {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "未知的密钥派生类型"));
    }
    let m = u32::from_be_bytes(b[5..9].try_into().unwrap());
    let t = u32::from_be_bytes(b[9..13].try_into().unwrap());
    let p = b[13] as u32;
    if m == 0 || t == 0 || p == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "保险箱文件头参数无效"));
    }
    let salt: [u8; 16] = b[14..30].try_into().unwrap();
    let nonce: [u8; 12] = b[30..42].try_into().unwrap();
    Ok((kid, m, t, p, salt, nonce))
}

// ── 段头（33B）────────────────────────────────────────────────

/// 段头：类型(1) + 序号(8) + 数据长度(8) + nonce(12) + CRC32(4)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegHead {
    pub seg_type: u8,
    pub seq: u64,
    pub len: u64,
    pub nonce: [u8; 12],
}

/// 已扫描段的位置。body_offset 指向密文起始，后面紧跟 16B tag。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentMeta {
    pub head: SegHead,
    pub body_offset: u64,
}

/// 段在容器中占用的总长度（段头 + 密文 + tag）。
pub fn segment_disk_len(seg: SegmentMeta) -> io::Result<u64> {
    (SEG_HDR_SZ as u64)
        .checked_add(seg.head.len)
        .and_then(|n| n.checked_add(TAG_SZ as u64))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "段长度溢出"))
}

fn seg_crc(h: &SegHead) -> u32 {
    let mut c = crc32fast::Hasher::new();
    c.update(&[h.seg_type]);
    c.update(&h.seq.to_be_bytes());
    c.update(&h.len.to_be_bytes());
    c.update(&h.nonce);
    c.finalize()
}

pub fn encode_seg_head(h: &SegHead) -> [u8; SEG_HDR_SZ] {
    let mut b = [0u8; SEG_HDR_SZ];
    b[0] = h.seg_type;
    b[1..9].copy_from_slice(&h.seq.to_be_bytes());
    b[9..17].copy_from_slice(&h.len.to_be_bytes());
    b[17..29].copy_from_slice(&h.nonce);
    b[29..33].copy_from_slice(&seg_crc(h).to_be_bytes());
    b
}

pub fn decode_seg_head(b: &[u8]) -> io::Result<SegHead> {
    if b.len() < SEG_HDR_SZ {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "段头截断"));
    }
    let h = SegHead {
        seg_type: b[0],
        seq: u64::from_be_bytes(b[1..9].try_into().unwrap()),
        len: u64::from_be_bytes(b[9..17].try_into().unwrap()),
        nonce: b[17..29].try_into().unwrap(),
    };
    if h.seg_type != SEG_DATA && h.seg_type != SEG_MANIFEST {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "未知的段类型"));
    }
    let crc = u32::from_be_bytes(b[29..33].try_into().unwrap());
    if crc != seg_crc(&h) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "段头校验失败（数据可能被改动）",
        ));
    }
    Ok(h)
}

/// 扫描从全局头开始的连续段链。
///
/// 未完成的尾段（崩溃留下的头或半截密文）被视为尾部垃圾并忽略；序号不连续
/// 也停止扫描，调用方可以使用此前已经完整写入的 manifest 回退。
pub fn scan_segments(f: &mut File) -> io::Result<Vec<SegmentMeta>> {
    let file_len = f.metadata()?.len();
    let mut pos = HDR_SZ as u64;
    let mut want_seq = 1u64;
    let mut out = Vec::new();
    while pos.saturating_add(SEG_HDR_SZ as u64 + TAG_SZ as u64) <= file_len {
        f.seek(SeekFrom::Start(pos))?;
        let mut hb = [0u8; SEG_HDR_SZ];
        if f.read_exact(&mut hb).is_err() {
            break;
        }
        let head = match decode_seg_head(&hb) {
            Ok(h) => h,
            Err(_) => break,
        };
        if head.seq != want_seq || head.len > MAX_SEGMENT_LEN {
            break;
        }
        let body_offset = pos + SEG_HDR_SZ as u64;
        let end = body_offset
            .checked_add(head.len)
            .and_then(|x| x.checked_add(TAG_SZ as u64));
        let Some(end) = end else { break };
        if end > file_len {
            break;
        }
        out.push(SegmentMeta { head, body_offset });
        pos = end;
        let Some(next) = want_seq.checked_add(1) else { break };
        want_seq = next;
    }
    Ok(out)
}

/// 读取并认证一个已扫描的段。调用方决定是否把明文写入磁盘。
pub fn read_segment(f: &mut File, seg: SegmentMeta, key: &[u8; 32]) -> io::Result<Vec<u8>> {
    if seg.head.len > MAX_MANIFEST_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "该段不能一次性读入内存（请使用流式读取）",
        ));
    }
    let len = usize::try_from(seg.head.len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "段长度超出平台上限"))?;
    f.seek(SeekFrom::Start(seg.body_offset))?;
    let mut ct = vec![0u8; len];
    f.read_exact(&mut ct)?;
    let mut tag = [0u8; TAG_SZ];
    f.read_exact(&mut tag)?;
    decrypt_payload(
        key,
        seg.head.seg_type,
        seg.head.seq,
        &seg.head.nonce,
        &ct,
        &tag,
    )
}

/// 有界读取并认证 manifest。这个函数是打开路径唯一允许分配段长度大小内存的位置。
pub fn read_manifest_segment(
    f: &mut File,
    seg: SegmentMeta,
    key: &[u8; 32],
) -> io::Result<Vec<u8>> {
    if seg.head.seg_type != SEG_MANIFEST {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "不是 manifest 段"));
    }
    if seg.head.len > MAX_MANIFEST_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "manifest 段超出安全上限"));
    }
    read_segment(f, seg, key)
}

/// 流式认证解密数据段到调用者提供的临时文件。
///
/// 调用者必须只在本函数成功后使用输出，并负责在失败时覆写清理临时文件；这样不会把
/// 未认证的明文暴露到最终导出位置，也不会按照段头中的长度分配内存。
pub fn decrypt_segment_to_file(
    f: &mut File,
    seg: SegmentMeta,
    key: &[u8; 32],
    out: &mut File,
) -> io::Result<u64> {
    if seg.head.seg_type != SEG_DATA || seg.head.len > MAX_SEGMENT_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "数据段长度或类型无效"));
    }
    f.seek(SeekFrom::Start(seg.body_offset))?;
    let mut g = Gcm::new(key, &seg.head.nonce, &seg_aad(seg.head.seg_type, seg.head.seq));
    let mut buf = vec![0u8; IO_BLOCK];
    let mut left = seg.head.len;
    while left > 0 {
        let take = left.min(IO_BLOCK as u64) as usize;
        f.read_exact(&mut buf[..take])?;
        g.ghash_data(&buf[..take]);
        g.crypt_in_place(&mut buf[..take]);
        out.write_all(&buf[..take])?;
        left -= take as u64;
    }
    let mut tag = [0u8; TAG_SZ];
    f.read_exact(&mut tag)?;
    if !ct_eq(&g.finish_tag(), &tag) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "段认证失败：数据被改动或序号不符"));
    }
    out.sync_all()?;
    Ok(seg.head.len)
}

/// 仅认证段内容，不保存或分配明文。新容器原子替换前用它做完整自校验。
pub fn verify_segment(f: &mut File, seg: SegmentMeta, key: &[u8; 32]) -> io::Result<()> {
    if seg.head.len > MAX_SEGMENT_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "段长度超出格式上限"));
    }
    f.seek(SeekFrom::Start(seg.body_offset))?;
    let mut g = Gcm::new(key, &seg.head.nonce, &seg_aad(seg.head.seg_type, seg.head.seq));
    let mut buf = vec![0u8; IO_BLOCK];
    let mut left = seg.head.len;
    while left > 0 {
        let take = left.min(IO_BLOCK as u64) as usize;
        f.read_exact(&mut buf[..take])?;
        g.ghash_data(&buf[..take]);
        left -= take as u64;
    }
    let mut tag = [0u8; TAG_SZ];
    f.read_exact(&mut tag)?;
    if !ct_eq(&g.finish_tag(), &tag) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "段认证失败：数据被改动或序号不符"));
    }
    Ok(())
}

/// 在文件尾追加一个流式加密段。段头在 tag 写入后才回填：意外中断时扫描器会把
/// 占位头视作尾部垃圾，仍可回退到此前已认证的 manifest。
pub fn append_stream_segment<F>(
    f: &mut File,
    seg_type: u8,
    seq: u64,
    key: &[u8; 32],
    nonce: [u8; NONCE_SZ],
    write_plain: F,
) -> io::Result<SegmentMeta>
where
    F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
    if seg_type != SEG_DATA && seg_type != SEG_MANIFEST || seq == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "段类型或序号无效"));
    }
    let header_offset = f.seek(SeekFrom::End(0))?;
    f.write_all(&[0u8; SEG_HDR_SZ])?;
    let mut writer = SegmentEncWriter {
        f,
        g: Some(Gcm::new(key, &nonce, &seg_aad(seg_type, seq))),
        len: 0,
        pend: Vec::with_capacity(ENC_BUF + (1 << 12)),
        start: 0,
    };
    profile::phase("seg-pack", || write_plain(&mut writer))?;
    let len = profile::phase("seg-finish", || writer.finish())?;
    if len > MAX_SEGMENT_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "段数据超出格式上限"));
    }
    let head = SegHead { seg_type, seq, len, nonce };
    let end = writer.f.seek(SeekFrom::End(0))?;
    writer.f.seek(SeekFrom::Start(header_offset))?;
    writer.f.write_all(&encode_seg_head(&head))?;
    writer.f.seek(SeekFrom::Start(end))?;
    profile::phase("seg-sync", || writer.f.sync_all())?;
    Ok(SegmentMeta { head, body_offset: header_offset + SEG_HDR_SZ as u64 })
}

/// 加密写缓冲：tar 打包以 8 KiB 小片喂入，这里聚合成大块再加密写盘，
/// 避免每片一次分配与 8 KiB 级小系统调用（5 GiB 场景可差一个数量级）。
const ENC_BUF: usize = 1 << 20;

struct SegmentEncWriter<'a> {
    f: &'a mut File,
    g: Option<Gcm>,
    len: u64,
    pend: Vec<u8>,
    start: usize,
}

impl SegmentEncWriter<'_> {
    fn finish(&mut self) -> io::Result<u64> {
        // 加密残余明文（不足 ENC_BUF 的尾部）
        if self.start < self.pend.len() {
            let g = self.g.as_mut().expect("segment writer finished twice");
            let mut ct = self.pend[self.start..].to_vec();
            g.crypt_in_place(&mut ct);
            g.ghash_data(&ct);
            self.f.write_all(&ct)?;
        }
        let tag = self.g.take().expect("segment writer finished twice").finish_tag();
        self.f.write_all(&tag)?;
        Ok(self.len)
    }

    fn flush_full(&mut self) -> io::Result<()> {
        while self.pend.len() - self.start >= ENC_BUF {
            profile::phase("seg-crypt-write", || {
                let g = self.g.as_mut().expect("segment writer finished");
                let mut ct = self.pend[self.start..self.start + ENC_BUF].to_vec();
                g.crypt_in_place(&mut ct);
                g.ghash_data(&ct);
                self.f.write_all(&ct)
            })?;
            self.start += ENC_BUF;
        }
        if self.start > 0 {
            self.pend.drain(..self.start);
            self.start = 0;
        }
        Ok(())
    }
}

impl Write for SegmentEncWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let add = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        if self.len.checked_add(add).filter(|n| *n <= MAX_SEGMENT_LEN).is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "段数据超出格式上限"));
        }
        self.pend.extend_from_slice(buf);
        self.flush_full()?;
        self.len += add;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_full()?;
        self.f.flush()
    }
}

// ── 段 AAD ────────────────────────────────────────────────────

/// 段 AAD：MAGIC + 用途 + 段序号（8B BE）。用途为 manifest=0x00、数据=0x01；
/// 段序号进 AAD → 防重排/防截断/防拼接。段头类型保持数据=0x01、manifest=0x02。
pub fn seg_aad(seg_type: u8, seq: u64) -> [u8; 13] {
    let mut a = [0u8; 13];
    a[..4].copy_from_slice(MAGIC);
    a[4] = match seg_type {
        SEG_MANIFEST => 0x00,
        SEG_DATA => 0x01,
        _ => 0xff,
    };
    a[5..].copy_from_slice(&seq.to_be_bytes());
    a
}

// ── manifest（文件树索引）─────────────────────────────────────

/// manifest 条目：扁平记录 [name_len(2)][name][is_dir(1)][size(8)][mtime(8)][seg(8)][tar_path_len(2)][tar_path]。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: i64,
    /// 数据段序号；目录条目 = 0（无数据段）
    pub seg: u64,
    /// 该文件在数据段 tar 内的路径（还原/导出定位用）
    pub tar_path: String,
}

pub fn encode_manifest(entries: &[MEntry]) -> io::Result<Vec<u8>> {
    if entries.len() > MAX_ENTRIES || entries.len() > u32::MAX as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "manifest 条目数超上限"));
    }
    let mut out = Vec::new();
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for e in entries {
        let nb = e.name.as_bytes();
        if nb.len() > MAX_NAME || nb.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "名字长度超上限"));
        }
        let tb = e.tar_path.as_bytes();
        if tb.len() > MAX_NAME || tb.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "tar 路径长度超上限"));
        }
        out.extend_from_slice(&(nb.len() as u16).to_be_bytes());
        out.extend_from_slice(nb);
        out.push(e.is_dir as u8);
        out.extend_from_slice(&e.size.to_be_bytes());
        out.extend_from_slice(&e.mtime.to_be_bytes());
        out.extend_from_slice(&e.seg.to_be_bytes());
        out.extend_from_slice(&(tb.len() as u16).to_be_bytes());
        out.extend_from_slice(tb);
    }
    Ok(out)
}

pub fn decode_manifest(b: &[u8]) -> io::Result<Vec<MEntry>> {
    let mut o = 0usize;
    let take = |o: &mut usize, n: usize, what: &str| -> io::Result<&[u8]> {
        if b.len() - *o < n {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("manifest 截断：{what} 不足"),
            ));
        }
        let s = &b[*o..*o + n];
        *o += n;
        Ok(s)
    };
    let count = u32::from_be_bytes(take(&mut o, 4, "条目数")?.try_into().unwrap()) as usize;
    if count > MAX_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "manifest 条目数超上限",
        ));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let nl = u16::from_be_bytes(take(&mut o, 2, "名字长度")?.try_into().unwrap()) as usize;
        if nl > MAX_NAME {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "名字长度超上限"));
        }
        let name =
            String::from_utf8(take(&mut o, nl, "名字")?.to_vec()).map_err(invalid_utf8)?;
        let is_dir = take(&mut o, 1, "类型")?[0] != 0;
        let size = u64::from_be_bytes(take(&mut o, 8, "大小")?.try_into().unwrap());
        let mtime = i64::from_be_bytes(take(&mut o, 8, "时间")?.try_into().unwrap());
        let seg = u64::from_be_bytes(take(&mut o, 8, "段号")?.try_into().unwrap());
        let tl = u16::from_be_bytes(take(&mut o, 2, "tar 路径长度")?.try_into().unwrap()) as usize;
        if tl > MAX_NAME {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "tar 路径长度超上限"));
        }
        let tar_path =
            String::from_utf8(take(&mut o, tl, "tar 路径")?.to_vec()).map_err(invalid_utf8)?;
        out.push(MEntry {
            name,
            is_dir,
            size,
            mtime,
            seg,
            tar_path,
        });
    }
    if o != b.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "manifest 含有尾随数据",
        ));
    }
    Ok(out)
}

fn invalid_utf8(_: std::string::FromUtf8Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "manifest 名字不是合法 UTF-8")
}

// ── 段体加解密原语（P0：非流式；P1 容器读写再演进为流式）────────

/// 已加密数据段的结果：顺序写回容器时使用（P6 并行加密路径）。
#[derive(Debug)]
pub struct BatchResult {
    pub seq: u64,
    pub ct: Vec<u8>,
    pub tag: [u8; 16],
    pub nonce: [u8; 12],
}

/// 并行加密一批明文段（每段独立 nonce/AAD，互不依赖，可跨线程）。
/// 返回与输入顺序一致的加密结果（按 seq 排序）。`workers` 为 0/1 时退化为串行。
/// 明文按值传入并原地加密，避免并行时出现「明文 + 密文」双份内存驻留。
pub fn encrypt_batches_parallel(
    key: &[u8; 32],
    seg_type: u8,
    start_seq: u64,
    plains: Vec<Vec<u8>>,
    workers: usize,
) -> io::Result<Vec<BatchResult>> {
    if plains.is_empty() {
        return Ok(Vec::new());
    }
    if plains.len() as u64 > u64::MAX - start_seq {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "段序号溢出"));
    }
    let workers = workers.max(1).min(plains.len());
    let out: std::sync::Mutex<Vec<(usize, BatchResult)>> = std::sync::Mutex::new(Vec::with_capacity(plains.len()));
    let mut plains: Vec<Option<Vec<u8>>> = plains.into_iter().map(Some).collect();
    std::thread::scope(|scope| {
        for w in 0..workers {
            let mine: Vec<(usize, Vec<u8>)> = plains
                .iter_mut()
                .enumerate()
                .skip(w)
                .step_by(workers)
                .filter_map(|(i, p)| p.take().map(|plain| (i, plain)))
                .collect();
            let out = &out;
            scope.spawn(move || {
                let mut rng = rand::thread_rng();
                let mut local = Vec::with_capacity(mine.len());
                for (i, plain) in mine {
                    let mut nonce = [0u8; NONCE_SZ];
                    rand::RngCore::fill_bytes(&mut rng, &mut nonce);
                    let seq = start_seq + i as u64;
                    let (ct, tag) = encrypt_payload_owned(key, seg_type, seq, &nonce, plain);
                    local.push((i, BatchResult { seq, ct, tag, nonce }));
                }
                out.lock().unwrap().extend(local);
            });
        }
    });
    let mut results = out.into_inner().unwrap();
    results.sort_by_key(|(i, _)| *i);
    Ok(results.into_iter().map(|(_, r)| r).collect())
}

/// 顺序写回一批已加密的数据段：占位段头 + 密文 + tag 全部写完后再统一回填段头，
/// 最后单次 fsync。中途崩溃时未回填的段头 CRC 无效，扫描停止，回退到此前已认证 manifest。
/// `results` 必须按 seq 升序。
pub fn write_segments_sequential(f: &mut File, results: Vec<BatchResult>) -> io::Result<Vec<SegmentMeta>> {
    let mut metas = Vec::with_capacity(results.len());
    let mut offsets: Vec<(u64, &BatchResult)> = Vec::with_capacity(results.len());
    for r in &results {
        if r.ct.len() as u64 > MAX_SEGMENT_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "段数据超出格式上限"));
        }
        let header_offset = f.seek(SeekFrom::End(0))?;
        f.write_all(&[0u8; SEG_HDR_SZ])?;
        f.write_all(&r.ct)?;
        f.write_all(&r.tag)?;
        offsets.push((header_offset, r));
    }
    for (header_offset, r) in &offsets {
        let head = SegHead { seg_type: SEG_DATA, seq: r.seq, len: r.ct.len() as u64, nonce: r.nonce };
        f.seek(SeekFrom::Start(*header_offset))?;
        f.write_all(&encode_seg_head(&head))?;
        metas.push(SegmentMeta { head, body_offset: header_offset + SEG_HDR_SZ as u64 });
    }
    f.seek(SeekFrom::End(0))?;
    f.sync_all()?;
    Ok(metas)
}

/// 并行认证校验一批段（每线程独立文件句柄），任一失败即返回该错误。
pub fn verify_segments_parallel(path: &Path, segs: &[SegmentMeta], key: &[u8; 32], workers: usize) -> io::Result<()> {
    let n = segs.len();
    if n == 0 {
        return Ok(());
    }
    let workers = workers.max(1).min(n);
    let errs: std::sync::Mutex<Option<io::Error>> = std::sync::Mutex::new(None);
    std::thread::scope(|scope| {
        for w in 0..workers {
            let mine: Vec<SegmentMeta> = segs.iter().skip(w).step_by(workers).cloned().collect();
            let errs = &errs;
            scope.spawn(move || {
                if errs.lock().unwrap().is_some() {
                    return;
                }
                let mut f = match File::open(path) {
                    Ok(f) => f,
                    Err(e) => {
                        *errs.lock().unwrap() = Some(e);
                        return;
                    }
                };
                for seg in mine {
                    if let Err(e) = verify_segment(&mut f, seg, key) {
                        *errs.lock().unwrap() = Some(e);
                        return;
                    }
                }
            });
        }
    });
    match errs.into_inner().unwrap() {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// 加密段体 → (密文, tag)。AAD 绑定段类型与序号。
pub fn encrypt_payload(
    key: &[u8; 32],
    seg_type: u8,
    seq: u64,
    nonce: &[u8; 12],
    plain: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    encrypt_payload_owned(key, seg_type, seq, nonce, plain.to_vec())
}

/// 同 `encrypt_payload`，但明文按值传入并原地加密（大段可省一次整段拷贝）。
fn encrypt_payload_owned(
    key: &[u8; 32],
    seg_type: u8,
    seq: u64,
    nonce: &[u8; 12],
    mut plain: Vec<u8>,
) -> (Vec<u8>, [u8; 16]) {
    let mut g = Gcm::new(key, nonce, &seg_aad(seg_type, seq));
    g.crypt_in_place(&mut plain);
    g.ghash_data(&plain);
    let tag = g.finish_tag();
    (plain, tag)
}

/// 认证解密段体：校验通过才返回明文；AAD（含序号）不符即认证失败。
pub fn decrypt_payload(
    key: &[u8; 32],
    seg_type: u8,
    seq: u64,
    nonce: &[u8; 12],
    ct: &[u8],
    tag: &[u8],
) -> io::Result<Vec<u8>> {
    if tag.len() < TAG_SZ {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "缺认证标记"));
    }
    let mut v = Gcm::new(key, nonce, &seg_aad(seg_type, seq));
    v.ghash_data(ct);
    if !ct_eq(&v.finish_tag(), &tag[..TAG_SZ]) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "段认证失败：数据被改动或序号不符",
        ));
    }
    let mut g = Gcm::new(key, nonce, &seg_aad(seg_type, seq));
    let mut plain = ct.to_vec();
    g.crypt_in_place(&mut plain);
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn fixture_entries() -> Vec<MEntry> {
        vec![
            MEntry {
                name: "图片/a.png".to_string(),
                is_dir: false,
                size: 12_345,
                mtime: 1_700_000_000,
                seg: 1,
                tar_path: "p/0/a.png".to_string(),
            },
            MEntry {
                name: "文档/报告.pdf".to_string(),
                is_dir: false,
                size: 9_876_543_210,
                mtime: 1_700_000_001,
                seg: 2,
                tar_path: "p/1/报告.pdf".to_string(),
            },
            MEntry {
                name: "项目".to_string(),
                is_dir: true,
                size: 0,
                mtime: 1_700_000_002,
                seg: 0,
                tar_path: String::new(),
            },
        ]
    }

    #[test]
    fn header_vector_roundtrip_and_validation() {
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let nonce = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        ];
        let header = encode_header(KID_ARGON2ID, 65_536, 3, 1, &salt, &nonce).unwrap();
        assert_eq!(header.len(), HDR_SZ);
        assert_eq!(hex(&header), include_str!("../tests/vectors/vgs2_header.hex").trim());
        assert_eq!(
            decode_header(&header).unwrap(),
            (KID_ARGON2ID, 65_536, 3, 1, salt, nonce)
        );
        assert!(encode_header(KID_ARGON2ID, 65_536, 3, 256, &salt, &nonce).is_err());
        let mut bad = header;
        bad[0] ^= 1;
        assert!(decode_header(&bad).is_err());
    }

    #[test]
    fn scan_complete_chain_ignores_incomplete_tail() {
        let path = std::env::temp_dir().join(format!(
            "vaultguard-vgs2-scan-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let key = [0x42; 32];
        let nonce = [0x24; NONCE_SZ];
        let mut f = File::create(&path).unwrap();
        f.write_all(&encode_header(KID_ARGON2ID, 65_536, 3, 1, &[0x11; 16], &[0x22; 12]).unwrap())
            .unwrap();
        for (kind, seq, plain) in [
            (SEG_DATA, 1u64, b"data segment".as_slice()),
            (SEG_MANIFEST, 2u64, b"manifest segment".as_slice()),
        ] {
            let (ct, tag) = encrypt_payload(&key, kind, seq, &nonce, plain);
            let head = SegHead {
                seg_type: kind,
                seq,
                len: ct.len() as u64,
                nonce,
            };
            f.write_all(&encode_seg_head(&head)).unwrap();
            f.write_all(&ct).unwrap();
            f.write_all(&tag).unwrap();
        }
        // 模拟断电：下一段只写入部分段头。已完成的两个段仍应可定位并读取。
        f.write_all(&[SEG_MANIFEST, 0, 0, 0, 0]).unwrap();
        f.sync_all().unwrap();
        drop(f);

        let mut f = File::open(&path).unwrap();
        let segments = scan_segments(&mut f).unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].head.seq, 1);
        assert_eq!(segments[1].head.seq, 2);
        assert_eq!(read_segment(&mut f, segments[0], &key).unwrap(), b"data segment");
        assert_eq!(read_segment(&mut f, segments[1], &key).unwrap(), b"manifest segment");
        drop(f);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn deterministic_manifest_vector_roundtrip() {
        // 这个向量同时覆盖中文名、目录、64 位大小和段认证；固定字节见 tests/vectors/。
        let entries = fixture_entries();
        let man = encode_manifest(&entries).unwrap();
        assert_eq!(man.len(), 149);
        assert_eq!(hex(&man), include_str!("../tests/vectors/vgs2_manifest.hex").trim());
        let key: [u8; 32] = [0x42; 32];
        let nonce: [u8; 12] = [0x24; 12];
        let (ct, tag) = encrypt_payload(&key, SEG_MANIFEST, 7, &nonce, &man);
        assert_eq!(decrypt_payload(&key, SEG_MANIFEST, 7, &nonce, &ct, &tag).unwrap(), man);
    }

    #[test]
    fn seg_head_roundtrip_and_crc_tamper() {
        let h = SegHead {
            seg_type: SEG_DATA,
            seq: 42,
            len: 1024,
            nonce: [7; 12],
        };
        let b = encode_seg_head(&h);
        assert_eq!(b.len(), SEG_HDR_SZ);
        assert_eq!(decode_seg_head(&b).unwrap(), h);
        let mut bad = b;
        bad[1] ^= 0x01; // 改序号
        assert!(decode_seg_head(&bad).is_err(), "篡改段头必须被拒绝");
        let mut bad2 = b;
        bad2[0] = 0x99; // 未知段类型
        assert!(decode_seg_head(&bad2).is_err());
    }

    #[test]
    fn manifest_roundtrip_unicode_and_large_values() {
        let entries = fixture_entries();
        let enc = encode_manifest(&entries).unwrap();
        assert_eq!(decode_manifest(&enc).unwrap(), entries);
        // 截断必须报错
        let mut truncated = enc.clone();
        truncated.truncate(enc.len() - 3);
        assert!(decode_manifest(&truncated).is_err());
        // 恶意名字长度
        let mut evil = enc.clone();
        evil[4] = 0xFF;
        evil[5] = 0xFF;
        assert!(decode_manifest(&evil).is_err(), "超长名字声明应被拒绝");
        let oversized = MEntry {
            name: "x".repeat(MAX_NAME + 1),
            is_dir: false,
            size: 0,
            mtime: 0,
            seg: 1,
            tar_path: "x".to_string(),
        };
        assert!(encode_manifest(&[oversized]).is_err(), "编码超长名字必须被拒绝");
    }

    #[test]
    fn seg_aad_is_stable() {
        // 固化格式：MAGIC + 用途（manifest=0 / data=1）+ 序号（8B BE）
        assert_eq!(
            seg_aad(SEG_MANIFEST, 7),
            [b'V', b'G', b'S', b'2', 0, 0, 0, 0, 0, 0, 0, 0, 7]
        );
        assert_eq!(seg_aad(SEG_DATA, 0), [b'V', b'G', b'S', b'2', 1, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn reorder_seq_rejected_by_aad() {
        let key: [u8; 32] = [0x42; 32];
        let nonce: [u8; 12] = [0x24; 12];
        let plain = b"segment payload";
        let (ct, tag) = encrypt_payload(&key, SEG_DATA, 1, &nonce, plain);
        // 正确序号可解
        let back = decrypt_payload(&key, SEG_DATA, 1, &nonce, &ct, &tag).unwrap();
        assert_eq!(back, plain);
        // AAD 换序号（模拟段重排）→ 认证失败
        assert!(decrypt_payload(&key, SEG_DATA, 2, &nonce, &ct, &tag).is_err());
        // 换段类型（模拟拼接他段数据）→ 认证失败
        assert!(decrypt_payload(&key, SEG_MANIFEST, 1, &nonce, &ct, &tag).is_err());
    }

    fn scan_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "vaultguard-vgs2-{tag}-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn parallel_batch_encrypt_write_and_scan_roundtrip() {
        // P6/§十二 并行加密：每段独立 nonce/AAD，可跨线程；写盘必须按序号顺序。
        let path = scan_path("parallel");
        let key = [0x5a; 32];
        let plains: Vec<Vec<u8>> = vec![
            b"seg-one".to_vec(),
            vec![0x11; 4096],
            Vec::new(),
            vec![0x22; 300_000],
            b"seg-five".to_vec(),
        ];
        let mut f = File::create(&path).unwrap();
        f.write_all(&encode_header(KID_ARGON2ID, 65_536, 3, 1, &[0x11; 16], &[0x22; 12]).unwrap())
            .unwrap();
        let expected = plains.clone();
        let results = encrypt_batches_parallel(&key, SEG_DATA, 1, plains, 4).unwrap();
        assert_eq!(results.len(), expected.len());
        // 序号必须与输入顺序一致
        for (i, r) in results.iter().enumerate() {
            assert_eq!(r.seq, 1 + i as u64);
        }
        let metas = write_segments_sequential(&mut f, results).unwrap();
        f.sync_all().unwrap();
        drop(f);

        let mut f = File::open(&path).unwrap();
        let scanned = scan_segments(&mut f).unwrap();
        assert_eq!(scanned, metas);
        assert_eq!(scanned.len(), expected.len());
        for (seg, want) in scanned.iter().zip(expected.iter()) {
            assert_eq!(&read_segment(&mut f, *seg, &key).unwrap(), want);
        }
        // 并行校验应通过；改动任一段密文后必须报错
        verify_segments_parallel(&path, &scanned, &key, 4).unwrap();
        drop(f);
        let mut bytes = std::fs::read(&path).unwrap();
        let tamper = (metas[1].body_offset + 3) as usize;
        bytes[tamper] ^= 0x40;
        std::fs::write(&path, bytes).unwrap();
        assert!(verify_segments_parallel(&path, &scanned, &key, 4).is_err(), "篡改段必须被并行校验拒绝");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn workers_one_matches_multi_worker_output_shape() {
        // 单线程退化路径与多线程路径产出的段结构一致（nonce 随机，只比结构）
        let key = [0x33; 32];
        let mk = || vec![vec![7u8; 1000], vec![8u8; 2000], vec![9u8; 3000]];
        let a = encrypt_batches_parallel(&key, SEG_DATA, 10, mk(), 1).unwrap();
        let b = encrypt_batches_parallel(&key, SEG_DATA, 10, mk(), 8).unwrap();
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.seq, y.seq);
            assert_eq!(x.ct.len(), y.ct.len());
            assert_ne!(x.nonce, y.nonce, "每段必须独立 nonce");
        }
    }
}

//! 三壳容器：PNG(私有块 vGDT) / JPEG(APP15 段) / DOCX(word/vaultData.bin)。
//! 字节级兼容 VaultGuard 原版格式，同时支持 VG\x01 旧产物（FMT_V1）识别与解析。

use std::fs::File;
use std::io::{self, Cursor, Read, Write};
use std::path::Path;

use crate::crypto::{FMT_ALL, FMT_V1, FMT_V2, FMT_V3};

pub const PNG_SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
pub const JPG_SIG: [u8; 2] = [0xFF, 0xD8];
pub const CHUNK_T: &[u8; 4] = b"vGDT";
pub const JPG_APP: u8 = 0xEF;
pub const DOCX_PART: &str = "word/vaultData.bin";
pub const SUB_HEAD: u8 = 0;
pub const SUB_DATA: u8 = 1;
pub const SUB_TAG: u8 = 2;
pub const JPG_PAY_MAX: usize = 60_000;
pub const PROBE_LIM: u64 = 16 << 20;

// 伪装底图资源（仅容器外观，不承载数据）
#[allow(dead_code)]
const BG_PNGS: [&[u8]; 3] = [
    include_bytes!("../res/bg0.png"),
    include_bytes!("../res/bg1.png"),
    include_bytes!("../res/bg2.png"),
];
#[allow(dead_code)]
const BG_JPGS: [&[u8]; 3] = [
    include_bytes!("../res/bg0.jpg"),
    include_bytes!("../res/bg1.jpg"),
    include_bytes!("../res/bg2.jpg"),
];
#[allow(dead_code)]
const DOCX_TPLS: [&[u8]; 3] = [
    include_bytes!("../res/tpl0.docx"),
    include_bytes!("../res/tpl1.docx"),
    include_bytes!("../res/tpl2.docx"),
];

/// 加密事件。
pub enum Ev {
    H(Vec<u8>),
    D(Vec<u8>),
    T(Vec<u8>),
}

impl Ev {
    pub fn sub(&self) -> u8 {
        match self {
            Ev::H(_) => SUB_HEAD,
            Ev::D(_) => SUB_DATA,
            Ev::T(_) => SUB_TAG,
        }
    }
    pub fn data(&self) -> &[u8] {
        match self {
            Ev::H(v) | Ev::D(v) | Ev::T(v) => v,
        }
    }
}

/// 事件汇流口：各壳把加密事件序列包装成自身容器格式写出。
pub trait Sink {
    fn emit(&mut self, ev: &Ev) -> io::Result<()>;
}

// ── PNG 壳 ────────────────────────────────────────────────────────
fn crc32_cat(a: &[u8], b: &[u8]) -> [u8; 4] {
    let mut h = crc32fast::Hasher::new();
    h.update(a);
    h.update(b);
    h.finalize().to_be_bytes()
}

fn bg_prefix(bg: &[u8]) -> io::Result<Vec<u8>> {
    let mut off = 8usize;
    while off + 8 <= bg.len() {
        let ln = u32::from_be_bytes([bg[off], bg[off + 1], bg[off + 2], bg[off + 3]]) as usize;
        let t = &bg[off + 4..off + 8];
        off += 12 + ln;
        if t == b"IEND" {
            return Ok(bg[..off - 12].to_vec());
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "底图损坏"))
}

struct PngSink {
    f: File,
}

impl PngSink {
    fn wchunk(&mut self, tag: &[u8; 4], data: &[u8]) -> io::Result<()> {
        self.f.write_all(&(data.len() as u32).to_be_bytes())?;
        self.f.write_all(tag)?;
        self.f.write_all(data)?;
        self.f.write_all(&crc32_cat(tag, data))?;
        Ok(())
    }
}

impl Sink for PngSink {
    fn emit(&mut self, ev: &Ev) -> io::Result<()> {
        let mut d = Vec::with_capacity(ev.data().len() + 1);
        d.push(ev.sub());
        d.extend_from_slice(ev.data());
        self.wchunk(CHUNK_T, &d)
    }
}

pub fn enc_png<G>(out: &Path, gen: G) -> io::Result<()>
where
    G: FnOnce(&mut dyn Sink) -> io::Result<()>,
{
    let bg = BG_PNGS[(rand::random::<u32>() as usize) % BG_PNGS.len()];
    let pref = bg_prefix(bg)?;
    let mut f = File::create(out)?;
    f.write_all(&pref)?;
    let mut sink = PngSink { f };
    gen(&mut sink)?;
    sink.wchunk(b"IEND", &[])?;
    sink.f.flush()?;
    Ok(())
}

/// 解析 PNG 加密事件（CRC 校验）。
pub fn evs_png<F>(path: &Path, mut on: F) -> io::Result<()>
where
    F: FnMut(Ev) -> io::Result<()>,
{
    let mut f = File::open(path)?;
    let mut sig = [0u8; 8];
    f.read_exact(&mut sig)?;
    if sig != PNG_SIG {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "不是 PNG 文件"));
    }
    loop {
        let mut hdr = [0u8; 8];
        if f.read(&mut hdr)? < 8 {
            break; // 结构截断但已读完则结束（与 python 一致：不足 8 视为结束）
        }
        let ln = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
        let tag = [hdr[4], hdr[5], hdr[6], hdr[7]];
        let mut data = vec![0u8; ln];
        f.read_exact(&mut data)?;
        let mut crcb = [0u8; 4];
        f.read_exact(&mut crcb)?;
        if crcb != crc32_cat(&tag, &data) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "数据损坏"));
        }
        if tag == *CHUNK_T && !data.is_empty() {
            let sub = data[0];
            let pl = data[1..].to_vec();
            let ev = match sub {
                SUB_HEAD => Ev::H(pl),
                SUB_DATA => Ev::D(pl),
                SUB_TAG => Ev::T(pl),
                _ => continue,
            };
            on(ev)?;
        }
        if tag == *b"IEND" {
            break;
        }
    }
    Ok(())
}

// ── JPEG 壳 ───────────────────────────────────────────────────────
fn jseg(sub: u8, body: &[u8], out: &mut Vec<u8>) {
    let mut seg = Vec::with_capacity(9 + body.len());
    seg.push(sub);
    seg.extend_from_slice(&(body.len() as u32).to_be_bytes());
    let mut h = crc32fast::Hasher::new();
    h.update(&seg);
    h.update(body);
    seg.extend_from_slice(&h.finalize().to_be_bytes());
    seg.extend_from_slice(body);
    out.push(0xFF);
    out.push(JPG_APP);
    out.extend_from_slice(&((seg.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(&seg);
}

struct JpgSink {
    buf: Vec<u8>,
}

impl Sink for JpgSink {
    fn emit(&mut self, ev: &Ev) -> io::Result<()> {
        let sub = ev.sub();
        match ev {
            Ev::D(pl) => {
                let mut off = 0usize;
                while off < pl.len() {
                    let e = (off + JPG_PAY_MAX).min(pl.len());
                    jseg(sub, &pl[off..e], &mut self.buf);
                    off = e;
                }
            }
            _ => jseg(sub, ev.data(), &mut self.buf),
        }
        Ok(())
    }
}

pub fn enc_jpg<G>(out: &Path, gen: G) -> io::Result<()>
where
    G: FnOnce(&mut dyn Sink) -> io::Result<()>,
{
    let bg = BG_JPGS[(rand::random::<u32>() as usize) % BG_JPGS.len()];
    let mut sink = JpgSink {
        buf: Vec::with_capacity(1 << 20),
    };
    gen(&mut sink)?;
    let mut f = File::create(out)?;
    f.write_all(&JPG_SIG)?;
    f.write_all(&sink.buf)?;
    f.write_all(&bg[2..])?;
    f.flush()?;
    Ok(())
}

/// 遍历 JPEG 段，回调 (marker, payload)。EOI 后结束。
fn iter_jpeg_segs<F>(f: &mut File, mut cb: F) -> io::Result<()>
where
    F: FnMut(u8, Vec<u8>) -> io::Result<()>,
{
    let mut byte = [0u8; 1];
    loop {
        if f.read(&mut byte)? == 0 {
            return Ok(());
        }
        if byte[0] != 0xFF {
            continue;
        }
        let mk = loop {
            if f.read(&mut byte)? == 0 {
                return Ok(());
            }
            if byte[0] != 0xFF {
                break byte[0];
            }
        };
        let no_len = mk == 0xD8 || mk == 0xD9 || mk == 0x01 || (0xD0..=0xD7).contains(&mk);
        if no_len {
            if mk == 0xD9 {
                return Ok(()); // EOI
            }
            continue;
        }
        let mut lnb = [0u8; 2];
        if f.read(&mut lnb)? != 2 {
            return Ok(());
        }
        let ln = u16::from_be_bytes(lnb) as usize;
        if ln < 2 {
            return Ok(());
        }
        let mut pl = vec![0u8; ln - 2];
        if f.read(&mut pl)? != pl.len() {
            return Ok(());
        }
        cb(mk, pl)?;
    }
}

/// 解析 JPEG 加密事件（v2 帧头 + CRC，v1 兼容）。
pub fn evs_jpg<F>(path: &Path, mut on: F) -> io::Result<()>
where
    F: FnMut(Ev) -> io::Result<()>,
{
    let mut f = File::open(path)?;
    let mut sig = [0u8; 2];
    f.read_exact(&mut sig)?;
    if sig != JPG_SIG {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "不是 JPEG 文件"));
    }
    let mut fmt: Option<[u8; 3]> = None;
    iter_jpeg_segs(&mut f, |mk, pl| {
        if mk != JPG_APP || pl.is_empty() {
            return Ok(());
        }
        let sub = pl[0];
        let body = &pl[1..];
        let payload: Vec<u8>;
        if sub == SUB_HEAD && fmt.is_none() {
            if body.len() >= 3 && FMT_ALL.contains(&&body[..3]) {
                fmt = Some([body[0], body[1], body[2]]);
                payload = body.to_vec();
            } else {
                // v2: 剥 8B 帧头
                if body.len() < 8 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "JPEG 加密段结构损坏",
                    ));
                }
                let ln = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
                let crc = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                if ln + 8 != body.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "JPEG 加密段长度不符",
                    ));
                }
                check_jseg_crc(sub, &body, crc)?;
                if !FMT_ALL.contains(&&body[8..11]) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "不是本工具产物",
                    ));
                }
                fmt = Some([body[8], body[9], body[10]]);
                payload = body[8..].to_vec();
            }
        } else if fmt == Some(*FMT_V2) || fmt == Some(*FMT_V3) {
            if body.len() < 8 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "JPEG 加密段结构损坏",
                ));
            }
            let ln = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
            let crc = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
            if ln + 8 != body.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "JPEG 加密段长度不符",
                ));
            }
            check_jseg_crc(sub, &body, crc)?;
            payload = body[8..].to_vec();
        } else if fmt == Some([FMT_V1[0], FMT_V1[1], FMT_V1[2]]) {
            payload = body.to_vec();
        } else {
            return Ok(()); // fmt 未定，跳过非 HEAD 段
        }
        match sub {
            SUB_HEAD => on(Ev::H(payload)),
            SUB_DATA => on(Ev::D(payload)),
            SUB_TAG => on(Ev::T(payload)),
            _ => Ok(()),
        }
    })?;
    Ok(())
}

fn check_jseg_crc(sub: u8, body: &[u8], expect: u32) -> io::Result<()> {
    let mut h = crc32fast::Hasher::new();
    h.update(&[sub]);
    h.update(&body[..4]);
    h.update(&body[8..]);
    if h.finalize() != expect {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "JPEG 数据校验失败(可能被改动)",
        ));
    }
    Ok(())
}

// ── DOCX 壳 ───────────────────────────────────────────────────────
struct DocxSink {
    zout: zip::ZipWriter<File>,
    opts: zip::write::FileOptions,
    started: bool,
}

impl Sink for DocxSink {
    fn emit(&mut self, ev: &Ev) -> io::Result<()> {
        if !self.started {
            self.zout.start_file(DOCX_PART, self.opts)?;
            self.started = true;
        }
        self.zout
            .write_all(&[ev.sub()])?;
        self.zout
            .write_all(&(ev.data().len() as u32).to_be_bytes())?;
        self.zout.write_all(ev.data())?;
        Ok(())
    }
}

pub fn enc_docx<G>(out: &Path, gen: G) -> io::Result<()>
where
    G: FnOnce(&mut dyn Sink) -> io::Result<()>,
{
    let tpl = DOCX_TPLS[(rand::random::<u32>() as usize) % DOCX_TPLS.len()];
    let mut zin = zip::ZipArchive::new(Cursor::new(tpl))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("模板损坏: {}", e)))?;
    let mut zout = zip::ZipWriter::new(File::create(out)?);
    let opts = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o644);
    for i in 0..zin.len() {
        let mut entry = zin
            .by_index(i)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let name = entry.name().to_string();
        if name == DOCX_PART {
            continue; // 模板自身声明会被下方重写
        }
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;
        zout.start_file(name, opts)?;
        zout.write_all(&buf)?;
    }
    let mut sink = DocxSink {
        zout,
        opts,
        started: false,
    };
    gen(&mut sink)?;
    if !sink.started {
        sink.zout.start_file(DOCX_PART, opts)?;
    }
    sink.zout
        .finish()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    Ok(())
}

/// 解析 DOCX 加密事件。
pub fn evs_docx<F>(path: &Path, mut on: F) -> io::Result<()>
where
    F: FnMut(Ev) -> io::Result<()>,
{
    let file = File::open(path)?;
    let mut zin = zip::ZipArchive::new(file)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("不是有效 Office 文档: {}", e)))?;
    let mut src = match zin.by_name(DOCX_PART) {
        Ok(s) => s,
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "文档内无加密数据零件",
            ))
        }
    };
    loop {
        let mut hdr = [0u8; 5];
        let n = src.read(&mut hdr)?;
        if n == 0 {
            break;
        }
        if n != 5 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "加密数据零件损坏"));
        }
        let sub = hdr[0];
        let ln = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
        let mut pl = vec![0u8; ln];
        src.read_exact(&mut pl)?;
        let ev = match sub {
            SUB_HEAD => Ev::H(pl),
            SUB_DATA => Ev::D(pl),
            SUB_TAG => Ev::T(pl),
            _ => continue,
        };
        on(ev)?;
    }
    Ok(())
}

// ── 识别 ──────────────────────────────────────────────────────────
pub fn probe_png(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut sig = [0u8; 8];
    if f.read_exact(&mut sig).is_err() || sig != PNG_SIG {
        return false;
    }
    let mut n: u64 = 8;
    loop {
        let mut hdr = [0u8; 8];
        if f.read(&mut hdr).unwrap_or(0) == 0 {
            return false;
        }
        if hdr.len() != 8 {
            return false;
        }
        let ln = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as u64;
        let t = [hdr[4], hdr[5], hdr[6], hdr[7]];
        n += 8;
        if ln > PROBE_LIM - n {
            return false;
        }
        let mut data = vec![0u8; ln as usize];
        if f.read(&mut data).unwrap_or(0) != ln as usize {
            return false;
        }
        let mut crc = [0u8; 4];
        if f.read(&mut crc).unwrap_or(0) != 4 {
            return false;
        }
        n += ln + 4;
        if t == *CHUNK_T
            && !data.is_empty()
            && data[0] == SUB_HEAD
            && data.len() >= 4
            && FMT_ALL.contains(&&data[1..4])
        {
            return true;
        }
        if t == *b"IEND" {
            return false;
        }
    }
}

pub fn probe_jpg(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut sig = [0u8; 2];
    if f.read_exact(&mut sig).is_err() || sig != JPG_SIG {
        return false;
    }
    let mut n: u64 = 2;
    let mut hit = false;
    let r = iter_jpeg_segs(&mut f, |mk, pl| {
        n += pl.len() as u64 + 4;
        if n > PROBE_LIM {
            return Ok(());
        }
        if mk == JPG_APP && !pl.is_empty() && pl[0] == SUB_HEAD && pl.len() >= 4 {
            if FMT_ALL.contains(&&pl[1..4]) {
                hit = true;
                return Ok(());
            }
            if pl.len() >= 12 {
                let ln = u32::from_be_bytes([pl[1], pl[2], pl[3], pl[4]]) as usize;
                if 1 + 8 + ln == pl.len() && FMT_ALL.contains(&&pl[9..12]) {
                    hit = true;
                    return Ok(());
                }
            }
        }
        Ok(())
    });
    r.is_ok() && hit
}

pub fn probe_docx(path: &Path) -> bool {
    let Ok(file) = File::open(path) else {
        return false;
    };
    let Ok(mut zin) = zip::ZipArchive::new(file) else {
        return false;
    };
    let Ok(mut f) = zin.by_name(DOCX_PART) else {
        return false;
    };
    let mut head = [0u8; 8];
    if f.read(&mut head).unwrap_or(0) != 8 {
        return false;
    }
    if head.len() < 8 || head[0] != SUB_HEAD {
        return false;
    }
    let ln = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    ln >= 3 && FMT_ALL.contains(&&head[5..8])
}

/// 识别外壳：'png' | 'jpg' | 'docx' | None
pub fn probe_vault(path: &Path) -> Option<&'static str> {
    let mut f = File::open(path).ok()?;
    let mut sig = [0u8; 8];
    f.read_exact(&mut sig).ok()?;
    drop(f);
    if sig.starts_with(&PNG_SIG[..8]) && probe_png(path) {
        return Some("png");
    }
    if sig.starts_with(&JPG_SIG[..2]) && probe_jpg(path) {
        return Some("jpg");
    }
    if &sig[..2] == b"PK" && probe_docx(path) {
        return Some("docx");
    }
    None
}

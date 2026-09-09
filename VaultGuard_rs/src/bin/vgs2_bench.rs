//! VGS2 保险箱性能基准（P4/P5/P7 验收工具，本机运行，CI 不跑）。
//!
//! 用法：
//!   vgs2-bench run --files <N> --total-bytes <B> [--runs <R>] [--profile] [--keep]
//!
//! 每次 run 独立生成 <N> 个文件、合计 <B> 字节的夹具目录，然后依次测量：
//!   create —— 新建空箱（含首次空保存）
//!   add    —— add_paths 暂存拷贝
//!   save   —— 首次保存（新建箱为 V2 后的追加式：数据段 + manifest）
//!   open   —— manifest 打开
//!   compact—— 全量压缩（GC 重写）
//!   upgrade—— VGS1 打开后新增一文件再保存（旧格式首次保存 = 全量重写）
//! 输出以 `key=value` 一行一个阶段；`--profile` 时另打印每个操作的阶段耗时
//! （来自 vaultguard::profile，运行时开启）。
//!
//! 临时目录、夹具与保险箱都在 std::env::temp_dir() 下；磁盘不足时请把
//! TEMP/TMP 指到空间足够的盘再运行。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use vaultguard::crypto::Gcm;
use vaultguard::safe;

const PASS: &str = "bench-pass-2026";

struct Opts {
    files: u64,
    total: u64,
    runs: u32,
    profile: bool,
    keep: bool,
}

fn parse(args: &[String]) -> Result<Opts, String> {
    let mut files = 0u64;
    let mut total = 0u64;
    let mut runs = 1u32;
    let mut profile = false;
    let mut keep = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "run" => {} // 兼容子命令写法：vgs2-bench run --files ...
            "--files" => {
                i += 1;
                files = args.get(i).ok_or("--files 需要数值")?.parse().map_err(|_| "--files 数值无效")?;
            }
            "--total-bytes" => {
                i += 1;
                total = args.get(i).ok_or("--total-bytes 需要数值")?.parse().map_err(|_| "--total-bytes 数值无效")?;
            }
            "--runs" => {
                i += 1;
                runs = args.get(i).ok_or("--runs 需要数值")?.parse().map_err(|_| "--runs 数值无效")?;
            }
            "--profile" => profile = true,
            "--keep" => keep = true,
            other => return Err(format!("未知参数: {other}")),
        }
        i += 1;
    }
    if files == 0 || total == 0 {
        return Err("必须提供 --files 与 --total-bytes".to_string());
    }
    Ok(Opts { files, total, runs, profile, keep })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(|s| s.as_str()) == Some("crypto") {
        let bytes: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1 << 30);
        crypto_throughput(bytes);
        return;
    }
    if args.first().map(|s| s.as_str()) == Some("pack") {
        let files: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1000);
        let bytes: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1 << 30);
        pack_throughput(files, bytes);
        return;
    }
    if args.first().map(|s| s.as_str()) == Some("segenc") {
        let bytes: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1 << 30);
        segenc_throughput(bytes);
        return;
    }
    if args.first().map(|s| s.as_str()) == Some("segenc-pack") {
        let files: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1000);
        let bytes: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1 << 30);
        segenc_pack(files, bytes);
        return;
    }
    if args.first().map(|s| s.as_str()) == Some("staged-pack") {
        let files: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1000);
        let bytes: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1 << 30);
        staged_pack(files, bytes);
        return;
    }
    let opts = match parse(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("参数错误: {e}");
            std::process::exit(2);
        }
    };
    println!("files={} total={} runs={}", opts.files, opts.total, opts.runs);
    for run in 1..=opts.runs {
        let result = run_once(&opts, run);
        match result {
            Ok(line) => println!("{line}"),
            Err(e) => {
                println!("run={run} ERROR {e}");
                if opts.keep {
                    println!("临时目录已保留（--keep），路径见上方 ERROR 前的 run 输出");
                }
            }
        }
    }
}

/// 与真实 save 更接近：夹具先经 std::fs::copy 拷入 staged 目录（同 add_paths），
/// 再从 staged 读取打包加密。用于定位「读 staged 副本」与「读夹具」的差异。
fn staged_pack(files: u64, bytes: u64) {
    let work = unique_workdir();
    std::fs::create_dir_all(&work).unwrap();
    let fixture = work.join("src");
    gen_fixture(&fixture, files, bytes).expect("夹具生成失败");
    let staged = work.join("adds");
    std::fs::create_dir_all(&staged).unwrap();
    let mut srcs: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&fixture) {
        for e in rd.flatten() {
            srcs.push(e.path());
        }
    }
    let t0 = Instant::now();
    let mut items: Vec<(PathBuf, String, bool)> = Vec::new();
    for (i, src) in srcs.iter().enumerate() {
        let dst = staged.join(format!("{:016x}", i + 1));
        // 手动缓冲拷贝（对比 std::fs::copy 的冷读表现）
        let mut dst_f = std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(&dst).expect("create"));
        let mut src_f = std::io::BufReader::with_capacity(1 << 20, std::fs::File::open(src).expect("open"));
        std::io::copy(&mut src_f, &mut dst_f).expect("copy");
        dst_f.flush().expect("flush");
        items.push((dst, format!("f{i:05}.bin"), false));
    }
    let copy_s = t0.elapsed().as_secs_f64();
    // 纯读诊断：从 staged 打包到 sink（无加密无写盘）
    let t0 = Instant::now();
    vaultguard::tarx::pack_entries_to_writer(&items, std::io::sink()).expect("打包失败");
    let read_s = t0.elapsed().as_secs_f64();
    let fpath = work.join("seg.bin");
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let mut f = std::fs::File::create(&fpath).unwrap();
    f.write_all(vaultguard::vgs2::encode_header(1, 65536, 3, 1, &[0x11; 16], &[0x22; 12]).unwrap().as_slice()).unwrap();
    vaultguard::profile::begin();
    let t0 = Instant::now();
    vaultguard::vgs2::append_stream_segment(&mut f, vaultguard::vgs2::SEG_DATA, 1, &key, nonce, |w| {
        vaultguard::tarx::pack_entries_to_writer(&items, w)
    })
    .unwrap();
    let secs = t0.elapsed().as_secs_f64();
    let stats = vaultguard::profile::end();
    let mut s = format!("staged_pack_mbs={:.1} copy_s={copy_s:.3} read_s={read_s:.3} secs={secs:.3}", bytes as f64 / 1e6 / secs);
    for (name, t, c) in stats {
        s.push_str(&format!(" {name}={t:.3}x{c}"));
    }
    println!("{s}");
    drop(f);
    let _ = std::fs::remove_dir_all(&work);
}

/// 与真实保存完全相同的组合：tar 打包 → SegmentEncWriter（加密 + 写段）。
/// 用于区分「打包-加密-写盘」三者叠加时的真实耗时。
fn segenc_pack(files: u64, bytes: u64) {
    let work = unique_workdir();
    std::fs::create_dir_all(&work).unwrap();
    let fixture = work.join("src");
    gen_fixture(&fixture, files, bytes).expect("夹具生成失败");
    let mut srcs: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&fixture) {
        for e in rd.flatten() {
            srcs.push(e.path());
        }
    }
    let items: Vec<(PathBuf, String, bool)> = srcs
        .iter()
        .map(|p| {
            let name = p.file_name().and_then(|x| x.to_str()).unwrap_or("f").to_string();
            (p.clone(), name, false)
        })
        .collect();
    let fpath = work.join("seg.bin");
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let mut f = std::fs::File::create(&fpath).unwrap();
    f.write_all(vaultguard::vgs2::encode_header(1, 65536, 3, 1, &[0x11; 16], &[0x22; 12]).unwrap().as_slice()).unwrap();
    vaultguard::profile::begin();
    let t0 = Instant::now();
    vaultguard::vgs2::append_stream_segment(&mut f, vaultguard::vgs2::SEG_DATA, 1, &key, nonce, |w| {
        vaultguard::tarx::pack_entries_to_writer(&items, w)
    })
    .unwrap();
    let secs = t0.elapsed().as_secs_f64();
    let stats = vaultguard::profile::end();
    let mut s = format!("segenc_pack_mbs={:.1} files={files} bytes={bytes} secs={secs:.3}", bytes as f64 / 1e6 / secs);
    for (name, t, c) in stats {
        s.push_str(&format!(" {name}={t:.3}x{c}"));
    }
    println!("{s}");
    drop(f);
    let _ = std::fs::remove_dir_all(&work);
}

/// 隔离测试 SegmentEncWriter 的「加密 + 写段」路径：不经过 tar 打包，
/// 直接向 append_stream_segment 灌 1 MiB 明文块。
fn segenc_throughput(bytes: u64) {
    let work = unique_workdir();
    std::fs::create_dir_all(&work).unwrap();
    let fpath = work.join("seg.bin");
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let mut f = std::fs::File::create(&fpath).unwrap();
    f.write_all(vaultguard::vgs2::encode_header(1, 65536, 3, 1, &[0x11; 16], &[0x22; 12]).unwrap().as_slice()).unwrap();
    let block = vec![0xABu8; 1 << 20];
    let nblocks = bytes / (1 << 20);
    vaultguard::profile::begin();
    let t0 = Instant::now();
    vaultguard::vgs2::append_stream_segment(&mut f, vaultguard::vgs2::SEG_DATA, 1, &key, nonce, |w| {
        for _ in 0..nblocks {
            w.write_all(&block)?;
        }
        Ok(())
    })
    .unwrap();
    let secs = t0.elapsed().as_secs_f64();
    let stats = vaultguard::profile::end();
    let mut s = format!("segenc_mbs={:.1} bytes={bytes} secs={secs:.3}", bytes as f64 / 1e6 / secs);
    for (name, t, c) in stats {
        s.push_str(&format!(" {name}={t:.3}x{c}"));
    }
    println!("{s}");
    drop(f);
    let _ = std::fs::remove_dir_all(&work);
}

/// 内存内 GCM 加密 + GHASH 吞吐（P5：隔离「AES-GCM 耗时」与磁盘 I/O）。
fn crypto_throughput(bytes: u64) {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let mut buf = vec![0xABu8; 1 << 20];
    // 完整 GCM：CTR + GHASH
    let mut g = Gcm::new(&key, &nonce, b"VGS2");
    let t0 = Instant::now();
    let mut total = 0u64;
    while total < bytes {
        g.crypt_in_place(&mut buf);
        g.ghash_data(&buf);
        total += buf.len() as u64;
    }
    let _ = g.finish_tag();
    let full = t0.elapsed().as_secs_f64();
    // 仅 GHASH（不含 CTR）：判断瓶颈是否在认证路径
    let mut g2 = Gcm::new(&key, &nonce, b"VGS2");
    let t0 = Instant::now();
    let mut total = 0u64;
    while total < bytes {
        g2.ghash_data(&buf);
        total += buf.len() as u64;
    }
    let _ = g2.finish_tag();
    let gh = t0.elapsed().as_secs_f64();
    println!(
        "gcm_mbs={:.1} ghash_only_mbs={:.1} bytes={} full_s={:.3} ghash_s={:.3}",
        bytes as f64 / 1e6 / full,
        bytes as f64 / 1e6 / gh,
        bytes,
        full,
        gh
    );
}

/// 纯 tar 打包吞吐：生成夹具目录后直接打包到 io::sink（无加密、无磁盘写）。
/// 用于区分「读文件/打包」与「加密/写盘」在保存路径中的占比。
fn pack_throughput(files: u64, bytes: u64) {
    let work = unique_workdir();
    let fixture = work.join("src");
    gen_fixture(&fixture, files, bytes).expect("夹具生成失败");
    let mut srcs: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&fixture) {
        for e in rd.flatten() {
            srcs.push(e.path());
        }
    }
    let items: Vec<(PathBuf, String, bool)> = srcs
        .iter()
        .map(|p| {
            let name = p.file_name().and_then(|x| x.to_str()).unwrap_or("f").to_string();
            (p.clone(), name, false)
        })
        .collect();
    let t0 = Instant::now();
    vaultguard::tarx::pack_entries_to_writer(&items, std::io::sink()).expect("打包失败");
    let secs = t0.elapsed().as_secs_f64();
    println!("pack_mbs={:.1} files={files} bytes={bytes} secs={secs:.3}", bytes as f64 / 1e6 / secs);
    let _ = std::fs::remove_dir_all(&work);
}

fn run_once(opts: &Opts, run: u32) -> Result<String, String> {
    let work = unique_workdir();
    let fixture = work.join("src");
    let box_path = work.join("box.vgsafe");
    let v1_path = work.join("box_v1.vgsafe");
    let mut out = format!("run={run} work={}", work.display());

    // 1) 夹具生成
    let t0 = Instant::now();
    gen_fixture(&fixture, opts.files, opts.total).map_err(|e| format!("夹具生成失败: {e}"))?;
    out.push_str(&format!(" gen_s={:.3}", t0.elapsed().as_secs_f64()));

    // 2) create（空箱，含一次空保存）
    profile_begin(opts);
    let t0 = Instant::now();
    let mut sess = safe::create(&box_path, PASS).map_err(|e| format!("create 阶段失败（box={}）: {e}", box_path.display()))?;
    out.push_str(&format!(" create_s={:.3}", t0.elapsed().as_secs_f64()));
    out.push_str(&profile_line("create", opts));

    // 3) add_paths（暂存拷贝）
    let mut srcs: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&fixture) {
        for e in rd.flatten() {
            srcs.push(e.path());
        }
    }
    profile_begin(opts);
    let t0 = Instant::now();
    sess.add_paths(&srcs).map_err(|e| format!("add 阶段失败: {e}"))?;
    out.push_str(&format!(" add_s={:.3}", t0.elapsed().as_secs_f64()));
    out.push_str(&profile_line("add", opts));

    // 4) 首次保存（新建箱为 V2 后走追加式：新数据段 + manifest）
    profile_begin(opts);
    let t0 = Instant::now();
    sess.save(&|_| {}).map_err(|e| format!("save 阶段失败: {e}"))?;
    out.push_str(&format!(" save_s={:.3}", t0.elapsed().as_secs_f64()));
    out.push_str(&profile_line("save", opts));

    // 5) 关闭会话（擦除暂存）后重新打开（只解 manifest）
    drop(sess);
    profile_begin(opts);
    let t0 = Instant::now();
    let opened = safe::open(&box_path, PASS).map_err(|e| format!("open 阶段失败: {e}"))?;
    out.push_str(&format!(" open_s={:.3}", t0.elapsed().as_secs_f64()));
    out.push_str(&profile_line("open", opts));

    // 6) 全量压缩（GC 重写：物化 → 重打包 → 自校验 → 原子替换）
    let mut sess = opened;
    profile_begin(opts);
    let t0 = Instant::now();
    sess.compact(&|_| {}).map_err(|e| format!("compact 阶段失败: {e}"))?;
    out.push_str(&format!(" compact_s={:.3}", t0.elapsed().as_secs_f64()));
    out.push_str(&profile_line("compact", opts));

    // 压缩后再次打开核对条目数
    drop(sess);
    let reopened = safe::open(&box_path, PASS).map_err(|e| format!("reopen 阶段失败: {e}"))?;
    out.push_str(&format!(" entries={}", reopened.entries.len()));
    drop(reopened);

    // 7) VGS1 → VGS2 升级首存（全量重写路径，对应文档「初次保存」场景）
    let t0 = Instant::now();
    build_vgs1_box(&fixture, &v1_path, PASS).map_err(|e| format!("VGS1 夹具构建失败: {e}"))?;
    out.push_str(&format!(" v1gen_s={:.3}", t0.elapsed().as_secs_f64()));
    profile_begin(opts);
    let t0 = Instant::now();
    let mut v1 = safe::open(&v1_path, PASS).map_err(|e| format!("v1open 阶段失败: {e}"))?;
    out.push_str(&format!(" v1open_s={:.3}", t0.elapsed().as_secs_f64()));
    out.push_str(&profile_line("v1open", opts));
    // 触发升级：打开旧箱后新增一个文件，保存即全量重写为 VGS2
    // （save() 在会话未修改时是 no-op，与 GUI 行为一致）。
    let small = work.join("small.bin");
    std::fs::write(&small, b"vg2-bench upgrade trigger\n").map_err(|e| e.to_string())?;
    v1.add_paths(&[small.clone()]).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&small);
    profile_begin(opts);
    let t0 = Instant::now();
    v1.save(&|_| {}).map_err(|e| format!("upgrade 阶段失败: {e}"))?;
    out.push_str(&format!(" upgrade_s={:.3}", t0.elapsed().as_secs_f64()));
    out.push_str(&profile_line("upgrade", opts));
    drop(v1);

    if !opts.keep {
        let _ = std::fs::remove_dir_all(&work);
    }
    Ok(out)
}

fn profile_begin(opts: &Opts) {
    if opts.profile {
        vaultguard::profile::begin();
    }
}

fn profile_line(op: &str, opts: &Opts) -> String {
    if !opts.profile {
        return String::new();
    }
    let stats = vaultguard::profile::end();
    let mut s = format!(" profile[{op}]");
    for (name, secs, calls) in stats {
        s.push_str(&format!(" {name}={secs:.3}x{calls}"));
    }
    s
}

/// 生成 <files> 个文件、合计 <total> 字节的夹具目录。内容为确定性伪随机，
/// 各文件按索引旋转起点，避免所有文件内容完全一致。
fn gen_fixture(dir: &Path, files: u64, total: u64) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let buf = pseudo_random(4 << 20, 0x9E3779B97F4A7C15u64);
    let per = total / files.max(1);
    let mut rem = total % files.max(1);
    for i in 0..files {
        let size = per + if rem > 0 { rem -= 1; 1 } else { 0 };
        if size == 0 {
            continue;
        }
        let p = dir.join(format!("f{i:05}.bin"));
        let mut f = std::fs::File::create(&p)?;
        let mut left = size;
        let mut pos = ((i as usize) * 7919) % buf.len();
        while left > 0 {
            let take = left.min(buf.len() as u64) as usize;
            let end = pos + take;
            if end <= buf.len() {
                f.write_all(&buf[pos..end])?;
                pos = end % buf.len();
            } else {
                f.write_all(&buf[pos..])?;
                let rest = take - (buf.len() - pos);
                f.write_all(&buf[..rest])?;
                pos = rest;
            }
            left -= take as u64;
        }
    }
    Ok(())
}

/// 确定性伪随机缓冲（xorshift64*），避免夹具生成成为基准的热点。
fn pseudo_random(len: usize, mut seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        let v = seed.wrapping_mul(0x2545F4914F6CDD1D);
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// 构造一个真实 VGS1 保险箱（头 42B + GCM(tar) + tag），供「VGS1 首次保存升级」
/// 基准场景使用。复刻 safe.rs 的 VGS1 格式与 AAD=b"VGS1"。
fn build_vgs1_box(src: &Path, box_path: &Path, pass: &str) -> std::io::Result<()> {
    use vaultguard::crypto::{derive_v3, ArgonParams, NONCE_SZ};
    let salt = [0x11u8; 16];
    let nonce = [0x22u8; NONCE_SZ];
    let prm = ArgonParams::default();
    let key = derive_v3(pass.as_bytes(), &salt, prm)?;
    let items = dir_items(src)?;
    let mut f = std::fs::File::create(box_path)?;
    f.write_all(b"VGS1")?;
    f.write_all(&[0x01])?;
    f.write_all(&prm.m_kib.to_be_bytes())?;
    f.write_all(&prm.t.to_be_bytes())?;
    f.write_all(&[prm.p as u8])?;
    f.write_all(&salt)?;
    f.write_all(&nonce)?;
    let mut g = Gcm::new(&key, &nonce, b"VGS1");
    {
        let mut enc = V1EncW { f: &mut f, g: &mut g };
        vaultguard::tarx::pack_entries_to_writer(&items, &mut enc)?;
    }
    let tag = g.finish_tag();
    f.write_all(&tag)?;
    f.sync_all()?;
    Ok(())
}

/// 目录条目：(物理路径, 相对路径, 是否目录)，排序稳定。
fn dir_items(dir: &Path) -> std::io::Result<Vec<(PathBuf, String, bool)>> {
    fn rec(base: &Path, d: &Path, out: &mut Vec<(PathBuf, String, bool)>) -> std::io::Result<()> {
        let mut kids: Vec<PathBuf> = std::fs::read_dir(d)?.flatten().map(|e| e.path()).collect();
        kids.sort();
        for p in kids {
            let rel = p.strip_prefix(base).unwrap_or(&p).to_string_lossy().replace('\\', "/");
            let md = std::fs::symlink_metadata(&p)?;
            if md.is_dir() {
                out.push((p.clone(), rel, true));
                rec(base, &p, out)?;
            } else {
                out.push((p, rel, false));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    rec(dir, dir, &mut out)?;
    Ok(out)
}

/// 直通文件写入器：VGS1 的 GCM 加密写（与 safe::EncW 一致：先加密后 GHASH 密文）。
struct V1EncW<'a> {
    f: &'a mut std::fs::File,
    g: &'a mut Gcm,
}

impl Write for V1EncW<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut b = buf.to_vec();
        self.g.crypt_in_place(&mut b);
        self.g.ghash_data(&b);
        self.f.write_all(&b)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.f.flush()
    }
}

fn unique_workdir() -> PathBuf {
    let base = std::env::temp_dir().join("vg2bench");
    let _ = std::fs::create_dir_all(&base);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    base.join(format!("run-{}-{nanos}", std::process::id()))
}

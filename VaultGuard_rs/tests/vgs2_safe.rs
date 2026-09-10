//! VGS2 保险箱 P1–P3 回归：免工作树打开、索引追加、崩溃回退、压缩和 VGS1 升级。

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use vaultguard::{crypto, safe, tarx, vgs2};

fn temp_root(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vg_vgs2_{name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn segment_kinds(path: &Path) -> Vec<u8> {
    let mut f = File::open(path).unwrap();
    vgs2::scan_segments(&mut f)
        .unwrap()
        .into_iter()
        .map(|x| x.head.seg_type)
        .collect()
}

#[test]
fn vgs2_incremental_index_and_export_roundtrip() {
    let root = temp_root("incremental");
    let vault = root.join("box.vgsafe");
    let input = root.join("报告.txt");
    fs::write(&input, "第一版内容").unwrap();

    let mut s = safe::create(&vault, "pass-1").unwrap();
    assert_eq!(&fs::read(&vault).unwrap()[..4], b"VGS2");
    s.add_paths(&[input]).unwrap();
    s.save(&|_| {}).unwrap();
    assert_eq!(segment_kinds(&vault), vec![vgs2::SEG_MANIFEST, vgs2::SEG_DATA, vgs2::SEG_MANIFEST]);
    drop(s);

    // P1：打开后的清单来自 manifest；P2：仅改名只追加新 manifest，不重写数据段。
    let mut s = safe::open(&vault, "pass-1").unwrap();
    assert_eq!(s.entries.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(), vec!["报告.txt"]);
    let before = segment_kinds(&vault);
    s.rename_entry("报告.txt", "归档/最终报告.txt").unwrap_err(); // 目标目录不存在，保持既有交互
    s.move_entry("报告.txt", "归档").unwrap();
    s.save(&|_| {}).unwrap();
    let after = segment_kinds(&vault);
    assert_eq!(after.len(), before.len() + 1);
    assert_eq!(*after.last().unwrap(), vgs2::SEG_MANIFEST);
    assert_eq!(after.iter().filter(|k| **k == vgs2::SEG_DATA).count(), 1);
    drop(s);

    let s = safe::open(&vault, "pass-1").unwrap();
    assert!(s.entries.iter().any(|x| x.name == "归档/报告.txt"));
    let out = root.join("out");
    let n = s.export_selective(&["归档/报告.txt".to_string()], &out).unwrap();
    assert_eq!(n, 1);
    assert_eq!(fs::read(out.join("归档/报告.txt")).unwrap(), "第一版内容".as_bytes());
    drop(s);
    fs::remove_dir_all(root).ok();
}

#[test]
fn vgs2_rolls_back_when_latest_manifest_tag_is_damaged() {
    let root = temp_root("rollback");
    let vault = root.join("box.vgsafe");
    let a = root.join("a.txt");
    let b = root.join("b.txt");
    fs::write(&a, "a").unwrap();
    fs::write(&b, "b").unwrap();
    let mut s = safe::create(&vault, "pass-2").unwrap();
    s.add_paths(&[a]).unwrap();
    s.save(&|_| {}).unwrap();
    s.add_paths(&[b]).unwrap();
    s.save(&|_| {}).unwrap();
    drop(s);

    // 模拟最后一次落盘的 manifest tag 损坏；上一版（只含 a）必须仍可打开。
    let mut bytes = fs::read(&vault).unwrap();
    *bytes.last_mut().unwrap() ^= 0x80;
    fs::write(&vault, bytes).unwrap();
    let s = safe::open(&vault, "pass-2").unwrap();
    assert!(s.entries.iter().any(|x| x.name == "a.txt"));
    assert!(!s.entries.iter().any(|x| x.name == "b.txt"));
    drop(s);
    fs::remove_dir_all(root).ok();
}

#[test]
fn compact_reclaims_deleted_segments_and_v1_save_upgrades() {
    let root = temp_root("compact_upgrade");
    let vault = root.join("box.vgsafe");
    let a = root.join("a.bin");
    let b = root.join("b.bin");
    fs::write(&a, vec![0x11; 300_000]).unwrap();
    fs::write(&b, vec![0x22; 300_000]).unwrap();
    let mut s = safe::create(&vault, "pass-3").unwrap();
    s.add_paths(&[a, b]).unwrap();
    s.save(&|_| {}).unwrap();
    s.remove_entries(&["a.bin".to_string()]).unwrap();
    s.save(&|_| {}).unwrap();
    let before = fs::metadata(&vault).unwrap().len();
    s.compact(&|_| {}).unwrap();
    let after = fs::metadata(&vault).unwrap().len();
    assert!(after < before, "压缩应回收删除条目的数据：{after} >= {before}");
    drop(s);
    let s = safe::open(&vault, "pass-3").unwrap();
    let out = root.join("out");
    s.export_selective(&["b.bin".to_string()], &out).unwrap();
    assert_eq!(fs::read(out.join("b.bin")).unwrap(), vec![0x22; 300_000]);
    drop(s);

    // 生成一个历史 VGS1，再验证它可读且保存时升级到 VGS2。
    let legacy_src = root.join("legacy_src");
    fs::create_dir_all(&legacy_src).unwrap();
    fs::write(legacy_src.join("old.txt"), "legacy").unwrap();
    let legacy = root.join("legacy.vgsafe");
    write_v1(&legacy, "old-pass", &legacy_src);
    let mut old = safe::open(&legacy, "old-pass").unwrap();
    assert!(old.entries.iter().any(|x| x.name == "old.txt"));
    old.rename_entry("old.txt", "new.txt").unwrap();
    old.save(&|_| {}).unwrap();
    assert_eq!(&fs::read(&legacy).unwrap()[..4], b"VGS2");
    drop(old);
    let reopened = safe::open(&legacy, "old-pass").unwrap();
    assert!(reopened.entries.iter().any(|x| x.name == "new.txt"));
    drop(reopened);
    fs::remove_dir_all(root).ok();
}

/// 同一次会话内多次 add（每次生成独立暂存 tar 批）必须先全部正确保存：
/// 段序号连续、manifest 指向正确段、两份内容都能原样导出。
#[test]
fn multiple_adds_before_save_keep_all_contents() {
    let root = temp_root("multi_add");
    let vault = root.join("box.vgsafe");
    let a = root.join("第一份.bin");
    let b = root.join("第二份.bin");
    let c = root.join("第三份.bin");
    fs::write(&a, vec![0xA1; 200_000]).unwrap();
    fs::write(&b, vec![0xB2; 200_000]).unwrap();
    fs::write(&c, vec![0xC3; 200_000]).unwrap();

    let mut s = safe::create(&vault, "pass-multi").unwrap();
    s.add_paths(&[a]).unwrap();
    s.add_paths(&[b]).unwrap();
    s.add_paths(&[c]).unwrap();
    s.save(&|_| {}).unwrap();
    assert_eq!(
        segment_kinds(&vault).iter().filter(|k| **k == vgs2::SEG_DATA).count(),
        3,
        "三次 add 应各自成为独立数据段"
    );
    drop(s);

    // 重新打开：段序号必须从 1 连续（扫描器只认连续序号），内容逐一比对
    let mut f = File::open(&vault).unwrap();
    let segs = vgs2::scan_segments(&mut f).unwrap();
    for (i, seg) in segs.iter().enumerate() {
        assert_eq!(seg.head.seq, 1 + i as u64);
    }
    drop(f);

    let s = safe::open(&vault, "pass-multi").unwrap();
    let out = root.join("out");
    s.export_selective(
        &["第一份.bin".to_string(), "第二份.bin".to_string(), "第三份.bin".to_string()],
        &out,
    )
    .unwrap();
    assert_eq!(fs::read(out.join("第一份.bin")).unwrap(), vec![0xA1; 200_000]);
    assert_eq!(fs::read(out.join("第二份.bin")).unwrap(), vec![0xB2; 200_000]);
    assert_eq!(fs::read(out.join("第三份.bin")).unwrap(), vec![0xC3; 200_000]);
    drop(s);
    fs::remove_dir_all(root).ok();
}

/// 分批打包（并行加密的粒度控制）：按目标字节数切多个 tar，条目下标必须完整覆盖。
#[test]
fn pack_split_tars_splits_by_target_and_covers_all_items() {
    let root = temp_root("split_tars");
    let mut items: Vec<(PathBuf, String)> = Vec::new();
    for i in 0..7u32 {
        let p = root.join(format!("f{i}.bin"));
        fs::write(&p, vec![i as u8; 40_000]).unwrap();
        items.push((p, format!("f{i}.bin")));
    }
    let dir = root.join("tars");
    let tars = tarx::pack_split_tars(&items, 100_000, &dir, 7).unwrap();
    assert!(tars.len() >= 3, "7×40KB / 100KB 目标应切成多个 tar，实际 {}", tars.len());
    let mut seen: Vec<usize> = tars.iter().flat_map(|(_, idx)| idx.clone()).collect();
    seen.sort_unstable();
    assert_eq!(seen, (0..items.len()).collect::<Vec<_>>(), "每个条目必须恰好归属一个 tar");
    for (p, _) in &tars {
        // 文件名带 tag 前缀，避免同一会话多次 add 互相覆盖
        assert!(p.file_name().unwrap().to_string_lossy().starts_with("00000007-"));
    }
    // 再次调用（同目录、不同 tag）不得覆盖上一批
    let again = tarx::pack_split_tars(&items, 100_000, &dir, 8).unwrap();
    assert_eq!(again.len(), tars.len());
    for (p, _) in &tars {
        assert!(p.exists(), "前一批暂存 tar 必须仍存在：{}", p.display());
    }
    fs::remove_dir_all(root).ok();
}

/// 转发分批（并行加密的粒度控制）：小条目驻留内存、超 mem_cap 的条目落盘成批，
/// 且每个内存批都是可独立解开的合法 tar（尾部补块必须完整）。
#[test]
fn relay_batches_mem_and_spill_paths() {
    let root = temp_root("relay_batches");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    let mut items: Vec<(PathBuf, String)> = Vec::new();
    for i in 0..5u32 {
        let p = src.join(format!("f{i}.bin"));
        fs::write(&p, vec![i as u8 + 1; 300_000]).unwrap();
        items.push((p, format!("f{i}.bin")));
    }
    let tp = root.join("src.tar");
    tarx::pack_recursive_entries(&items, File::create(&tp).unwrap()).unwrap();
    let wanted: Vec<(String, String)> = items.iter().map(|(_, a)| (a.clone(), a.clone())).collect();
    let spill = root.join("spill");

    // 小条目：全部驻留内存批（mem_cap 1 MiB > 单条目 ~300 KiB），按 target 切批
    let mut mem: Vec<(Vec<String>, Vec<u8>)> = Vec::new();
    let n = tarx::relay_files_batched(&tp, &wanted, 700_000, 1 << 20, &spill, &mut |b| {
        match b.plain {
            tarx::BatchPlain::Mem(v) => mem.push((b.arcs, v)),
            tarx::BatchPlain::Disk(_) => panic!("小条目不应落盘"),
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(n, 5);
    // 单条目 ≈ 300_544B（512 头 + 数据对齐）：2 条 601KB < 700KB 目标，3 条 901KB 超目标
    // 且再加一条会越过 1 MiB 的 mem_cap → 3 条一批 + 剩余 2 条一批
    assert_eq!(mem.len(), 2, "实际 {}", mem.len());
    assert_eq!(mem.iter().map(|(a, _)| a.len()).collect::<Vec<_>>(), vec![3, 2]);
    for (_, bytes) in &mem {
        assert!(bytes.len() as u64 <= 1 << 20, "内存批不得超过 mem_cap");
    }
    let arcs: usize = mem.iter().map(|(a, _)| a.len()).sum();
    assert_eq!(arcs, 5, "每个条目必须恰好归属一批");
    // 每个内存批都能独立解包（tar 尾部完整、条目数据不跨批）
    let out = root.join("unpack");
    let mut names: Vec<String> = Vec::new();
    for (i, (_, bytes)) in mem.iter().enumerate() {
        let p = root.join(format!("b{i}.tar"));
        fs::write(&p, bytes).unwrap();
        let k = tarx::unpack_file(&p, &out).unwrap();
        assert!(k >= 1, "内存批必须包含完整条目");
        for (name, _, _) in tarx::list_file(&p).unwrap() {
            names.push(name);
        }
    }
    names.sort();
    assert_eq!(names, vec!["f0.bin", "f1.bin", "f2.bin", "f3.bin", "f4.bin"]);

    // 超大条目：单条目 300 KiB > mem_cap 100 KiB → 独占一批并落盘
    let mut spilled = 0usize;
    let n = tarx::relay_files_batched(&tp, &wanted, 700_000, 100_000, &spill, &mut |b| {
        match b.plain {
            tarx::BatchPlain::Mem(_) => panic!("超过 mem_cap 的条目不应驻留内存"),
            tarx::BatchPlain::Disk(_) => spilled += 1,
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(n, 5);
    assert_eq!(spilled, 5);
    assert!(spill.read_dir().unwrap().count() >= 5);
    fs::remove_dir_all(root).ok();
}

fn write_v1(path: &Path, pass: &str, tree: &Path) {
    let mut plain = Vec::new();
    tarx::pack_dir(tree, &mut plain).unwrap();
    let prm = crypto::ArgonParams::default();
    let salt = [0x51; 16];
    let nonce = [0x23; crypto::NONCE_SZ];
    let key = crypto::derive_v3(pass.as_bytes(), &salt, prm).unwrap();
    let mut g = crypto::Gcm::new(&key, &nonce, safe::AAD);
    let mut ct = plain;
    g.crypt_in_place(&mut ct);
    g.ghash_data(&ct);
    let mut f = OpenOptions::new().create_new(true).write(true).open(path).unwrap();
    f.write_all(safe::MAGIC).unwrap();
    f.write_all(&[safe::KDF_ARGON2ID]).unwrap();
    f.write_all(&prm.m_kib.to_be_bytes()).unwrap();
    f.write_all(&prm.t.to_be_bytes()).unwrap();
    f.write_all(&[prm.p as u8]).unwrap();
    f.write_all(&salt).unwrap();
    f.write_all(&nonce).unwrap();
    f.write_all(&ct).unwrap();
    f.write_all(&g.finish_tag()).unwrap();
}

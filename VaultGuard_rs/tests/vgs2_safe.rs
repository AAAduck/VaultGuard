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

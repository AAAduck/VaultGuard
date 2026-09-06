//! 引擎往返回归测试：对应 README「验证要求」的可自动化子集。
//! 覆盖：v2（内置密钥）/ v3（口令）× png/jpg/docx 容器、目录打包、中文与二进制内容、
//! 错误口令拒绝、无口令提示、随机文件名。

use std::fs;
use std::path::PathBuf;

use vaultguard::engine::{self, KeySource};
use vaultguard::shells;

fn temp_root(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "vgtest_{}_{:x}",
        name,
        std::process::id() as usize ^ name.len() ^ 0x5eed
    ));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(d.join("in")).unwrap();
    d
}

fn sample_payload() -> Vec<u8> {
    let mut v = "VaultGuard 往返测试：中文 + 二进制混合内容。\n"
        .as_bytes()
        .to_vec();
    v.extend((0u16..4096).map(|i| (i % 251) as u8));
    v
}

#[test]
fn roundtrip_v2_png_with_dir_and_binary() {
    let root = temp_root("v2png");
    let out = root.join("out");
    let f1 = root.join("in/中文文档.txt");
    fs::write(&f1, sample_payload()).unwrap();
    let dir = root.join("in/子目录");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("bin.dat"), [7u8; 1000]).unwrap();

    let enc = engine::do_enc(
        &[f1, dir],
        "png",
        &out,
        &KeySource::Builtin,
        false,
        None,
    )
    .unwrap();
    assert!(shells::probe_vault(&enc.0).is_some(), "PNG 产物应可识别");
    // 随机文件名：不包含原文件名，扩展名正确
    assert!(
        !enc.0.to_string_lossy().contains("中文文档"),
        "随机名不应泄露原文件名"
    );
    assert!(enc.0.to_string_lossy().ends_with(".png"));

    let res = engine::do_dec(&enc.0, &out, None, None).unwrap();
    assert_eq!(res.entries, 3, "文件 + 目录 + 目录内文件 = 3 个 tar 条目");
    assert!(res.plain_bytes > 0);
    assert!(!res.hashes.is_empty(), "应产出还原文件哈希清单");
    assert_eq!(
        fs::read(res.dst.join("中文文档.txt")).unwrap(),
        sample_payload()
    );
    assert_eq!(
        fs::read(res.dst.join("子目录/bin.dat")).unwrap(),
        [7u8; 1000]
    );

    fs::remove_dir_all(&root).ok();
}

#[test]
fn roundtrip_v3_password_png_and_wrong_password() {
    let root = temp_root("v3png");
    let out = root.join("out");
    let f1 = root.join("in/secret.txt");
    fs::create_dir_all(f1.parent().unwrap()).unwrap();
    fs::write(&f1, b"top secret").unwrap();

    let enc = engine::do_enc(
        &[f1],
        "png",
        &out,
        &KeySource::Passphrase("口令abc123".into()),
        true,
        None,
    )
    .unwrap();
    assert!(shells::probe_vault(&enc.0).is_some(), "产物应可识别");
    // keep_name=true：保留原文件名
    assert!(
        enc.0.to_string_lossy().contains("secret"),
        "keep_name 应保留原名"
    );

    let err = engine::do_dec(&enc.0, &out, Some("wrong-pass"), None).unwrap_err();
    assert!(err.contains("口令"), "错误口令提示应指向口令: {err}");

    let err = engine::do_dec(&enc.0, &out, None, None).unwrap_err();
    assert!(err.contains("口令"), "无口令提示应指向口令: {err}");

    let res = engine::do_dec(&enc.0, &out, Some("口令abc123"), None).unwrap();
    assert_eq!(fs::read(res.dst).unwrap(), b"top secret");

    fs::remove_dir_all(&root).ok();
}

#[test]
fn roundtrip_v3_jpg_binary() {
    let root = temp_root("v3jpg");
    let out = root.join("out");
    let f1 = root.join("in/blob.bin");
    fs::create_dir_all(f1.parent().unwrap()).unwrap();
    let payload: Vec<u8> = (0..=255u8).cycle().take(70_000).collect(); // 跨 JPG 60k 分段
    fs::write(&f1, &payload).unwrap();

    let enc = engine::do_enc(
        &[f1],
        "jpg",
        &out,
        &KeySource::Passphrase("p@ss 中文".into()),
        false,
        None,
    )
    .unwrap();
    assert!(shells::probe_vault(&enc.0).is_some(), "JPG 产物应可识别");

    let res = engine::do_dec(&enc.0, &out, Some("p@ss 中文"), None).unwrap();
    assert_eq!(fs::read(res.dst).unwrap(), payload);

    fs::remove_dir_all(&root).ok();
}

#[test]
fn roundtrip_v2_docx() {
    let root = temp_root("v2docx");
    let out = root.join("out");
    let f1 = root.join("in/报表.xlsx");
    fs::create_dir_all(f1.parent().unwrap()).unwrap();
    fs::write(&f1, [3u8; 4096]).unwrap();

    let enc = engine::do_enc(&[f1], "docx", &out, &KeySource::Builtin, true, None).unwrap();
    assert!(shells::probe_vault(&enc.0).is_some(), "DOCX 产物应可识别");

    let res = engine::do_dec(&enc.0, &out, None, None).unwrap();
    assert_eq!(fs::read(res.dst).unwrap(), [3u8; 4096]);

    fs::remove_dir_all(&root).ok();
}

#[test]
fn encrypt_rejects_blank_passphrase() {
    let root = temp_root("blankpass");
    let out = root.join("out");
    let f1 = root.join("in/a.txt");
    fs::create_dir_all(f1.parent().unwrap()).unwrap();
    fs::write(&f1, b"x").unwrap();

    let err = engine::do_enc(
        &[f1],
        "png",
        &out,
        &KeySource::Passphrase("   ".into()),
        false,
        None,
    )
    .unwrap_err();
    assert!(err.contains("口令"), "空口令应有明确报错: {err}");

    fs::remove_dir_all(&root).ok();
}

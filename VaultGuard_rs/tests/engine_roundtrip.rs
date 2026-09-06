//! 引擎往返回归测试：对应 README「验证要求」的可自动化子集。
//! 覆盖：v2（内置密钥）/ v3（口令）× png/jpg/docx 容器、目录打包、中文与二进制内容、
//! 错误口令拒绝、无口令提示、随机文件名、自定义封面。

use std::fs;
use std::path::PathBuf;

use vaultguard::engine::{self, EncOptions, KeySource};
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

    let opts = EncOptions {
        key_src: KeySource::Builtin,
        keep_name: false,
        cover: None,
    };
    let enc = engine::do_enc(&[f1, dir], "png", &out, &opts, None).unwrap();
    assert!(shells::probe_vault(&enc.0).is_some(), "PNG 产物应可识别");
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

    let opts = EncOptions {
        key_src: KeySource::Passphrase("口令abc123".into()),
        keep_name: true,
        cover: None,
    };
    let enc = engine::do_enc(&[f1], "png", &out, &opts, None).unwrap();
    assert!(shells::probe_vault(&enc.0).is_some(), "产物应可识别");
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

    let opts = EncOptions {
        key_src: KeySource::Passphrase("p@ss 中文".into()),
        keep_name: false,
        cover: None,
    };
    let enc = engine::do_enc(&[f1], "jpg", &out, &opts, None).unwrap();
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

    let opts = EncOptions {
        key_src: KeySource::Builtin,
        keep_name: false,
        cover: None,
    };
    let enc = engine::do_enc(&[f1], "docx", &out, &opts, None).unwrap();
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

    let opts = EncOptions {
        key_src: KeySource::Passphrase("   ".into()),
        keep_name: false,
        cover: None,
    };
    let err = engine::do_enc(&[f1], "png", &out, &opts, None).unwrap_err();
    assert!(err.contains("口令"), "空口令应有明确报错: {err}");

    fs::remove_dir_all(&root).ok();
}

#[test]
fn roundtrip_custom_cover_png() {
    let root = temp_root("cover");
    let out = root.join("out");
    let f1 = root.join("in/secret.txt");
    fs::create_dir_all(f1.parent().unwrap()).unwrap();
    fs::write(&f1, b"custom cover test").unwrap();

    // 用仓库内置的另一张底图充当"用户自定义封面"（保证是合法 PNG）
    let opts = EncOptions {
        key_src: KeySource::Builtin,
        keep_name: false,
        cover: Some(PathBuf::from("res/bg1.png")),
    };
    let enc = engine::do_enc(&[f1], "png", &out, &opts, None).unwrap();
    assert!(
        shells::probe_vault(&enc.0).is_some(),
        "自定义封面产物应可识别"
    );

    let res = engine::do_dec(&enc.0, &out, None, None).unwrap();
    assert_eq!(fs::read(res.dst).unwrap(), b"custom cover test");

    fs::remove_dir_all(&root).ok();
}

#[test]
fn validate_cover_rejects_non_image() {
    let root = temp_root("coverbad");
    let bad = root.join("not_image.txt");
    fs::create_dir_all(&root).unwrap();
    fs::write(&bad, b"plain text, not an image").unwrap();

    assert!(
        shells::validate_cover("png", &bad).is_err(),
        "文本文件不能当 PNG 封面"
    );

    fs::remove_dir_all(&root).ok();
}

//! 长任务取消语义回归：取消必须是「什么都没发生」——
//! 容器逐字节不变、无残留明文/半成品，且会话复位后可原样继续。
//!
//! 覆盖三条主路径：增量保存（append_save）、段级压缩（compact_incremental）、
//! 导出（materialize，含解密落位前的临时明文擦除），以及伪装页加密管道。

use std::fs;
use std::path::PathBuf;

use vaultguard::cancel::CANCELLED_MSG;
use vaultguard::engine::{self, EncOptions, KeySource};
use vaultguard::safe;

fn temp_root(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vg_cancel_{name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// 增量保存被取消：容器不变；复位后重试仍能完成提交。
#[test]
fn cancel_save_keeps_container_byte_identical() {
    let root = temp_root("save");
    let vault = root.join("box.vgsafe");
    let a = root.join("a.txt");
    let b = root.join("b.txt");
    fs::write(&a, "AAA").unwrap();
    fs::write(&b, "BBB").unwrap();

    let mut s = safe::create(&vault, "pw").unwrap();
    s.add_paths(&[a]).unwrap();
    s.save(&|_| {}).unwrap();
    let before = fs::read(&vault).unwrap();

    s.add_paths(&[b]).unwrap();
    let c = s.cancel_flag();
    c.cancel();
    let err = s.save(&|_| {}).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Interrupted, "{err}");
    assert_eq!(fs::read(&vault).unwrap(), before, "取消后容器必须逐字节不变");
    assert!(s.is_cancelled());

    // 会话仍可用：复位后重试提交，新内容真正落盘
    c.reset();
    assert!(!s.is_cancelled());
    s.save(&|_| {}).unwrap();
    let after = fs::read(&vault).unwrap();
    assert_ne!(after, before, "重试保存应写入新数据段与 manifest");
    drop(s);

    let s = safe::open(&vault, "pw").unwrap();
    let names: Vec<&str> = s.entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"a.txt"), "{names:?}");
    assert!(names.contains(&"b.txt"), "{names:?}");
    drop(s);
    fs::remove_dir_all(root).ok();
}

/// 段级压缩被取消：容器不变；复位后压缩正常回收空间。
#[test]
fn cancel_compact_keeps_container_byte_identical() {
    let root = temp_root("compact");
    let vault = root.join("box.vgsafe");
    let a = root.join("a.bin");
    let b = root.join("b.bin");
    fs::write(&a, vec![1u8; 200_000]).unwrap();
    fs::write(&b, vec![2u8; 200_000]).unwrap();

    let mut s = safe::create(&vault, "pw").unwrap();
    s.add_paths(&[a, b]).unwrap();
    s.save(&|_| {}).unwrap();
    s.remove_entries(&["b.bin".to_string()]).unwrap();
    s.save(&|_| {}).unwrap();
    let before = fs::read(&vault).unwrap();

    let c = s.cancel_flag();
    c.cancel();
    let err = s.compact(&|_| {}).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Interrupted, "{err}");
    assert_eq!(fs::read(&vault).unwrap(), before, "取消后容器必须逐字节不变");

    c.reset();
    s.compact(&|_| {}).unwrap();
    assert!(
        fs::read(&vault).unwrap().len() < before.len(),
        "复位后压缩应真正回收已删除数据的段空间"
    );
    drop(s);

    let s = safe::open(&vault, "pw").unwrap();
    let names: Vec<&str> = s.entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"a.bin"), "{names:?}");
    assert!(!names.contains(&"b.bin"), "{names:?}");
    drop(s);
    fs::remove_dir_all(root).ok();
}

/// 导出被取消：容器不变、无半截落位；复位后可完整导出。
#[test]
fn cancel_export_keeps_container_intact() {
    let root = temp_root("export");
    let vault = root.join("box.vgsafe");
    let a = root.join("报告.txt");
    fs::write(&a, "内容").unwrap();
    let out = root.join("out");

    let mut s = safe::create(&vault, "pw").unwrap();
    s.add_paths(&[a]).unwrap();
    s.save(&|_| {}).unwrap();
    let before = fs::read(&vault).unwrap();

    let c = s.cancel_flag();
    c.cancel();
    let err = s.export(&out, &|_, _| {}).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Interrupted, "{err}");
    assert_eq!(fs::read(&vault).unwrap(), before);

    c.reset();
    let (_dst, n) = s.export(&out, &|_, _| {}).unwrap();
    assert_eq!(n, 1);
    drop(s);
    fs::remove_dir_all(root).ok();
}

/// 伪装页加密被取消：不残留半个产物，源文件不动。
#[test]
fn cancel_enc_leaves_no_partial_output() {
    let root = temp_root("enc");
    let src = root.join("big.bin");
    fs::write(&src, vec![9u8; 3 << 20]).unwrap();
    let out = root.join("out");
    fs::create_dir_all(&out).unwrap();

    let opts = EncOptions {
        key_src: KeySource::Builtin,
        keep_name: false,
        cover: None,
    };
    let c = vaultguard::cancel::Cancel::new();
    c.cancel();
    let err = engine::do_enc_c(&[src.clone()], "png", &out, &opts, None, &c).unwrap_err();
    assert!(err.contains(CANCELLED_MSG), "{err}");
    assert_eq!(
        fs::read_dir(&out).unwrap().count(),
        0,
        "取消后输出目录不应残留半个加密产物"
    );
    assert!(src.exists(), "源文件必须原样保留");

    // 复位后可正常加密
    c.reset();
    let (dst, n, bytes) = engine::do_enc_c(&[src], "png", &out, &opts, None, &c).unwrap();
    assert_eq!(n, 1);
    // bytes 是 tar 流字节（含 512B 头 + 1024B 尾），必然不小于源文件大小
    assert!(bytes >= 3 << 20, "{bytes}");
    assert!(dst.exists());
    fs::remove_dir_all(root).ok();
}

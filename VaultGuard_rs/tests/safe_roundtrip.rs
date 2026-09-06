//! 保险箱（.vgsafe）回归测试：创建/打开/增删/导出/换口令/错误口令。

use std::fs;
use std::path::PathBuf;

use vaultguard::safe;

fn temp_root(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "vgsafe_{}_{:x}",
        name,
        std::process::id() as usize ^ name.len() ^ 0x5eed
    ));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(d.join("in")).unwrap();
    d
}

#[test]
fn safe_roundtrip_and_password_change() {
    let root = temp_root("core");
    let vault = root.join("我的保险箱.vgsafe");
    let out = root.join("out");

    // 创建 + 添加
    let mut s = safe::create(&vault, "口令abc123").unwrap();
    let f1 = root.join("in/文档.txt");
    fs::create_dir_all(f1.parent().unwrap()).unwrap();
    fs::write(&f1, "hello safe 你好".as_bytes()).unwrap();
    let added = s.add_paths(&[f1]).unwrap();
    assert_eq!(added, 1);
    s.save(&|_| {}).unwrap();

    // 关闭（Drop 擦除临时树）后重开
    drop(s);
    let mut s = safe::open(&vault, "口令abc123").unwrap();
    assert_eq!(s.entries.len(), 1);
    assert_eq!(s.entries[0].name, "文档.txt");

    // 错误口令打不开
    assert!(safe::open(&vault, "wrong").is_err());

    // 导出全部并比对内容（单顶层文件：dst 即还原后的文件本身）
    let (dst, n) = s.export(&out, &|_, _| {}).unwrap();
    assert_eq!(n, 1);
    assert!(dst.is_file());
    assert_eq!(fs::read(&dst).unwrap(), "hello safe 你好".as_bytes());

    // 换口令：旧口令失效，新口令可用
    s.change_password("新口令456").unwrap();
    drop(s);
    assert!(safe::open(&vault, "口令abc123").is_err(), "旧口令应失效");
    let mut s = safe::open(&vault, "新口令456").unwrap();
    assert_eq!(s.entries.len(), 1);

    // 选择性导出
    let sel_out = root.join("sel");
    let n = s.export_selective(&["文档.txt".to_string()], &sel_out).unwrap();
    assert_eq!(n, 1);
    assert_eq!(
        fs::read(sel_out.join("文档.txt")).unwrap(),
        "hello safe 你好".as_bytes()
    );

    // 移除 + 保存
    assert_eq!(s.remove_entries(&["文档.txt".to_string()]).unwrap(), 1);
    s.save(&|_| {}).unwrap();
    assert!(s.entries.is_empty());

    drop(s);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn safe_create_rejects_existing_and_blank_pass() {
    let root = temp_root("edge");
    let vault = root.join("box.vgsafe");
    let s = safe::create(&vault, "口令").unwrap();
    drop(s);
    assert!(safe::create(&vault, "口令").is_err(), "重复创建应报错");
    assert!(safe::create(&root.join("b2.vgsafe"), "").is_err(), "空口令应报错");

    // 错误口令的 open 不产生错误数据
    assert!(safe::open(&vault, "bad").is_err());

    fs::remove_dir_all(&root).ok();
}

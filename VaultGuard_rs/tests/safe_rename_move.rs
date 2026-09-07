//! 保险箱条目重命名/移动（v1.3 中期功能）回归测试。
//! 覆盖：重命名持久化、移动自动建目录、重开验证内容、冲突自动加后缀、非法路径拒绝。

use std::fs;
use std::path::PathBuf;

use vaultguard::safe;

fn temp_safe(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "vgtest_{}_{:x}",
        name,
        std::process::id() as usize ^ name.len() ^ 0x77aa
    ));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d.join("box.vgsafe")
}

fn names(s: &safe::Session) -> Vec<String> {
    let mut v: Vec<String> = s.entries.iter().map(|e| e.name.clone()).collect();
    v.sort();
    v
}

fn fill(s: &mut safe::Session, root: &std::path::Path, files: &[&str]) {
    let mut srcs = Vec::new();
    for f in files {
        let p = root.join(f);
        fs::write(&p, f.as_bytes()).unwrap();
        srcs.push(p);
    }
    s.add_paths(&srcs).unwrap();
}

#[test]
fn rename_and_move_persist_after_save() {
    let path = temp_safe("renmv");
    let dir = path.parent().unwrap().to_path_buf();
    let mut s = safe::create(&path, "pw").unwrap();
    fill(&mut s, &dir, &["a.txt", "b.txt"]);

    // 重命名：只改名字，不改目录
    s.rename_entry("a.txt", "报表.txt").unwrap();
    let n = names(&s);
    assert!(n.contains(&"报表.txt".to_string()));
    assert!(!n.contains(&"a.txt".to_string()));

    // 移动：目标目录自动创建
    s.move_entry("b.txt", "工作/2026").unwrap();
    assert!(names(&s).contains(&"工作/2026/b.txt".to_string()));

    s.save(&|_| {}).unwrap();

    // 重开验证持久化与内容
    let s2 = safe::open(&path, "pw").unwrap();
    let n = names(&s2);
    assert!(n.contains(&"报表.txt".to_string()));
    assert!(n.contains(&"工作/2026/b.txt".to_string()));
    assert_eq!(
        s2.entries
            .iter()
            .find(|e| e.name == "报表.txt")
            .map(|e| e.size),
        Some(5), // "a.txt" 5 字节
        "重命名后内容应原样保留"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn move_auto_uniq_on_collision() {
    let path = temp_safe("mvuniq");
    let dir = path.parent().unwrap().to_path_buf();
    let mut s = safe::create(&path, "pw").unwrap();
    fill(&mut s, &dir, &["x.txt", "x.txt"]); // 第二个同名在根自动 uniq 成 x_2.txt

    s.move_entry("x.txt", "dir").unwrap(); // -> dir/x.txt
    s.move_entry("x_2.txt", "dir").unwrap(); // dir/x.txt 冲突 -> dir/x_2.txt

    let n = names(&s);
    assert!(n.contains(&"dir/x.txt".to_string()));
    assert!(n.contains(&"dir/x_2.txt".to_string()));
    assert!(!n.contains(&"x.txt".to_string()));

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn rename_move_reject_invalid() {
    let path = temp_safe("mvbad");
    let dir = path.parent().unwrap().to_path_buf();
    let mut s = safe::create(&path, "pw").unwrap();
    fill(&mut s, &dir, &["a.txt", "b.txt"]);

    // 重命名到已存在 -> 拒绝
    assert!(s.rename_entry("a.txt", "b.txt").is_err(), "重名应被拒绝");
    // 非法路径 -> 拒绝
    assert!(s.rename_entry("a.txt", "../evil").is_err(), "路径穿越应被拒绝");
    assert!(s.rename_entry("a.txt", "").is_err(), "空名应被拒绝");
    assert!(s.rename_entry("a.txt", "a\\b").is_err(), "反斜杠应被拒绝");
    // 不存在的条目 -> 拒绝
    assert!(s.rename_entry("nope.txt", "x.txt").is_err());
    // 移动到自身子目录 -> 拒绝
    assert!(s.move_entry("a.txt", "a.txt/sub").is_err(), "自身子树应被拒绝");
    // 原地移动 -> 无操作成功
    assert!(s.move_entry("a.txt", "").is_ok(), "原地移动应为无操作");

    fs::remove_dir_all(&dir).ok();
}

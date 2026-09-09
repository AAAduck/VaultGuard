//! 选择性导出：嵌套条目导出后保留目录层级（回归：曾被 safe_name 拍平为 a_b）。

use std::path::PathBuf;

use vaultguard::safe;

fn temp_root(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vg_test_{}_{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn export_selective_preserves_nested_paths() {
    let root = temp_root("export_nested");
    let src = root.join("项目");
    std::fs::create_dir_all(src.join("子")).unwrap();
    std::fs::write(src.join("报告.pdf"), "pdf-body").unwrap();
    std::fs::write(src.join("子").join("数据.xlsx"), "xlsx-body").unwrap();

    let box_path = root.join("box.vgsafe");
    let mut s = safe::create(&box_path, "pass1234").unwrap();
    s.add_paths(&[src.clone()]).unwrap();
    s.save(&|_| {}).unwrap();

    let out = root.join("out");
    let n = s
        .export_selective(&["项目/子/数据.xlsx".to_string()], &out)
        .unwrap();
    assert_eq!(n, 1);
    let p = out.join("项目").join("子").join("数据.xlsx");
    assert!(p.is_file(), "嵌套路径应保留目录层级：{}", p.display());
    assert_eq!(std::fs::read_to_string(&p).unwrap(), "xlsx-body");

    // 导出嵌套目录同样保留层级
    let out2 = root.join("out2");
    let n2 = s.export_selective(&["项目".to_string()], &out2).unwrap();
    assert_eq!(n2, 1);
    assert!(out2.join("项目").join("子").join("数据.xlsx").is_file());
    assert!(out2.join("项目").join("报告.pdf").is_file());
}

#[test]
fn export_selective_flat_name_unchanged() {
    let root = temp_root("export_flat");
    let box_path = root.join("box.vgsafe");
    let mut s = safe::create(&box_path, "pass1234").unwrap();
    let f = root.join("a.png");
    std::fs::write(&f, "png-body").unwrap();
    s.add_paths(&[f]).unwrap();
    s.save(&|_| {}).unwrap();

    let out = root.join("out");
    s.export_selective(&["a.png".to_string()], &out).unwrap();
    assert!(out.join("a.png").is_file(), "顶层条目导出名不变");
}

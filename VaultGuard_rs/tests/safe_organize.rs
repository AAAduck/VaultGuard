//! 目录前缀整理：添加文件按类型归档到子目录（可选开关），文件夹放根目录；保存后持久化。

use std::path::{Path, PathBuf};

use vaultguard::safe;

fn temp_root(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vg_test_{}_{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_files(dir: &Path, files: &[&str]) -> Vec<PathBuf> {
    files
        .iter()
        .map(|f| {
            let p = dir.join(f);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&p, format!("content:{f}")).unwrap();
            p
        })
        .collect()
}

fn names(s: &safe::Session) -> Vec<String> {
    s.entries.iter().map(|e| e.name.clone()).collect()
}

#[test]
fn organize_files_by_category_and_folder_stays_root() {
    let root = temp_root("organize");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let files = write_files(
        &src,
        &[
            "photo.png",
            "report.pdf",
            "data.zip",
            "song.mp3",
            "clip.mp4",
            "no_ext",
            "note.md",
            "archive.tar.gz",
        ],
    );
    let folder = src.join("我的文件夹");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("inner.txt"), "inner").unwrap();

    let box_path = root.join("box.vgsafe");
    let mut s = safe::create(&box_path, "pass1234").unwrap();
    let mut all = files.clone();
    all.push(folder.clone());
    let n = s.add_paths_organized(&all).unwrap();
    assert_eq!(n, 9, "8 文件 + 1 文件夹都应添加成功");

    let ns = names(&s);
    assert!(ns.contains(&"图片/photo.png".to_string()), "png 应进图片：{ns:?}");
    assert!(ns.contains(&"文档/report.pdf".to_string()), "pdf 应进文档");
    assert!(ns.contains(&"文档/note.md".to_string()), "md 应进文档");
    assert!(ns.contains(&"压缩包/data.zip".to_string()), "zip 应进压缩包");
    assert!(
        ns.contains(&"压缩包/archive.tar.gz".to_string()),
        "tar.gz 应进压缩包"
    );
    assert!(ns.contains(&"音频/song.mp3".to_string()), "mp3 应进音频");
    assert!(ns.contains(&"视频/clip.mp4".to_string()), "mp4 应进视频");
    assert!(ns.contains(&"其他/no_ext".to_string()), "无扩展名应进其他");
    assert!(ns.contains(&"我的文件夹".to_string()), "文件夹应留在根目录");
    assert!(
        !ns.iter().any(|n| n == "photo.png"),
        "文件不应留在根目录"
    );

    s.save(&|_| {}).unwrap();
    drop(s);

    // 重新打开验证归档已持久化
    let s2 = safe::open(&box_path, "pass1234").unwrap();
    assert_eq!(names(&s2), ns);
}

#[test]
fn organize_uniq_on_collision_in_same_category() {
    let root = temp_root("organize_uniq");
    let src1 = root.join("src1");
    let src2 = root.join("src2");
    std::fs::create_dir_all(&src1).unwrap();
    std::fs::create_dir_all(&src2).unwrap();
    std::fs::write(src1.join("a.png"), "one").unwrap();
    std::fs::write(src2.join("a.png"), "two").unwrap();

    let box_path = root.join("box.vgsafe");
    let mut s = safe::create(&box_path, "pass1234").unwrap();
    s.add_paths_organized(&[src1.join("a.png"), src2.join("a.png")])
        .unwrap();

    let ns = names(&s);
    assert!(ns.contains(&"图片/a.png".to_string()), "首个文件正常落位：{ns:?}");
    assert!(
        ns.contains(&"图片/a_2.png".to_string()),
        "同分类重名应自动加后缀：{ns:?}"
    );
}

#[test]
fn add_paths_without_organize_stays_root() {
    let root = temp_root("organize_off");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let files = write_files(&src, &["a.png", "b.pdf"]);

    let box_path = root.join("box.vgsafe");
    let mut s = safe::create(&box_path, "pass1234").unwrap();
    s.add_paths(&files).unwrap();

    let ns = names(&s);
    assert!(ns.contains(&"a.png".to_string()));
    assert!(ns.contains(&"b.pdf".to_string()));
    assert!(!ns.iter().any(|n| n.starts_with("图片/") || n.starts_with("文档/")));
}

#[test]
fn category_of_mapping() {
    assert_eq!(safe::category_of("a.PNG"), "图片", "扩展名大小写不敏感");
    assert_eq!(safe::category_of("a.tar.gz"), "压缩包", "多重扩展名取最后一段");
    assert_eq!(safe::category_of("README"), "其他", "无扩展名归其他");
    assert_eq!(safe::category_of("a.unknown"), "其他", "未知类型归其他");
    assert_eq!(safe::category_of("b.docx"), "文档");
    assert_eq!(safe::category_of("c.mkv"), "视频");
    assert_eq!(safe::category_of("d.flac"), "音频");
}

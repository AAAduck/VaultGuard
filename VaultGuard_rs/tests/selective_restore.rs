//! 选择性还原（v1.2）回归测试：解密预览 → 勾选部分顶层条目落位。
//! 对应路线图短期第 1 项验收：勾选 2/3 条目，落位结果与选择一致，SHA-256 仍可核对。
//! 覆盖：预览顶层清单、部分落位、全量落位（旧语义）、空选择拒绝。

use std::fs;
use std::path::PathBuf;

use vaultguard::engine::{self, EncOptions, KeySource};

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

fn write_inputs(root: &PathBuf, names: &[&str]) -> Vec<PathBuf> {
    names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let p = root.join("in").join(n);
            fs::write(&p, format!("content-{i}")).unwrap();
            p
        })
        .collect()
}

#[test]
fn selective_place_2_of_3_entries() {
    let root = temp_root("sel2of3");
    let out = root.join("out");
    let srcs = write_inputs(&root, &["a.txt", "b.txt", "c.txt"]);

    let opts = EncOptions {
        key_src: KeySource::Passphrase("sel-pass".into()),
        keep_name: false,
        cover: None,
    };
    let enc = engine::do_enc(&srcs, "png", &out, &opts, None).unwrap();

    // 阶段一：认证 + 预览，应列出 3 个顶层条目
    let preview = engine::do_dec_preview(&enc.0, Some("sel-pass"), None).unwrap();
    let mut top_names: Vec<String> = engine::top_entries(&preview.manifest)
        .iter()
        .map(|(n, _, _)| n.clone())
        .collect();
    top_names.sort();
    assert_eq!(top_names, ["a.txt", "b.txt", "c.txt"], "预览应列出全部顶层条目");

    // 阶段二：只落位选中的 2 个，落位结果与选择一致
    let sel = ["a.txt".to_string(), "c.txt".to_string()];
    let res = engine::do_dec_place(preview, &out, Some(&sel)).unwrap();
    assert_eq!(res.entries, 2, "应恰好落位 2 个条目");

    let mut placed_names: Vec<String> = fs::read_dir(&res.dst)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    placed_names.sort();
    assert_eq!(placed_names, ["a.txt", "c.txt"], "b.txt 不应被落位");

    assert_eq!(fs::read(res.dst.join("a.txt")).unwrap(), b"content-0");
    assert_eq!(fs::read(res.dst.join("c.txt")).unwrap(), b"content-2");
    assert!(!res.dst.join("b.txt").exists(), "未选中的条目不得落位");

    // 哈希清单只覆盖落位内容（路线图验收：SHA-256 仍可核对）
    assert!(
        res.hashes.iter().any(|(n, _)| n.contains("a.txt")),
        "哈希应覆盖已落位 a.txt"
    );
    assert!(
        !res.hashes.iter().any(|(n, _)| n.contains("b.txt")),
        "哈希不应覆盖未落位 b.txt"
    );

    fs::remove_dir_all(&root).ok();
}

#[test]
fn selective_none_all_and_empty() {
    // 无过滤 → 全量落位（保持旧语义：返回 tar 总条目数）
    let root = temp_root("selall");
    let out = root.join("out");
    let srcs = write_inputs(&root, &["a.txt", "b.txt"]);

    let opts = EncOptions {
        key_src: KeySource::Builtin,
        keep_name: false,
        cover: None,
    };
    let enc = engine::do_enc(&srcs, "png", &out, &opts, None).unwrap();

    let preview = engine::do_dec_preview(&enc.0, None, None).unwrap();
    let res = engine::do_dec_place(preview, &out, None).unwrap();
    assert_eq!(res.entries, 2, "全量落位应返回 tar 总条目数");
    assert!(res.dst.join("a.txt").exists() && res.dst.join("b.txt").exists());

    // 空选择 → 明确拒绝，不产生任何落位
    let preview2 = engine::do_dec_preview(&enc.0, None, None).unwrap();
    let err = engine::do_dec_place(preview2, &out, Some(&[])).unwrap_err();
    assert!(err.contains("没有匹配"), "空选择应报错: {err}");

    fs::remove_dir_all(&root).ok();
}

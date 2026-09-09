//! VaultGuard — 网盘伪装加密保险箱
//! 入口：无参数 -> GUI；有参数/拖放 -> 命令行处理。
//! release 以 windowed 发布（无控制台，结果用 MessageBox 展示）。
//!
//! 命令行口令：--password <值> 或 --password-stdin（脚本）。
//! 加密时提供口令 -> VG\x03（Argon2id）；不提供 -> VG\x02（内置密钥）。
//! 还原 VG\x03 产物必须提供正确口令。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod crypto;
mod engine;
mod gui;
mod paths;
mod safe;
mod shells;
mod tarx;
mod vgs2;

use std::path::{Path, PathBuf};

use engine::KeySource;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    // 崩溃日志：panic 信息写入 exe 同目录（release 为 panic=abort，hook 仍会先执行）
    std::panic::set_hook(Box::new(|info| {
        use std::io::Write;
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(dir.join("vg_crash.log"))
                {
                    let secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let _ = writeln!(f, "[secs={secs}] PANIC: {info}");
                }
            }
        }
    }));
    paths::sweep_old_tmp();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut shell = "png";
    let mut rest: Vec<String> = Vec::new();
    let mut no_msg = false;
    let mut ui_smoke = false;
    let mut keep_name = false;
    let mut cover: Option<PathBuf> = None;
    let mut password: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--png" => shell = "png",
            "--jpg" => shell = "jpg",
            "--docx" => shell = "docx",
            "--no-msg" => no_msg = true,
            "--ui-smoke" => ui_smoke = true,
            "--keep-name" => keep_name = true,
            "--cover" => {
                i += 1;
                if i < args.len() {
                    cover = Some(PathBuf::from(&args[i]));
                }
            }
            "--password" => {
                i += 1;
                if i < args.len() {
                    password = Some(args[i].clone());
                }
            }
            "--password-stdin" => {
                use std::io::Read;
                let mut s = String::new();
                let _ = std::io::stdin().read_to_string(&mut s);
                let s = s.trim_end_matches(['\r', '\n']).to_string();
                password = Some(s);
            }
            other => rest.push(other.trim_matches('"').to_string()),
        }
        i += 1;
    }
    if rest.is_empty() {
        if ui_smoke {
            gui::smoke();
        } else {
            gui::run();
        }
        return;
    }

    let out_root = paths::out_root();
    let single = rest.len() == 1 && Path::new(&rest[0]).is_file();
    let is_vault = single && shells::probe_vault(Path::new(&rest[0])).is_some();
    let result: Result<(PathBuf, Option<usize>, Option<u64>), String> = if is_vault {
        engine::do_dec(Path::new(&rest[0]), &out_root, password.as_deref(), None)
            .map(|r| (r.dst, Some(r.entries), Some(r.plain_bytes)))
    } else {
        let ps: Vec<PathBuf> = rest.iter().map(PathBuf::from).collect();
        let opts = engine::EncOptions {
            key_src: match password.as_deref() {
                Some(p) if !p.is_empty() => KeySource::Passphrase(p.to_string()),
                _ => KeySource::Builtin,
            },
            keep_name,
            cover,
        };
        engine::do_enc(&ps, shell, &out_root, &opts, None)
            .map(|(o, n, s)| (o, Some(n), Some(s)))
    };

    let mut lines: Vec<String> = Vec::new();
    match &result {
        Ok((out, n, s)) => {
            let kind = if is_vault { "还原" } else { "加密" };
            lines.push(format!("{} 完成: {}", kind, out.display()));
            if !is_vault && matches!(password.as_deref(), Some(p) if !p.is_empty()) {
                lines.push("已启用口令加密（VG\\03 / Argon2id）".to_string());
            }
            if !is_vault && keep_name {
                lines.push("输出名：保留原文件名".to_string());
            } else if !is_vault {
                lines.push("输出名：已随机化（--keep-name 可保留原名）".to_string());
            }
            if let Some(n) = n {
                lines.push(format!("包含 {} 项", n));
            }
            if let Some(s) = s {
                lines.push(format!("明文大小 {}", paths::sz(*s)));
            }
        }
        Err(e) => {
            lines.push(format!("未处理: {}（原文件未改动）", e));
        }
    }
    let text = lines.join("\n");
    report(&text, result.is_err(), no_msg);
}

fn report(text: &str, err: bool, no_msg: bool) {
    #[cfg(debug_assertions)]
    {
        println!();
        println!("{}", text);
        if !no_msg {
            let mut s = String::new();
            let _ = std::io::stdin().read_line(&mut s);
        }
    }
    #[cfg(not(debug_assertions))]
    {
        if !no_msg {
            msgbox(err, text);
        } else {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(std::env::current_exe().unwrap_or_default().with_file_name("vg_cli.log"))
            {
                let _ = writeln!(f, "[{}] {}", if err { "ERR" } else { "OK" }, text);
            }
        }
    }
}

#[cfg(not(debug_assertions))]
fn msgbox(err: bool, text: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK,
    };
    let title: Vec<u16> = format!("{} v{}", paths::APP, VERSION)
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let body: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let _ = MessageBoxW(
            0,
            body.as_ptr(),
            title.as_ptr(),
            MB_OK | (if err { MB_ICONERROR } else { MB_ICONINFORMATION }),
        );
    }
}

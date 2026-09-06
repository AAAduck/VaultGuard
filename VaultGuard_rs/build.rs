use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// 与 src-tauri/build.rs 同一套方案：本机 GNU 工具链没有 windres，资源（图标 + 清单）
// 由 zig 内建的 resinator 编译期生成 .res，再经链接参数进 exe：
//   build.rs 生成 .rc -> zig rc /c65001 编译成 .res -> cargo:rustc-link-arg-bins 挂给链接器
// 这样每次 cargo build 出来的 exe 天生自带图标/清单，无需编译后手动嵌入。
// zig 不可用时仅跳过资源（exe 无图标/清单，功能不受影响）。

const ZIG_FALLBACK: &str = "D:\\ZigTools\\zig0141\\zig-x86_64-windows-0.14.1\\zig.exe";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=VaultGuard.exe.manifest");
    println!("cargo:rerun-if-changed=icons/icon_bmp.ico");

    if let Err(e) = embed_resources() {
        println!("cargo:warning=VaultGuard: resource embedding skipped ({e})");
        println!("cargo:warning=VaultGuard: exe will lack icon/manifest");
    }
}

fn embed_resources() -> Result<(), String> {
    let out_dir = PathBuf::from(env::var("OUT_DIR").map_err(|e| e.to_string())?);
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").map_err(|e| e.to_string())?);
    let manifest = root.join("VaultGuard.exe.manifest");
    let ico = root.join("icons").join("icon_bmp.ico");
    if !manifest.is_file() {
        return Err(format!("missing {}", manifest.display()));
    }
    if !ico.is_file() {
        return Err(format!("missing {}", ico.display()));
    }

    let zig = env::var("ZIG_BIN").unwrap_or_else(|_| ZIG_FALLBACK.to_string());
    if !Path::new(&zig).is_file() {
        return Err(format!("zig not found at {zig} (set ZIG_BIN to override)"));
    }

    // .res 文件名带指纹（图标+清单）：内容变化 -> 文件名变化 -> 链接参数变化 -> cargo 必然重链接
    let mut stamp = String::new();
    for f in [&manifest, &ico] {
        let part = fs::metadata(f)
            .ok()
            .and_then(|m| {
                let len = m.len();
                let t = m.modified().ok()?;
                let t = t.duration_since(std::time::UNIX_EPOCH).ok()?;
                Some(format!("{len:x}{:x}", t.as_secs()))
            })
            .unwrap_or_else(|| "0".into());
        stamp.push_str(&part);
    }
    let res_path = out_dir.join(format!("vg_{stamp}.res"));
    let rc_path = out_dir.join(format!("vg_{stamp}.rc"));

    // .rc 内容为 UTF-8（路径含中文），配合 /c65001 让 resinator 按正确代码页解码
    let rc = format!(
        "1 ICON \"{}\"\n1 24 \"{}\"\n",
        ico.display(),
        manifest.display()
    );
    if !res_path.is_file() {
        fs::write(&rc_path, rc).map_err(|e| format!("write .rc: {e}"))?;
        let out = Command::new(&zig)
            .args([
                "rc",
                "/c65001",
                "/:no-preprocess",
                &format!("/fo{}", res_path.display()),
                &rc_path.display().to_string(),
            ])
            .output()
            .map_err(|e| format!("run zig rc: {e}"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let _ = fs::remove_file(&rc_path);
            return Err(format!("zig rc failed: {}", err.trim()));
        }
    }
    if !res_path.is_file() {
        return Err("zig rc produced no .res".into());
    }

    println!("cargo:rustc-link-arg-bins={}", res_path.display());
    Ok(())
}

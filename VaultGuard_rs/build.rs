use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

// 与 src-tauri/build.rs 同一套方案：本机 GNU 工具链没有 windres，资源（图标 + 清单）
// 由 zig 内建的 resinator 编译期生成 .res，再经链接参数进 exe：
//   build.rs 生成 .rc -> zig rc /c65001 编译成 .res -> cargo:rustc-link-arg-bins 挂给链接器
// 这样每次 cargo build 出来的 exe 天生自带图标/清单，无需编译后手动嵌入。
// zig 不可用时仅跳过资源（exe 无图标/清单，功能不受影响）。

const ZIG_FALLBACK: &str = "D:\\ZigTools\\zig0141\\zig-x86_64-windows-0.14.1\\zig.exe";

/// 从 CARGO_PKG_VERSION（如 "1.3.1"）拆出版本三元组。
fn version_triple() -> (u32, u32, u32) {
    let v = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let mut parts = v.split('.');
    let get = |p: Option<&str>| p.and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    (get(parts.next()), get(parts.next()), get(parts.next()))
}

/// 把 MSYS/Git Bash 风格路径（/c/hostedtoolcache/.../zig）规范为 Windows 路径，
/// 否则 Path::is_file 与 Command::new 都无法识别（CI 上 `which zig` 输出正是这种形式）。
fn resolve_zig(zig: &str) -> PathBuf {
    let b = zig.as_bytes();
    if zig.starts_with('/') && b.len() >= 3 && b[2] == b'/' && b[1].is_ascii_alphabetic() {
        let drive = (b[1] as char).to_ascii_uppercase();
        return PathBuf::from(format!("{}:\\{}", drive, &zig[3..]).replace('/', "\\"));
    }
    PathBuf::from(zig)
}

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
    let zig = resolve_zig(&zig);
    if !zig.is_file() {
        return Err(format!("zig not found at {} (set ZIG_BIN to override)", zig.display()));
    }

    // .res 文件名带指纹（图标+清单+版本）：任一项变化 -> 文件名变化 -> 链接参数变化
    // -> cargo 必然重链接。版本号必须进指纹：否则本地升版会用缓存的旧 .res（旧 VERSIONINFO）。
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
    let (vmaj, vmin, vpat) = version_triple();
    stamp.push_str(&format!("{vmaj}.{vmin}.{vpat}"));
    let res_path = out_dir.join(format!("vg_{stamp}.res"));
    let rc_path = out_dir.join(format!("vg_{stamp}.rc"));

    // .rc 内容为 UTF-8（路径含中文），配合 /c65001 让 resinator 按正确代码页解码
    // VERSIONINFO 给 exe 补身份信息（公司/产品/版本）——无版本资源的"匿名二进制"是杀软启发式误报的高发特征
    // 注意：.rc 字符串字面量里反斜杠是转义前缀（CI 路径 D:\a\... 的 \a 会被当转义符吃掉导致打不开文件），
    // 所以这里把路径统一换成正斜杠（resinator 与 Windows 均接受）。
    let (vmaj, vmin, vpat) = version_triple();
    let ver_str = format!("{vmaj}.{vmin}.{vpat}");
    let ico_rc = ico.display().to_string().replace('\\', "/");
    let manifest_rc = manifest.display().to_string().replace('\\', "/");
    let rc = format!(
        "1 ICON \"{}\"\n1 24 \"{}\"\n1 VERSIONINFO\nFILEVERSION {vmaj},{vmin},{vpat},0\nPRODUCTVERSION {vmaj},{vmin},{vpat},0\nFILEOS 0x40004\nFILETYPE 0x1\nBEGIN\n  BLOCK \"StringFileInfo\"\n  BEGIN\n    BLOCK \"080404b0\"\n    BEGIN\n      VALUE \"CompanyName\", \"VaultGuard\"\n      VALUE \"FileDescription\", \"VaultGuard - 网盘伪装加密保险箱\"\n      VALUE \"FileVersion\", \"{ver_str}\"\n      VALUE \"ProductName\", \"VaultGuard\"\n      VALUE \"ProductVersion\", \"{ver_str}\"\n      VALUE \"OriginalFilename\", \"VaultGuard.exe\"\n    END\n  END\n  BLOCK \"VarFileInfo\"\n  BEGIN\n    VALUE \"Translation\", 0x0804, 1200\n  END\nEND\n",
        ico_rc,
        manifest_rc
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
            .map_err(|e| format!("run zig rc: {e}"))?;        if !out.status.success() {
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

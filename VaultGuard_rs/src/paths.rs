//! 路径、命名、注册表等系统工具。

use std::path::{Path, PathBuf};

pub const APP: &str = "VaultGuard";

pub const REG_PATH: &str = r"Software\VaultGuard";

/// 清洗为合法文件名（替代 Python 的 _safe）
pub fn safe_name(s: &str, lim: usize) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if ":/\\|?*<>\"".contains(c) || (c as u32) < 32 {
            out.push('_');
        } else {
            out.push(c);
        }
    }
    let mut trimmed = out.trim().to_string();
    while trimmed.ends_with('.') {
        trimmed.pop();
    }
    while trimmed.ends_with(' ') {
        trimmed.pop();
    }
    if trimmed.is_empty() {
        trimmed = "file".to_string();
    }
    if trimmed.chars().count() > lim {
        let cut: String = trimmed.chars().take(lim - 8).collect();
        trimmed = format!("{}_{:08x}", cut, (rand::random::<u32>()) & 0xFFFF_FFFF);
        // 截到 lim 以内
        let mut t2: String = trimmed.chars().take(lim).collect();
        if t2.is_empty() {
            t2 = "file".to_string();
        }
        return t2;
    }
    trimmed
}

/// 冲突名自动加后缀 _2/_3（替代 Python _uniq）
pub fn uniq(path: &Path) -> PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }
    let d = path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let ext = path
        .extension()
        .map(|s| format!(".{}", s.to_string_lossy()))
        .unwrap_or_default();
    let mut i = 2;
    loop {
        let c = d.join(format!("{}_{}{}", stem, i, ext));
        if !c.exists() {
            return c;
        }
        i += 1;
    }
}

pub fn strip_vault_ext(name: &str) -> String {
    let low = name.to_lowercase();
    for suf in [".vault.png", ".vault.jpg", ".vault.docx"] {
        if low.ends_with(suf) {
            return name[..name.len() - suf.len()].to_string();
        }
    }
    for suf in [".png", ".jpg", ".docx"] {
        if low.ends_with(suf) {
            return name[..name.len() - suf.len()].to_string();
        }
    }
    name.to_string()
}

pub fn sz(n: u64) -> String {
    let mut v = n as f64;
    for u in ["B", "KB", "MB", "GB"] {
        if v < 1024.0 || u == "GB" {
            if u == "B" {
                return format!("{} B", n);
            }
            return format!("{:.1} {}", v, u);
        }
        v /= 1024.0;
    }
    format!("{:.1} TB", v / 1024.0)
}

/// 日期+随机的输出文件名：VG_YYYYMMDD_ab12.png（隐私：不泄露原文件名）
pub fn random_out_name(ext: &str) -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let hex = format!("{:04x}", rand::random::<u16>());
    format!("VG_{:04}{:02}{:02}_{}{}", y, m, d, hex, ext)
}

/// 天数 -> (年, 月, 日)，Howard Hinnant civil_from_days 算法
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1461 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 自定义封面目录：%APPDATA%\VaultGuard\covers（每个外壳各一份 cover.png/jpg/docx）
pub fn covers_dir() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| out_root().join(".config"));
    base.join(APP).join("covers")
}

/// 当前外壳是否设置了自定义封面
pub fn custom_cover(shell: &str) -> Option<PathBuf> {
    let p = covers_dir().join(format!("cover.{shell}"));
    p.is_file().then_some(p)
}

/// 启用自定义封面（复制进封面目录，之后移动/删除原文件不影响）
pub fn set_custom_cover(shell: &str, src: &Path) -> std::io::Result<()> {
    let dir = covers_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::copy(src, dir.join(format!("cover.{shell}"))).map(|_| ())
}

/// 恢复内置随机封面
pub fn clear_custom_cover(shell: &str) -> std::io::Result<()> {
    let p = covers_dir().join(format!("cover.{shell}"));
    if p.exists() {
        std::fs::remove_file(p)?;
    }
    Ok(())
}

/// 系统桌面目录
pub fn desktop_dir() -> PathBuf {
    if let Ok(up) = std::env::var("USERPROFILE") {
        let d = PathBuf::from(&up).join("Desktop");
        if d.is_dir() {
            return d;
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let d = PathBuf::from(&home).join("Desktop");
        if d.is_dir() {
            return d;
        }
    }
    PathBuf::from("C:\\Users\\Public\\Desktop")
}

/// 输出根目录：VG_OUT_ROOT env > EXE 同目录 > 桌面
pub fn out_root() -> PathBuf {
    if let Ok(e) = std::env::var("VG_OUT_ROOT") {
        if !e.is_empty() {
            return PathBuf::from(e);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(d) = exe.parent() {
            return d.to_path_buf();
        }
    }
    desktop_dir()
}

pub fn tmp_root() -> PathBuf {
    for k in ["TEMP", "TMP"] {
        if let Ok(v) = std::env::var(k) {
            if !v.is_empty() {
                return PathBuf::from(v);
            }
        }
    }
    desktop_dir()
}

pub const TMP_PREFIX: &str = "vg_tmp_";
pub const TMP_MAX_AGE: u64 = 3600;

pub fn sweep_old_tmp() {
    let base = tmp_root();
    let Ok(rd) = std::fs::read_dir(&base) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name();
        if !name.to_string_lossy().starts_with(TMP_PREFIX) {
            continue;
        }
        let p = e.path();
        if let Ok(meta) = e.metadata() {
            if let Ok(now) = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
            {
                let age = now.as_secs().saturating_sub(
                    meta.modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                );
                if age > TMP_MAX_AGE {
                    let _ = std::fs::remove_dir_all(&p);
                }
            }
        }
    }
}

pub fn mktmpdir() -> PathBuf {
    let d = tmp_root();
    loop {
        let name = format!("{}{:08x}", TMP_PREFIX, rand::random::<u32>());
        let p = d.join(name);
        if std::fs::create_dir_all(&p).is_ok() {
            return p;
        }
    }
}

/// 清理临时文件/目录：先覆写内容再删除（best-effort，防明文临时残留被恢复）
pub fn cleanup(path: &Path) {
    wipe_tree(path);
    if path.is_dir() {
        let _ = std::fs::remove_dir_all(path);
    } else if path.exists() {
        let _ = std::fs::remove_file(path);
    }
}

fn wipe_tree(p: &Path) {
    if p.is_dir() {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                wipe_tree(&e.path());
            }
        }
    } else if p.is_file() {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(p) {
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            use std::io::{Seek, SeekFrom, Write as IoWrite};
            let _ = f.seek(SeekFrom::Start(0));
            let zero = [0u8; 4096];
            let mut left = len;
            while left > 0 {
                let n = left.min(zero.len() as u64) as usize;
                if f.write_all(&zero[..n]).is_err() {
                    break;
                }
                left -= n as u64;
            }
            let _ = f.sync_all();
        }
    }
}

/// 读取上次外壳选择（注册表记忆）
pub fn reg_get_shell() -> Option<String> {
    use winreg::enums::HKEY_CURRENT_USER;
    let hk = winreg::RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(k) = hk.open_subkey(REG_PATH) {
        if let Ok(v) = k.get_value::<String, _>("shell") {
            return Some(v);
        }
    }
    None
}

pub fn reg_set_shell(s: &str) {
    use winreg::enums::HKEY_CURRENT_USER;
    let hk = winreg::RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(k) = hk.create_subkey(REG_PATH) {
        let _ = k.0.set_value("shell", &s);
    }
}

// ── 口令更换提醒（每 90 天，可关闭）───────────────────────────────

pub const PASS_TIP_DAYS: i64 = 90;
const PASS_TIP_DAY_SECS: i64 = PASS_TIP_DAYS * 86_400;

fn pass_tip_file() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| out_root().join(".config"));
    base.join(APP).join("pass_tip.json")
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 读取提醒状态：(last 时间戳, disabled)。文件缺失按"刚设置过"处理（首启不打扰）。
pub fn pass_tip_load() -> (i64, bool) {
    let s = match std::fs::read_to_string(pass_tip_file()) {
        Ok(s) => s,
        Err(_) => return (now_secs(), false),
    };
    let mut last = 0i64;
    let mut disabled = false;
    if let Some(i) = s.find("\"last\":") {
        let rest = &s[i + 7..];
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        last = rest[..end].parse().unwrap_or(0);
    }
    if let Some(i) = s.find("\"disabled\":") {
        let rest = &s[i + 11..];
        disabled = rest.trim_start().starts_with("true");
    }
    if last == 0 {
        return (now_secs(), disabled);
    }
    (last, disabled)
}

fn pass_tip_save(last: i64, disabled: bool) {
    let f = pass_tip_file();
    if let Some(d) = f.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(f, format!("{{\"last\":{},\"disabled\":{}}}", last, disabled));
}

/// 记录"已设置/更换口令"（重置 90 天周期，同时解除关闭状态）。
pub fn pass_tip_touch() {
    pass_tip_save(now_secs(), false);
}

/// 关闭提醒（保持不打扰，直到下次设置口令重新开启）。
pub fn pass_tip_disable() {
    let (last, _) = pass_tip_load();
    pass_tip_save(last, true);
}

/// 纯逻辑：距上次设置/更换是否已超过 90 天且未关闭。
pub fn pass_tip_due_state(last: i64, now: i64, disabled: bool) -> bool {
    !disabled && now.saturating_sub(last) >= PASS_TIP_DAY_SECS
}

/// 当前是否应提醒（读取文件状态后判定）。
pub fn pass_tip_due() -> bool {
    let (last, disabled) = pass_tip_load();
    pass_tip_due_state(last, now_secs(), disabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_tip_due_logic() {
        let now = 1_800_000_000i64; // 任意基准时刻
        assert!(!pass_tip_due_state(now, now, false), "刚设置不应提醒");
        assert!(
            !pass_tip_due_state(now - PASS_TIP_DAY_SECS + 60, now, false),
            "未满 90 天不应提醒"
        );
        assert!(
            pass_tip_due_state(now - PASS_TIP_DAY_SECS - 1, now, false),
            "超过 90 天应提醒"
        );
        assert!(
            !pass_tip_due_state(now - PASS_TIP_DAY_SECS * 5, now, true),
            "已关闭不应提醒"
        );
    }
}

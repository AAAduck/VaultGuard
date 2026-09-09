//! 路径、命名、注册表等系统工具。

use std::path::{Path, PathBuf};

pub const APP: &str = "VaultGuard";

pub const REG_PATH: &str = r"Software\VaultGuard";

/// Windows 保留设备名（大小写不敏感，命中需让位）
fn is_reserved_win_stem(stem: &str) -> bool {
    const RES: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let up = stem.to_ascii_uppercase();
    RES.contains(&up.as_str())
}

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
    // Windows 保留设备名（CON/PRN/AUX/NUL/COM1-9/LPT1-9，含扩展名同样保留）：
    // 创建名为 CON 的文件会打开控制台设备而非落盘，须让位
    let stem = trimmed.split('.').next().unwrap_or("");
    if is_reserved_win_stem(stem) {
        trimmed = format!("_{}", trimmed);
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
/// 活跃标记：会话/预览持有期间定期刷新，防启动清扫误删长时间打开的临时数据
pub const ACTIVE_MARKER: &str = ".vg_active";
pub const TMP_MAX_AGE: u64 = 3600; // 无活跃标记的旧目录（历史遗留）
pub const ACTIVE_MAX_AGE: u64 = 86_400; // 活跃标记过期（进程崩溃残留）上限

/// 刷新活跃标记（写当前时间）。打开中的保险箱会话与解密预览定期调用。
pub fn touch_active(dir: &Path) -> std::io::Result<()> {
    std::fs::write(dir.join(ACTIVE_MARKER), b"1")
}

/// 启动清扫：删除过期临时目录。判定规则：
/// 有活跃标记 → 标记 mtime 超过 ACTIVE_MAX_AGE（崩溃残留）才删；
/// 无活跃标记 → 目录 mtime 超过 TMP_MAX_AGE（历史遗留）才删。
pub fn sweep_old_tmp() {
    sweep_dir(&tmp_root());
}

fn sweep_dir(base: &Path) {
    let Ok(rd) = std::fs::read_dir(base) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name();
        if !name.to_string_lossy().starts_with(TMP_PREFIX) {
            continue;
        }
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        let marker = p.join(ACTIVE_MARKER);
        let (have_marker, age) = if marker.is_file() {
            (true, file_age(&marker).unwrap_or(0))
        } else {
            (false, file_age(&p).unwrap_or(0))
        };
        let limit = if have_marker {
            ACTIVE_MAX_AGE
        } else {
            TMP_MAX_AGE
        };
        if age > limit {
            let _ = std::fs::remove_dir_all(&p);
        }
    }
}

fn file_age(p: &Path) -> Option<u64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let mt = p
        .metadata()
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(now.saturating_sub(mt))
}

pub fn mktmpdir() -> PathBuf {
    let d = tmp_root();
    loop {
        let name = format!("{}{:08x}", TMP_PREFIX, rand::random::<u32>());
        let p = d.join(name);
        if std::fs::create_dir_all(&p).is_ok() {
            let _ = touch_active(&p);
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
    let zero = vec![0u8; 1 << 20];
    wipe_tree_with(p, &zero);
}

fn wipe_tree_with(p: &Path, zero: &[u8]) {
    if p.is_dir() {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                wipe_tree_with(&e.path(), zero);
            }
        }
    } else if p.is_file() {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(p) {
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            use std::io::{Seek, SeekFrom, Write as IoWrite};
            let _ = f.seek(SeekFrom::Start(0));
            // 1 MiB 覆写块，避免 4 KiB 级小写拖慢大批量清理；
            // 不逐文件 fsync —— 覆写擦除是 best-effort（SSD 介质残留需整体擦除），
            // 且文件随即删除，逐文件同步在 1 万文件场景可占压缩耗时近半。
            let mut left = len;
            while left > 0 {
                let n = left.min(zero.len() as u64) as usize;
                if f.write_all(&zero[..n]).is_err() {
                    break;
                }
                left -= n as u64;
            }
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

    #[test]
    fn safe_name_reserved_devices_are_displaced() {
        assert_eq!(safe_name("CON", 100), "_CON", "设备名必须让位");
        assert_eq!(safe_name("com1.txt", 100), "_com1.txt", "带扩展名同样保留");
        assert_eq!(safe_name("LPT9", 100), "_LPT9");
        assert_eq!(safe_name("aux.log", 100), "_aux.log");
        assert_eq!(safe_name("正常.txt", 100), "正常.txt", "普通名不受影响");
        assert_eq!(safe_name("console.log", 100), "console.log", "仅精确设备名命中");
    }

    #[test]
    fn sweep_skips_active_and_removes_stale() {
        let base = std::env::temp_dir().join(format!("vg_sweep_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        // 1) 新鲜活跃标记：无论目录多旧都不能删
        let active = base.join("vg_tmp_active");
        std::fs::create_dir_all(&active).unwrap();
        touch_active(&active).unwrap();

        // 2) 标记已过期（进程崩溃残留）：应删
        let stale = base.join("vg_tmp_stale");
        std::fs::create_dir_all(&stale).unwrap();
        touch_active(&stale).unwrap();
        set_mtime_old(&stale.join(ACTIVE_MARKER), 25 * 3600);

        // 3) 无标记但目录未超时（历史遗留，刚创建）：不应删
        let legacy = base.join("vg_tmp_legacy");
        std::fs::create_dir_all(&legacy).unwrap();

        sweep_dir(&base);

        assert!(active.exists(), "新鲜标记的目录不能被清扫");
        assert!(!stale.exists(), "标记过期的目录应被清扫");
        assert!(legacy.exists(), "无标记但未超时的目录不应被清扫");
        let _ = std::fs::remove_dir_all(&base);
    }

    fn set_mtime_old(p: &std::path::Path, secs: u64) {
        use std::time::{Duration, SystemTime};
        if let Ok(t) = std::fs::File::options().write(true).open(p) {
            let _ = t.set_modified(SystemTime::now() - Duration::from_secs(secs));
        }
    }
}

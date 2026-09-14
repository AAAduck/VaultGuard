//! egui 图形界面 —— zinc/emerald 暗色主题（移植自退役 React 版的设计语言）。
//! 双页：伪装加密页（一次性打包）+ 隐私保险箱页（.vgsafe 增量容器）。
//! 原生支持窗口内拖放（egui dropped_files）+ rfd 文件/文件夹选择；后台线程处理不阻塞 UI。

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};

use eframe::egui;
use egui::Color32;

use crate::cancel::{self, Cancel};
use crate::crypto;
use crate::engine;
use crate::paths;
use crate::safe;
use crate::shells;

const SHELLS: [&str; 3] = ["png", "jpg", "docx"];
const SHELL_NAMES: [&str; 3] = ["PNG 图片伪装", "JPG 图片伪装", "DOCX 文档伪装"];
const SHELL_DESCS: [&str; 3] = [
    "输出为正常显示的 PNG 图片",
    "输出为正常显示的 JPG 图片",
    "输出为可打开的 Word 文档",
];
const SHELL_BADGES: [&str; 3] = ["png", "jpg", "docx"];

// ── 视觉令牌：字号 / 间距 / 圆角 / 控件尺寸 ──────────────────────────────
// 改造前各处直接写魔法数，全文件出现 10 档字号、10 档间距、6 档圆角、
// 6 档内边距——相邻档只差 0.5px 时人眼读到的是「参差」而不是「层级」，
// 这正是界面显拥挤、显乱的主因。下面把取值收敛成有限档位，样式点统一取令牌。
//
// 字号：4 档（原来 9.0/9.5/10.0/10.5/11.0/11.5/12.0/12.5/13.0/14.5 共 10 档）
/// 品牌名 / 页面级标题
const FS_TITLE: f32 = 15.0;
/// 正文、按钮、列表主文字
const FS_BODY: f32 = 13.0;
/// 次级标签、区块小标题
const FS_SUB: f32 = 12.0;
/// 说明文字、状态小字、徽标（原先小到 9.0，可读性不足）
const FS_NOTE: f32 = 11.0;
/// 页面大标题（egui Style 层的 Heading）
const FS_H1: f32 = 16.0;

// 间距：6 档阶梯（4 的倍数，形成节奏）
/// 紧贴：标签与它自己的控件之间
const SP_XS: f32 = 4.0;
/// 同组元素之间
const SP_S: f32 = 8.0;
/// 区块与区块之间
const SP_L: f32 = 16.0;
/// 大间隔 / 空状态上下留白
const SP_XL: f32 = 24.0;
/// 控件之间的默认间距（egui Style 层；沿用原值 10，不在 4 的倍数阶梯内）
const SP_CTRL: f32 = 10.0;

// 内边距：卡片统一一套，不再每个卡片各自为政
/// 卡片左右内边距
const PAD_X: f32 = 14.0;
/// 卡片上下内边距
const PAD_Y: f32 = 12.0;
/// 顶栏内边距（比卡片略大，作为页面留白基准）
const HEADER_PAD_X: f32 = 20.0;
const HEADER_PAD_Y: f32 = 14.0;

// 圆角：3 档
/// 卡片（原先 8/10 混用）
const R_MD: f32 = 12.0;
/// 控件 / 小卡片
const R_SM: f32 = 8.0;
/// 徽标
const R_CHIP: f32 = 4.0;
/// 行内圆点等极小元素
const R_XS: f32 = 2.0;

// 控件高度：分层，拉开主次（原先全挤在 22–36 之间且无规律）
/// 主操作按钮（开始加密）
const H_BTN_MAIN: f32 = 40.0;
/// 次级按钮（还原 / 文件 / 文件夹）
const H_BTN_SEC: f32 = 34.0;
/// 行内小按钮（顶栏页签、表单内幽灵按钮）
const H_BTN: f32 = 30.0;
/// 迷你按钮（次级操作：移除/清空/分享说明；状态条与提醒条内的按钮）
const H_BTN_SM: f32 = 24.0;
/// Spinner 直径（几何尺寸，非文字）
const ICON_S: f32 = 12.0;

// 窗口与侧栏尺寸
/// 左侧栏宽度（原 262：口令说明等文案在窄栏里反复折行，是「挤」的主要来源）
const SIDE_W: f32 = 300.0;
const WINDOW_W: f32 = 1060.0;
const WINDOW_H: f32 = 720.0;
const MIN_WINDOW_W: f32 = 860.0;
const MIN_WINDOW_H: f32 = 600.0;
/// 文件行列内：右侧元信息（徽标 + 大小 + 移除）预留宽度
const ROW_META_W: f32 = 132.0;
/// 文件行内徽标占位宽度（无徽标时补空格，保证名称列对齐）
const ROW_BADGE_W: f32 = 74.0;
/// 文件行高（原 20：行与行贴在一起，长列表读起来很挤）
const ROW_H: f32 = 26.0;

// 列表区高度：原先按窗口比例定高（*0.46 / *0.30），窗口一矮就压成一条缝、
// 一高又把底部内容顶出可视区。改成分档区间，高度只在这两个数之间取值。
/// 待处理列表 / 保险箱表格的下限与上限
const LIST_H_MIN: f32 = 140.0;
const LIST_H_MAX: f32 = 320.0;
/// 保险箱表格（行高固定，可多给一点）
const TABLE_H_MIN: f32 = 160.0;
const TABLE_H_MAX: f32 = 360.0;
/// 解密预览列表（条目通常很少）
const PICK_H_MIN: f32 = 120.0;
const PICK_H_MAX: f32 = 260.0;
/// 日志面板展开后的高度
const LOG_H: f32 = 160.0;

// 几何小件：原先散落在绘制代码里，同名不同值（圆点 7、logo 30、圆角 2/5/8）
/// 顶栏品牌方块边长
const LOGO_S: f32 = 30.0;
/// 行内类型圆点直径
const DOT_S: f32 = 7.0;
/// 徽标内边距（比卡片更紧）
const CHIP_PAD_X: f32 = 6.0;
const CHIP_PAD_Y: f32 = 2.0;
/// 状态条内「取消」按钮的最小宽度
const W_BTN_CANCEL: f32 = 52.0;
/// 进度条高度（原先页内 10 / 面板内 12 两套）
const H_PROGRESS: f32 = 12.0;
/// 表单文本输入框宽度
const W_INPUT: f32 = 300.0;
/// 保险箱过滤框宽度
const W_FILTER: f32 = 170.0;
/// 状态条进度条宽度
const W_PROGRESS: f32 = 180.0;
/// 按钮内上下边距（egui Style 层，比左右 PAD_X 更紧）
const BTN_PAD_Y: f32 = 9.0;
/// 交互控件最小宽度（egui Style 层）
const W_INTERACT: f32 = 64.0;

// 文件行自绘几何：原先直接写在 draw_row 里（8 / 3.5 / 14 / 10 / 54 / 20）
/// 行内左右内边距
const ROW_PAD_L: f32 = 8.0;
const ROW_PAD_R: f32 = 10.0;
/// 类型圆点右缘到文件名的间距
const ROW_DOT_GAP: f32 = 14.0;
/// 名称右侧为文件大小文字预留的宽度
const ROW_SIZE_W: f32 = 54.0;
/// 名称列的最小可见宽度（窗口极窄时仍留一段可读文字）
const ROW_NAME_MIN: f32 = 20.0;
/// item_row 里名称列宽的下限
const W_NAME_MIN: f32 = 80.0;

// 宽度预留：与输入框并排的控件占位，原先散在各处的经验值
/// 输入框右侧一个次级按钮的占位宽（含控件间距；原 74 / 76 两处统一取值）
const W_SLOT_BTN: f32 = 76.0;
/// 两个并排口令框各自的右侧余量
const W_SLOT_HALF: f32 = 56.0;
/// 保险箱路径框右侧三按钮（新建 / 打开 / 浏览…）的占位宽
const W_SLOT_VAULT_BTNS: f32 = 276.0;
/// 输入框最小宽度
const W_INPUT_MIN: f32 = 180.0;
/// 右键菜单最小宽度
const W_MENU_MIN: f32 = 150.0;

// ── 主题与配色：深色 / 浅色两套令牌（对齐退役 React 版的 tailwind 配色）──

/// 界面主题。选择持久化在注册表 `HKCU\Software\VaultGuard\theme`。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThemeMode {
    Dark,
    Light,
}

impl ThemeMode {
    fn as_str(self) -> &'static str {
        match self {
            ThemeMode::Dark => "dark",
            ThemeMode::Light => "light",
        }
    }

    fn parse(s: &str) -> ThemeMode {
        if s.eq_ignore_ascii_case("light") {
            ThemeMode::Light
        } else {
            ThemeMode::Dark
        }
    }

    fn toggled(self) -> ThemeMode {
        match self {
            ThemeMode::Dark => ThemeMode::Light,
            ThemeMode::Light => ThemeMode::Dark,
        }
    }

    /// 按钮文案显示的是「切过去之后的结果」。
    fn switch_label(self) -> &'static str {
        match self {
            ThemeMode::Dark => "☀ 浅色",
            ThemeMode::Light => "☾ 深色",
        }
    }
}

/// 一套配色令牌。字段与旧常量一一对应，浅色只换值不换语义。
#[derive(Clone, Copy)]
struct Pal {
    /// 浅色标记：装配 egui 样式时据此选 light()/dark() 基准
    is_light: bool,
    bg: Color32,
    panel: Color32,
    card: Color32,
    card_hover: Color32,
    border: Color32,
    text: Color32,
    text_sub: Color32,
    text_muted: Color32,
    text_faint: Color32,
    /// 禁用态文字：明显变淡但仍看得清（egui 默认会把禁用文字淡到几乎不可见）
    text_off: Color32,
    /// 禁用态描边
    border_off: Color32,
    accent: Color32,
    accent_text: Color32,
    /// 强调色的极淡底（卡片/徽标底，10% 上下）
    accent_dim: Color32,
    /// 文本选中/拖选高亮（要明显看得出选中范围，比 accent_dim 浓）
    sel_bg: Color32,
    /// 强调色按钮上的文字
    on_accent: Color32,
    dir_sky: Color32,
    danger: Color32,
    busy_amber: Color32,
    /// 提醒卡底色（琥珀色调）
    warn_bg: Color32,
    /// 悬停高亮叠加（深色加白、浅色加黑）
    hover_tint: Color32,
    log_default: Color32,
    extreme_bg: Color32,
    faint_bg: Color32,
}

const PAL_DARK: Pal = Pal {
    is_light: false,
    bg: Color32::from_rgb(0x0A, 0x0A, 0x0C),
    panel: Color32::from_rgb(0x13, 0x13, 0x16),
    card: Color32::from_rgb(0x18, 0x18, 0x1B),
    card_hover: Color32::from_rgb(0x20, 0x20, 0x24),
    border: Color32::from_rgb(0x2A, 0x2A, 0x2E),
    text: Color32::from_rgb(0xE4, 0xE4, 0xE7),
    text_sub: Color32::from_rgb(0xB6, 0xB6, 0xBF),
    text_muted: Color32::from_rgb(0x8C, 0x8C, 0x96),
    text_faint: Color32::from_rgb(0x64, 0x64, 0x6D),
    text_off: Color32::from_rgb(0x7E, 0x7E, 0x88),
    border_off: Color32::from_rgb(0x26, 0x26, 0x2A),
    accent: Color32::from_rgb(0x05, 0x96, 0x69),
    accent_text: Color32::from_rgb(0x6E, 0xE7, 0xB7),
    accent_dim: Color32::from_rgba_premultiplied(2, 19, 13, 26),
    // accent(#059669) 约 38% 不透明度的预乘值
    sel_bg: Color32::from_rgba_premultiplied(2, 57, 40, 97),
    on_accent: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    dir_sky: Color32::from_rgb(0x38, 0xBD, 0xF8),
    danger: Color32::from_rgb(0xF8, 0x71, 0x71),
    busy_amber: Color32::from_rgb(0xFB, 0xBF, 0x24),
    warn_bg: Color32::from_rgb(0x1D, 0x18, 0x08),
    // = from_white_alpha(6)（该构造器非 const，展开为预乘值）
    hover_tint: Color32::from_rgba_premultiplied(6, 6, 6, 6),
    log_default: Color32::from_rgb(0x9C, 0x9C, 0xA4),
    extreme_bg: Color32::from_rgb(0x0D, 0x0D, 0x10),
    faint_bg: Color32::from_rgb(0x14, 0x14, 0x17),
};

const PAL_LIGHT: Pal = Pal {
    is_light: true,
    bg: Color32::from_rgb(0xF4, 0xF5, 0xF7),
    panel: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    card: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    card_hover: Color32::from_rgb(0xEC, 0xEE, 0xF2),
    border: Color32::from_rgb(0xD5, 0xD9, 0xE0),
    text: Color32::from_rgb(0x18, 0x18, 0x1B),
    text_sub: Color32::from_rgb(0x3F, 0x3F, 0x46),
    text_muted: Color32::from_rgb(0x60, 0x60, 0x69),
    text_faint: Color32::from_rgb(0x8C, 0x8C, 0x96),
    text_off: Color32::from_rgb(0x9C, 0x9C, 0xA6),
    border_off: Color32::from_rgb(0xE3, 0xE6, 0xEB),
    accent: Color32::from_rgb(0x05, 0x96, 0x69),
    accent_text: Color32::from_rgb(0x04, 0x78, 0x57),
    // = from_rgba_unmultiplied(5,150,105,28) 的预乘等价
    accent_dim: Color32::from_rgba_premultiplied(1, 16, 12, 28),
    // accent 约 26% 不透明度（白底上够明显，又不盖住黑字）
    sel_bg: Color32::from_rgba_premultiplied(1, 39, 27, 66),
    on_accent: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    dir_sky: Color32::from_rgb(0x02, 0x84, 0xC7),
    danger: Color32::from_rgb(0xDC, 0x26, 0x26),
    busy_amber: Color32::from_rgb(0xB4, 0x53, 0x09),
    warn_bg: Color32::from_rgb(0xFF, 0xFB, 0xEB),
    hover_tint: Color32::from_rgba_premultiplied(0, 0, 0, 8),
    log_default: Color32::from_rgb(0x3F, 0x3F, 0x46),
    extreme_bg: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    faint_bg: Color32::from_rgb(0xEC, 0xEE, 0xF2),
};

thread_local! {
    /// 当前线程的调色板（GUI 全程单线程，切换即时生效）
    static PAL: std::cell::Cell<Pal> = std::cell::Cell::new(PAL_DARK);
}

/// 当前调色板。所有取色点统一走这里。
fn pal() -> Pal {
    PAL.with(|p| p.get())
}

/// 当前是否浅色主题。
fn is_light() -> bool {
    pal().is_light
}

fn set_pal(mode: ThemeMode) {
    PAL.with(|p| {
        p.set(match mode {
            ThemeMode::Dark => PAL_DARK,
            ThemeMode::Light => PAL_LIGHT,
        })
    });
}

// ── 后台任务消息 ──
enum Msg {
    Line(String),
    Pct(u8),
    Done(Option<PathBuf>), // 加密/还原完成（携带产物路径）
    PreviewReady(engine::DecPreview), // 解密预览就绪（认证通过，等待用户选择落位范围）
}

enum VMsg {
    Line(String),
    Pct(u8),
    Done(Result<String, String>, Option<safe::Session>),
}

enum Page {
    Disguise,
    Vault,
}

enum VaultTask {
    Create(String, String),
    Open(String, String),
    Add(Vec<PathBuf>, bool), // (路径列表, 是否按类型归档)
    Remove(Vec<String>),
    Rename(String, String),
    MoveEntry(String, String),
    ExportAll(String),
    ExportSel(Vec<String>, String),
    Compact,
    ChangePass(String),
}

struct VaultApp {
    items: Vec<PathBuf>,
    sel: HashSet<usize>,
    shell: usize,
    out_dir: String,
    passphrase: String,
    passphrase2: String,
    show_pass: bool,
    allow_no_pass: bool,
    keep_name: bool,
    busy: bool,
    progress: Option<u8>,
    last_output: Option<PathBuf>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    logs: Vec<String>,
    last_error: Option<String>, // P2：最近一次失败（独立成卡片展示，可复制详情）
    vault_flags: Vec<bool>,
    vault_count: usize,
    page: Page,
    vp: VaultPage,
    // 选择性还原：解密预览就绪后，存放在此等待用户勾选落位
    dec_preview: Option<engine::DecPreview>,
    dec_sel: HashSet<String>,
    dec_origin: Option<PathBuf>, // 预览对应的源文件路径（用于日志展示）
    // 任务栏标题状态跟踪：避免每帧重复发送 ViewportCommand::Title
    title_busy: bool,
    /// 伪装页后台任务共享的取消令牌（加密/还原/落位期间有效）。
    enc_cancel: Option<Cancel>,
    /// 当前外观主题（深色/浅色），选择记在注册表。
    theme: ThemeMode,
    // 口令到期提醒（90 天）
    pass_tip_due: bool,
    // 活跃标记心跳节流（保险箱会话/解密预览存在时每 30s 刷新一次）
    hb_last: std::time::Instant,
}

struct VaultPage {
    path: String,
    pass: String,
    pass2: String,
    changing: bool, // 更换口令模式
    renaming: bool, // 重命名输入行
    ren_val: String,
    moving: bool, // 移动输入行
    mv_val: String,
    busy: bool,
    session: Option<safe::Session>,
    legacy_upgrade_ack: bool,
    sel: HashSet<usize>, // sess.entries 下标（P1-8：改名/移动后选中仍跟随）
    organize: bool, // 添加时按类型归档到子目录
    // P1：列表能力
    filter: String,        // 名字子串过滤（纯内存，不落盘、不建索引）
    focus_filter: bool,    // Ctrl+F：下一帧聚焦过滤框
    tree: bool,            // 目录树视图（否则平铺）
    sort: SortKey,         // 排序键
    sort_desc: bool,       // 降序
    anchor: Option<usize>, // Shift 连选锚点（条目下标）
    // P0：分层与反馈（状态条/就地确认）
    stage: String,          // 底部状态栏的阶段名
    confirm_remove: bool,   // 「移除」就地确认条
    confirm_compact: bool,  // 「压缩」就地确认条
    /// 当前后台任务共享的取消令牌（新建/打开等不涉及会话的任务为 None）。
    cancel: Option<Cancel>,
    tx: Sender<VMsg>,
    rx: Receiver<VMsg>,
}

impl VaultPage {
    fn new() -> Self {
        let (tx, rx) = channel::<VMsg>();
        Self {
            path: String::new(),
            pass: String::new(),
            pass2: String::new(),
            changing: false,
            renaming: false,
            ren_val: String::new(),
            moving: false,
            mv_val: String::new(),
            busy: false,
            session: None,
            legacy_upgrade_ack: true,
            sel: HashSet::new(),
            organize: false,
            filter: String::new(),
            focus_filter: false,
            tree: false,
            sort: SortKey::Name,
            sort_desc: false,
            anchor: None,
            stage: String::new(),
            confirm_remove: false,
            confirm_compact: false,
            cancel: None,
            tx,
            rx,
        }
    }

    /// 当前选中条目的名字（选中集是 sess.entries 的下标；导出/移除/重命名共用这一处转换）。
    fn sel_names(&self) -> Vec<String> {
        let Some(sess) = self.session.as_ref() else {
            return Vec::new();
        };
        self.sel
            .iter()
            .filter_map(|&i| sess.entries.get(i).map(|e| e.name.clone()))
            .collect()
    }

    /// 过滤 + 排序后的可见条目下标（P1-1/4：纯内存，不落盘、不建索引）。
    fn visible_indices(&self) -> Vec<usize> {
        let Some(sess) = self.session.as_ref() else {
            return Vec::new();
        };
        let e = &sess.entries;
        let pat = self.filter.trim().to_lowercase();
        let mut v: Vec<usize> = (0..e.len())
            .filter(|&i| pat.is_empty() || e[i].name.to_lowercase().contains(&pat))
            .collect();
        match self.sort {
            SortKey::Name => v.sort_by(|&a, &b| e[a].name.cmp(&e[b].name)),
            SortKey::Size => {
                v.sort_by(|&a, &b| e[a].size.cmp(&e[b].size).then(e[a].name.cmp(&e[b].name)))
            }
            SortKey::Kind => {
                v.sort_by(|&a, &b| kind_key(&e[a]).cmp(&kind_key(&e[b])).then(e[a].name.cmp(&e[b].name)))
            }
        }
        if self.sort_desc {
            v.reverse();
        }
        v
    }
}

impl VaultApp {
    fn new(theme: ThemeMode) -> Self {
        let (tx, rx) = channel::<Msg>();
        let mut shell = 0usize;
        if let Some(s) = paths::reg_get_shell() {
            if let Some(i) = SHELLS.iter().position(|&x| x == s) {
                shell = i;
            }
        }
        Self {
            items: Vec::new(),
            sel: HashSet::new(),
            shell,
            out_dir: paths::out_root().display().to_string(),
            passphrase: String::new(),
            passphrase2: String::new(),
            show_pass: false,
            allow_no_pass: false,
            keep_name: false,
            busy: false,
            progress: None,
            last_output: None,
            tx,
            rx,
            logs: Vec::new(),
            last_error: None,
            vault_flags: Vec::new(),
            vault_count: 0,
            page: Page::Disguise,
            vp: VaultPage::new(),
            dec_preview: None,
            dec_sel: HashSet::new(),
            dec_origin: None,
            title_busy: false,
            enc_cancel: None,
            theme,
            pass_tip_due: paths::pass_tip_due(),
            hb_last: std::time::Instant::now(),
        }
    }

    fn log(&mut self, line: &str) {
        let full = format!("[{}] {}", now_hms(), line);
        // P2：错误独立成卡片，不再只沉在日志里
        if full.contains("失败") || full.contains("未处理") || full.contains("错误") {
            self.last_error = Some(full.clone());
        }
        self.logs.push(full);
        if self.logs.len() > 800 {
            self.logs.remove(0);
        }
    }

    fn drain(&mut self) {
        while let Ok(m) = self.rx.try_recv() {
            match m {
                Msg::Line(line) => self.log(&line),
                Msg::Pct(p) => self.progress = Some(p),
                Msg::Done(path) => {
                    let cancelled = self.enc_cancel.as_ref().is_some_and(|c| c.is_cancelled());
                    self.busy = false;
                    self.progress = None;
                    self.enc_cancel = None;
                    if let Some(p) = path {
                        self.last_output = Some(p);
                    }
                    self.log(if cancelled {
                        "已取消：本次操作未提交，原文件与已有产物保持原状。"
                    } else {
                        "后台任务已结束，可继续操作。"
                    });
                }
                Msg::PreviewReady(preview) => {
                    self.busy = false;
                    self.progress = None;
                    self.enc_cancel = None;
                    // 解密预览就绪：存入 dec_preview 等待用户勾选落位
                    let tops = engine::top_entries(&preview.manifest);
                    let n = tops.len();
                    self.dec_sel.clear();
                    // 默认全选，用户可取消不需要的
                    for (name, _, _) in &tops {
                        self.dec_sel.insert(name.clone());
                    }
                    self.log(&format!(
                        "解密完成，认证通过：{} 个顶层条目。请在下方勾选要落位的内容。",
                        n
                    ));
                    self.dec_preview = Some(preview);
                }
            }
        }
    }

    fn drain_vault(&mut self) {
        while let Ok(m) = self.vp.rx.try_recv() {
            match m {
                VMsg::Line(line) => self.log(&line),
                VMsg::Pct(p) => self.progress = Some(p),
                VMsg::Done(res, sess) => {
                    let cancelled = sess.as_ref().is_some_and(|s| s.is_cancelled());
                    self.vp.busy = false;
                    self.progress = None;
                    self.vp.cancel = None;
                    self.vp.session = sess;
                    self.vp.legacy_upgrade_ack = !self
                        .vp
                        .session
                        .as_ref()
                        .is_some_and(|s| s.is_legacy_v1());
                    match res {
                        _ if cancelled => self.log(
                            "已取消：本次操作未写入容器，保险箱内容保持原状（会话仍可继续使用）。",
                        ),
                        Ok(msg) => self.log(&format!("完成：{}", msg)),
                        Err(e) => self.log(&format!("失败：{}", e)),
                    }
                }
            }
        }
    }

    fn run_enc(&mut self) {
        if self.busy {
            self.log("已有任务在后台处理，请稍候。");
            return;
        }
        if self.items.is_empty() {
            self.log("请先添加文件/文件夹。");
            return;
        }
        let pass_ok = if self.passphrase.is_empty() {
            self.allow_no_pass
        } else {
            self.passphrase == self.passphrase2
        };
        if !pass_ok {
            self.log("请先设置口令（两次输入需一致），或点击「跳过口令」。");
            return;
        }
        if !self.passphrase.is_empty() {
            paths::pass_tip_touch();
        }
        self.last_error = None;
        let items = self.items.clone();
        let shell = SHELLS[self.shell];
        let shell_name = SHELL_NAMES[self.shell];
        let out_dir = PathBuf::from(self.out_dir.trim());
        let opts = engine::EncOptions {
            key_src: if self.passphrase.is_empty() {
                engine::KeySource::Builtin
            } else {
                engine::KeySource::Passphrase(self.passphrase.clone())
            },
            keep_name: self.keep_name,
            cover: paths::custom_cover(SHELLS[self.shell]),
        };
        let use_pass = matches!(opts.key_src, engine::KeySource::Passphrase(_));
        let custom_cover = opts.cover.is_some();
        let tx = self.tx.clone();
        let cancel = Cancel::new();
        self.enc_cancel = Some(cancel.clone());
        self.busy = true;
        self.log(&format!(
            ">>> 加密 {} 项（外壳 {}，{}，封面 {}）…",
            items.len(),
            shell_name,
            if use_pass { "口令加密" } else { "内置密钥" },
            if custom_cover { "自定义" } else { "内置" }
        ));
        std::thread::spawn(move || {
            let _ = tx.send(Msg::Line(format!(
                "后台线程启动，目标目录: {}",
                out_dir.display()
            )));
            let prog = |d: u64, t: u64| {
                let pct = if t == 0 {
                    0
                } else {
                    (d.min(t) * 100 / t).min(99) as u8
                };
                let _ = tx.send(Msg::Pct(pct));
            };
            match engine::do_enc_c(&items, shell, &out_dir, &opts, Some(&prog), &cancel) {
                Ok((o, n, s)) => {
                    let _ = tx.send(Msg::Line(format!("完成: {}", o.display())));
                    let _ = tx.send(Msg::Line(format!("   {} 项，明文 {}", n, paths::sz(s))));
                }
                Err(e) => {
                    let _ = tx.send(Msg::Line(format!("未处理: {}（原文件未改动）", e)));
                }
            }
            let _ = tx.send(Msg::Done(Some(out_dir)));
        });
    }

    fn run_dec(&mut self) {
        if self.busy {
            self.log("已有任务在后台处理，请稍候。");
            return;
        }
        // 若有未落位的预览，先丢弃（用户重新点了还原）
        if self.dec_preview.is_some() {
            self.dec_preview = None;
            self.dec_sel.clear();
            self.dec_origin = None;
            self.log("已放弃上一次的解密预览。");
        }
        self.last_error = None;
        let vaults: Vec<PathBuf> = self
            .items
            .iter()
            .filter(|p| p.is_file() && shells::probe_vault(p).is_some())
            .cloned()
            .collect();
        if vaults.is_empty() {
            self.log("列表中没有可还原的 VaultGuard 文件。");
            return;
        }
        let out_dir = PathBuf::from(self.out_dir.trim());
        let pass: Option<String> = Some(self.passphrase.clone()).filter(|s| !s.is_empty());

        // 单文件：走两阶段（预览 → 用户勾选 → 落位），支持选择性还原
        if vaults.len() == 1 {
            let v = vaults[0].clone();
            let tx = self.tx.clone();
            let cancel = Cancel::new();
            self.enc_cancel = Some(cancel.clone());
            self.busy = true;
            self.dec_origin = Some(v.clone());
            self.log(&format!(">>> 解密 {}（认证后可勾选落位）…", v.display()));
            std::thread::spawn(move || {
                let prog = |d: u64, t: u64| {
                    let pct = if t == 0 {
                        0
                    } else {
                        (d.min(t) * 100 / t).min(99) as u8
                    };
                    let _ = tx.send(Msg::Pct(pct));
                };
                match engine::do_dec_preview_c(&v, pass.as_deref(), Some(&prog), &cancel) {
                    Ok(preview) => {
                        let _ = tx.send(Msg::PreviewReady(preview));
                    }
                    Err(e) if cancel::is_cancel_msg(&e) => {
                        let _ = tx.send(Msg::Line(format!(
                            "已取消：{} 未落位，未产生任何明文输出。",
                            v.display()
                        )));
                        let _ = tx.send(Msg::Done(None));
                    }
                    Err(e) => {
                        let _ = tx.send(Msg::Line(format!("失败 {}: {}", v.display(), e)));
                        let _ = tx.send(Msg::Done(None));
                    }
                }
            });
            return;
        }

        // 多文件：全量还原（保持原行为）
        let tx = self.tx.clone();
        let cancel = Cancel::new();
        self.enc_cancel = Some(cancel.clone());
        self.busy = true;
        self.log(&format!(">>> 还原 {} 个加密文件…", vaults.len()));
        std::thread::spawn(move || {
            let _ = tx.send(Msg::Line(format!("还原到目录: {}", out_dir.display())));
            let prog = |d: u64, t: u64| {
                let pct = if t == 0 {
                    0
                } else {
                    (d.min(t) * 100 / t).min(99) as u8
                };
                let _ = tx.send(Msg::Pct(pct));
            };
            let mut ok = 0;
            let mut fail = 0;
            for v in &vaults {
                if cancel.is_cancelled() {
                    let _ = tx.send(Msg::Line(
                        "已取消：剩余文件未处理，已完成的产物保持有效。".to_string(),
                    ));
                    break;
                }
                match engine::do_dec_c(v, &out_dir, pass.as_deref(), Some(&prog), &cancel) {
                    Ok(res) => {
                        ok += 1;
                        let _ = tx.send(Msg::Line(format!(
                            "还原 {} -> {}",
                            v.display(),
                            res.dst.display()
                        )));
                        let _ = tx.send(Msg::Line(format!(
                            "   {} 项，明文 {}",
                            res.entries,
                            paths::sz(res.plain_bytes)
                        )));
                        // 内容清单：认证已通过，展示箱里到底有什么
                        if !res.manifest.is_empty() {
                            let _ = tx.send(Msg::Line("   ── 内容清单 ──".to_string()));
                            for (name, sz, is_dir) in res.manifest.iter().take(16) {
                                let tag = if *is_dir { "[目录]" } else { "[文件]" };
                                let _ = tx.send(Msg::Line(format!(
                                    "   {} {}（{}）",
                                    tag,
                                    name,
                                    paths::sz(*sz)
                                )));
                            }
                            if res.manifest.len() > 16 {
                                let _ = tx.send(Msg::Line(format!(
                                    "   …其余 {} 项省略",
                                    res.manifest.len() - 16
                                )));
                            }
                        }
                        for (name, hash) in res.hashes.iter().take(4) {
                            let _ = tx.send(Msg::Line(format!("   SHA256 {} {}", name, hash)));
                        }
                        if res.hashes.len() > 4 {
                            let _ = tx.send(Msg::Line(format!(
                                "   …其余 {} 个文件哈希省略",
                                res.hashes.len() - 4
                            )));
                        }
                    }
                    Err(e) if cancel::is_cancel_msg(&e) => {
                        let _ = tx.send(Msg::Line(format!("已取消（{} 处理中止）。", v.display())));
                        break;
                    }
                    Err(e) => {
                        fail += 1;
                        let _ = tx.send(Msg::Line(format!("失败 {}: {}", v.display(), e)));
                    }
                }
            }
            let _ = tx.send(Msg::Line(format!(
                "还原结束：成功 {}，失败 {}",
                ok, fail
            )));
            let _ = tx.send(Msg::Done(None));
        });
    }

    fn remove_selected(&mut self) {
        if self.sel.is_empty() {
            return;
        }
        let removed: std::collections::BTreeSet<usize> = self.sel.drain().collect();
        let mut kept: Vec<PathBuf> = Vec::with_capacity(self.items.len());
        for (i, p) in self.items.drain(..).enumerate() {
            if !removed.contains(&i) {
                kept.push(p);
            }
        }
        self.items = kept; // 移除的正是被勾选的项，选择集随之清空
    }

    /// 从解密预览落位：filter=None 全量，Some 只落位选中的顶层条目。
    fn run_dec_place(&mut self, filter: Option<Vec<String>>) {
        let preview = match self.dec_preview.take() {
            Some(p) => p,
            None => {
                self.log("没有待落位的解密预览。");
                return;
            }
        };
        let out_dir = PathBuf::from(self.out_dir.trim());
        let origin = self.dec_origin.clone();
        let tx = self.tx.clone();
        let cancel = Cancel::new();
        self.enc_cancel = Some(cancel.clone());
        self.busy = true;
        self.dec_sel.clear();
        let label = match &filter {
            None => "全部落位".to_string(),
            Some(s) => format!("落位选中 {} 项", s.len()),
        };
        self.log(&format!(">>> {}…", label));
        std::thread::spawn(move || {
            let res = engine::do_dec_place_c(preview, &out_dir, filter.as_deref(), &cancel);
            match res {
                Ok(r) => {
                    let _ = tx.send(Msg::Line(format!(
                        "落位 {} -> {}（{} 项，明文 {}）",
                        origin
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default(),
                        r.dst.display(),
                        r.entries,
                        paths::sz(r.plain_bytes)
                    )));
                    for (name, hash) in r.hashes.iter().take(4) {
                        let _ = tx.send(Msg::Line(format!("   SHA256 {} {}", name, hash)));
                    }
                    if r.hashes.len() > 4 {
                        let _ = tx.send(Msg::Line(format!(
                            "   …其余 {} 个文件哈希省略",
                            r.hashes.len() - 4
                        )));
                    }
                    let _ = tx.send(Msg::Done(Some(r.dst)));
                }
                Err(e) if cancel::is_cancel_msg(&e) => {
                    let _ = tx.send(Msg::Line(
                        "已取消：未落位任何内容，临时明文已擦除。".to_string(),
                    ));
                    let _ = tx.send(Msg::Done(None));
                }
                Err(e) => {
                    let _ = tx.send(Msg::Line(format!("落位失败: {}", e)));
                    let _ = tx.send(Msg::Done(None));
                }
            }
        });
    }

    /// 放弃当前解密预览（Drop 擦除临时明文）。
    fn cancel_dec_preview(&mut self) {
        if self.dec_preview.is_some() {
            self.dec_preview = None;
            self.dec_sel.clear();
            self.dec_origin = None;
            self.log("已放弃解密预览，临时数据已擦除。");
        }
    }

    fn ui_header(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("header")
            .frame(
                egui::Frame::default()
                    .fill(pal().panel)
                    .stroke(egui::Stroke::new(1.0_f32, pal().border))
                    .inner_margin(egui::Margin::symmetric(HEADER_PAD_X, HEADER_PAD_Y)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(LOGO_S, LOGO_S), egui::Sense::hover());
                    ui.painter().rect_filled(rect, R_SM, pal().accent_dim);
                    ui.painter()
                        .rect_stroke(rect, R_SM, egui::Stroke::new(1.0_f32, pal().accent));
                    ui.painter().text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        "VG",
                        egui::FontId::monospace(FS_BODY),
                        pal().accent_text,
                    );
                    ui.add_space(SP_XS);
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("VaultGuard")
                                    .size(FS_TITLE)
                                    .strong()
                                    .color(pal().text),
                            );
                        });
                        ui.label(
                            egui::RichText::new("网盘伪装加密保险箱 —— 加密/还原均不触碰原文件")
                                .size(FS_NOTE)
                                .color(pal().text_muted),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // 主题切换（默认深色，选择记在注册表，下次启动沿用）
                        let target = self.theme.toggled();
                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new(self.theme.switch_label())
                                        .size(FS_BODY)
                                        .color(pal().text_sub),
                                )
                                .fill(Color32::TRANSPARENT)
                                .stroke(egui::Stroke::new(1.0_f32, pal().border))
                                .rounding(R_SM)
                                .min_size(egui::vec2(0.0, H_BTN)),
                            )
                            .on_hover_text("切换深色 / 浅色外观")
                            .clicked()
                        {
                            self.theme = target;
                            paths::reg_set_theme(target.as_str());
                            apply_theme(ctx, target);
                        }
                        ui.add_space(SP_S);
                        if tab_button(ui, "伪装加密", matches!(&self.page, Page::Disguise)) {
                            self.page = Page::Disguise;
                        }
                        if tab_button(ui, "隐私保险箱", matches!(&self.page, Page::Vault)) {
                            self.page = Page::Vault;
                        }
                    });
                });
            });
    }

    fn ui_left(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("side")
            .resizable(false)
            .exact_width(SIDE_W)
            .frame(
                egui::Frame::default()
                    .fill(pal().bg)
                    .inner_margin(egui::Margin::same(SP_L)),
            )
            .show(ctx, |ui| {
                let width = ui.available_width();

                // 底部操作区用嵌套面板钉在栏底：面板高度由 egui 按内容计算——
                // 原先靠 magic number（group_height = 106.0）撑空白，间距一改就错位。
                // 面板必须先声明：声明之后，剩余空间才归上方字段区。
                egui::TopBottomPanel::bottom("side_actions")
                    .show_separator_line(false)
                    .frame(egui::Frame::default().inner_margin(egui::Margin {
                        left: 0.0,
                        right: 0.0,
                        top: SP_L,
                        bottom: 0.0,
                    }))
                    .show_inside(ui, |ui| {
                        // 操作按钮组固定在面板底部：用空白撑开后从上往下排
                        let busy = self.busy;
                        ui.columns(2, |cols| {
                            let w0 = cols[0].available_width();
                            let w1 = cols[1].available_width();
                            if cols[0]
                                .add_enabled(
                                    !busy,
                                    egui::Button::new("文件").min_size(egui::vec2(w0, H_BTN_SEC)),
                                )
                                .clicked()
                            {
                                if let Some(files) = rfd::FileDialog::new().pick_files() {
                                    let n = files.len();
                                    for f in files {
                                        self.items.push(f);
                                    }
                                    self.log(&format!("添加 {} 个文件", n));
                                }
                            }
                            if cols[1]
                                .add_enabled(
                                    !busy,
                                    egui::Button::new("文件夹").min_size(egui::vec2(w1, H_BTN_SEC)),
                                )
                                .clicked()
                            {
                                if let Some(d) = rfd::FileDialog::new().pick_folder() {
                                    self.items.push(d);
                                    self.log("添加文件夹");
                                }
                            }
                        });

                        // 操作按钮组固定在面板底部：用空白撑开后从上往下排
                        let pass_ready = (!self.passphrase.is_empty()
                            && self.passphrase == self.passphrase2)
                            || self.allow_no_pass;
                        if ui
                            .add_enabled(
                                !self.busy && pass_ready,
                                primary_button("开始加密（所选外壳）").min_size(egui::vec2(width, H_BTN_MAIN)),
                            )
                            .clicked()
                        {
                            self.run_enc();
                        }
                        ui.add_space(SP_S);
                        let dec_label = if self.vault_count > 0 {
                            format!("还原 VaultGuard 文件（{}）", self.vault_count)
                        } else {
                            "还原 VaultGuard 文件".to_string()
                        };
                        if ui.add_sized([width, H_BTN_SEC], secondary_button(dec_label)).clicked() {
                            self.run_dec();
                        }
                        // 次级操作：降到迷你档，权重明显低于上方两个主操作；
                        // 不可用时用悬停文字说明原因，避免「点了没反应」的困惑。
                        // 注：不按条件隐藏——按钮生灭会让下方字段区跳动。
                        ui.add_space(SP_S);
                        ui.columns(3, |cols| {
                            let ws = [
                                cols[0].available_width(),
                                cols[1].available_width(),
                                cols[2].available_width(),
                            ];
                            if cols[0]
                                .add_enabled(
                                    !self.sel.is_empty() && !self.busy,
                                    ghost_button_mini("移除选中")
                                        .min_size(egui::vec2(ws[0], H_BTN_SM)),
                                )
                                .on_disabled_hover_text("先在右侧列表中选中条目，再执行移除。")
                                .clicked()
                            {
                                self.remove_selected();
                            }
                            if cols[1]
                                .add_enabled(
                                    !self.items.is_empty() && !self.busy,
                                    ghost_button_mini("清空列表")
                                        .min_size(egui::vec2(ws[1], H_BTN_SM)),
                                )
                                .on_disabled_hover_text("列表为空，无需清空。")
                                .clicked()
                            {
                                self.items.clear();
                                self.sel.clear();
                                self.log("列表已清空");
                            }
                            if cols[2]
                                .add_enabled(
                                    self.last_output.is_some(),
                                    ghost_button_mini("分享说明")
                                        .min_size(egui::vec2(ws[2], H_BTN_SM)),
                                )
                                .on_disabled_hover_text("加密完成后，可在此复制带口令的分享文案。")
                                .clicked()
                            {
                                let out = self.last_output.clone();
                                if let Some(out) = out {
                                    // 口令会随文案进剪贴板（Win+V 剪贴板历史会留存），复制前确认
                                    if !self.passphrase.is_empty() {
                                        let ok = rfd::MessageDialog::new()
                                            .set_title("分享说明")
                                            .set_description(
                                                "分享文案将包含口令并复制到剪贴板。\n注意：Windows 剪贴板历史（Win+V）会留存口令，用后建议清空剪贴板。\n\n是否继续？",
                                            )
                                            .set_buttons(rfd::MessageButtons::OkCancel)
                                            .show();
                                        if ok != rfd::MessageDialogResult::Ok {
                                            self.log("已取消复制分享说明。");
                                            return;
                                        }
                                    }
                                    let pass_note = if self.passphrase.is_empty() {
                                        "（未设口令：内置密钥模式）".to_string()
                                    } else {
                                        self.passphrase.clone()
                                    };
                                    let text = format!(
                                        "【VaultGuard 分享说明】\n文件：{}\n口令：{}\n接收方步骤：打开 VaultGuard.exe → 拖入本文件 → 输入口令 → 还原。\n下载：https://github.com/AAAduck/VaultGuard/releases （或由发送方直接提供 VaultGuard.exe）\n安全提醒：口令请勿与文件走同一渠道发送；口令遗忘无法找回。",
                                        out.display(),
                                        pass_note
                                    );
                                    cols[2].output_mut(|o| o.copied_text = text);
                                    self.log("分享说明已复制到剪贴板。");
                                }
                            }
                        });
                    });

                // 字段区：窗口变矮时在剩余空间内滚动，不再挤压或裁掉下方按钮
                egui::ScrollArea::vertical()
                    .id_source("side_fields")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        // 滚动条出现时会吃掉一点宽度，这里按实际可用宽度重算
                        let width = ui.available_width();
                        section_title(ui, "伪装外壳");
                        for (i, name) in SHELL_NAMES.iter().enumerate() {
                            let active = self.shell == i;
                            if shell_card(
                                ui,
                                &format!("shell{}", i),
                                active,
                                name,
                                SHELL_BADGES[i],
                                SHELL_DESCS[i],
                            ) {
                                self.shell = i;
                                paths::reg_set_shell(SHELLS[i]);
                            }
                            ui.add_space(SP_XS);
                        }

                        ui.add_space(SP_L);
                        section_title(ui, "口令（保护隐私，推荐设置）");
                        ui.horizontal(|ui| {
                            let r1 = ui.add(
                                egui::TextEdit::singleline(&mut self.passphrase)
                                    .password(!self.show_pass)
                                    .hint_text("输入口令")
                                    .desired_width(width - W_SLOT_BTN)
                                    .font(egui::TextStyle::Monospace),
                            );
                            if ui
                                .add(ghost_button(if self.show_pass { "隐藏" } else { "显示" }))
                                .clicked()
                            {
                                self.show_pass = !self.show_pass;
                            }
                            if r1.changed() {
                                self.allow_no_pass = false;
                            }
                        });
                        ui.add_space(SP_XS);
                        let r2 = ui.add(
                            egui::TextEdit::singleline(&mut self.passphrase2)
                                .password(true)
                                .hint_text("再次输入口令确认")
                                .desired_width(width - SP_XS)
                                .font(egui::TextStyle::Monospace),
                        );
                        ui.add_space(SP_XS);
                        if ui
                            .add_enabled(
                                !self.busy && self.passphrase.is_empty(),
                                ghost_button("生成强口令（自动填入并复制）"),
                            )
                            .clicked()
                        {
                            let gen = crypto::generate_passphrase(16);
                            self.passphrase = gen.clone();
                            self.passphrase2 = gen;
                            ui.output_mut(|o| o.copied_text = self.passphrase.clone());
                            self.log("已生成 16 位强口令并复制到剪贴板，请妥善保存（遗忘无法找回）。");
                        }
                        if r2.changed() {
                            self.allow_no_pass = false;
                        }
                        ui.add_space(SP_XS);
                        // 口令状态机：未设口令时提供 跳过/取消跳过 双向按钮，跳过后也能反悔
                        if self.passphrase.is_empty() {
                            if self.allow_no_pass {
                                ui.label(
                                    egui::RichText::new("已跳过口令：拿到程序的人都能解密")
                                        .size(FS_NOTE)
                                        .color(pal().text_muted),
                                )
                                .on_hover_text(
                                    "跳过口令 = 使用内置密钥：仅防随手翻看，任何拿到程序的人都能解密；敏感文件不建议跳过。",
                                );
                                if ui.add(ghost_button("取消跳过，改设口令")).clicked() {
                                    self.allow_no_pass = false;
                                    self.log("已取消跳过口令：设置口令（两次输入一致）后即可口令加密。");
                                }
                            } else {
                                ui.label(
                                    egui::RichText::new("未设置口令：拿到程序的人都能解密")
                                        .size(FS_NOTE)
                                        .color(pal().text_muted),
                                )
                                .on_hover_text(
                                    "仅防随手翻看，任何拿到程序的人都可解密；不推荐用于敏感文件。",
                                );
                                if ui.add(ghost_button("跳过口令，不设口令继续")).clicked() {
                                    self.allow_no_pass = true;
                                    self.log("已跳过口令：本次加密使用内置密钥（不推荐用于敏感文件）。");
                                }
                            }
                        } else if self.passphrase != self.passphrase2 {
                            ui.label(
                                egui::RichText::new("两次输入的口令不一致")
                                    .size(FS_NOTE)
                                    .color(pal().busy_amber),
                            );
                        } else {
                            // 口令强度实时评估：常见弱口令 / 长度 / 字符类
                            let (lv, msg) = pass_strength(&self.passphrase);
                            let color = match lv {
                                2 => pal().accent_text,
                                1 => pal().busy_amber,
                                _ => pal().danger,
                            };
                            ui.label(
                                egui::RichText::new(format!(
                                    "{}（Argon2id）· 钥匙指纹 {}",
                                    msg,
                                    crypto::pass_fingerprint(&self.passphrase)
                                ))
                                .size(FS_NOTE)
                                .color(color),
                            )
                            .on_hover_text(
                                "同一条口令的指纹相同，可用于核对是否输错。口令遗忘后文件无法找回。",
                            );
                        }

                        ui.add_space(SP_L);
                        section_title(ui, "输出目录");
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.out_dir)
                                    .desired_width(width - W_SLOT_BTN)
                                    .font(egui::TextStyle::Monospace),
                            );
                            if ui.add(b_ghost("浏览…")).clicked() {
                                if let Some(d) = rfd::FileDialog::new().pick_folder() {
                                    self.out_dir = d.display().to_string();
                                }
                            }
                        });

                        ui.add_space(SP_L);
                        // 自定义封面：跟随当前选中的外壳，各自记忆（存于 %APPDATA% 封面目录）
                        let shell = SHELLS[self.shell];
                        let custom = paths::custom_cover(shell).is_some();
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(format!(
                                    "封面：{}",
                                    if custom { "自定义 ✔" } else { "内置随机" }
                                ))
                                .size(FS_NOTE)
                                .color(if custom { pal().accent_text } else { pal().text_muted }),
                            );
                            if ui.add_enabled(!self.busy, ghost_button("自定义…")).clicked() {
                                let (filter, exts): (&str, &[&str]) = match shell {
                                    "jpg" => ("JPG 图片", &["jpg", "jpeg"]),
                                    "docx" => ("DOCX 文档", &["docx"]),
                                    _ => ("PNG 图片", &["png"]),
                                };
                                if let Some(p) =
                                    rfd::FileDialog::new().add_filter(filter, exts).pick_file()
                                {
                                    match shells::validate_cover(shell, &p) {
                                        Ok(()) => match paths::set_custom_cover(shell, &p) {
                                            Ok(()) => self.log(&format!(
                                                "已启用自定义封面（{} 外壳）：{}",
                                                shell,
                                                p.display()
                                            )),
                                            Err(e) => self.log(&format!("失败：{e}")),
                                        },
                                        Err(e) => self.log(&format!("失败：{e}")),
                                    }
                                }
                            }
                            if custom
                                && ui
                                    .add_enabled(!self.busy, ghost_button("恢复默认"))
                                    .clicked()
                            {
                                match paths::clear_custom_cover(shell) {
                                    Ok(()) => self.log("已恢复内置随机封面。"),
                                    Err(e) => self.log(&format!("失败：{e}")),
                                }
                            }
                        });
                        if let Some(p) = paths::custom_cover(shell) {
                            ui.label(
                                egui::RichText::new(format!("　└ {}", p.display()))
                                    .monospace()
                                    .size(FS_NOTE)
                                    .color(pal().text_faint),
                            );
                        }
                        ui.add_space(SP_XS);
                        ui.checkbox(&mut self.keep_name, "保留原文件名作为输出名")
                            .on_hover_text("默认随机命名，不泄露原文件名。");

                    });
            });
    }

    fn ui_center(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(pal().bg)
                    .inner_margin(egui::Margin::same(SP_L)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .id_source("center_scroll")
                    // 正文超出可视区时整页滚动；底部错误卡 / 日志不再被裁掉。
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let dragging = ui.input(|i| !i.raw.hovered_files.is_empty());

                        // ── 口令到期提醒（90 天，可关闭/确认）──
                        if self.pass_tip_due {
                            // 安全提醒保留（只在这条确实到期时出现，并非常驻），但去掉整圈琥珀描边、
                            // 收窄上下内边距、按钮降档：仍看得见，不再抢走整页第一眼的注意力。
                            egui::Frame::default()
                                .fill(pal().warn_bg)
                                .rounding(R_SM)
                                .inner_margin(egui::Margin::symmetric(PAD_X, SP_S))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            egui::RichText::new("距上次设置/更换口令已超过 90 天，建议更换。")
                                                .size(FS_NOTE)
                                                .color(pal().busy_amber),
                                        );
                                        if ui
                                            .add(ghost_button_mini("已更换口令"))
                                            .on_hover_text("记录为今天刚换过，90 天后再次提醒。")
                                            .clicked()
                                        {
                                            paths::pass_tip_touch();
                                            self.pass_tip_due = false;
                                            self.log("口令更换时间已记录，90 天后再次提醒。");
                                        }
                                        if ui
                                            .add(ghost_button_mini("关闭提醒"))
                                            .on_hover_text("本次不再提醒；下次设置口令时自动恢复。")
                                            .clicked()
                                        {
                                            paths::pass_tip_disable();
                                            self.pass_tip_due = false;
                                            self.log("口令更换提醒已关闭（下次设置口令时重新开启）。");
                                        }
                                    });
                                });
                            ui.add_space(SP_S);
                        }

                        // ── 文件列表卡片 ──
                        egui::Frame::default()
                            .fill(if dragging { pal().accent_dim } else { pal().card })
                            .stroke(egui::Stroke::new(
                                1.0_f32,
                                if dragging { pal().accent } else { pal().border },
                            ))
                            .rounding(R_MD)
                            .inner_margin(egui::Margin::symmetric(PAD_X, PAD_Y))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.add_space(SP_XS);
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "待处理项目（{}）{}",
                                            self.items.len(),
                                            if dragging {
                                                " —— 松开鼠标即可添加"
                                            } else {
                                                " —— 可直接把文件/文件夹拖进本窗口"
                                            }
                                        ))
                                        .size(FS_SUB)
                                        .color(if dragging { pal().accent_text } else { pal().text_muted }),
                                    );
                                });
                                ui.add_space(SP_XS);
                                egui::ScrollArea::vertical()
                                    .id_source("items")
                                    .max_height(ui.available_height().clamp(LIST_H_MIN, LIST_H_MAX))
                                    .show(ui, |ui| {
                                        if self.items.is_empty() {
                                            empty_state(
                                                ui,
                                                "把文件或文件夹拖进窗口",
                                                Some("加密后的容器拖回来即可还原"),
                                            );
                                            return;
                                        }
                                        let mut remove_idx: Option<usize> = None;
                                        for (i, p) in self.items.iter().enumerate() {
                                            let flag = self.vault_flags.get(i).copied().unwrap_or(false);
                                            if let RowAction::Remove = item_row(
                                                ui,
                                                i,
                                                p,
                                                flag,
                                                &mut self.sel,
                                            ) {
                                                remove_idx = Some(i);
                                            }
                                        }
                                        if let Some(i) = remove_idx {
                                            if i < self.items.len() {
                                                self.items.remove(i);
                                                self.sel.remove(&i);
                                            }
                                        }
                                    });
                            });

                        ui.add_space(SP_L);

                        // ── 选择性还原预览面板（解密就绪后出现）──
                        if self.dec_preview.is_some() {
                            self.ui_dec_preview(ui);
                            ui.add_space(SP_L);
                        }

                        // ── 上次输出快捷入口 ──
                        if let Some(out) = &self.last_output {
                            egui::Frame::default()
                                .fill(pal().card)
                                .stroke(egui::Stroke::new(1.0_f32, pal().accent))
                                .rounding(R_MD)
                                .inner_margin(egui::Margin::symmetric(PAD_X, PAD_Y))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        if ui
                                            .add(primary_button("打开输出目录").min_size(egui::vec2(0.0, H_BTN_SEC)))
                                            .clicked()
                                        {
                                            open_in_explorer(out);
                                        }
                                        ui.label(
                                            egui::RichText::new(format!("上次输出: {}", out.display()))
                                                .size(FS_NOTE)
                                                .color(pal().text_faint)
                                                .monospace(),
                                        );
                                    });
                                });
                            ui.add_space(SP_XS);
                        }

                        error_card(ui, &mut self.last_error);
                        log_panel(ui, self.busy, self.progress, &self.logs, self.enc_cancel.as_ref());
                    });
            });
    }

    /// 解密预览面板：列出顶层条目供勾选，提供「落位选中」「全部落位」「取消」。
    fn ui_dec_preview(&mut self, ui: &mut egui::Ui) {
        let busy = self.busy;
        // 取出 manifest 的顶层条目（不消费 preview）
        let tops: Vec<(String, u64, bool)> = match &self.dec_preview {
            Some(p) => engine::top_entries(&p.manifest),
            None => return,
        };
        egui::Frame::default()
            .fill(pal().card)
            .stroke(egui::Stroke::new(1.0_f32, pal().accent))
            .rounding(R_MD)
            .inner_margin(egui::Margin::symmetric(PAD_X, PAD_Y))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(SP_XS);
                    ui.label(
                        egui::RichText::new(format!(
                            "解密预览（{} 个顶层条目）—— 勾选要落位的内容",
                            tops.len()
                        ))
                        .size(FS_SUB)
                        .color(pal().accent_text),
                    );
                });
                ui.add_space(SP_XS);
                egui::ScrollArea::vertical()
                    .id_source("dec_preview")
                    .max_height(ui.available_height().clamp(PICK_H_MIN, PICK_H_MAX))
                    .show(ui, |ui| {
                        for (name, sz, is_dir) in &tops {
                            let checked = self.dec_sel.contains(name);
                            let tag = if *is_dir { "[目录]" } else { "[文件]" };
                            let mut new_state = checked;
                            ui.horizontal(|ui| {
                                if ui
                                    .checkbox(&mut new_state, "")
                                    .on_hover_text("勾选以落位此条目")
                                    .changed()
                                {
                                    if new_state {
                                        self.dec_sel.insert(name.clone());
                                    } else {
                                        self.dec_sel.remove(name);
                                    }
                                }
                                ui.label(
                                    egui::RichText::new(tag)
                                        .monospace()
                                        .size(FS_NOTE)
                                        .color(pal().text_muted),
                                );
                                ui.label(
                                    egui::RichText::new(name)
                                        .monospace()
                                        .size(FS_SUB)
                                        .color(pal().text),
                                );
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |r| {
                                        r.label(
                                            egui::RichText::new(if *is_dir {
                                                "-".to_string()
                                            } else {
                                                paths::sz(*sz)
                                            })
                                            .monospace()
                                            .size(FS_NOTE)
                                            .color(pal().text_faint),
                                        );
                                    },
                                );
                            });
                        }
                    });
                ui.add_space(SP_XS);
                ui.horizontal(|ui| {
                    let sel_count = self.dec_sel.len();
                    let place_sel = ui.add_enabled(
                        !busy && sel_count > 0,
                        secondary_button(format!("落位选中（{}）", sel_count)),
                    );
                    if place_sel.clicked() {
                        let sel: Vec<String> = tops
                            .iter()
                            .filter(|(n, _, _)| self.dec_sel.contains(n))
                            .map(|(n, _, _)| n.clone())
                            .collect();
                        self.run_dec_place(Some(sel));
                    }
                    if ui
                        .add_enabled(!busy, secondary_button("全部落位"))
                        .clicked()
                    {
                        self.run_dec_place(None);
                    }
                    if ui
                        .add_enabled(!busy, ghost_button("取消").min_size(egui::vec2(0.0, H_BTN_SEC)))
                        .clicked()
                    {
                        self.cancel_dec_preview();
                    }
                });
            });
    }
    /// 统一的保险箱任务派发：设阶段名 → 置忙 → 交后台线程（会话经通道传回）。
    fn start_vault(&mut self, task: VaultTask, stage: &str) {
        self.last_error = None;
        self.vp.stage = stage.to_string();
        let sess = self.vp.session.take();
        // 会话自带的取消令牌就是后台任务的可中断点；新建/打开等无会话任务不可取消。
        let c = sess.as_ref().map(|s| s.cancel_flag());
        if let Some(c) = &c {
            c.reset();
        }
        self.vp.cancel = c;
        self.vp.busy = true;
        let tx = self.vp.tx.clone();
        std::thread::spawn(move || vault_worker(sess, task, tx));
    }

    /// 保险箱页顶部固定状态条（P0）：入口与状态各就其位，不再和列表抢版面。
    /// 未打开 = 路径 + 口令 + 新建/打开/浏览；已打开 = 名称 · 条目 · 体积 + 锁定。
    fn ui_vault_bar(&mut self, ctx: &egui::Context) {
        let busy = self.vp.busy;
        egui::TopBottomPanel::top("vault_bar")
            .frame(
                egui::Frame::default()
                    .fill(pal().panel)
                    .stroke(egui::Stroke::new(1.0_f32, pal().border))
                    .inner_margin(egui::Margin::symmetric(PAD_X, SP_S)),
            )
            .show(ctx, |ui| {
                if self.vp.session.is_none() {
                    let width = ui.available_width();
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = SP_S;
                        ui.label(egui::RichText::new("保险箱").size(FS_SUB).color(pal().text_sub));
                        ui.add(
                            egui::TextEdit::singleline(&mut self.vp.path)
                                .desired_width((width - W_SLOT_VAULT_BTNS).max(W_INPUT_MIN))
                                .font(egui::TextStyle::Monospace)
                                .hint_text(r"D:\…\我的保险箱.vgsafe"),
                        );
                        let create_ready = !busy
                            && !self.vp.path.trim().is_empty()
                            && !self.vp.pass.is_empty()
                            && self.vp.pass == self.vp.pass2;
                        let open_ready =
                            !busy && !self.vp.path.trim().is_empty() && !self.vp.pass.is_empty();
                        if ui
                            .add_enabled(create_ready, b_primary("新建"))
                            .on_hover_text("用当前口令创建一个新的空保险箱")
                            .clicked()
                        {
                            let path = self.vp.path.trim().to_string();
                            let pass = self.vp.pass.clone();
                            self.start_vault(VaultTask::Create(path, pass), "创建容器");
                        }
                        if ui
                            .add_enabled(open_ready, b_secondary("打开"))
                            .on_hover_text("认证并解锁已有保险箱（只填第一格口令）")
                            .clicked()
                        {
                            let path = self.vp.path.trim().to_string();
                            let pass = self.vp.pass.clone();
                            self.start_vault(VaultTask::Open(path, pass), "打开并认证");
                        }
                        if ui.add_enabled(!busy, b_ghost("浏览…").min_size(egui::vec2(0.0, H_BTN_SEC))).clicked() {
                            if let Some(p) = rfd::FileDialog::new()
                                .add_filter("VaultGuard 保险箱", &["vgsafe"])
                                .pick_file()
                            {
                                self.vp.path = p.display().to_string();
                            }
                        }
                    });
                    ui.add_space(SP_XS);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = SP_S;
                        let w = ui.available_width();
                        ui.label(egui::RichText::new("口令").size(FS_SUB).color(pal().text_sub));
                        ui.add(
                            egui::TextEdit::singleline(&mut self.vp.pass)
                                .password(true)
                                .desired_width(w / 2.0 - W_SLOT_HALF)
                                .font(egui::TextStyle::Monospace)
                                .hint_text("口令（新建与打开共用）"),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut self.vp.pass2)
                                .password(true)
                                .desired_width(w / 2.0 - W_SLOT_HALF)
                                .font(egui::TextStyle::Monospace)
                                .hint_text("确认口令（新建必填，打开可留空）"),
                        );
                    });
                    ui.label(
                        egui::RichText::new("新建需两次口令一致；打开已有保险箱只填第一格。口令遗忘后保险箱无法找回。")
                            .size(FS_NOTE)
                            .color(pal().text_faint),
                    );
                } else {
                    let name = Path::new(self.vp.path.trim())
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| self.vp.path.clone());
                    let (n, legacy) = self
                        .vp
                        .session
                        .as_ref()
                        .map(|s| (s.entries.len(), s.is_legacy_v1()))
                        .unwrap_or((0, false));
                    let disk = std::fs::metadata(self.vp.path.trim())
                        .map(|m| m.len())
                        .unwrap_or(0);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = SP_S;
                        ui.label(egui::RichText::new("已解锁").size(FS_NOTE).color(pal().accent_text));
                        ui.label(egui::RichText::new(name).size(FS_BODY).strong().color(pal().text));
                        ui.label(
                            egui::RichText::new(format!("· {} 个条目 · 容器 {}", n, paths::sz(disk)))
                                .size(FS_NOTE)
                                .color(pal().text_sub),
                        );
                        if legacy {
                            ui.label(
                                egui::RichText::new("· VGS1 旧格式").size(FS_NOTE).color(pal().busy_amber),
                            );
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .add_enabled(!busy, b_ghost("锁定"))
                                .on_hover_text("关闭保险箱并擦除临时数据")
                                .clicked()
                            {
                                self.vp.session = None;
                                self.vp.sel.clear();
                                self.vp.anchor = None;
                                self.log("保险箱已锁定，临时数据已擦除。");
                            }
                        });
                    });
                }
            });
    }

    /// 保险箱页底部固定状态栏（P0）：阶段名 + 进度条；空闲时给一行提示。
    /// 进度不再与日志共用一个卡片（P0-5）。
    fn ui_vault_statusbar(&mut self, ctx: &egui::Context) {
        let busy = self.vp.busy;
        let progress = self.progress;
        let stage = self.vp.stage.clone();
        let cancel = self.vp.cancel.clone();
        let tail = self.logs.last().cloned().unwrap_or_default();
        egui::TopBottomPanel::bottom("vault_status")
            .frame(
                egui::Frame::default()
                    .fill(pal().panel)
                    .stroke(egui::Stroke::new(1.0_f32, pal().border))
                    .inner_margin(egui::Margin::symmetric(PAD_X, SP_S)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = SP_S;
                    if busy {
                        ui.add(egui::Spinner::new().size(ICON_S));
                        ui.label(
                            egui::RichText::new(format!("{}…", stage))
                                .size(FS_NOTE)
                                .color(pal().busy_amber),
                        );
                        if let Some(p) = progress {
                            ui.add(
                                egui::ProgressBar::new(p as f32 / 100.0)
                                    .fill(pal().accent)
                                    .desired_height(H_PROGRESS)
                                    .desired_width(W_PROGRESS)
                                    .show_percentage(),
                            );
                        }
                        if let Some(c) = &cancel {
                            ui.add_space(SP_S);
                            cancel_button(ui, c);
                        }
                        ui.label(
                            egui::RichText::new("期间请勿断电或关闭程序")
                                .size(FS_NOTE)
                                .color(pal().text_faint),
                        );
                    } else {
                        ui.label(egui::RichText::new("就绪").size(FS_NOTE).color(pal().text_muted));
                        ui.label(egui::RichText::new(tail).size(FS_NOTE).color(pal().text_faint));
                    }
                });
            });
    }

    /// 未打开保险箱时的引导（P2 空状态之一：首次使用）。
    fn ui_vault_intro(&mut self, ui: &mut egui::Ui) {
        egui::Frame::default()
            .fill(pal().card)
            .stroke(egui::Stroke::new(1.0_f32, pal().border))
            .rounding(R_MD)
            .inner_margin(egui::Margin::symmetric(PAD_X, PAD_Y))
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new("开始使用隐私保险箱")
                        .size(FS_BODY)
                        .strong()
                        .color(pal().text),
                );
                ui.add_space(SP_S);
                for s in [
                    "1. 在上方填写 .vgsafe 的保存路径，或点「浏览…」选一个已有的保险箱。",
                    "2. 设置口令：新建需两次输入一致；打开已有保险箱只填第一格。",
                    "3. 点「新建」创建空保险箱，或点「打开」解锁。",
                ] {
                    ui.label(egui::RichText::new(s).size(FS_SUB).color(pal().text_sub));
                    ui.add_space(SP_XS);
                }
                ui.add_space(SP_XS);
                ui.label(
                    egui::RichText::new(
                        "一个 .vgsafe 就是一个文件：可放网盘、U 盘、邮件附件；解锁后才显示其中的条目。",
                    )
                    .size(FS_NOTE)
                    .color(pal().text_muted),
                );
            });
        ui.add_space(SP_L);
        error_card(ui, &mut self.last_error);
        log_panel(ui, false, None, &self.logs, None);
    }

    /// 重命名 / 移动 / 更换口令：改为浮层窗口，进出不再改变列表版面高度（P0-3）。
    fn ui_vault_editors(&mut self, ctx: &egui::Context) {
        let can = !self.vp.busy;
        if self.vp.renaming {
            let from = self.vp.sel_names().into_iter().next().unwrap_or_default();
            let mut open = true;
            egui::Window::new("重命名条目")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label(
                        egui::RichText::new(format!("当前：{}", from))
                            .monospace()
                            .size(FS_NOTE)
                            .color(pal().text_sub),
                    );
                    ui.add_space(SP_XS);
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut self.vp.ren_val)
                            .desired_width(W_INPUT)
                            .font(egui::TextStyle::Monospace),
                    );
                    if ui.memory(|m| m.focused().is_none()) {
                        r.request_focus();
                    }
                    ui.add_space(SP_XS);
                    ui.label(
                        egui::RichText::new("只改名字、不改所在目录；移动位置请用「移动」。")
                            .size(FS_NOTE)
                            .color(pal().text_faint),
                    );
                    ui.add_space(SP_S);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = SP_S;
                        let ready = can && !from.is_empty() && !self.vp.ren_val.trim().is_empty();
                        if ui.add_enabled(ready, b_primary("确定重命名")).clicked() {
                            let to = self.vp.ren_val.trim().to_string();
                            self.vp.renaming = false;
                            self.vp.sel.clear();
                            self.vp.anchor = None;
                            self.start_vault(VaultTask::Rename(from.clone(), to), "重命名");
                        }
                        if ui.add(b_ghost("取消").min_size(egui::vec2(0.0, H_BTN_SEC))).clicked() {
                            self.vp.renaming = false;
                        }
                    });
                });
            if !open {
                self.vp.renaming = false;
            }
        }
        if self.vp.moving {
            let name = self.vp.sel_names().into_iter().next().unwrap_or_default();
            let mut open = true;
            egui::Window::new("移动到目录")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label(
                        egui::RichText::new(format!("当前：{}", name))
                            .monospace()
                            .size(FS_NOTE)
                            .color(pal().text_sub),
                    );
                    ui.add_space(SP_XS);
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut self.vp.mv_val)
                            .desired_width(W_INPUT)
                            .font(egui::TextStyle::Monospace)
                            .hint_text("目标目录，留空 = 根目录（如 工作/2026）"),
                    );
                    if ui.memory(|m| m.focused().is_none()) {
                        r.request_focus();
                    }
                    ui.add_space(SP_XS);
                    ui.label(
                        egui::RichText::new("目标目录不存在会自动创建；重名自动加 _2/_3 后缀。")
                            .size(FS_NOTE)
                            .color(pal().text_faint),
                    );
                    ui.add_space(SP_S);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = SP_S;
                        if ui
                            .add_enabled(can && !name.is_empty(), b_primary("确定移动"))
                            .clicked()
                        {
                            let dir = self.vp.mv_val.trim().to_string();
                            self.vp.moving = false;
                            self.vp.sel.clear();
                            self.vp.anchor = None;
                            self.start_vault(VaultTask::MoveEntry(name.clone(), dir), "移动条目");
                        }
                        if ui.add(b_ghost("取消").min_size(egui::vec2(0.0, H_BTN_SEC))).clicked() {
                            self.vp.moving = false;
                        }
                    });
                });
            if !open {
                self.vp.moving = false;
            }
        }
        if self.vp.changing {
            let mut open = true;
            egui::Window::new("更换口令")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label(
                        egui::RichText::new("更换会重写整个容器；口令遗忘后保险箱无法打开。")
                            .size(FS_NOTE)
                            .color(pal().text_sub),
                    );
                    ui.add_space(SP_XS);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vp.pass)
                            .password(true)
                            .desired_width(W_INPUT)
                            .font(egui::TextStyle::Monospace)
                            .hint_text("新口令"),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vp.pass2)
                            .password(true)
                            .desired_width(W_INPUT)
                            .font(egui::TextStyle::Monospace)
                            .hint_text("确认新口令"),
                    );
                    if !self.vp.pass.is_empty() && self.vp.pass != self.vp.pass2 {
                        ui.label(
                            egui::RichText::new("两次输入的新口令不一致")
                                .size(FS_NOTE)
                                .color(pal().busy_amber),
                        );
                    }
                    ui.add_space(SP_S);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = SP_S;
                        let ready = can && !self.vp.pass.is_empty() && self.vp.pass == self.vp.pass2;
                        if ui.add_enabled(ready, b_primary("应用新口令")).clicked() {
                            let new_pass = self.vp.pass.clone();
                            self.vp.changing = false;
                            self.vp.pass.clear();
                            self.vp.pass2.clear();
                            self.start_vault(VaultTask::ChangePass(new_pass), "更换口令（重写容器）");
                        }
                        if ui.add(b_ghost("取消").min_size(egui::vec2(0.0, H_BTN_SEC))).clicked() {
                            self.vp.changing = false;
                            self.vp.pass.clear();
                            self.vp.pass2.clear();
                        }
                    });
                });
            if !open {
                self.vp.changing = false;
            }
        }
    }

    /// 键盘可达（P1-6）：常用动作不依赖鼠标。
    /// 输入框有焦点时不抢键；浮层窗口打开时 Esc 只关窗口。
    fn vault_shortcuts(&mut self, ctx: &egui::Context) {
        if ctx.wants_keyboard_input() {
            return;
        }
        let ctrl = ctx.input(|i| i.modifiers.command);
        let open = self.vp.session.is_some();
        if !open {
            if !ctrl || self.vp.busy {
                return;
            }
            let (new, opn) = ctx.input(|i| (i.key_pressed(egui::Key::N), i.key_pressed(egui::Key::O)));
            let ready = !self.vp.path.trim().is_empty() && !self.vp.pass.is_empty();
            if new && ready && self.vp.pass == self.vp.pass2 {
                let path = self.vp.path.trim().to_string();
                let pass = self.vp.pass.clone();
                self.start_vault(VaultTask::Create(path, pass), "创建容器");
            } else if opn && ready {
                let path = self.vp.path.trim().to_string();
                let pass = self.vp.pass.clone();
                self.start_vault(VaultTask::Open(path, pass), "打开并认证");
            }
            return;
        }
        if self.vp.renaming || self.vp.moving || self.vp.changing {
            if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
                self.vp.renaming = false;
                self.vp.moving = false;
                self.vp.changing = false;
            }
            return;
        }
        if self.vp.busy {
            return;
        }
        let (all, del, f2, enter, esc, find) = ctx.input(|i| {
            (
                i.modifiers.command && i.key_pressed(egui::Key::A),
                i.key_pressed(egui::Key::Delete),
                i.key_pressed(egui::Key::F2),
                i.key_pressed(egui::Key::Enter),
                i.key_pressed(egui::Key::Escape),
                i.modifiers.command && i.key_pressed(egui::Key::F),
            )
        });
        if find {
            self.vp.focus_filter = true;
        } else if all {
            for i in self.vp.visible_indices() {
                self.vp.sel.insert(i);
            }
        } else if esc {
            if self.vp.filter.is_empty() {
                self.vp.sel.clear();
                self.vp.anchor = None;
            } else {
                self.vp.filter.clear();
            }
        } else if del {
            if !self.vp.sel.is_empty() {
                self.vp.confirm_compact = false;
                self.vp.confirm_remove = true;
            }
        } else if f2 {
            if self.vp.sel.len() == 1 {
                self.vp.ren_val = self.vp.sel_names().into_iter().next().unwrap_or_default();
                self.vp.renaming = true;
            }
        } else if enter {
            let names = self.vp.sel_names();
            if !names.is_empty() {
                if let Some(d) = rfd::FileDialog::new().pick_folder() {
                    let dir = d.display().to_string();
                    self.start_vault(VaultTask::ExportSel(names, dir), "导出选中");
                }
            }
        }
    }

    fn ui_vault(&mut self, ctx: &egui::Context) {
        self.vault_shortcuts(ctx);
        self.ui_vault_bar(ctx);
        self.ui_vault_statusbar(ctx);
        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(pal().bg)
                    .inner_margin(egui::Margin::same(SP_L)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .id_source("vault_scroll")
                    // 正文超出可视区时整页滚动；底部错误卡 / 日志不再被裁掉。
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if self.vp.session.is_none() {
                            self.ui_vault_intro(ui);
                            return;
                        }
                        let busy = self.vp.busy;
                        let legacy_unconfirmed = self
                            .vp
                            .session
                            .as_ref()
                            .is_some_and(|s| s.is_legacy_v1() && !self.vp.legacy_upgrade_ack);
                        let can_mutate = !busy && !legacy_unconfirmed;

                        if legacy_unconfirmed {
                            egui::Frame::default()
                                .fill(pal().card)
                                .stroke(egui::Stroke::new(1.0_f32, pal().busy_amber))
                                .rounding(R_SM)
                                .inner_margin(egui::Margin::symmetric(PAD_X, PAD_Y))
                                .show(ui, |ui| {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.label(
                                            egui::RichText::new("此保险箱为旧 VGS1 格式；第一次保存会升级为 VGS2，旧格式仍可由新版打开。")
                                                .size(FS_NOTE)
                                                .color(pal().busy_amber),
                                        );
                                        if ui.add(b_ghost("确认后允许升级保存")).clicked() {
                                            self.vp.legacy_upgrade_ack = true;
                                        }
                                    });
                                });
                            ui.add_space(SP_S);
                        }

                        // 列表交互动作（P1）：在渲染闭包外统一应用，避免与 session 的不可变借用冲突。
                        let mut pending: Option<ListAction> = None;

                        // 忙时整页禁用（P0-2：状态决定可见操作），只在底部状态栏保留进度。
                        let _ = ui.add_enabled_ui(!busy, |ui| {
                            // ── 工具行：4 个主操作 + 「更多 ▾」（P0-1 操作分层）──
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = SP_S;
                                ui.add_enabled_ui(can_mutate, |ui| {
                                    ui.menu_button(
                                        egui::RichText::new("添加 ▾").size(FS_SUB).color(pal().text),
                                        |ui| {
                                            if ui.button("添加文件…").clicked() {
                                                ui.close_menu();
                                                if let Some(files) = rfd::FileDialog::new().pick_files() {
                                                    let organize = self.vp.organize;
                                                    self.start_vault(
                                                        VaultTask::Add(files, organize),
                                                        "添加条目",
                                                    );
                                                }
                                            }
                                            if ui.button("添加文件夹…").clicked() {
                                                ui.close_menu();
                                                if let Some(d) = rfd::FileDialog::new().pick_folder() {
                                                    let organize = self.vp.organize;
                                                    self.start_vault(
                                                        VaultTask::Add(vec![d], organize),
                                                        "添加条目",
                                                    );
                                                }
                                            }
                                            ui.separator();
                                            ui.checkbox(&mut self.vp.organize, "按类型归档到子目录");
                                        },
                                    );
                                });
                                ui.add_enabled_ui(!busy, |ui| {
                                    ui.menu_button(
                                        egui::RichText::new("导出 ▾").size(FS_SUB).color(pal().text),
                                        |ui| {
                                            if ui.button("导出全部…").clicked() {
                                                ui.close_menu();
                                                if let Some(d) = rfd::FileDialog::new().pick_folder() {
                                                    self.start_vault(
                                                        VaultTask::ExportAll(d.display().to_string()),
                                                        "导出全部",
                                                    );
                                                }
                                            }
                                            let n = self.vp.sel.len();
                                            if ui
                                                .add_enabled(
                                                    n > 0,
                                                    egui::Button::new(format!("导出选中（{}）…", n)),
                                                )
                                                .clicked()
                                            {
                                                ui.close_menu();
                                                if let Some(d) = rfd::FileDialog::new().pick_folder() {
                                                    let names = self.vp.sel_names();
                                                    self.start_vault(
                                                        VaultTask::ExportSel(
                                                            names,
                                                            d.display().to_string(),
                                                        ),
                                                        "导出选中",
                                                    );
                                                }
                                            }
                                        },
                                    );
                                });
                                let n = self.vp.sel.len();
                                if ui
                                    .add_enabled(can_mutate && n > 0, b_ghost(&format!("移除（{}）", n)))
                                    .on_hover_text("从保险箱中移除选中条目（会先确认）")
                                    .clicked()
                                {
                                    self.vp.confirm_compact = false;
                                    self.vp.confirm_remove = true;
                                }
                                if ui
                                    .add_enabled(can_mutate, b_ghost("压缩"))
                                    .on_hover_text("重写容器以回收已删除条目占用的空间（会先确认）")
                                    .clicked()
                                {
                                    self.vp.confirm_remove = false;
                                    self.vp.confirm_compact = true;
                                }
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    ui.menu_button(
                                        egui::RichText::new("更多 ▾").size(FS_SUB).color(pal().text_sub),
                                        |ui| {
                                            let one = self.vp.sel.len() == 1;
                                            if ui
                                                .add_enabled(can_mutate && one, egui::Button::new("重命名…"))
                                                .clicked()
                                            {
                                                ui.close_menu();
                                                self.vp.ren_val =
                                                    self.vp.sel_names().into_iter().next().unwrap_or_default();
                                                self.vp.renaming = true;
                                            }
                                            if ui
                                                .add_enabled(can_mutate && one, egui::Button::new("移动到…"))
                                                .clicked()
                                            {
                                                ui.close_menu();
                                                self.vp.mv_val.clear();
                                                self.vp.moving = true;
                                            }
                                            ui.separator();
                                            if ui
                                                .add_enabled(can_mutate, egui::Button::new("更换口令…"))
                                                .clicked()
                                            {
                                                ui.close_menu();
                                                self.vp.pass.clear();
                                                self.vp.pass2.clear();
                                                self.vp.changing = true;
                                            }
                                            ui.separator();
                                            if ui
                                                .add_enabled(!busy, egui::Button::new("关闭保险箱"))
                                                .clicked()
                                            {
                                                ui.close_menu();
                                                self.vp.session = None;
                                                self.vp.sel.clear();
                                                self.vp.anchor = None;
                                                self.log("保险箱已关闭，临时数据已擦除。");
                                            }
                                        },
                                    );
                                });
                            });
                            ui.add_space(SP_S);

                            // ── 就地二次确认（P0-4：不用弹窗，不离开当前版面）──
                            if self.vp.confirm_remove {
                                let n = self.vp.sel.len();
                                egui::Frame::default()
                                    .fill(pal().card)
                                    .stroke(egui::Stroke::new(1.0_f32, pal().danger))
                                    .rounding(R_SM)
                                    .inner_margin(egui::Margin::symmetric(PAD_X, PAD_Y))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.spacing_mut().item_spacing.x = SP_S;
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "确认从保险箱移除 {} 个条目？移除后可用「压缩」回收空间。",
                                                    n
                                                ))
                                                .size(FS_NOTE)
                                                .color(pal().danger),
                                            );
                                            if ui
                                                .add_enabled(can_mutate && n > 0, b_primary("确认移除"))
                                                .clicked()
                                            {
                                                let names = self.vp.sel_names();
                                                self.vp.confirm_remove = false;
                                                self.vp.sel.clear();
                                                self.vp.anchor = None;
                                                self.start_vault(VaultTask::Remove(names), "移除条目");
                                            }
                                            if ui.add(b_ghost("取消").min_size(egui::vec2(0.0, H_BTN_SEC))).clicked() {
                                                self.vp.confirm_remove = false;
                                            }
                                        });
                                    });
                                ui.add_space(SP_S);
                            }
                            if self.vp.confirm_compact {
                                let disk = std::fs::metadata(self.vp.path.trim())
                                    .map(|m| m.len())
                                    .unwrap_or(0);
                                egui::Frame::default()
                                    .fill(pal().card)
                                    .stroke(egui::Stroke::new(1.0_f32, pal().busy_amber))
                                    .rounding(R_SM)
                                    .inner_margin(egui::Margin::symmetric(PAD_X, PAD_Y))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.spacing_mut().item_spacing.x = SP_S;
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "压缩会重写整个容器（当前 {}）以回收空间，期间请勿断电或关闭程序。",
                                                    paths::sz(disk)
                                                ))
                                                .size(FS_NOTE)
                                                .color(pal().busy_amber),
                                            );
                                            if ui.add_enabled(can_mutate, b_primary("开始压缩")).clicked() {
                                                self.vp.confirm_compact = false;
                                                self.start_vault(VaultTask::Compact, "压缩容器（重写中）");
                                            }
                                            if ui.add(b_ghost("取消").min_size(egui::vec2(0.0, H_BTN_SEC))).clicked() {
                                                self.vp.confirm_compact = false;
                                            }
                                        });
                                    });
                                ui.add_space(SP_S);
                            }

                            // ── 过滤 / 视图 / 排序（P1-1/2/4）──
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = SP_S;
                                let f = ui.add(
                                    egui::TextEdit::singleline(&mut self.vp.filter)
                                        .desired_width(W_FILTER)
                                        .hint_text("按名字过滤（Ctrl+F）"),
                                );
                                if self.vp.focus_filter {
                                    f.request_focus();
                                    self.vp.focus_filter = false;
                                }
                                if !self.vp.filter.is_empty() && ui.add(b_ghost("清除")).clicked() {
                                    self.vp.filter.clear();
                                }
                                ui.separator();
                                ui.checkbox(&mut self.vp.tree, "目录树");
                                ui.separator();
                                egui::ComboBox::from_id_source("vault_sort")
                                    .selected_text(match self.vp.sort {
                                        SortKey::Name => "按名字",
                                        SortKey::Size => "按大小",
                                        SortKey::Kind => "按类型",
                                    })
                                    .show_ui(ui, |ui| {
                                        ui.selectable_value(&mut self.vp.sort, SortKey::Name, "按名字");
                                        ui.selectable_value(&mut self.vp.sort, SortKey::Size, "按大小");
                                        ui.selectable_value(&mut self.vp.sort, SortKey::Kind, "按类型");
                                    });
                                if ui
                                    .add(b_ghost(if self.vp.sort_desc { "降序 ↓" } else { "升序 ↑" }))
                                    .clicked()
                                {
                                    self.vp.sort_desc = !self.vp.sort_desc;
                                }
                            });
                            ui.add_space(SP_XS);

                            let visible = self.vp.visible_indices();
                            let total = self
                                .vp
                                .session
                                .as_ref()
                                .map(|s| s.entries.len())
                                .unwrap_or(0);
                            egui::Frame::default()
                                .fill(pal().card)
                                .stroke(egui::Stroke::new(1.0_f32, pal().border))
                                .rounding(R_MD)
                                .inner_margin(egui::Margin::symmetric(PAD_X, PAD_Y))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.add_space(SP_XS);
                                        ui.label(
                                            egui::RichText::new(if visible.len() == total {
                                                format!("保险箱内容（{} 个条目）", total)
                                            } else {
                                                format!(
                                                    "保险箱内容（{} / {} 个条目）",
                                                    visible.len(),
                                                    total
                                                )
                                            })
                                            .size(FS_SUB)
                                            .color(pal().text_muted),
                                        );
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                ui.label(
                                                    egui::RichText::new(format!(
                                                        "已选 {}",
                                                        self.vp.sel.len()
                                                    ))
                                                    .size(FS_NOTE)
                                                    .color(pal().text_faint),
                                                );
                                                if ui.add(b_ghost("清空选择")).clicked() {
                                                    self.vp.sel.clear();
                                                    self.vp.anchor = None;
                                                }
                                                if ui.add(b_ghost("反选")).clicked() {
                                                    for &i in &visible {
                                                        if !self.vp.sel.remove(&i) {
                                                            self.vp.sel.insert(i);
                                                        }
                                                    }
                                                }
                                                if ui.add(b_ghost("全选")).clicked() {
                                                    for &i in &visible {
                                                        self.vp.sel.insert(i);
                                                    }
                                                }
                                            },
                                        );
                                    });
                                    ui.add_space(SP_XS);
                                    let Some(sess) = self.vp.session.as_ref() else {
                                        return;
                                    };
                                    let entries: &[safe::Entry] = &sess.entries;
                                    if entries.is_empty() {
                                        empty_state(
                                            ui,
                                            "保险箱是空的：点上方「添加 ▾」放入文件或文件夹",
                                            None,
                                        );
                                        return;
                                    }
                                    if visible.is_empty() {
                                        empty_state(
                                            ui,
                                            "没有匹配的条目：清空过滤条件可看全部",
                                            None,
                                        );
                                        return;
                                    }
                                    let tree = self.vp.tree.then(|| build_tree(entries, &visible));
                                    let sel = &mut self.vp.sel;
                                    let anchor = &mut self.vp.anchor;
                                    egui::ScrollArea::vertical()
                                        .id_source("safe_items")
                                        .max_height(ui.available_height().clamp(TABLE_H_MIN, TABLE_H_MAX))
                                        .show(ui, |ui| {
                                            let mut cx = RowCtx {
                                                sel,
                                                anchor,
                                                visible: &visible,
                                                pending: &mut pending,
                                            };
                                            match &tree {
                                                Some(t) => draw_tree(ui, &mut cx, entries, t, "", 0),
                                                None => {
                                                    for &idx in &visible {
                                                        draw_row(ui, &mut cx, entries, idx, 0.0);
                                                    }
                                                }
                                            }
                                        });
                                });
                        });

                        // 列表交互动作的落地：导出（双击 / 右键）/ 重命名 / 移动 / 移除确认。
                        if let Some(act) = pending.take() {
                            match act {
                                ListAction::ExportOne(name) => {
                                    if let Some(d) = rfd::FileDialog::new().pick_folder() {
                                        self.start_vault(
                                            VaultTask::ExportSel(vec![name], d.display().to_string()),
                                            "导出条目",
                                        );
                                    }
                                }
                                ListAction::RenameOne(name) => {
                                    self.vp.ren_val = name;
                                    self.vp.renaming = true;
                                }
                                ListAction::MoveOne => {
                                    self.vp.mv_val.clear();
                                    self.vp.moving = true;
                                }
                                ListAction::AskRemove => {
                                    self.vp.confirm_compact = false;
                                    self.vp.confirm_remove = true;
                                }
                            }
                        }

                        ui.add_space(SP_L);
                        error_card(ui, &mut self.last_error);
                        log_panel(ui, false, None, &self.logs, None);
                    });
            });
        self.ui_vault_editors(ctx);
    }
}

/// 排序键（P1-4 排序切换）。
#[derive(Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Name,
    Size,
    Kind,
}

/// 类型分组键：目录最前（0），其余按扩展名分组（1, ext）。
fn kind_key(e: &safe::Entry) -> (u8, &str) {
    if e.is_dir {
        (0, "")
    } else {
        (
            1,
            match e.name.rsplit_once('.') {
                Some((_, ext)) => ext,
                None => "",
            },
        )
    }
}

/// 列表交互动作：在渲染闭包之外统一应用，避免与 session 的不可变借用冲突（P1-5/7）。
enum ListAction {
    ExportOne(String),
    RenameOne(String),
    MoveOne,
    AskRemove,
}

/// 行渲染的共享可变状态（P1-3：Shift 连选 / Ctrl 追加 / 全选反选）。
struct RowCtx<'a> {
    sel: &'a mut HashSet<usize>,
    anchor: &'a mut Option<usize>,
    visible: &'a [usize],
    pending: &'a mut Option<ListAction>,
}

/// 单行：整行可点（单击选中、Ctrl 追加、Shift 连选）、双击导出该项、右键出菜单。
/// 自绘而不用 SelectableLabel，是为了让整行成为同一个交互目标（含右键与双击）。
fn draw_row(
    ui: &mut egui::Ui,
    cx: &mut RowCtx<'_>,
    entries: &[safe::Entry],
    idx: usize,
    indent: f32,
) {
    let e = &entries[idx];
    let (rect, resp) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), ROW_H),
        egui::Sense::click(),
    );
    let selected = cx.sel.contains(&idx);
    if selected {
        ui.painter().rect_filled(rect, R_CHIP, pal().accent_dim);
    } else if resp.hovered() {
        ui.painter().rect_filled(rect, R_CHIP, pal().card_hover);
    }
    let dot_x = rect.left() + ROW_PAD_L + indent;
    let dot = egui::Rect::from_center_size(
        egui::pos2(dot_x + DOT_S / 2.0, rect.center().y),
        egui::vec2(DOT_S, DOT_S),
    );
    ui.painter()
        .rect_filled(dot, R_XS, if e.is_dir { pal().dir_sky } else { pal().text_muted });

    let name_left = dot_x + ROW_DOT_GAP;
    let size_right = rect.right() - ROW_PAD_R;
    ui.painter()
        .with_clip_rect(egui::Rect::from_min_max(
            egui::pos2(name_left, rect.top()),
            egui::pos2((size_right - ROW_SIZE_W).max(name_left + ROW_NAME_MIN), rect.bottom()),
        ))
        .text(
            egui::pos2(name_left, rect.center().y),
            egui::Align2::LEFT_CENTER,
            &e.name,
            egui::FontId::monospace(FS_NOTE),
            if e.is_dir { pal().text_sub } else { pal().text },
        );
    ui.painter().text(
        egui::pos2(size_right, rect.center().y),
        egui::Align2::RIGHT_CENTER,
        if e.is_dir {
            "-".to_string()
        } else {
            paths::sz(e.size)
        },
        egui::FontId::monospace(FS_NOTE),
        pal().text_faint,
    );

    if resp.clicked() {
        let (cmd, shift) = ui.input(|i| (i.modifiers.command, i.modifiers.shift));
        if shift {
            let a = cx.anchor.and_then(|x| cx.visible.iter().position(|&v| v == x));
            let b = cx.visible.iter().position(|&v| v == idx);
            if let (Some(a), Some(b)) = (a, b) {
                let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                for k in lo..=hi {
                    if let Some(&v) = cx.visible.get(k) {
                        cx.sel.insert(v);
                    }
                }
            } else {
                cx.sel.insert(idx);
            }
            *cx.anchor = Some(idx);
        } else if cmd {
            if !cx.sel.remove(&idx) {
                cx.sel.insert(idx);
            }
            *cx.anchor = Some(idx);
        } else {
            cx.sel.clear();
            cx.sel.insert(idx);
            *cx.anchor = Some(idx);
        }
    }
    if resp.double_clicked() {
        *cx.pending = Some(ListAction::ExportOne(e.name.clone()));
    }
    resp.context_menu(|ui| {
        ui.set_min_width(W_MENU_MIN);
        if ui.button("导出该项…").clicked() {
            *cx.pending = Some(ListAction::ExportOne(e.name.clone()));
            ui.close_menu();
        }
        if ui.button("重命名…").clicked() {
            cx.sel.clear();
            cx.sel.insert(idx);
            *cx.anchor = Some(idx);
            *cx.pending = Some(ListAction::RenameOne(e.name.clone()));
            ui.close_menu();
        }
        if ui.button("移动到…").clicked() {
            cx.sel.clear();
            cx.sel.insert(idx);
            *cx.pending = Some(ListAction::MoveOne);
            ui.close_menu();
        }
        ui.separator();
        if ui.button("移除该项").clicked() {
            cx.sel.clear();
            cx.sel.insert(idx);
            *cx.pending = Some(ListAction::AskRemove);
            ui.close_menu();
        }
        if ui.button("复制内部路径").clicked() {
            ui.output_mut(|o| o.copied_text = e.name.clone());
            ui.close_menu();
        }
    });
}

/// 目录树节点（P1-2 按 `/` 分层）。
#[derive(Default)]
struct DirNode {
    own: Vec<usize>,
    files: Vec<usize>,
    children: std::collections::BTreeMap<String, DirNode>,
}

impl DirNode {
    fn count(&self) -> usize {
        self.own.len() + self.files.len() + self.children.values().map(|c| c.count()).sum::<usize>()
    }
}

/// 由「可见条目下标」构建目录树（不建持久索引，每次从名字现算）。
fn build_tree(entries: &[safe::Entry], visible: &[usize]) -> DirNode {
    let mut root = DirNode::default();
    for &i in visible {
        let e = &entries[i];
        let parts: Vec<&str> = e.name.split('/').filter(|x| !x.is_empty()).collect();
        if parts.is_empty() {
            continue;
        }
        let mut node = &mut root;
        for seg in &parts[..parts.len() - 1] {
            node = node.children.entry((*seg).to_string()).or_default();
        }
        let last = parts[parts.len() - 1];
        if e.is_dir {
            let child = node.children.entry(last.to_string()).or_default();
            child.own.push(i);
        } else {
            node.files.push(i);
        }
    }
    root
}

/// 递归渲染目录树（id 用完整内部路径，避免同名子目录的折叠状态互相串台）。
fn draw_tree(
    ui: &mut egui::Ui,
    cx: &mut RowCtx<'_>,
    entries: &[safe::Entry],
    node: &DirNode,
    prefix: &str,
    depth: usize,
) {
    let indent = 8.0 + (depth as f32 + 1.0) * 12.0;
    for (seg, child) in &node.children {
        let path = if prefix.is_empty() {
            seg.clone()
        } else {
            format!("{}/{}", prefix, seg)
        };
        egui::CollapsingHeader::new(
            egui::RichText::new(format!("{}（{}）", seg, child.count()))
                .size(FS_SUB)
                .color(pal().text_sub),
        )
        .id_source(format!("tree:{}", path))
        .default_open(true)
        .show(ui, |ui| {
            for &i in &child.own {
                draw_row(ui, cx, entries, i, indent + 12.0);
            }
            for &i in &child.files {
                draw_row(ui, cx, entries, i, indent + 12.0);
            }
            draw_tree(ui, cx, entries, child, &path, depth + 1);
        });
    }
    for &i in &node.files {
        draw_row(ui, cx, entries, i, indent);
    }
}


/// 区块小标题。改造前是「比正文小 2px 且和说明文字同色」——读者分不出这是标题。
/// 现在提亮一档（text_sub）、比正文只小 1px，区块分界清晰但不喧哗。
fn section_title(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).size(FS_SUB).strong().color(pal().text_sub));
    ui.add_space(SP_S);
}

/// 空状态：主文案 +（可选）副文案。加密页与保险箱页原先各写一套，上下留白与
/// 字号都不一致；统一成同一呈现，同类场景不再有三种长相。
fn empty_state(ui: &mut egui::Ui, main: &str, sub: Option<&str>) {
    ui.vertical_centered(|ui| {
        ui.add_space(SP_XL);
        ui.label(egui::RichText::new(main).size(FS_BODY).color(pal().text_sub));
        if let Some(s) = sub {
            ui.add_space(SP_XS);
            ui.label(egui::RichText::new(s).size(FS_NOTE).color(pal().text_faint));
        }
        ui.add_space(SP_XL);
    });
}

/// 口令强度评估：返回 (强度级 0弱/1中/2强, 说明)。
fn pass_strength(pass: &str) -> (u8, &'static str) {
    const COMMON: [&str; 10] = [
        "123456",
        "12345678",
        "password",
        "qwerty",
        "111111",
        "123456789",
        "abc123",
        "000000",
        "admin",
        "letmein",
    ];
    let len = pass.chars().count();
    let mut classes = 0usize;
    if pass.chars().any(|c| c.is_ascii_lowercase()) {
        classes += 1;
    }
    if pass.chars().any(|c| c.is_ascii_uppercase()) {
        classes += 1;
    }
    if pass.chars().any(|c| c.is_ascii_digit()) {
        classes += 1;
    }
    if pass.chars().any(|c| !c.is_ascii_alphanumeric()) {
        classes += 1;
    }
    if COMMON.contains(&pass.to_lowercase().as_str()) || len < 6 {
        (0, "口令偏弱：过于常见或太短，极易被猜出")
    } else if len >= 12 && classes >= 3 {
        (2, "口令强度高")
    } else if len >= 8 && classes >= 2 {
        (1, "口令强度中等，建议再加长度或字符种类")
    } else {
        (0, "口令偏弱：建议 12 位以上并混用大小写/数字/符号")
    }
}

/// 伪装外壳卡片：名称 + 右侧 mono 徽标，第二行描述；选中态 emerald 描边。
fn shell_card(
    ui: &mut egui::Ui,
    id: &str,
    active: bool,
    name: &str,
    badge: &str,
    desc: &str,
) -> bool {
    let mut content_rect = egui::Rect::NOTHING;
    egui::Frame::default()
        .fill(if active { pal().accent_dim } else { pal().card })
        .stroke(egui::Stroke::new(
            1.0_f32,
            if active { pal().accent } else { pal().border },
        ))
        .rounding(R_SM)
        // 外壳卡片刻意收窄：内边距与两行间距都取最小档，卡片更轻、更不占左栏
        .inner_margin(egui::Margin::symmetric(SP_S + SP_XS, SP_S))
        .show(ui, |inner| {
            inner.spacing_mut().item_spacing.y = SP_XS;
            inner.horizontal(|h| {
                h.label(
                    egui::RichText::new(name)
                        .size(FS_SUB)
                        .strong()
                        .color(if active { pal().accent_text } else { pal().text }),
                );
                h.with_layout(egui::Layout::right_to_left(egui::Align::Center), |r| {
                    r.label(egui::RichText::new(badge).monospace().size(FS_NOTE).color(pal().text_faint));
                });
            });
            inner.label(egui::RichText::new(desc).size(FS_NOTE).color(pal().text_muted));
            content_rect = inner.min_rect();
        });
    let resp = ui.interact(content_rect, egui::Id::new(id), egui::Sense::click());
    if resp.hovered() && !active {
        ui.painter()
            .rect_filled(content_rect, R_SM, pal().hover_tint);
    }
    resp.clicked()
}

/// 文件行：类型圆点 + 名称（mono，可点选）+ VaultGuard 徽标 + 大小 + 移除按钮。
fn item_row(
    ui: &mut egui::Ui,
    i: usize,
    p: &std::path::Path,
    is_vault: bool,
    sel: &mut HashSet<usize>,
) -> RowAction {
    let is_dir = p.is_dir();
    let selected = sel.contains(&i);
    let mut action = RowAction::None;
    ui.horizontal(|ui| {
        ui.add_space(SP_XS);
        let (rect, _) = ui.allocate_exact_size(egui::vec2(DOT_S, DOT_S), egui::Sense::hover());
        ui.painter()
            .rect_filled(rect, R_XS, if is_dir { pal().dir_sky } else { pal().text_muted });
        let name_w = (ui.available_width() - ROW_META_W).max(W_NAME_MIN);
        let name_text = egui::RichText::new(p.display().to_string())
            .monospace()
            .size(FS_SUB)
            .color(if is_dir { pal().text_sub } else { pal().text });
        let resp = ui.add_sized(
            [name_w, ROW_H],
            egui::SelectableLabel::new(selected, name_text),
        );
        if resp.clicked() {
            if selected {
                sel.remove(&i);
            } else {
                sel.insert(i);
            }
        }
        if is_vault {
            egui::Frame::default()
                .fill(pal().accent_dim)
                .stroke(egui::Stroke::new(1.0_f32, pal().accent))
                .rounding(R_CHIP)
                .inner_margin(egui::Margin::symmetric(CHIP_PAD_X, CHIP_PAD_Y))
                .show(ui, |chip| {
                    chip.label(
                        egui::RichText::new("VaultGuard")
                            .monospace()
                            .size(FS_NOTE)
                            .color(pal().accent_text),
                    );
                });
        } else {
            ui.add_space(ROW_BADGE_W);
        }
        let size = if is_dir {
            "-".to_string()
        } else {
            paths::sz(p.metadata().map(|m| m.len()).unwrap_or(0))
        };
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |r| {
            // 原先显式 fill(TRANSPARENT) + stroke(NONE)：Button 渲染取
            // fill.unwrap_or(visuals.weak_bg_fill)，一旦显式给值就不再随交互态变化，
            // hover 与按下都没有任何视觉反馈——按钮可点却看不出可点。
            // 改为局部把静止态设为透明，hover / 按下仍走主题默认视觉。
            let clicked = r
                .scope(|ui| {
                    let w = &mut ui.style_mut().visuals.widgets;
                    w.inactive.weak_bg_fill = Color32::TRANSPARENT;
                    w.inactive.bg_stroke = egui::Stroke::NONE;
                    ui.add(
                        egui::Button::new(
                            egui::RichText::new("×").size(FS_SUB).color(pal().text_muted),
                        )
                        .small(),
                    )
                })
                .inner
                .on_hover_text("移除")
                .clicked();
            if clicked {
                action = RowAction::Remove;
            }
            r.label(egui::RichText::new(size).monospace().size(FS_NOTE).color(pal().text_faint));
        });
    });
    action
}

enum RowAction {
    None,
    Remove,
}

/// 日志面板（P0-5 / 统一）：空闲时折叠成一行，运行中自动展开。
/// 加密页与保险箱页原先各写一套（常驻卡片 vs 折叠面板），现在共用同一个呈现：
/// 进度与「取消」随面板一起出现、忙时锁开，折叠不会丢掉运行中的可见反馈。
fn log_panel(
    ui: &mut egui::Ui,
    busy: bool,
    progress: Option<u8>,
    logs: &[String],
    cancel: Option<&Cancel>,
) {
    let title = match (busy, progress) {
        (true, Some(p)) => format!("处理中… {}%（{} 行日志）", p, logs.len()),
        (true, None) => format!("处理中…（{} 行日志）", logs.len()),
        _ => format!("日志（{} 行）", logs.len()),
    };
    egui::CollapsingHeader::new(
        egui::RichText::new(title)
            .size(FS_SUB)
            .color(if busy { pal().busy_amber } else { pal().text_muted }),
    )
    .id_source("logs_panel")
    .default_open(false)
    // 运行中锁开：进度与「取消」必须一眼可见；空闲时把开合权交回用户。
    .open(busy.then_some(true))
    .show(ui, |ui| {
        egui::Frame::default()
            .fill(pal().card)
            .stroke(egui::Stroke::new(1.0_f32, pal().border))
            .rounding(R_MD)
            .inner_margin(egui::Margin::symmetric(PAD_X, PAD_Y))
            .show(ui, |ui| {
                if busy || progress.is_some() {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = SP_S;
                        if busy {
                            ui.add(egui::Spinner::new().size(ICON_S));
                            ui.label(
                                egui::RichText::new("后台处理中…")
                                    .size(FS_NOTE)
                                    .color(pal().busy_amber),
                            );
                        }
                        if let Some(p) = progress {
                            ui.add(
                                egui::ProgressBar::new(p as f32 / 100.0)
                                    .fill(pal().accent)
                                    .desired_height(H_PROGRESS)
                                    .show_percentage(),
                            );
                        }
                        if let Some(c) = cancel {
                            cancel_button(ui, c);
                        }
                    });
                    ui.add_space(SP_XS);
                }
                egui::ScrollArea::vertical()
                    .id_source("logs_scroll")
                    .stick_to_bottom(true)
                    .max_height(LOG_H)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for l in logs {
                            ui.label(
                                egui::RichText::new(l)
                                    .monospace()
                                    .size(FS_SUB)
                                    .color(log_color(l)),
                            );
                        }
                    });
            });
    });
}

/// 错误卡片（P2）：最近一次失败独立成卡片，含「复制详情 / 知道了」。
/// 失败不再只写进日志——用户不必翻日志才能看懂发生了什么。
fn error_card(ui: &mut egui::Ui, err: &mut Option<String>) {
    let Some(msg) = err.clone() else {
        return;
    };
    egui::Frame::default()
        .fill(pal().card)
        .stroke(egui::Stroke::new(1.0_f32, pal().danger))
        .rounding(R_MD)
        .inner_margin(egui::Margin::symmetric(PAD_X, PAD_Y))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = SP_S;
                ui.label(
                    egui::RichText::new("上一步失败")
                        .size(FS_SUB)
                        .strong()
                        .color(pal().danger),
                );
                ui.label(egui::RichText::new(msg.clone()).size(FS_NOTE).color(pal().text));
            });
            ui.add_space(SP_XS);
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = SP_S;
                if ui.add(b_ghost("复制详情")).clicked() {
                    ui.output_mut(|o| o.copied_text = msg.clone());
                }
                if ui.add(b_ghost("知道了")).clicked() {
                    *err = None;
                }
            });
        });
    ui.add_space(SP_S);
}

fn log_color(line: &str) -> Color32 {
    if line.starts_with(">>>") {
        pal().accent_text
    } else if line.contains("失败") || line.contains("未处理") || line.contains("错误") {
        pal().danger
    } else if line.contains("完成") || line.contains("成功") || line.contains("就绪") {
        pal().accent
    } else {
        pal().log_default
    }
}

fn b_primary(text: &str) -> egui::Button<'static> {
    egui::Button::new(
        egui::RichText::new(text)
            .size(FS_SUB)
            .strong()
            .color(pal().on_accent),
    )
    .fill(pal().accent)
    .stroke(egui::Stroke::NONE)
    .rounding(R_SM)
    .min_size(egui::vec2(0.0, H_BTN_SEC))
}

fn b_secondary(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text).size(FS_SUB).color(pal().text))
        .fill(pal().card_hover)
        .stroke(egui::Stroke::new(1.0_f32, pal().border))
        .rounding(R_SM)
        .min_size(egui::vec2(0.0, H_BTN_SEC))
}

fn b_ghost(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text).size(FS_SUB).color(pal().text))
        .fill(Color32::TRANSPARENT)
        .stroke(egui::Stroke::new(1.0_f32, pal().border))
        .rounding(R_SM)
        .min_size(egui::vec2(0.0, H_BTN))
}

/// 状态条内的紧凑「取消」按钮：已请求取消时退化为文字提示。
/// 点击只是置位令牌，长任务在下一个检查点停下，容器与已有产物保持原状。
fn cancel_button(ui: &mut egui::Ui, c: &Cancel) {
    if c.is_cancelled() {
        ui.label(egui::RichText::new("正在取消…").size(FS_NOTE).color(pal().danger));
        return;
    }
    let btn = egui::Button::new(egui::RichText::new("取消").size(FS_SUB).color(pal().text))
        .fill(Color32::TRANSPARENT)
        .stroke(egui::Stroke::new(1.0_f32, pal().border))
        .rounding(R_SM)
        .min_size(egui::vec2(W_BTN_CANCEL, H_BTN_SM));
    if ui
        .add(btn)
        .on_hover_text("在当前检查点停下；容器与已有产物保持原状")
        .clicked()
    {
        c.cancel();
    }
}

fn primary_button(text: impl Into<String>) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text).size(FS_BODY).strong().color(pal().on_accent))
        .fill(pal().accent)
        .stroke(egui::Stroke::NONE)
        .rounding(R_SM)
        .min_size(egui::vec2(0.0, H_BTN_MAIN))
}

fn secondary_button(text: impl Into<String>) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text).size(FS_BODY).color(pal().text))
        .fill(pal().card_hover)
        .stroke(egui::Stroke::new(1.0_f32, pal().border))
        .rounding(R_SM)
        .min_size(egui::vec2(0.0, H_BTN_SEC))
}

/// 顶栏页签：选中态用实心强调色 + 白字（默认 selectable_label 的选中态是
/// 近透明底 + 深绿字，深色主题下几乎读不出来）。
fn tab_button(ui: &mut egui::Ui, text: &str, selected: bool) -> bool {
    let p = pal();
    let (fg, bg, stroke) = if selected {
        (p.on_accent, p.accent, egui::Stroke::NONE)
    } else {
        (p.text_sub, Color32::TRANSPARENT, egui::Stroke::new(1.0_f32, p.border))
    };
    ui.add(
        egui::Button::new(egui::RichText::new(text).size(FS_BODY).color(fg))
            .fill(bg)
            .stroke(stroke)
            .rounding(R_SM)
            .min_size(egui::vec2(0.0, H_BTN)),
    )
    .clicked()
}

fn ghost_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text).size(FS_SUB).color(pal().text))
        .fill(Color32::TRANSPARENT)
        .stroke(egui::Stroke::new(1.0_f32, pal().border))
        .rounding(R_SM)
        .min_size(egui::vec2(0.0, H_BTN))
}

/// 次级操作按钮：比 ghost 再矮一档、字号小一档、字色更淡，
/// 保留描边（hover 时仍有边框可辨认），只降权不隐藏。
fn ghost_button_mini(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text).size(FS_NOTE).color(pal().text_sub))
        .fill(Color32::TRANSPARENT)
        .stroke(egui::Stroke::new(1.0_f32, pal().border))
        .rounding(R_SM)
        .min_size(egui::vec2(0.0, H_BTN_SM))
}

/// 保险箱后台任务执行器（在 worker 线程中运行）。会话经由通道传回。
fn vault_worker(
    mut sess: Option<safe::Session>,
    task: VaultTask,
    tx: Sender<VMsg>,
) {
    let line = |s: String| {
        let _ = tx.send(VMsg::Line(s));
    };
    let prog = |d: u64, t: u64| {
        let pct = if t == 0 {
            0
        } else {
            ((d.min(t) * 100 / t).min(99)) as u8
        };
        let _ = tx.send(VMsg::Pct(pct));
    };
    let save_prog = |pct: u8| {
        let _ = tx.send(VMsg::Pct(pct));
    };
    let res: Result<String, String> = match task {
        VaultTask::Create(path, pass) => match safe::create(Path::new(&path), &pass) {
            Ok(s) => {
                let n = s.entries.len();
                sess = Some(s);
                Ok(format!("保险箱已创建：{}（{} 个条目）", path, n))
            }
            Err(e) => Err(e.to_string()),
        },
        VaultTask::Open(path, pass) => match safe::open(Path::new(&path), &pass) {
            Ok(s) => {
                let n = s.entries.len();
                let legacy = s.is_legacy_v1();
                sess = Some(s);
                Ok(if legacy {
                    format!("保险箱已打开：{}（{} 个条目，旧 VGS1；确认后首次保存将升级 VGS2）", path, n)
                } else {
                    format!("保险箱已打开：{}（{} 个条目）", path, n)
                })
            }
            Err(e) => Err(e.to_string()),
        },
        VaultTask::Add(files, organize) => match sess.as_mut() {
            Some(s) => {
                let n = files.len();
                let add = if organize {
                    s.add_paths_organized(&files)
                } else {
                    s.add_paths(&files)
                };
                add.and_then(|added| {
                    line(format!("已添加 {} 项，正在保存…", added));
                    s.save(&save_prog)
                })
                .map(|_| {
                    if organize {
                        format!("已添加 {} 项并按类型归档保存", n)
                    } else {
                        format!("已添加 {} 项并保存", n)
                    }
                })
                .map_err(|e| e.to_string())
            }
            None => Err("保险箱未打开".into()),
        },
        VaultTask::Remove(names) => match sess.as_mut() {
            Some(s) => {
                let n = names.len();
                s.remove_entries(&names)
                    .and_then(|removed| {
                        line(format!("已移除 {} 项，正在保存…", removed));
                        s.save(&save_prog)
                    })
                    .map(|_| format!("已移除 {} 项并保存", n))
                    .map_err(|e| e.to_string())
            }
            None => Err("保险箱未打开".into()),
        },
        VaultTask::Rename(from, to) => match sess.as_mut() {
            Some(s) => s
                .rename_entry(&from, &to)
                .and_then(|_| {
                    line(format!("已重命名 {} -> {}，正在保存…", from, to));
                    s.save(&save_prog)
                })
                .map(|_| format!("已重命名 {} -> {}", from, to))
                .map_err(|e| e.to_string()),
            None => Err("保险箱未打开".into()),
        },
        VaultTask::MoveEntry(name, dir) => match sess.as_mut() {
            Some(s) => s
                .move_entry(&name, &dir)
                .and_then(|_| {
                    let dst = if dir.is_empty() {
                        "根目录".to_string()
                    } else {
                        dir.clone()
                    };
                    line(format!("已移动 {} -> {}，正在保存…", name, dst));
                    s.save(&save_prog)
                })
                .map(|_| {
                    let dst = if dir.is_empty() {
                        "根目录".to_string()
                    } else {
                        dir.clone()
                    };
                    format!("已移动 {} 到 {}", name, dst)
                })
                .map_err(|e| e.to_string()),
            None => Err("保险箱未打开".into()),
        },
        VaultTask::ExportAll(out) => match sess.as_ref() {
            Some(s) => s
                .export(Path::new(&out), &prog)
                .map(|(d, n)| format!("已导出 {} 个条目到 {}", n, d.display()))
                .map_err(|e| e.to_string()),
            None => Err("保险箱未打开".into()),
        },
        VaultTask::ExportSel(names, out) => match sess.as_ref() {
            Some(s) => s
                .export_selective(&names, Path::new(&out))
                .map(|n| format!("已导出 {} 个条目到 {}", n, out))
                .map_err(|e| e.to_string()),
            None => Err("保险箱未打开".into()),
        },
        VaultTask::Compact => match sess.as_mut() {
            Some(s) => s
                .compact(&save_prog)
                .map(|_| "保险箱已压缩，已回收历史数据段空间".to_string())
                .map_err(|e| e.to_string()),
            None => Err("保险箱未打开".into()),
        },
        VaultTask::ChangePass(new) => match sess.as_mut() {
            Some(s) => s
                .change_password(&new)
                .map(|_| {
                    paths::pass_tip_touch();
                    "口令已更换并重新加密保存".to_string()
                })
                .map_err(|e| e.to_string()),
            None => Err("保险箱未打开".into()),
        },
    };
    let _ = tx.send(VMsg::Done(res, sess.take()));
}

impl eframe::App for VaultApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain();
        self.drain_vault();

        // 活跃标记心跳：会话/预览存在时每 30s 刷新，防启动清扫误删长时间打开的临时数据
        if self.hb_last.elapsed().as_secs() >= 30 {
            self.hb_last = std::time::Instant::now();
            if let Some(s) = &self.vp.session {
                let _ = s.touch();
            }
            if let Some(p) = &self.dec_preview {
                let _ = p.touch();
            }
        }

        // 任务栏/标题栏状态标题：处理中时显示「处理中…」，空闲时恢复默认
        let want_busy_title = self.busy || self.vp.busy;
        if want_busy_title != self.title_busy {
            self.title_busy = want_busy_title;
            let title = if want_busy_title {
                "VaultGuard — 处理中…".to_string()
            } else {
                "VaultGuard — 网盘伪装加密保险箱".to_string()
            };
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(title));
        }

        // 统一探测 VaultGuard 文件（按钮计数与列表徽标共用一份结果）
        self.vault_flags = self
            .items
            .iter()
            .map(|p| p.is_file() && shells::probe_vault(p).is_some())
            .collect();
        self.vault_count = self.vault_flags.iter().filter(|&&v| v).count();

        // 窗口内拖放：天然支持，无需第三方库
        let dropped: Vec<_> = ctx.input(|i| i.raw.dropped_files.clone());
        let mut added = 0usize;
        for d in dropped {
            if let Some(p) = d.path {
                if p.exists() {
                    self.items.push(p);
                    added += 1;
                }
            }
        }
        if added > 0 {
            self.log(&format!("拖放添加 {} 项", added));
        }

        self.ui_header(ctx);
        match &self.page {
            Page::Disguise => {
                self.ui_left(ctx);
                self.ui_center(ctx);
            }
            Page::Vault => self.ui_vault(ctx),
        }
        // P2：忙时每帧重绘保证进度实时；空闲时降频，避免空转烧 CPU
        if self.busy || self.vp.busy {
            ctx.request_repaint();
        } else {
            ctx.request_repaint_after(std::time::Duration::from_millis(400));
        }
    }
}

/// GUI 主入口（无命令行参数时由 main 调用）
pub fn run() {
    // 标题栏/任务栏图标取自 exe 内嵌的图标资源（RT_GROUP_ICON id=1，见 build.rs）
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([WINDOW_W, WINDOW_H])
        .with_min_inner_size([MIN_WINDOW_W, MIN_WINDOW_H]);
    if let Some(icon) = load_window_icon() {
        viewport = viewport.with_icon(icon);
    }
    let opts = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    let app_name = "VaultGuard — 网盘伪装加密保险箱";
    let _ = eframe::run_native(
        &app_name,
        opts,
        Box::new(|cc| {
            let theme = ThemeMode::parse(&paths::reg_get_theme());
            install_fonts(&cc.egui_ctx);
            apply_theme(&cc.egui_ctx, theme);
            Ok(Box::new(VaultApp::new(theme)))
        }),
    );
}

/// 切换外观：更新调色板并即时重建样式（深色/浅色各一套令牌）。
fn apply_theme(ctx: &egui::Context, mode: ThemeMode) {
    set_pal(mode);
    ctx.set_style(build_style());
}

/// 系统 CJK/等宽字体。只装一次（切换主题不重复解析字体）。
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    if let Some(bytes) = load_cjk_font_bytes() {
        fonts
            .font_data
            .insert("cjk".into(), egui::FontData::from_owned(bytes));
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            if let Some(list) = fonts.families.get_mut(&family) {
                list.push("cjk".into());
            }
        }
    }
    if let Some(bytes) = load_mono_font_bytes() {
        fonts
            .font_data
            .insert("mono-win".into(), egui::FontData::from_owned(bytes));
        if let Some(list) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
            list.insert(0, "mono-win".into());
        }
    }
    ctx.set_fonts(fonts);
}

/// 按当前调色板装配样式（深色 zinc/emerald 为设计基线，浅色逐项对应）。
fn build_style() -> egui::Style {
    let mut style = egui::Style::default();
    let v = &mut style.visuals;
    *v = if is_light() {
        egui::Visuals::light()
    } else {
        egui::Visuals::dark()
    };
    v.panel_fill = pal().bg;
    v.window_fill = pal().card;
    v.extreme_bg_color = pal().extreme_bg;
    v.faint_bg_color = pal().faint_bg;
    v.window_stroke = egui::Stroke::new(1.0_f32, pal().border);
    v.window_rounding = egui::Rounding::same(R_MD);
    // 拖选高亮：默认 accent_dim 只有 10% 透明度，选中范围几乎看不出
    v.selection.bg_fill = pal().sel_bg;
    v.selection.stroke = egui::Stroke::new(1.0_f32, pal().accent);
    v.hyperlink_color = pal().accent_text;
    v.warn_fg_color = pal().busy_amber;
    v.override_text_color = Some(pal().text);

    for (w, bg, fg) in [
        (&mut v.widgets.inactive, pal().card, pal().text),
        (&mut v.widgets.hovered, pal().card_hover, pal().text),
        (&mut v.widgets.active, pal().accent_dim, pal().accent_text),
    ] {
        w.weak_bg_fill = bg;
        w.bg_fill = bg;
        w.fg_stroke = egui::Stroke::new(1.0_f32, fg);
        w.bg_stroke = egui::Stroke::new(1.0_f32, pal().border);
        w.rounding = egui::Rounding::same(R_SM);
    }
    v.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0_f32, pal().text_sub);
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0_f32, pal().border);
    // 禁用控件会被淡向这个颜色（egui 的 gray_out 目标）。默认值在深色下接近纯黑，
    // 禁用文字会糊成一片；改成面板底色，禁用态 = 「淡一档」而不是「看不见」。
    v.widgets.noninteractive.weak_bg_fill = pal().panel;

    // 控件之间留 10px（原 8px）——控件不再互相挨着，是「不挤」的第一来源
    style.spacing.item_spacing = egui::vec2(SP_CTRL, SP_CTRL);
    style.spacing.button_padding = egui::vec2(PAD_X, BTN_PAD_Y);
    // 输入类控件高度统一到 30px（原 28px），文字与边框之间有余量
    style.spacing.interact_size = egui::vec2(W_INTERACT, H_BTN);
    style.spacing.menu_margin = egui::Margin::same(SP_S);

    style
        .text_styles
        .insert(egui::TextStyle::Heading, egui::FontId::proportional(FS_H1));
    style
        .text_styles
        .insert(egui::TextStyle::Body, egui::FontId::proportional(FS_BODY));
    style
        .text_styles
        .insert(egui::TextStyle::Button, egui::FontId::proportional(FS_BODY));
    style
        .text_styles
        .insert(egui::TextStyle::Small, egui::FontId::proportional(FS_NOTE));
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, egui::FontId::monospace(FS_SUB));

    style
}

fn load_cjk_font_bytes() -> Option<Vec<u8>> {
    let dir = std::env::var_os("WINDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("Fonts");
    for name in ["msyh.ttc", "simhei.ttf", "Deng.ttf", "simsun.ttc"] {
        if let Ok(bytes) = std::fs::read(dir.join(name)) {
            if bytes.len() > 1_000_000 {
                return Some(bytes);
            }
        }
    }
    None
}

fn load_mono_font_bytes() -> Option<Vec<u8>> {
    let dir = std::env::var_os("WINDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("Fonts");
    for name in ["CascadiaCode.ttf", "CascadiaMono.ttf", "consola.ttf"] {
        if let Ok(bytes) = std::fs::read(dir.join(name)) {
            if bytes.len() > 100_000 {
                return Some(bytes);
            }
        }
    }
    None
}

/// 从 exe 内嵌图标资源画到 32bpp 内存位图上取 RGBA，交给 eframe 作窗口/任务栏图标。
fn load_window_icon() -> Option<egui::IconData> {
    use windows_sys::Win32::Foundation::{HWND, HINSTANCE};
    use windows_sys::Win32::Graphics::Gdi::{
        CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GetDC, ReleaseDC,
        SelectObject, BITMAPINFO, BITMAPINFOHEADER, RGBQUAD, DIB_RGB_COLORS,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DestroyIcon, DrawIconEx, LoadImageW, DI_NORMAL, IMAGE_ICON, LR_DEFAULTSIZE,
    };

    const SIZE: usize = 32;

    unsafe {
        let hinst: HINSTANCE = GetModuleHandleW(std::ptr::null());
        if hinst == 0 {
            return None;
        }
        let hicon = LoadImageW(hinst, 1 as *const u16, IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);
        if hicon == 0 {
            return None;
        }

        let hdc_screen = GetDC(0 as HWND);
        let memdc = CreateCompatibleDC(hdc_screen);
        ReleaseDC(0 as HWND, hdc_screen);
        if memdc == 0 {
            DestroyIcon(hicon);
            return None;
        }

        let bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: SIZE as i32,
                biHeight: -(SIZE as i32),
                biPlanes: 1,
                biBitCount: 32,
                biCompression: 0,
                biSizeImage: 0,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            bmiColors: [RGBQUAD {
                rgbBlue: 0,
                rgbGreen: 0,
                rgbRed: 0,
                rgbReserved: 0,
            }],
        };
        let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
        let hbmp = CreateDIBSection(memdc, &bmi, DIB_RGB_COLORS, &mut bits, 0, 0);
        if hbmp == 0 || bits.is_null() {
            DeleteDC(memdc);
            DestroyIcon(hicon);
            return None;
        }
        let old = SelectObject(memdc, hbmp);
        DrawIconEx(memdc, 0, 0, hicon, SIZE as i32, SIZE as i32, 0, 0, DI_NORMAL);

        let src = bits as *const u8;
        let mut rgba = vec![0u8; SIZE * SIZE * 4];
        for i in 0..SIZE * SIZE {
            let b = *src.add(i * 4) as u16;
            let g = *src.add(i * 4 + 1) as u16;
            let r = *src.add(i * 4 + 2) as u16;
            let a = *src.add(i * 4 + 3);
            let (r, g, b) = if a > 0 && a < 255 {
                (r * 255 / a as u16, g * 255 / a as u16, b * 255 / a as u16)
            } else {
                (r, g, b)
            };
            rgba[i * 4] = r as u8;
            rgba[i * 4 + 1] = g as u8;
            rgba[i * 4 + 2] = b as u8;
            rgba[i * 4 + 3] = a;
        }

        SelectObject(memdc, old);
        DeleteObject(hbmp);
        DeleteDC(memdc);
        DestroyIcon(hicon);

        Some(egui::IconData {
            width: SIZE as u32,
            height: SIZE as u32,
            rgba,
        })
    }
}

/// 当前本地时间 HH:MM:SS（GetLocalTime，与系统时区一致）。
fn now_hms() -> String {
    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    unsafe {
        let mut st: SYSTEMTIME = std::mem::zeroed();
        GetLocalTime(&mut st);
        format!("{:02}:{:02}:{:02}", st.wHour, st.wMinute, st.wSecond)
    }
}

/// 在资源管理器中打开指定路径：目录直接打开，文件则打开其所在目录。
fn open_in_explorer(path: &Path) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let target = if path.is_file() {
        path.parent().unwrap_or(path).to_path_buf()
    } else {
        path.to_path_buf()
    };
    let verb: Vec<u16> = "open\0".encode_utf16().collect();
    let target_w: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        let _ = ShellExecuteW(
            0,
            verb.as_ptr(),
            target_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
    }
}

/// --ui-smoke 自检：验证 GUI 状态可构造（读注册表/提醒文件，供自动化冒烟）。
pub fn smoke() {
    // 两种主题各装配一次样式并构造一次界面，确保主题分支都不 panic
    for mode in [ThemeMode::Dark, ThemeMode::Light] {
        set_pal(mode);
        let style = build_style();
        assert_eq!(style.visuals.dark_mode, !is_light(), "主题与基准 Visuals 不一致");
        let _app = VaultApp::new(mode);
    }
}

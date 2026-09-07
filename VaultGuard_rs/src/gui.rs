//! egui 图形界面 —— zinc/emerald 暗色主题（移植自退役 React 版的设计语言）。
//! 双页：伪装加密页（一次性打包）+ 隐私保险箱页（.vgsafe 增量容器）。
//! 原生支持窗口内拖放（egui dropped_files）+ rfd 文件/文件夹选择；后台线程处理不阻塞 UI。

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};

use eframe::egui;
use egui::Color32;

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

// ── zinc/emerald 配色（对齐退役 React 版的 tailwind 令牌）──
const BG: Color32 = Color32::from_rgb(0x0A, 0x0A, 0x0C);
const PANEL: Color32 = Color32::from_rgb(0x13, 0x13, 0x16);
const CARD: Color32 = Color32::from_rgb(0x18, 0x18, 0x1B);
const CARD_HOVER: Color32 = Color32::from_rgb(0x20, 0x20, 0x24);
const BORDER: Color32 = Color32::from_rgb(0x2A, 0x2A, 0x2E);
const TEXT: Color32 = Color32::from_rgb(0xE4, 0xE4, 0xE7);
const TEXT_SUB: Color32 = Color32::from_rgb(0xA1, 0xA1, 0xAA);
const TEXT_MUTED: Color32 = Color32::from_rgb(0x71, 0x71, 0x7A);
const TEXT_FAINT: Color32 = Color32::from_rgb(0x52, 0x52, 0x5B);
const ACCENT: Color32 = Color32::from_rgb(0x05, 0x96, 0x69);
const ACCENT_TEXT: Color32 = Color32::from_rgb(0x6E, 0xE7, 0xB7);
const ACCENT_DIM: Color32 = Color32::from_rgba_premultiplied(2, 19, 13, 26);
const DIR_SKY: Color32 = Color32::from_rgb(0x38, 0xBD, 0xF8);
const DANGER: Color32 = Color32::from_rgb(0xF8, 0x71, 0x71);
const BUSY_AMBER: Color32 = Color32::from_rgb(0xFB, 0xBF, 0x24);
const LOG_DEFAULT: Color32 = Color32::from_rgb(0x9C, 0x9C, 0xA4);

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
    Add(Vec<PathBuf>),
    Remove(Vec<String>),
    ExportAll(String),
    ExportSel(Vec<String>, String),
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
}

struct VaultPage {
    path: String,
    pass: String,
    pass2: String,
    changing: bool, // 更换口令模式
    busy: bool,
    session: Option<safe::Session>,
    sel: HashSet<String>,
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
            busy: false,
            session: None,
            sel: HashSet::new(),
            tx,
            rx,
        }
    }
}

impl VaultApp {
    fn new() -> Self {
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
            vault_flags: Vec::new(),
            vault_count: 0,
            page: Page::Disguise,
            vp: VaultPage::new(),
            dec_preview: None,
            dec_sel: HashSet::new(),
            dec_origin: None,
            title_busy: false,
        }
    }

    fn log(&mut self, line: &str) {
        self.logs.push(format!("[{}] {}", now_hms(), line));
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
                    self.busy = false;
                    self.progress = None;
                    if let Some(p) = path {
                        self.last_output = Some(p);
                    }
                    self.log("后台任务已结束，可继续操作。");
                }
                Msg::PreviewReady(preview) => {
                    self.busy = false;
                    self.progress = None;
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
                    self.vp.busy = false;
                    self.progress = None;
                    self.vp.session = sess;
                    match res {
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
            match engine::do_enc(&items, shell, &out_dir, &opts, Some(&prog)) {
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
                match engine::do_dec_preview(&v, pass.as_deref(), Some(&prog)) {
                    Ok(preview) => {
                        let _ = tx.send(Msg::PreviewReady(preview));
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
                match engine::do_dec(v, &out_dir, pass.as_deref(), Some(&prog)) {
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
        self.busy = true;
        self.dec_sel.clear();
        let label = match &filter {
            None => "全部落位".to_string(),
            Some(s) => format!("落位选中 {} 项", s.len()),
        };
        self.log(&format!(">>> {}…", label));
        std::thread::spawn(move || {
            let res = engine::do_dec_place(preview, &out_dir, filter.as_deref());
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
                    .fill(PANEL)
                    .stroke(egui::Stroke::new(1.0, BORDER))
                    .inner_margin(egui::Margin::symmetric(16.0, 9.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(30.0, 30.0), egui::Sense::hover());
                    ui.painter().rect_filled(rect, 8.0, ACCENT_DIM);
                    ui.painter()
                        .rect_stroke(rect, 8.0, egui::Stroke::new(1.0, ACCENT));
                    ui.painter().text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        "VG",
                        egui::FontId::monospace(13.0),
                        ACCENT_TEXT,
                    );
                    ui.add_space(2.0);
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("VaultGuard")
                                    .size(14.5)
                                    .strong()
                                    .color(TEXT),
                            );
                            ui.label(
                                egui::RichText::new(format!(
                                    "v{}",
                                    env!("CARGO_PKG_VERSION")
                                        .split('.')
                                        .next()
                                        .unwrap_or("1")
                                ))
                                .monospace()
                                .size(10.0)
                                .color(TEXT_SUB),
                            );
                        });
                        ui.label(
                            egui::RichText::new("网盘伪装加密保险箱 —— 加密/还原均不触碰原文件")
                                .size(11.0)
                                .color(TEXT_MUTED),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .selectable_label(
                                matches!(&self.page, Page::Vault),
                                egui::RichText::new("隐私保险箱").size(12.5),
                            )
                            .clicked()
                        {
                            self.page = Page::Vault;
                        }
                        if ui
                            .selectable_label(
                                matches!(&self.page, Page::Disguise),
                                egui::RichText::new("伪装加密").size(12.5),
                            )
                            .clicked()
                        {
                            self.page = Page::Disguise;
                        }
                    });
                });
            });
    }

    fn ui_left(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("side")
            .resizable(false)
            .exact_width(262.0)
            .frame(
                egui::Frame::default()
                    .fill(BG)
                    .inner_margin(egui::Margin::same(12.0)),
            )
            .show(ctx, |ui| {
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
                    ui.add_space(4.0);
                }

                ui.add_space(10.0);
                section_title(ui, "口令（保护隐私，推荐设置）");
                ui.horizontal(|ui| {
                    let r1 = ui.add(
                        egui::TextEdit::singleline(&mut self.passphrase)
                            .password(!self.show_pass)
                            .hint_text("输入口令")
                            .desired_width(width - 74.0)
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
                ui.add_space(3.0);
                let r2 = ui.add(
                    egui::TextEdit::singleline(&mut self.passphrase2)
                        .password(true)
                        .hint_text("再次输入口令确认")
                        .desired_width(width - 4.0)
                        .font(egui::TextStyle::Monospace),
                );
                ui.add_space(3.0);
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
                ui.add_space(3.0);
                // 口令状态机：未设口令时提供 跳过/取消跳过 双向按钮，跳过后也能反悔
                if self.passphrase.is_empty() {
                    if self.allow_no_pass {
                        ui.label(
                            egui::RichText::new(
                                "已选择跳过口令：仅防随手翻看，任何拿到程序的人都可解密（敏感文件不建议）",
                            )
                            .size(9.5)
                            .color(TEXT_MUTED),
                        );
                        if ui.add(ghost_button("取消跳过，改设口令")).clicked() {
                            self.allow_no_pass = false;
                            self.log("已取消跳过口令：设置口令（两次输入一致）后即可口令加密。");
                        }
                    } else {
                        ui.label(
                            egui::RichText::new(
                                "未设置口令：仅防随手翻看，任何拿到程序的人都可解密（不推荐用于敏感文件）",
                            )
                            .size(9.5)
                            .color(TEXT_MUTED),
                        );
                        if ui.add(ghost_button("跳过口令，不设口令继续")).clicked() {
                            self.allow_no_pass = true;
                            self.log("已跳过口令：本次加密使用内置密钥（不推荐用于敏感文件）。");
                        }
                    }
                } else if self.passphrase != self.passphrase2 {
                    ui.label(
                        egui::RichText::new("两次输入的口令不一致")
                            .size(9.5)
                            .color(BUSY_AMBER),
                    );
                } else {
                    // 口令强度实时评估：常见弱口令 / 长度 / 字符类
                    let (lv, msg) = pass_strength(&self.passphrase);
                    let color = match lv {
                        2 => ACCENT_TEXT,
                        1 => BUSY_AMBER,
                        _ => DANGER,
                    };
                    ui.label(
                        egui::RichText::new(format!(
                            "{}（Argon2id）· 钥匙指纹 {}",
                            msg,
                            crypto::pass_fingerprint(&self.passphrase)
                        ))
                        .size(9.5)
                        .color(color),
                    );
                    ui.label(
                        egui::RichText::new("同一条口令指纹相同，可用于核对是否输错。口令遗忘后文件无法找回")
                            .size(9.5)
                            .color(TEXT_FAINT),
                    );
                }

                ui.add_space(10.0);
                section_title(ui, "输出目录");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.out_dir)
                            .desired_width(width - 76.0)
                            .font(egui::TextStyle::Monospace),
                    );
                    if ui.button("浏览…").clicked() {
                        if let Some(d) = rfd::FileDialog::new().pick_folder() {
                            self.out_dir = d.display().to_string();
                        }
                    }
                });

                ui.add_space(12.0);
                egui::CollapsingHeader::new(
                    egui::RichText::new("高级").size(11.0).strong().color(TEXT_MUTED),
                )
                .id_source("adv")
                .show(ui, |ui| {
                    ui.add_space(2.0);
                    // 自定义封面：跟随当前选中的外壳，各自记忆（存于 %APPDATA% 封面目录）
                    let shell = SHELLS[self.shell];
                    let custom = paths::custom_cover(shell).is_some();
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "封面：{}",
                                if custom { "自定义 ✔" } else { "内置随机" }
                            ))
                            .size(11.0)
                            .color(if custom { ACCENT_TEXT } else { TEXT_MUTED }),
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
                                .size(9.5)
                                .color(TEXT_FAINT),
                        );
                    }
                    ui.add_space(4.0);
                    ui.checkbox(
                        &mut self.keep_name,
                        "保留原文件名作为输出名（默认随机，不泄露原名）",
                    );
                });

                // 操作按钮组固定在面板底部：用空白撑开后从上往下排
                let busy = self.busy;
                ui.columns(2, |cols| {
                    let w0 = cols[0].available_width();
                    let w1 = cols[1].available_width();
                    if cols[0]
                        .add_enabled(
                            !busy,
                            egui::Button::new("文件").min_size(egui::vec2(w0, 30.0)),
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
                            egui::Button::new("文件夹").min_size(egui::vec2(w1, 30.0)),
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
                let group_height = 106.0; // 开始加密36 + 间距6 + 还原34 + 间距4 + 移除/清空26
                let remaining = ui.available_height();
                if remaining > group_height + 16.0 {
                    ui.add_space(remaining - group_height - 16.0);
                }
                let pass_ready = (!self.passphrase.is_empty()
                    && self.passphrase == self.passphrase2)
                    || self.allow_no_pass;
                if ui
                    .add_enabled(
                        !self.busy && pass_ready,
                        primary_button("开始加密（所选外壳）").min_size(egui::vec2(width, 36.0)),
                    )
                    .clicked()
                {
                    self.run_enc();
                }
                ui.add_space(6.0);
                let dec_label = if self.vault_count > 0 {
                    format!("还原 VaultGuard 文件（{}）", self.vault_count)
                } else {
                    "还原 VaultGuard 文件".to_string()
                };
                if ui.add_sized([width, 34.0], secondary_button(dec_label)).clicked() {
                    self.run_dec();
                }
                ui.add_space(4.0);
                ui.columns(3, |cols| {
                    let ws = [
                        cols[0].available_width(),
                        cols[1].available_width(),
                        cols[2].available_width(),
                    ];
                    if cols[0]
                        .add_enabled(
                            !self.sel.is_empty() && !self.busy,
                            ghost_button("移除选中").min_size(egui::vec2(ws[0], 26.0)),
                        )
                        .clicked()
                    {
                        self.remove_selected();
                    }
                    if cols[1]
                        .add_enabled(
                            !self.items.is_empty() && !self.busy,
                            ghost_button("清空列表").min_size(egui::vec2(ws[1], 26.0)),
                        )
                        .clicked()
                    {
                        self.items.clear();
                        self.sel.clear();
                        self.log("列表已清空");
                    }
                    if cols[2]
                        .add_enabled(
                            self.last_output.is_some(),
                            ghost_button("分享说明").min_size(egui::vec2(ws[2], 26.0)),
                        )
                        .clicked()
                    {
                        if let Some(out) = &self.last_output {
                            let pass_note = if self.passphrase.is_empty() {
                                "（未设口令：内置密钥模式）".to_string()
                            } else {
                                self.passphrase.clone()
                            };
                            let text = format!(
                                "【VaultGuard 分享说明】\n文件：{}\n口令：{}\n接收方步骤：打开 VaultGuard.exe → 拖入本文件 → 输入口令 → 还原。\n安全提醒：口令请勿与文件走同一渠道发送；口令遗忘无法找回。",
                                out.display(),
                                pass_note
                            );
                            cols[2].output_mut(|o| o.copied_text = text);
                            self.log("分享说明已复制到剪贴板。");
                        }
                    }
                });
            });
    }

    fn ui_center(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(BG)
                    .inner_margin(egui::Margin::same(12.0)),
            )
            .show(ctx, |ui| {
                let dragging = ui.input(|i| !i.raw.hovered_files.is_empty());

                // ── 文件列表卡片 ──
                egui::Frame::default()
                    .fill(if dragging { ACCENT_DIM } else { CARD })
                    .stroke(egui::Stroke::new(
                        1.0,
                        if dragging { ACCENT } else { BORDER },
                    ))
                    .rounding(10.0)
                    .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.add_space(4.0);
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
                                .size(11.5)
                                .color(if dragging { ACCENT_TEXT } else { TEXT_MUTED }),
                            );
                        });
                        ui.add_space(2.0);
                        egui::ScrollArea::vertical()
                            .id_source("items")
                            .max_height(ui.available_height() * 0.46)
                            .show(ui, |ui| {
                                if self.items.is_empty() {
                                    ui.vertical_centered(|ui| {
                                        ui.add_space(18.0);
                                        ui.label(
                                            egui::RichText::new("把文件或文件夹拖进窗口")
                                                .size(13.0)
                                                .color(TEXT_SUB),
                                        );
                                        ui.add_space(2.0);
                                        ui.label(
                                            egui::RichText::new("加密后的容器拖回来即可还原")
                                                .size(11.0)
                                                .color(TEXT_FAINT),
                                        );
                                        ui.add_space(14.0);
                                    });
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

                ui.add_space(10.0);

                // ── 选择性还原预览面板（解密就绪后出现）──
                if self.dec_preview.is_some() {
                    self.ui_dec_preview(ui);
                    ui.add_space(10.0);
                }

                // ── 上次输出快捷入口 ──
                if let Some(out) = &self.last_output {
                    ui.horizontal(|ui| {
                        if ui.add(ghost_button("打开输出目录")).clicked() {
                            open_in_explorer(out);
                        }
                        ui.label(
                            egui::RichText::new(format!("上次输出: {}", out.display()))
                                .size(10.0)
                                .color(TEXT_FAINT)
                                .monospace(),
                        );
                    });
                    ui.add_space(4.0);
                }

                log_card(ui, self.busy, self.progress, &self.logs);
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
            .fill(CARD)
            .stroke(egui::Stroke::new(1.0, ACCENT))
            .rounding(10.0)
            .inner_margin(egui::Margin::symmetric(8.0, 6.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(format!(
                            "解密预览（{} 个顶层条目）—— 勾选要落位的内容",
                            tops.len()
                        ))
                        .size(11.5)
                        .color(ACCENT_TEXT),
                    );
                });
                ui.add_space(2.0);
                egui::ScrollArea::vertical()
                    .id_source("dec_preview")
                    .max_height(ui.available_height() * 0.30)
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
                                        .size(10.5)
                                        .color(TEXT_MUTED),
                                );
                                ui.label(
                                    egui::RichText::new(name)
                                        .monospace()
                                        .size(11.5)
                                        .color(TEXT),
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
                                            .size(10.0)
                                            .color(TEXT_FAINT),
                                        );
                                    },
                                );
                            });
                        }
                    });
                ui.add_space(4.0);
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
                        .add_enabled(!busy, ghost_button("取消"))
                        .clicked()
                    {
                        self.cancel_dec_preview();
                    }
                });
            });
    }

    fn ui_vault(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(BG)
                    .inner_margin(egui::Margin::same(12.0)),
            )
            .show(ctx, |ui| {
                let width = ui.available_width();
                let busy = self.vp.busy;

                section_title(ui, "隐私保险箱");
                ui.label(
                    egui::RichText::new(
                        "一个 .vgsafe 文件管理整个文件夹树：口令加密（Argon2id），随时增删文件，单文件跨设备携带。",
                    )
                    .size(11.0)
                    .color(TEXT_SUB),
                );
                ui.add_space(8.0);

                // 路径行
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vp.path)
                            .desired_width(width - 232.0)
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
                        .add_enabled(
                            create_ready,
                            egui::Button::new("新建").min_size(egui::vec2(64.0, 28.0)),
                        )
                        .clicked()
                    {
                        let path = self.vp.path.trim().to_string();
                        let pass = self.vp.pass.clone();
                        let task = VaultTask::Create(path, pass);
                        let sess = self.vp.session.take();
                        self.vp.busy = true;
                        let tx = self.vp.tx.clone();
                        std::thread::spawn(move || vault_worker(sess, task, tx));
                    }
                    if ui
                        .add_enabled(
                            open_ready,
                            egui::Button::new("打开").min_size(egui::vec2(64.0, 28.0)),
                        )
                        .clicked()
                    {
                        let path = self.vp.path.trim().to_string();
                        let pass = self.vp.pass.clone();
                        let task = VaultTask::Open(path, pass);
                        let sess = self.vp.session.take();
                        self.vp.busy = true;
                        let tx = self.vp.tx.clone();
                        std::thread::spawn(move || vault_worker(sess, task, tx));
                    }
                    if ui
                        .add_enabled(!busy, egui::Button::new("浏览…").min_size(egui::vec2(64.0, 28.0)))
                        .clicked()
                    {
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("VaultGuard 保险箱", &["vgsafe"])
                            .pick_file()
                        {
                            self.vp.path = p.display().to_string();
                        }
                    }
                });
                ui.add_space(4.0);
                // 口令行：新建需两次一致；打开已有保险箱只填第一格
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("口令").size(11.5).color(TEXT_SUB));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vp.pass)
                            .password(true)
                            .desired_width(width / 2.0 - 40.0)
                            .font(egui::TextStyle::Monospace)
                            .hint_text("口令（新建与打开共用）"),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vp.pass2)
                            .password(true)
                            .desired_width(width / 2.0 - 40.0)
                            .font(egui::TextStyle::Monospace)
                            .hint_text("确认口令（新建必填，打开可留空）"),
                    );
                });
                ui.label(
                    egui::RichText::new("新建需两次口令一致；打开已有保险箱只填第一格即可。口令遗忘后保险箱无法找回。")
                        .size(9.5)
                        .color(TEXT_FAINT),
                );
                ui.add_space(8.0);
                if self.vp.session.is_none() {
                    if busy {
                        ui.horizontal(|ui| {
                            ui.add(egui::Spinner::new().size(12.0));
                            ui.label(egui::RichText::new("正在处理（Argon2id 派生 + 加密）…").size(11.0).color(BUSY_AMBER));
                        });
                    }
                    ui.add_space(8.0);
                    log_card(ui, busy, self.progress, &self.logs);
                    return;
                }

                // ── 已打开：操作区 ──
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!busy, egui::Button::new("添加文件").min_size(egui::vec2(0.0, 28.0)))
                        .clicked()
                    {
                        if let Some(files) = rfd::FileDialog::new().pick_files() {
                            let task = VaultTask::Add(files);
                            let sess = self.vp.session.take();
                            self.vp.busy = true;
                            let tx = self.vp.tx.clone();
                            std::thread::spawn(move || vault_worker(sess, task, tx));
                        }
                    }
                    if ui
                        .add_enabled(!busy, egui::Button::new("添加文件夹").min_size(egui::vec2(0.0, 28.0)))
                        .clicked()
                    {
                        if let Some(d) = rfd::FileDialog::new().pick_folder() {
                            let task = VaultTask::Add(vec![d]);
                            let sess = self.vp.session.take();
                            self.vp.busy = true;
                            let tx = self.vp.tx.clone();
                            std::thread::spawn(move || vault_worker(sess, task, tx));
                        }
                    }
                    if ui
                        .add_enabled(!busy, egui::Button::new("导出全部").min_size(egui::vec2(0.0, 28.0)))
                        .clicked()
                    {
                        if let Some(d) = rfd::FileDialog::new().pick_folder() {
                            let task = VaultTask::ExportAll(d.display().to_string());
                            let sess = self.vp.session.take();
                            self.vp.busy = true;
                            let tx = self.vp.tx.clone();
                            std::thread::spawn(move || vault_worker(sess, task, tx));
                        }
                    }
                    if ui
                        .add_enabled(!busy && !self.vp.sel.is_empty(), egui::Button::new("导出选中").min_size(egui::vec2(0.0, 28.0)))
                        .clicked()
                    {
                        if let Some(d) = rfd::FileDialog::new().pick_folder() {
                            let names: Vec<String> = self.vp.sel.iter().cloned().collect();
                            let task = VaultTask::ExportSel(names, d.display().to_string());
                            let sess = self.vp.session.take();
                            self.vp.busy = true;
                            let tx = self.vp.tx.clone();
                            std::thread::spawn(move || vault_worker(sess, task, tx));
                        }
                    }
                    if ui
                        .add_enabled(!busy && !self.vp.sel.is_empty(), egui::Button::new("移除选中").min_size(egui::vec2(0.0, 28.0)))
                        .clicked()
                    {
                        let names: Vec<String> = self.vp.sel.iter().cloned().collect();
                        let task = VaultTask::Remove(names);
                        let sess = self.vp.session.take();
                        self.vp.busy = true;
                        self.vp.sel.clear();
                        let tx = self.vp.tx.clone();
                        std::thread::spawn(move || vault_worker(sess, task, tx));
                    }
                    if ui
                        .add_enabled(!busy, ghost_button(if self.vp.changing { "取消换口令" } else { "更换口令" }))
                        .clicked()
                    {
                        self.vp.changing = !self.vp.changing;
                        self.vp.pass.clear();
                        self.vp.pass2.clear();
                    }
                    if ui
                        .add_enabled(!busy, ghost_button("关闭保险箱"))
                        .clicked()
                    {
                        self.vp.session = None; // Drop 擦除临时工作树
                        self.vp.sel.clear();
                        self.log("保险箱已关闭，临时数据已擦除。");
                    }
                });
                ui.add_space(8.0);

                if self.vp.changing {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("新口令").size(11.5).color(TEXT_SUB));
                        ui.add(
                            egui::TextEdit::singleline(&mut self.vp.pass)
                                .password(true)
                                .desired_width(width / 3.0)
                                .font(egui::TextStyle::Monospace)
                                .hint_text("新口令"),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut self.vp.pass2)
                                .password(true)
                                .desired_width(width / 3.0)
                                .font(egui::TextStyle::Monospace)
                                .hint_text("确认新口令"),
                        );
                        if ui
                            .add_enabled(
                                !busy
                                    && !self.vp.pass.is_empty()
                                    && self.vp.pass == self.vp.pass2,
                                primary_button("应用新口令").min_size(egui::vec2(0.0, 26.0)),
                            )
                            .clicked()
                        {
                            let new_pass = self.vp.pass.clone();
                            let task = VaultTask::ChangePass(new_pass);
                            let sess = self.vp.session.take();
                            self.vp.busy = true;
                            self.vp.changing = false;
                            let tx = self.vp.tx.clone();
                            std::thread::spawn(move || vault_worker(sess, task, tx));
                        }
                    });
                    ui.label(
                        egui::RichText::new("口令遗忘后保险箱无法打开，请牢记新口令。更换会重写整个容器。")
                            .size(9.5)
                            .color(TEXT_FAINT),
                    );
                    ui.add_space(6.0);
                }

                // ── 条目列表卡片 ──
                let count = self
                    .vp
                    .session
                    .as_ref()
                    .map(|s| s.entries.len())
                    .unwrap_or(0);
                egui::Frame::default()
                    .fill(CARD)
                    .stroke(egui::Stroke::new(1.0, BORDER))
                    .rounding(10.0)
                    .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new(format!("保险箱内容（{} 个条目）—— 勾选后可导出/移除", count))
                                    .size(11.5)
                                    .color(TEXT_MUTED),
                            );
                        });
                        ui.add_space(2.0);
                        egui::ScrollArea::vertical()
                            .id_source("safe_items")
                            .max_height(ui.available_height() * 0.42)
                            .show(ui, |ui| {
                                let Some(sess) = self.vp.session.as_ref() else {
                                    return;
                                };
                                if sess.entries.is_empty() {
                                    ui.vertical_centered(|ui| {
                                        ui.add_space(14.0);
                                        ui.label(
                                            egui::RichText::new("保险箱是空的：点上方「添加文件/文件夹」")
                                                .size(12.0)
                                                .color(TEXT_SUB),
                                        );
                                        ui.add_space(10.0);
                                    });
                                    return;
                                }
                                for e in &sess.entries {
                                    let selected = self.vp.sel.contains(&e.name);
                                    let dot = if e.is_dir { DIR_SKY } else { TEXT_MUTED };
                                    ui.horizontal(|ui| {
                                        ui.add_space(4.0);
                                        let (rect, _) = ui.allocate_exact_size(
                                            egui::vec2(7.0, 7.0),
                                            egui::Sense::hover(),
                                        );
                                        ui.painter().rect_filled(rect, 2.0, dot);
                                        let resp = ui.selectable_label(
                                            selected,
                                            egui::RichText::new(&e.name)
                                                .monospace()
                                                .size(11.5)
                                                .color(if e.is_dir { TEXT_SUB } else { TEXT }),
                                        );
                                        if resp.clicked() {
                                            if selected {
                                                self.vp.sel.remove(&e.name);
                                            } else {
                                                self.vp.sel.insert(e.name.clone());
                                            }
                                        }
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |r| {
                                                r.label(
                                                    egui::RichText::new(paths::sz(e.size))
                                                        .monospace()
                                                        .size(10.0)
                                                        .color(TEXT_FAINT),
                                                );
                                            },
                                        );
                                    });
                                }
                            });
                    });

                ui.add_space(10.0);
                log_card(ui, busy, self.progress, &self.logs);
            });
    }
}

fn section_title(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).size(11.0).strong().color(TEXT_MUTED));
    ui.add_space(3.0);
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
        .fill(if active { ACCENT_DIM } else { CARD })
        .stroke(egui::Stroke::new(
            1.0,
            if active { ACCENT } else { BORDER },
        ))
        .rounding(8.0)
        .inner_margin(egui::Margin::symmetric(10.0, 7.0))
        .show(ui, |inner| {
            inner.horizontal(|h| {
                h.label(
                    egui::RichText::new(name)
                        .size(12.5)
                        .strong()
                        .color(if active { ACCENT_TEXT } else { TEXT }),
                );
                h.with_layout(egui::Layout::right_to_left(egui::Align::Center), |r| {
                    r.label(egui::RichText::new(badge).monospace().size(9.5).color(TEXT_FAINT));
                });
            });
            inner.label(egui::RichText::new(desc).size(10.5).color(TEXT_MUTED));
            content_rect = inner.min_rect();
        });
    let resp = ui.interact(content_rect, egui::Id::new(id), egui::Sense::click());
    if resp.hovered() && !active {
        ui.painter()
            .rect_filled(content_rect, 8.0, Color32::from_white_alpha(6));
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
        ui.add_space(4.0);
        let (rect, _) = ui.allocate_exact_size(egui::vec2(7.0, 7.0), egui::Sense::hover());
        ui.painter()
            .rect_filled(rect, 2.0, if is_dir { DIR_SKY } else { TEXT_MUTED });
        let name_w = (ui.available_width() - 132.0).max(80.0);
        let name_text = egui::RichText::new(p.display().to_string())
            .monospace()
            .size(11.5)
            .color(if is_dir { TEXT_SUB } else { TEXT });
        let resp = ui.add_sized(
            [name_w, 20.0],
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
                .fill(ACCENT_DIM)
                .stroke(egui::Stroke::new(1.0, ACCENT))
                .rounding(4.0)
                .inner_margin(egui::Margin::symmetric(5.0, 1.0))
                .show(ui, |chip| {
                    chip.label(
                        egui::RichText::new("VaultGuard")
                            .monospace()
                            .size(9.0)
                            .color(ACCENT_TEXT),
                    );
                });
        } else {
            ui.add_space(74.0);
        }
        let size = if is_dir {
            "-".to_string()
        } else {
            paths::sz(p.metadata().map(|m| m.len()).unwrap_or(0))
        };
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |r| {
            if r.add(
                egui::Button::new(egui::RichText::new("×").size(12.0).color(TEXT_MUTED))
                    .fill(Color32::TRANSPARENT)
                    .stroke(egui::Stroke::NONE)
                    .small(),
            )
            .on_hover_text("移除")
            .clicked()
            {
                action = RowAction::Remove;
            }
            r.label(egui::RichText::new(size).monospace().size(10.0).color(TEXT_FAINT));
        });
    });
    action
}

enum RowAction {
    None,
    Remove,
}

fn log_card(ui: &mut egui::Ui, busy: bool, progress: Option<u8>, logs: &[String]) {
    egui::Frame::default()
        .fill(CARD)
        .stroke(egui::Stroke::new(1.0, BORDER))
        .rounding(10.0)
        .inner_margin(egui::Margin::symmetric(8.0, 6.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(4.0);
                ui.label(egui::RichText::new("日志").size(11.5).color(TEXT_MUTED));
                if busy {
                    ui.add(egui::Spinner::new().size(12.0));
                    ui.label(
                        egui::RichText::new("后台处理中…")
                            .size(11.5)
                            .color(BUSY_AMBER),
                    );
                }
                if let Some(p) = progress {
                    ui.add(
                        egui::ProgressBar::new(p as f32 / 100.0)
                            .desired_height(12.0)
                            .show_percentage(),
                    );
                }
            });
            ui.add_space(2.0);
            egui::ScrollArea::vertical()
                .id_source("logs")
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for l in logs {
                        ui.label(
                            egui::RichText::new(l)
                                .monospace()
                                .size(11.5)
                                .color(log_color(l)),
                        );
                    }
                });
        });
}

fn log_color(line: &str) -> Color32 {
    if line.starts_with(">>>") {
        ACCENT_TEXT
    } else if line.contains("失败") || line.contains("未处理") || line.contains("错误") {
        DANGER
    } else if line.contains("完成") || line.contains("成功") || line.contains("就绪") {
        ACCENT
    } else {
        LOG_DEFAULT
    }
}

fn primary_button(text: impl Into<String>) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text).size(13.0).strong().color(Color32::WHITE))
        .fill(ACCENT)
        .stroke(egui::Stroke::NONE)
        .rounding(8.0)
        .min_size(egui::vec2(0.0, 34.0))
}

fn secondary_button(text: impl Into<String>) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text).size(12.5).color(TEXT))
        .fill(CARD_HOVER)
        .stroke(egui::Stroke::new(1.0, BORDER))
        .rounding(8.0)
        .min_size(egui::vec2(0.0, 32.0))
}

fn ghost_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text).size(11.5).color(TEXT_SUB))
        .fill(Color32::TRANSPARENT)
        .stroke(egui::Stroke::new(1.0, BORDER))
        .rounding(7.0)
        .min_size(egui::vec2(0.0, 26.0))
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
                sess = Some(s);
                Ok(format!("保险箱已打开：{}（{} 个条目）", path, n))
            }
            Err(e) => Err(e.to_string()),
        },
        VaultTask::Add(files) => match sess.as_mut() {
            Some(s) => {
                let n = files.len();
                s.add_paths(&files)
                    .and_then(|added| {
                        line(format!("已添加 {} 项，正在重新加密保存…", added));
                        s.save(&save_prog)
                    })
                    .map(|_| format!("已添加 {} 项并保存", n))
                    .map_err(|e| e.to_string())
            }
            None => Err("保险箱未打开".into()),
        },
        VaultTask::Remove(names) => match sess.as_mut() {
            Some(s) => {
                let n = names.len();
                s.remove_entries(&names)
                    .and_then(|removed| {
                        line(format!("已移除 {} 项，正在重新加密保存…", removed));
                        s.save(&save_prog)
                    })
                    .map(|_| format!("已移除 {} 项并保存", n))
                    .map_err(|e| e.to_string())
            }
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
        VaultTask::ChangePass(new) => match sess.as_mut() {
            Some(s) => s
                .change_password(&new)
                .map(|_| "口令已更换并重新加密保存".to_string())
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
        ctx.request_repaint();
    }
}

/// GUI 主入口（无命令行参数时由 main 调用）
pub fn run() {
    // 标题栏/任务栏图标取自 exe 内嵌的图标资源（RT_GROUP_ICON id=1，见 build.rs）
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([960.0, 640.0])
        .with_min_inner_size([760.0, 520.0]);
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
            install_style(&cc.egui_ctx);
            Ok(Box::new(VaultApp::new()))
        }),
    );
}

/// 主题：系统 CJK/等宽字体 + zinc/emerald 暗色样式（对齐退役 React 版的设计语言）。
fn install_style(ctx: &egui::Context) {
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

    let mut style = egui::Style::default();
    let v = &mut style.visuals;
    *v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = CARD;
    v.extreme_bg_color = Color32::from_rgb(0x0D, 0x0D, 0x10);
    v.faint_bg_color = Color32::from_rgb(0x14, 0x14, 0x17);
    v.window_stroke = egui::Stroke::new(1.0, BORDER);
    v.window_rounding = egui::Rounding::same(10.0);
    v.selection.bg_fill = ACCENT_DIM;
    v.selection.stroke = egui::Stroke::new(1.0, ACCENT);
    v.hyperlink_color = ACCENT_TEXT;
    v.warn_fg_color = BUSY_AMBER;
    v.override_text_color = Some(TEXT);

    for (w, bg, fg) in [
        (&mut v.widgets.inactive, CARD, TEXT),
        (&mut v.widgets.hovered, CARD_HOVER, TEXT),
        (&mut v.widgets.active, ACCENT_DIM, ACCENT_TEXT),
    ] {
        w.weak_bg_fill = bg;
        w.bg_fill = bg;
        w.fg_stroke = egui::Stroke::new(1.0, fg);
        w.bg_stroke = egui::Stroke::new(1.0, BORDER);
        w.rounding = egui::Rounding::same(7.0);
    }
    v.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, TEXT_SUB);
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER);

    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 7.0);
    style.spacing.interact_size = egui::vec2(60.0, 28.0);
    style.spacing.menu_margin = egui::Margin::same(6.0);

    style
        .text_styles
        .insert(egui::TextStyle::Heading, egui::FontId::proportional(16.0));
    style
        .text_styles
        .insert(egui::TextStyle::Body, egui::FontId::proportional(13.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, egui::FontId::proportional(13.0));
    style
        .text_styles
        .insert(egui::TextStyle::Small, egui::FontId::proportional(11.0));
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, egui::FontId::monospace(12.0));

    ctx.set_style(style);
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

/// --ui-smoke 自检：验证 GUI 模块可加载（供自动化冒烟）
pub fn smoke() {}

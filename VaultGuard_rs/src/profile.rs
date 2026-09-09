//! 轻量阶段剖析（运行时按需开启，未开启时每次调用仅一次线程局部变量读取）。
//!
//! 供 `vgs2-bench` 定位保险箱首存 / 压缩 / 打开路径的主导耗时：调用方用
//! [`phase`] 包裹感兴趣的操作，同一线程内按阶段名累计耗时与调用次数。
//! 基准工具在会话开始/结束时用 [`begin`] / [`end`] 采集，不在本模块内做 I/O。

use std::cell::RefCell;
use std::time::Instant;

/// 单一阶段累计结果：(阶段名, 总秒数, 调用次数)。
pub type PhaseStat = (&'static str, f64, u64);

thread_local! {
    static SLOT: RefCell<Option<Vec<PhaseStat>>> = const { RefCell::new(None) };
}

/// 开启采集（清空既有数据）。随后本线程内的 [`phase`] 调用开始累计。
/// 仅 `vgs2-bench` 使用，主二进制中无调用方。
#[allow(dead_code)]
pub fn begin() {
    SLOT.with(|s| *s.borrow_mut() = Some(Vec::new()));
}

/// 结束采集并取出全部阶段统计。未开启时返回空向量。
#[allow(dead_code)]
pub fn end() -> Vec<PhaseStat> {
    SLOT.with(|s| s.borrow_mut().take()).unwrap_or_default()
}

/// 执行 `f`；若采集开启，把耗时累计到 `name` 阶段。
pub fn phase<R>(name: &'static str, f: impl FnOnce() -> R) -> R {
    let on = SLOT.with(|s| s.borrow().is_some());
    if !on {
        return f();
    }
    let t0 = Instant::now();
    let r = f();
    let secs = t0.elapsed().as_secs_f64();
    SLOT.with(|s| {
        if let Some(v) = s.borrow_mut().as_mut() {
            if let Some((_, total, calls)) = v.iter_mut().find(|(n, _, _)| *n == name) {
                *total += secs;
                *calls += 1;
            } else {
                v.push((name, secs, 1));
            }
        }
    });
    r
}

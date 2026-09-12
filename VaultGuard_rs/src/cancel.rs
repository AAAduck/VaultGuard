//! 长任务取消令牌：GUI 与后台工作线程共享一个原子标志。
//!
//! 约定：
//! - 长任务在「可中断点」调用 [`Cancel::check`]，已取消则返回
//!   `io::ErrorKind::Interrupted`（消息文本见 [`CANCELLED_MSG`]）；
//! - 调用方必须保证取消后**容器与输出保持原状**。VGS2 天然满足：只有新内容
//!   完整落盘并原子替换后才生效，半途放弃等于「什么都没发生」；已产生的临时
//!   明文一律走 `paths::cleanup` 覆写擦除。
//! - 取消是「协作式」的：正在进行的单次 I/O（如写一个 64 MiB 数据段）不会被打断，
//!   线程会在下一个检查点返回，因此 UI 应显示「正在取消…」而不是立即结束。

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// 取消错误的固定消息文本（GUI 据此区分「用户取消」与「真失败」，不要改）。
pub const CANCELLED_MSG: &str = "已取消";

/// 克隆即共享同一标志的取消令牌。
#[derive(Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// 未持有的空令牌：不参与取消（命令行、测试、内部委托用）。
    pub fn never() -> Self {
        Self::new()
    }

    /// 请求取消（GUI 线程调用，立即生效）。
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// 复用令牌开始新任务前复位。
    pub fn reset(&self) {
        self.0.store(false, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// 可中断点检查：已取消则返回 `Interrupted`。
    pub fn check(&self) -> io::Result<()> {
        if self.is_cancelled() {
            Err(cancelled_err())
        } else {
            Ok(())
        }
    }
}

pub fn cancelled_err() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, CANCELLED_MSG)
}

/// 判断一个 `io::Error` 是否来自取消。
#[allow(dead_code)] // 库 API：二进制侧统一用 is_cancel_msg 判定
pub fn is_cancel(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Interrupted
}

/// 判断已经转成字符串的错误是否来自取消（GUI 消息层用）。
pub fn is_cancel_msg(msg: &str) -> bool {
    msg == CANCELLED_MSG
}

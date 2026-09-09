//! 库入口：把核心模块暴露为 lib target，供集成测试（tests/）复用。
//! 现有二进制入口 main.rs 不受影响。

pub mod crypto;
pub mod engine;
pub mod paths;
pub mod profile;
pub mod safe;
pub mod shells;
pub mod tarx;
pub mod vgs2;

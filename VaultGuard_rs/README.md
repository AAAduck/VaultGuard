# VaultGuard Source

此目录是 VaultGuard 的 Rust 主源码。发布程序在上级目录的 `VaultGuard.exe`；运行该文件不需要本目录、Rust、Zig 或其他外部资源。

## 架构

| 模块 | 职责 |
| --- | --- |
| `main.rs` | 命令行解析（含 `--password`）、GUI 入口与结果报告 |
| `gui.rs` | egui 窗口（zinc/emerald 暗色主题）、拖放、口令输入、任务进度和日志 |
| `engine.rs` | 加密、还原和流式任务编排；tar 流直通加密管道（明文不落盘） |
| `crypto.rs` | 密钥派生（HKDF/PBKDF2/Argon2id）+ 流式 AES-256-GCM（GHASH 用 ghash crate） |
| `safe.rs` | `.vgsafe` 保险箱会话：VGS2 manifest 懒打开、追加保存、导出/压缩与 VGS1 兼容升级 |
| `shells.rs` | PNG、JPEG、DOCX 容器读写与自动探测 |
| `tarx.rs` | 归档、还原与路径安全检查 |
| `paths.rs` | 输出目录、临时目录、擦除清理和安全命名 |
| `build.rs` | 链接期把产品图标与 comctl32 v6 清单嵌入 EXE（zig rc 生成 .res） |
| `res/` | 伪装外壳背景图与 DOCX 模板（`include_bytes!` 内嵌） |
| `icons/` | 产品图标（`build.rs` 嵌入用） |
| `tests/` | 引擎往返回归测试（对应「验证要求」的可自动化子集） |

## 容器格式与密钥

| 格式 | 密钥 | 定位 |
| --- | --- | --- |
| `VG\x03` | 用户口令 → Argon2id(m=64MiB, t=3, p=1, 随机盐) | 当前默认推荐；KDF 参数随文件头存储 |
| `VG\x02` | 内置主密钥 → HKDF-SHA256 | 无口令便捷模式（防随手翻看） |
| `VG\x01` | 内置主密钥 → PBKDF2(600k) | 旧版，仅解密兼容 |

- AAD 绑定「格式版本 + 外壳类型」，跨外壳改名会被 GCM 认证拒绝；
- 认证标记用常量时间比较；口令错误返回明确报错；
- 三种格式均可正常还原，旧文件无需迁移。

### 保险箱格式

- 新建保险箱为 `VGS2`：50B 全局头后串接数据段（`0x01`）和加密 manifest 段（`0x02`）。段头 CRC32 用于扫描，GCM AAD 是 `"VGS2" + 用途字节（manifest `0x00` / 数据 `0x01`）+ 段序号；序号重排、段拼接都会认证失败。
- 打开只扫描段头并认证最后一份有效 manifest；末尾未完成或认证失败的 manifest 自动回退到上一份完整版本。manifest 一次性读取上限为 64MiB；数据段始终流式处理，不按不可信长度分配内存。
- 新增内容追加一个数据段和新 manifest；删除、改名、移动只追加 manifest。删除立即不可见，但物理数据在压缩前仍留在旧段；手动「压缩保险箱」或自动阈值（垃圾率 >30% 且 >256MB，或 32 份 manifest）会原子重写回收空间。
- `VGS1` 可正常打开；界面明确确认后，首次保存升级为 `VGS2`。格式变更保留 VGS1 解密路径与 VGS2 字节向量测试。

## 构建

工程使用 Windows GNU 目标和 Zig 链接器包装程序，配置位于 `.cargo/config.toml`。构建需要 Rust 工具链与 `D:\ZigTools`（`build.rs` 的 zig 路径可用环境变量 `ZIG_BIN` 覆盖）：

```bat
cargo build --release
cargo test --release
```

产物：

```text
target\x86_64-pc-windows-gnu\release\vaultguard.exe
```

发布前跑 `cargo test --release`（往返矩阵：3 容器 × v2/v3 × 错误口令拒绝等）。发布时只复制该 EXE 到上级目录并命名为 `VaultGuard.exe`。zig 不可用时 build.rs 只发警告不阻断构建（EXE 功能不受影响，仅缺图标/清单）。不要提交或发布 `target/`、运行日志和临时验证文件。

## 验证要求

每次修改加密格式、容器解析或归档逻辑后，至少验证：

1. PNG、JPG、DOCX 各自的加密和还原（`cargo test --release` 覆盖大部分）。
2. 单文件、目录、中文文件名、二进制文件和跨盘输出。
3. v1/v2 旧产物与当前 v3 的解密兼容（旧文件无需迁移）。
4. 还原文件与原始文件的 SHA-256 一致。
5. 口令文件：正确口令还原、错误口令明确报错。

GCM 的认证计算必须保持标准实现兼容。不要在缺少跨实现测试向量的情况下自行修改计数器、GHASH 填充或认证标签逻辑。

## 维护原则

- Rust 是唯一的主实现；不要继续为新功能维护 Python 与 Rust 两套逻辑。
- 新功能优先在 `engine`、`shells`、`gui` 的边界内实现，避免把 GUI、文件系统和密码学流程混在一起。
- 格式兼容性优先于界面和性能优化。任何不兼容变更都需要新的格式版本与迁移策略。
- 主密钥沿用历史格式的内嵌设计。若未来加入用户口令或可替换密钥，必须保留旧格式的明确还原路径。
- 保持「单文件发布」原则：不引入外部资源文件与运行时依赖——字体走系统、图标/模板/清单走内嵌。
- 不手写密码学原语：GHASH/计数器等一律使用 RustCrypto crate。

## 单文件原则

`res/` 的图片与 DOCX 模板在编译时通过 `include_bytes!` 嵌入 EXE；图标与清单由 `build.rs` 在每次 `cargo build` 时自动链接进 EXE；中文字体不随程序分发，GUI 启动时从系统字体目录加载（微软雅黑优先，simhei/Deng/simsun 依次兜底，均缺失则回退默认字体），标题栏与任务栏图标取自内嵌图标资源。

# VGS2 v2.0 发布验收记录（2026-09-10）

> 提交代码的最终官方记录（`v2.0.0` tag 对应源码）。工具：`tools/run_vgs2_bench.ps1` + `vgs2-bench`（本机跑，CI 不跑）。
> 原始数据：`raw/vgs2-target-2026-09-10-record.txt`。每轮独立生成夹具 → 新建空箱 → 添加 → 首次保存 → 打开 → 全量压缩 → VGS1 升级。

## 机器配置

- CPU: AMD Ryzen 7 4800H（8 核 / 16 线程）
- RAM: 16 GiB
- 系统盘: SAMSUNG MZVLB512HBJQ-000L2（NVMe SSD）
- 基准临时目录: `D:\vg2bench_tmp`

## 目标档（10,000 文件 / 5 GiB，独立 3 次）

| run | gen_s | create_s | add_s | save_s | open_s | compact_s | upgrade_s | v1open_s | entries |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | - | - | - | 28.237 | 0.191 | 54.240 | 31.299 | 46.870 | 10000 |
| 2 | - | - | - | 28.132 | 0.187 | 50.218 | 29.050 | 44.533 | 10000 |
| 3 | - | - | - | 27.204 | 0.180 | 52.286 | 29.602 | 44.713 | 10000 |

（gen/add/create 阶段值见原始文件；v1open 为 VGS1 旧格式打开耗时，属一次性兼容路径，不在闸门内。）

## 闸门判定（三次中位数）

| 指标 | 中位数 | 闸门 | 结果 |
| --- | --- | --- | --- |
| manifest 打开（open_s） | **0.187s** | <10s | ✅ |
| 首次保存（save_s） | **28.1s** | <60s | ✅ |
| 全量压缩（compact_s） | **52.3s** | <60s | ✅ |
| VGS1 升级首存（upgrade_s） | **29.6s** | <60s | ✅ |

对比 P4 基线（166.007s / 167.932s）：首次保存提升约 5.9×，全量压缩提升约 3.2×。

## 阶段剖析（--profile，见原始文件）

目标档 save：seg-pack（含 staged-relay + seg-crypt-write）主导，crypto ~16-17s，其余为打包与 fsync。
目标档 compact：seg-decrypt（~19s）+ relay（~20s）+ verify（~6s）+ fsync；无树物化、无逐文件擦除。
目标档 upgrade：legacy-relay + seg-crypt-write + verify，无逐文件重打包。

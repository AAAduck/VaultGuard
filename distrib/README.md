# 分发清单（winget / scoop）

本目录存放 VaultGuard 在 Windows 包管理器上的上架清单。产物来源统一为
GitHub Releases 的 `VaultGuard.exe`（CI 构建，随 tag 生成）。

## 目录

```text
winget/manifests/a/AAAduck/VaultGuard/<version>/   # microsoft/winget-pkgs 目录规范
  AAAduck.VaultGuard.yaml                          # 版本声明（ManifestType: version）
  AAAduck.VaultGuard.installer.yaml                # 安装器（portable 单文件）
  AAAduck.VaultGuard.locale.en-US.yaml             # 英文元数据
  AAAduck.VaultGuard.locale.zh-CN.yaml             # 中文元数据
scoop/VaultGuard.json                              # Scoop 清单（含 checkver/autoupdate）
```

## 上架流程

### Scoop（零门槛，可先上）

Scoop 对清单无签名要求，当前状态与可选动作：

2. **自有 bucket（已就绪，2026-09-11）**：<https://github.com/AAAduck/scoop-bucket>
   —— 用户执行 `scoop bucket add aaaduck https://github.com/AAAduck/scoop-bucket`
   后 `scoop install vaultguard` 即可安装；仓库内 `bucket/VaultGuard.json` 与本目录
   `scoop/VaultGuard.json` 保持同步（改版本/哈希时两处一起改）。
3. **提交到官方 bucket（ScoopInstaller/Extras）**：清单进 `bucket/VaultGuard.json`，
   向 https://github.com/ScoopInstaller/Extras 发起 PR；合入后
   `scoop bucket add extras; scoop install vaultguard`（bucket 内文件名即应用名，
   官方 Extras 统一小写）。

`checkver` 会自动跟踪 GitHub 最新 Release，`autoupdate` 会在新版本发布后
由 Excavator 自动生成更新 PR，日常维护只靠打 tag。

### winget（需签名，配合代码签名决策）

[microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) 的 PR
要求清单必须带代码签名（`winget sign`，需要代码签名证书）。所以 winget 上架
挂在「代码签名」决策之后（见项目路线图 §四）：

- 有证书后：在清单目录执行
  `wingetcreate update AAAduck.VaultGuard --urls <新exe直链> --version <新版本>`，
  对四个 yaml 逐一 `winget sign`，再向 microsoft/winget-pkgs 发起 PR；
- 无证书的过渡期：先用 **Scoop + 手动下载 + SHA256SUMS 校验** 覆盖安装渠道。

### 每次发版的更新清单

1. 打 tag 触发 CI 生成 Release（`VaultGuard.exe` + `SHA256SUMS`）；
2. `Get-FileHash .\VaultGuard.exe -Algorithm SHA256` 拿到新哈希；
3. 同步改 `winget/manifests/a/AAAduck/VaultGuard/<版本>/` 下的版本号与
   `InstallerSha256`，以及 `scoop/VaultGuard.json` 的 `version`/`hash`；
4. scoop 的 `checkver`/`autoupdate` 会自动提示新版本，winget 需手动发起 PR。

## 校验

本地 `VaultGuard.exe` 与 GitHub Release 产物同哈希（v1.3.3 起 CI 保证），
发布前可交叉验证：

```powershell
Get-FileHash .\VaultGuard.exe -Algorithm SHA256
# 输出应与清单中的 InstallerSha256 / hash 一致
```

清单自身的一致性（版本、Release URL、SHA-256 字段）可在仓库根目录运行：

```powershell
.\distrib\verify.ps1
```

CI 会在 Windows 测试任务中自动运行同一检查，避免发布链接或哈希与清单漂移。

# VGS2 保险箱性能基准入口（P4/P5/P7；本机运行，CI 不跑）
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File tools\run_vgs2_bench.ps1
#     [-SkipBuild] [-Profile] [-SmokeRuns 1] [-MediumRuns 1] [-TargetRuns 3] [-Tag 自定义标签]
#
# 默认跑三档：
#   smoke  =   100 文件 /  256 MiB
#   medium = 1,000 文件 /    1 GiB
#   target = 10,000 文件 /    5 GiB （目标档，独立跑 3 次取中位数）
#
# 原始输出落在 docs/benchmarks/raw/，汇总 markdown 落在 docs/benchmarks/。

param(
    [switch]$SkipBuild,
    [switch]$Profile,
    [int]$SmokeRuns = 1,
    [int]$MediumRuns = 1,
    [int]$TargetRuns = 3,
    [string]$Tag = ""
)

$ErrorActionPreference = "Stop"
$rs   = Split-Path -Parent $PSScriptRoot   # .../VaultGuard_rs
$repo = Split-Path -Parent $rs             # 仓库根（含 VaultGuard_rs/ 与 docs/）
$benchDir = Join-Path $repo "docs\benchmarks"
$rawDir   = Join-Path $benchDir "raw"
New-Item -ItemType Directory -Force -Path $rawDir | Out-Null

if (-not $SkipBuild) {
    Write-Host "==> cargo build --release --bin vgs2-bench"
    Push-Location $rs
    cargo build --release --bin vgs2-bench
    if ($LASTEXITCODE -ne 0) { throw "vgs2-bench 构建失败" }
    Pop-Location
}
# .cargo/config.toml 把 target 指到了自定义目录（x86_64-pc-windows-gnu），
# 产物位置不固定，这里在 target/ 下递归找最新的 vgs2-bench.exe。
$exe = (Get-ChildItem -Path (Join-Path $rs "target") -Recurse -Filter "vgs2-bench.exe" |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
if (-not $exe) { throw "找不到 vgs2-bench.exe（先不加 -SkipBuild 构建一次）" }

# 磁盘预算：目标档峰值约 15 GiB（夹具+暂存+物化树+临时容器）。
# 优先使用 D: 盘的大空间临时目录，避免 C: 空间不足。
$benchTmp = Join-Path $env:TEMP "vg2bench"
if (Test-Path "D:\") {
    $free = (Get-PSDrive D).Free
    if ($free -gt 60GB) { $benchTmp = "D:\vg2bench_tmp" }
}
New-Item -ItemType Directory -Force -Path $benchTmp | Out-Null
$env:TEMP = $benchTmp
$env:TMP  = $benchTmp

$stamp = Get-Date -Format "yyyy-MM-dd-HHmm"
if ([string]::IsNullOrWhiteSpace($Tag)) { $Tag = "run" }
$profArgs = @()
if ($Profile) { $profArgs += "--profile" }

function Invoke-Tier {
    param([string]$Name, [int]$Files, [long]$Bytes, [int]$Runs)
    $raw = Join-Path $rawDir "vgs2-$Name-$stamp.txt"
    Write-Host "==> tier=$Name files=$Files bytes=$Bytes runs=$Runs"
    & $exe run --files $Files --total-bytes $Bytes --runs $Runs @profArgs | Tee-Object -FilePath $raw | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "tier=$Name 运行失败" }
    return $raw
}

function Get-Median {
    param($values)
    $v = @($values | Sort-Object)
    if ($v.Count -eq 0) { return 0.0 }
    $m = [int]($v.Count / 2)
    if ($v.Count % 2 -eq 1) { return $v[$m] }
    return ($v[$m - 1] + $v[$m]) / 2.0
}

$tiers = @(
    @{ Name = "smoke";  Files = 100;   Bytes = 256MB * 1;        Runs = $SmokeRuns },
    @{ Name = "medium"; Files = 1000;  Bytes = 1GB;              Runs = $MediumRuns },
    @{ Name = "target"; Files = 10000; Bytes = 5GB;              Runs = $TargetRuns }
)

$summary = New-Object System.Collections.Generic.List[string]
$summary.Add("# VGS2 基准结果（$stamp）")
$summary.Add("")
$summary.Add('> 工具：`tools/run_vgs2_bench.ps1` + `vgs2-bench`（CI 不跑，阶段剖析经 `vaultguard::profile` 运行时开启）。')
$summary.Add("> 方法：每次 run 独立生成夹具 → 新建空箱 → 添加 → 首次保存 → 打开 → 全量压缩；目标档独立跑多次取中位数。")
$summary.Add("")
$summary.Add("## 机器配置")
$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
$ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
$diskModel = (Get-CimInstance Win32_DiskDrive | Select-Object -First 1).Model
$summary.Add("- CPU: $cpu")
$summary.Add("- RAM: ${ram} GiB")
$summary.Add("- 系统盘: $diskModel")
$summary.Add("- 基准临时目录: $benchTmp")
$summary.Add("")

$gate = $true
foreach ($t in $tiers) {
    $raw = Invoke-Tier -Name $t.Name -Files $t.Files -Bytes $t.Bytes -Runs $t.Runs
    $lines = Get-Content $raw | Where-Object { $_ -match "^run=" }
    $summary.Add("## tier=$($t.Name)（$($t.Files) 文件 / $([math]::Round($t.Bytes / 1MB, 1)) MiB，runs=$($lines.Count))")
    $summary.Add("")
    $summary.Add("| run | gen_s | create_s | add_s | save_s | open_s | compact_s | entries |")
    $summary.Add("| --- | --- | --- | --- | --- | --- | --- | --- |")
    $saves = @(); $opens = @(); $compacts = @()
    foreach ($ln in $lines) {
        $run = [regex]::Match($ln, "run=(\d+)").Groups[1].Value
        $gen  = [regex]::Match($ln, "gen_s=([\d.]+)").Groups[1].Value
        $cre  = [regex]::Match($ln, "create_s=([\d.]+)").Groups[1].Value
        $add  = [regex]::Match($ln, "add_s=([\d.]+)").Groups[1].Value
        $save = [regex]::Match($ln, "save_s=([\d.]+)").Groups[1].Value
        $open = [regex]::Match($ln, "open_s=([\d.]+)").Groups[1].Value
        $comp = [regex]::Match($ln, "compact_s=([\d.]+)").Groups[1].Value
        $ent  = [regex]::Match($ln, "entries=(\d+)").Groups[1].Value
        $saves += [double]$save; $opens += [double]$open; $compacts += [double]$comp
        $summary.Add("| $run | $gen | $cre | $add | $save | $open | $comp | $ent |")
    }
    $msave = Get-Median $saves; $mopen = Get-Median $opens; $mcomp = Get-Median $compacts
    $summary.Add("")
    $summary.Add("**中位数：open=$([math]::Round($mopen,3))s，save=$([math]::Round($msave,2))s，compact=$([math]::Round($mcomp,2))s**")
    $status = @()
    if ($mopen -lt 10)  { $status += "open<10s ✔" }  else { $status += "open<10s ✘"; $gate = $false }
    if ($msave -lt 60)  { $status += "save<60s ✔" }  else { $status += "save<60s ✘"; $gate = $false }
    if ($mcomp -lt 60)  { $status += "compact<60s ✔" } else { $status += "compact<60s ✘"; $gate = $false }
    $summary.Add("")
    $summary.Add("**目标闸门：$($status -join '，')**")
    $summary.Add("")
    if ($Profile) {
        $summary.Add("阶段剖析（--profile）见原始文件 `raw/vgs2-$($t.Name)-$stamp.txt` 中的 `profile[...]` 行。")
        $summary.Add("")
    }
}

$mdPath = Join-Path $benchDir "vgs2-$Tag-$stamp.md"
$summary | Set-Content -Encoding UTF8 $mdPath
Write-Host ""
Write-Host "汇总: $mdPath"
Write-Host "原始: $rawDir\vgs2-*-$stamp.txt"
if ($gate) { Write-Host "目标档闸门: 全部达标" } else { Write-Host "目标档闸门: 未全部达标（详见汇总）" }
exit 0

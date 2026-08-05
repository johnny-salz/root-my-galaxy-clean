param(
    [string]$Serial,
    [string]$OutDir = (Join-Path (Get-Location) "target-input"),
    [string]$RootHelper = "/data/local/tmp/rmg-root"
)

$ErrorActionPreference = "Stop"
$adb = (Get-Command adb -ErrorAction Stop).Source
$device = if ($Serial) { @("-s", $Serial) } else { @() }

function Invoke-Adb {
    $result = & $adb @device @args 2>&1
    if ($LASTEXITCODE -ne 0) { throw "adb failed: $($result -join "`n")" }
    return ($result -join "`n")
}

if (-not $Serial) {
    $online = @(& $adb devices | Select-String "`tdevice$")
    if ($online.Count -ne 1) { throw "need one adb device, or pass -Serial" }
}
New-Item -ItemType Directory -Force $OutDir | Out-Null

$facts = @(
    "model=$(Invoke-Adb shell getprop ro.product.model)",
    "build=$(Invoke-Adb shell getprop ro.build.version.incremental)",
    "kernel=$(Invoke-Adb shell uname -r)",
    "kernel_version=$(Invoke-Adb shell cat /proc/version)",
    "sched_blocked_reason_id=$(Invoke-Adb shell cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id)",
    "mm_page_alloc_id=$(Invoke-Adb shell "$RootHelper -c `"cat /sys/kernel/tracing/events/kmem/mm_page_alloc/id`"")",
    "kmem_cache_alloc_id=$(Invoke-Adb shell "$RootHelper -c `"cat /sys/kernel/tracing/events/kmem/kmem_cache_alloc/id`"")"
)
$facts | Set-Content -Encoding ascii (Join-Path $OutDir "facts.txt")
Invoke-Adb shell "$RootHelper -c `"cat /proc/kallsyms`"" | Set-Content -Encoding ascii (Join-Path $OutDir "kallsyms.txt")

$remoteConfig = "/data/local/tmp/rmg-kernel.config.gz"
Invoke-Adb shell "$RootHelper -c `"cp /proc/config.gz $remoteConfig && chmod 0644 $remoteConfig`"" | Out-Null
& $adb @device pull $remoteConfig (Join-Path $OutDir "kernel.config.gz")
if ($LASTEXITCODE -ne 0) { throw "config pull failed" }
Write-Host "target data saved at $OutDir"

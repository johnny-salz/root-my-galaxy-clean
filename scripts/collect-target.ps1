param(
    [string]$Serial,
    [string]$OutDir = (Join-Path (Get-Location) "target-input"),
    [string]$RootHelper = "/data/local/tmp/rmg-root"
)

$ErrorActionPreference = "Stop"
$adb = (Get-Command adb -ErrorAction Stop).Source
$device = if ($Serial) { @("-s", $Serial) } else { @() }

function Invoke-Adb {
    $savedErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $result = & $adb @device @args 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorAction
    }
    if ($exitCode -ne 0) { throw "adb $($args -join ' ') failed ($exitCode): $($result -join "`n")" }
    return ($result -join "`n")
}

if (-not $Serial) {
    $online = @(& $adb devices | Select-String "`tdevice$")
    if ($online.Count -ne 1) { throw "need one adb device, or pass -Serial" }
}
New-Item -ItemType Directory -Force $OutDir | Out-Null

$remoteCollector = "/data/local/tmp/rmg-collect-target"
$remoteKallsyms = "/data/local/tmp/rmg-kallsyms.txt"
$remotePageAlloc = "/data/local/tmp/rmg-mm-page-alloc.id"
$remoteCacheAlloc = "/data/local/tmp/rmg-kmem-cache-alloc.id"
$remoteConfig = "/data/local/tmp/rmg-kernel.config.gz"
$localCollector = [IO.Path]::GetTempFileName()
$localKallsyms = Join-Path $OutDir "kallsyms.txt"
$localPageAlloc = Join-Path $OutDir "mm-page-alloc.id"
$localCacheAlloc = Join-Path $OutDir "kmem-cache-alloc.id"
$localConfig = Join-Path $OutDir "kernel.config.gz"
$collector = @"
#!/system/bin/sh
set -eu
cat /proc/kallsyms > $remoteKallsyms
cat /sys/kernel/tracing/events/kmem/mm_page_alloc/id > $remotePageAlloc
cat /sys/kernel/tracing/events/kmem/kmem_cache_alloc/id > $remoteCacheAlloc
cp /proc/config.gz $remoteConfig
chmod 0644 $remoteKallsyms $remotePageAlloc $remoteCacheAlloc $remoteConfig
"@
[IO.File]::WriteAllText($localCollector, ($collector -replace "`r`n", "`n"), [Text.Encoding]::ASCII)

try {
    Invoke-Adb push $localCollector $remoteCollector | Out-Null
    Invoke-Adb shell chmod 0755 $remoteCollector | Out-Null
    Invoke-Adb shell $RootHelper $remoteCollector | Out-Null

    foreach ($item in @(
        @($remoteKallsyms, $localKallsyms),
        @($remotePageAlloc, $localPageAlloc),
        @($remoteCacheAlloc, $localCacheAlloc),
        @($remoteConfig, $localConfig)
    )) {
        Invoke-Adb pull $item[0] $item[1] | Out-Null
    }

    $facts = @(
        "model=$(Invoke-Adb shell getprop ro.product.model)",
        "build=$(Invoke-Adb shell getprop ro.build.version.incremental)",
        "kernel=$(Invoke-Adb shell uname -r)",
        "kernel_version=$(Invoke-Adb shell cat /proc/version)",
        "sched_blocked_reason_id=$(Invoke-Adb shell cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id)",
        "mm_page_alloc_id=$((Get-Content -LiteralPath $localPageAlloc -Raw).Trim())",
        "kmem_cache_alloc_id=$((Get-Content -LiteralPath $localCacheAlloc -Raw).Trim())"
    )
    $facts | Set-Content -Encoding ascii (Join-Path $OutDir "facts.txt")
} finally {
    Remove-Item -LiteralPath $localCollector -Force
    Invoke-Adb shell rm -f $remoteCollector $remoteKallsyms $remotePageAlloc $remoteCacheAlloc $remoteConfig | Out-Null
}
Write-Host "target data saved at $OutDir"

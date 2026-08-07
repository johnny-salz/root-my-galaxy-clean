param(
    [string]$Serial,
    [switch]$StartChain,
    [int]$PollSeconds = 30
)

$adb = (Get-Command adb -ErrorAction Stop).Source
$device = if ($Serial) { @("-s", $Serial) } else { @() }

function Invoke-Device([string]$Command) {
    & $adb @device shell $Command 2>&1
}

$prefetch = (Invoke-Device "A53_PREFETCH_EDGE_RUN=8 A53_PREFETCH_REPEATS=3 /data/local/tmp/qroutehold2 prefetch") -join "`n"
if ($prefetch -notmatch "prefetch consensus=(0x[0-9a-fA-F]+)") {
    throw "prefetch consensus missing`n$prefetch"
}
$slide = $Matches[1]
Write-Output "prefetch consensus=$slide"

if (-not $StartChain) {
    exit 0
}

Invoke-Device "rm -rf /data/local/tmp/clean-oracle; mkdir -p /data/local/tmp/clean-oracle; A536_ORACLE_DETACH=1 A536_SHADOW_DIR=/data/local/tmp/clean-oracle nohup /data/local/tmp/root-bridge-a536-v2 chain-auto /data/local/tmp/qroutehold2 >/data/local/tmp/clean-chain.log 2>&1 &" | Out-Null
$deadline = (Get-Date).AddSeconds($PollSeconds)
while ((Get-Date) -lt $deadline) {
    $log = (Invoke-Device "tail -80 /data/local/tmp/clean-chain.log 2>/dev/null") -join "`n"
    if ($log -match "ROOT_OK") {
        Write-Output ($log | Select-String "auto slide|ROOT_OK|oracle detach")
        $id = (Invoke-Device "/data/local/tmp/rmg-root -c id") -join "`n"
        Write-Output $id
        exit 0
    }
    if ($log -match "FAIL|CHAIN_FAIL|ROOT_FAIL") {
        throw "clean chain failed`n$log"
    }
    Start-Sleep -Milliseconds 500
}
throw "clean chain timeout"

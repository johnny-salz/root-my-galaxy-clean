param(
    [string]$Serial,
    [string]$RootHelper = "/data/local/tmp/rmg-root",
    [string]$OutFile = (Join-Path $PSScriptRoot "..\debug\kernel-log.txt")
)

$ErrorActionPreference = "Stop"
$adb = (Get-Command adb -ErrorAction Stop).Source
$device = if ($Serial) { @("-s", $Serial) } else { @() }

function Invoke-Root([string]$command) {
    $remote = "$RootHelper -c `"$command`""
    $result = & $adb @device shell $remote 2>&1
    if ($LASTEXITCODE -ne 0) { throw "root log read failed: $($result -join "`n")" }
    return ($result -join "`n")
}

$id = Invoke-Root "id"
if ($id -notmatch "uid=0\(root\).*context=u:r:kernel:s0") {
    throw "need kernel-context root, got: $id"
}

$dir = Split-Path -Parent $OutFile
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$text = @(
    "id"
    $id
    "bootreason"
    (Invoke-Root "getprop ro.boot.bootreason")
    "pstore"
    (Invoke-Root "ls -la /sys/fs/pstore")
    "dmesg"
    (Invoke-Root "dmesg | tail -n 300")
)
$text -join "`n" | Set-Content -LiteralPath $OutFile -Encoding utf8
Get-Content -LiteralPath $OutFile

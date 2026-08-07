param(
    [string]$Serial,
    [string]$RootHelper = "/data/local/tmp/rmg-root",
    [string]$OutFile = (Join-Path $PSScriptRoot "..\debug\kernel-log.txt")
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

$id = Invoke-Adb shell $RootHelper -c id
if ($id -notmatch "uid=0\(root\).*context=u:r:kernel:s0") {
    throw "need kernel-context root, got: $id"
}

$remoteReader = "/data/local/tmp/rmg-read-kernel-log"
$localReader = [IO.Path]::GetTempFileName()
$reader = @"
#!/system/bin/sh
set -u
echo id
id
echo bootreason
getprop ro.boot.bootreason
echo pstore
ls -la /sys/fs/pstore
echo dmesg
dmesg | tail -n 300
"@
[IO.File]::WriteAllText($localReader, ($reader -replace "`r`n", "`n"), [Text.Encoding]::ASCII)

$dir = Split-Path -Parent $OutFile
New-Item -ItemType Directory -Force -Path $dir | Out-Null
try {
    Invoke-Adb push $localReader $remoteReader | Out-Null
    Invoke-Adb shell chmod 0755 $remoteReader | Out-Null
    $text = Invoke-Adb shell $RootHelper $remoteReader
    $text | Set-Content -LiteralPath $OutFile -Encoding utf8
} finally {
    Remove-Item -LiteralPath $localReader -Force
    Invoke-Adb shell rm -f $remoteReader | Out-Null
}
Get-Content -LiteralPath $OutFile

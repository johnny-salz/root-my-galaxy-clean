param(
    [Parameter(Mandatory)]
    [string]$Serial,
    [string]$Dir = "/data/local/tmp/clean-oracle",
    [ValidateSet("read", "write", "mapped", "windows", "quit")]
    [string]$Operation = "read",
    [string]$Address,
    [int]$Length = 8,
    [string]$Value
)

$ErrorActionPreference = "Stop"
$adb = (Get-Command adb -ErrorAction Stop).Source

if ($Dir -notmatch "^/[A-Za-z0-9._/-]+$") { throw "bad oracle dir" }
if ($Operation -in @("read", "write", "mapped") -and $Address -notmatch "^(0x)?[0-9a-fA-F]+$") {
    throw "bad address"
}
if ($Operation -eq "read" -and ($Length -lt 1 -or $Length -gt 0x4000)) {
    throw "bad length"
}
if ($Operation -eq "write" -and $Value -notmatch "^[0-9a-fA-F]+$|^0x[0-9a-fA-F]+$") {
    throw "bad value"
}
if ($Operation -eq "write" -and $Value.StartsWith("0x")) {
    $Value = $Value.Substring(2)
}
if ($Operation -eq "write" -and ($Value.Length -eq 0 -or ($Value.Length % 2))) {
    throw "bad value length"
}
if ($Operation -eq "windows" -and $Address) {
    throw "windows takes no address"
}

$request = switch ($Operation) {
    "read" { "read $Address $Length" }
    "mapped" { "mapped $Address" }
    "write" { "write $Address $Value" }
    "windows" { "windows" }
    "quit" { "quit" }
}
$requestPath = "$Dir/request"
$responsePath = "$Dir/response"
$temporaryPath = "$Dir/request.tmp"
$remote = "rm -f $requestPath $responsePath $temporaryPath; printf '%s\n' '$request' > $temporaryPath; mv $temporaryPath $requestPath"
& $adb -s $Serial shell $remote | Out-Null

for ($index = 0; $index -lt 100; $index++) {
    $ready = ((& $adb -s $Serial shell "test -f $responsePath && echo ready" 2>&1) -join "`n").Trim()
    if ($ready -eq "ready") { break }
    Start-Sleep -Milliseconds 100
}
$response = ((& $adb -s $Serial shell "cat $responsePath" 2>&1) -join "`n").Trim()
& $adb -s $Serial shell "rm -f $responsePath" | Out-Null
if (-not $response) { throw "oracle response timeout" }
Write-Output $response

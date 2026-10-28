# Windows: a served `exec` and `shell` run with the ACCOUNT's environment.
#
#   pwsh -File cli/tests/windows-user-env-gates.ps1 -Bin <tunlion.exe> [-Python <python>]
#
# Hermetic: two config dirs, a local backend, reciprocal pairing; boxB serves.
# boxB's daemon starts with one variable only it has (TUNLION_DAEMON_ONLY_PROBE).
# AFTER the daemon is up, a user variable is set and a new directory appended
# to the USER PATH in HKCU\Environment (restored on exit), holding a new tool.
# Then `exec` and a `shell` session each run one probe script on boxB.
#
# Gates, for exec (E*) and shell (S*):
#   1 OS and NUMBER_OF_PROCESSORS are present (the account block, not the
#     old allowlist, which had neither)
#   2 the user variable set after the daemon started is visible
#   3 the tool in the PATH directory added after the daemon started is found
#   4 the daemon-only variable is NOT visible
# plus E5: the new tool runs as a bare `exec` argv[0] (resolved on the fresh PATH),
# and S5: the shell is the user's default PowerShell with its profile loaded
# (a variable the user's profile.ps1 sets is visible).
param(
    [Parameter(Mandatory = $true)][string]$Bin,
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
$Bin = (Resolve-Path -LiteralPath $Bin).Path
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$nonce = [guid]::NewGuid().ToString('N').Substring(0, 10)
$work = Join-Path ([System.IO.Path]::GetTempPath()) "wt-userenv-$nonce"
New-Item -ItemType Directory -Force -Path $work | Out-Null
$pass = 0; $fail = 0; $failed = @()
function Ok([string]$m) { Write-Host "PASS: $m"; $script:pass++ }
function Bad([string]$m) { Write-Host "FAIL: $m"; $script:fail++; $script:failed += $m }

$userVar = "TUNLION_ENVPROBE_USER_$nonce"
$userVal = "user-value-$nonce"
$leakVar = 'TUNLION_DAEMON_ONLY_PROBE'
$leakVal = "daemon-only-$nonce"
$toolDir = Join-Path $work "late-bin"
$tool = "envprobe$nonce"
$savedUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$procs = @()
$docs = [Environment]::GetFolderPath('MyDocuments')
$profiles = @((Join-Path $docs 'PowerShell\profile.ps1'), (Join-Path $docs 'WindowsPowerShell\profile.ps1'))
$savedProfiles = @{}
foreach ($pf in $profiles) { $savedProfiles[$pf] = if (Test-Path -LiteralPath $pf) { Get-Content -LiteralPath $pf -Raw } else { $null } }

try {
    # ---------------------------------------------------------------- backend
    $port = Get-Random -Minimum 20000 -Maximum 40000
    $server = "http://127.0.0.1:$port"
    $backend = Join-Path $repo 'backend'
    $env:PORT = "$port"; $env:FIL_ASYNC_MODE = 'eventlet'; $env:FIL_SELF_MONKEYPATCH = '1'; $env:FIL_CLAIM_LIMIT = '1000000'
    $procs += Start-Process -FilePath $Python -ArgumentList 'app.py' -WorkingDirectory $backend -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $work 'backend.out') -RedirectStandardError (Join-Path $work 'backend.err')
    Remove-Item Env:PORT, Env:FIL_ASYNC_MODE, Env:FIL_SELF_MONKEYPATCH, Env:FIL_CLAIM_LIMIT
    $up = $false
    for ($i = 0; $i -lt 60 -and -not $up; $i++) {
        Start-Sleep -Milliseconds 500
        try { Invoke-RestMethod "$server/api/health" -TimeoutSec 2 | Out-Null; $up = $true } catch { }
    }
    if (-not $up) { Get-Content (Join-Path $work 'backend.err') | Write-Host; throw "no backend at $server" }

    # ---------------------------------------------------------------- pairing
    $da = Join-Path $work 'A'; $db = Join-Path $work 'B'; $drop = Join-Path $work 'Bdrop'
    New-Item -ItemType Directory -Force -Path $da, $db, $drop | Out-Null
    $secret = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) })
    "[{`"name`":`"boxB`",`"secret`":`"$secret`"}]" | Set-Content -LiteralPath (Join-Path $da 'devices.json') -Encoding Ascii
    "[{`"name`":`"boxA`",`"secret`":`"$secret`"}]" | Set-Content -LiteralPath (Join-Path $db 'devices.json') -Encoding Ascii

    # boxB's daemon, with a variable only it has.
    $env:TUNLION_CONFIG_DIR = $db; $env:TUNLION_NAME = 'boxB'; $env:TUNLION_L2 = '1'
    $env:TUNLION_L3_USERSPACE = '1'; $env:TUNLION_CAP_AUTHORITATIVE = '0'
    Set-Item -Path "Env:$leakVar" -Value $leakVal
    & $Bin grant boxA shell 2>&1 | Write-Host
    $procs += Start-Process -FilePath $Bin -PassThru -NoNewWindow `
        -ArgumentList "up --userspace --shell --i-know --dir `"$drop`" --server $server" `
        -RedirectStandardOutput (Join-Path $work 'upB.out') -RedirectStandardError (Join-Path $work 'upB.err')
    Remove-Item "Env:$leakVar", Env:TUNLION_NAME, Env:TUNLION_L2
    Start-Sleep -Seconds 4

    # --------------------------------- the user's environment changes NOW
    New-Item -ItemType Directory -Force -Path $toolDir | Out-Null
    "@echo off`r`necho TOOL-RAN-$nonce`r`n" | Set-Content -LiteralPath (Join-Path $toolDir "$tool.cmd") -Encoding Ascii
    [Environment]::SetEnvironmentVariable($userVar, $userVal, 'User')
    [Environment]::SetEnvironmentVariable('Path', ($(if ($savedUserPath) { "$savedUserPath;" } else { '' }) + $toolDir), 'User')
    foreach ($pf in $profiles) {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $pf) | Out-Null
        Add-Content -LiteralPath $pf -Value "`$env:TUNLION_PROFILE_PROBE = 'profile-ran-$nonce'"
    }

    $probe = Join-Path $work 'probe.cmd'
    @(
        '@echo off'
        'echo PROBE-OS=%OS%'
        'echo PROBE-NUM=%NUMBER_OF_PROCESSORS%'
        "echo PROBE-USER=%$userVar%"
        "echo PROBE-LEAK=%$leakVar%"
        "where $tool >nul 2>&1 && echo PROBE-TOOL=found || echo PROBE-TOOL=missing"
        'echo PROBE-PROFILE=%TUNLION_PROFILE_PROBE%'
    ) -join "`r`n" | Set-Content -LiteralPath $probe -Encoding Ascii

    $env:TUNLION_CONFIG_DIR = $da; $env:TUNLION_NAME = 'boxA'
    function Run-Tunlion([string]$label, [string[]]$a) {
        $out = Join-Path $work "$label.out"; $err = Join-Path $work "$label.err"
        $p = Start-Process -FilePath $Bin -ArgumentList (@('--server', $server) + $a | ForEach-Object {
                if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -PassThru -NoNewWindow `
            -RedirectStandardOutput $out -RedirectStandardError $err -RedirectStandardInput (Join-Path $work 'empty.in')
        $null = $p.Handle
        if (-not $p.WaitForExit(90000)) { $p.Kill(); Write-Host "$label timed out" }
        $text = (Get-Content -LiteralPath $out -Raw) + "`n" + (Get-Content -LiteralPath $err -Raw)
        Write-Host "---- $label (exit $($p.ExitCode)) ----"; Write-Host $text
        return $text
    }
    '' | Set-Content -LiteralPath (Join-Path $work 'empty.in')

    function Check([string]$k, [string]$text) {
        if ($text -match 'PROBE-OS=Windows_NT' -and $text -match 'PROBE-NUM=\d+') {
            Ok "${k}1: OS and NUMBER_OF_PROCESSORS reach the child"
        } else { Bad "${k}1: OS / NUMBER_OF_PROCESSORS missing" }
        if ($text -match [regex]::Escape("PROBE-USER=$userVal")) {
            Ok "${k}2: a user variable set after the daemon started is visible"
        } else { Bad "${k}2: the user variable set after the daemon started is missing" }
        if ($text -match 'PROBE-TOOL=found') {
            Ok "${k}3: a tool on a user PATH entry added after the daemon started is found"
        } else { Bad "${k}3: the late PATH entry is not on the child's PATH" }
        if ($text -match 'PROBE-LEAK=' -and $text -notmatch [regex]::Escape($leakVal)) {
            Ok "${k}4: the daemon-only variable does not reach the child"
        } else { Bad "${k}4: the daemon-only variable reached the child (or the probe did not run)" }
    }

    $execText = Run-Tunlion 'exec' @('exec', 'boxB', '--', $probe)
    Check 'E' $execText
    $toolText = Run-Tunlion 'exec-tool' @('exec', 'boxB', '--', $tool)
    if ($toolText -match "TOOL-RAN-$nonce") {
        Ok 'E5: a tool installed after the daemon started runs as a bare exec argv[0]'
    } else { Bad 'E5: the late tool was not found as a bare exec argv[0]' }
    $shellText = Run-Tunlion 'shell' @('shell', 'boxB', '--', $probe)
    Check 'S' $shellText
    if ($shellText -match "PROBE-PROFILE=profile-ran-$nonce") {
        Ok 'S5: the shell is the user''s PowerShell with its profile loaded'
    } else { Bad 'S5: the user''s PowerShell profile did not run in the shell' }
} finally {
    [Environment]::SetEnvironmentVariable($userVar, $null, 'User')
    [Environment]::SetEnvironmentVariable('Path', $savedUserPath, 'User')
    foreach ($pf in $profiles) {
        if ($null -eq $savedProfiles[$pf]) { Remove-Item -LiteralPath $pf -Force -ErrorAction SilentlyContinue }
        else { Set-Content -LiteralPath $pf -Value $savedProfiles[$pf] -NoNewline }
    }
    foreach ($p in $procs) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
    if ($fail -gt 0 -or $pass -eq 0) {
        foreach ($f in @('upB.err', 'upB.out', 'backend.err')) {
            $path = Join-Path $work $f
            if (Test-Path $path) { Write-Host "---- $f (tail) ----"; Get-Content $path -Tail 40 | Write-Host }
        }
    }
}
Write-Host "windows user-env gates: $pass passed, $fail failed$(if ($failed) { ': ' + ($failed -join '; ') })"
if ($fail -gt 0 -or $pass -ne 10) { exit 1 }
exit 0

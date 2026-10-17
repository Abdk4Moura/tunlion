# tunlion installer (Windows) - https://tunlion.autumated.com/install.ps1
#
#   irm https://tunlion.autumated.com/install.ps1 | iex
#
# Detects your platform, downloads the latest release .zip from GitHub, verifies
# its SHA-256 against the release's SHA256SUMS, and installs tunlion.exe (with
# the bundled wintun.dll) to %LOCALAPPDATA%\Programs\tunlion, adding it to your
# user PATH. Override the location with $env:TUNLION_INSTALL_DIR. No admin, no
# telemetry. Source: scripts/install.ps1 in https://github.com/Abdk4Moura/tunlion
#
# All users (prompts UAC once):
#
#   & ([scriptblock]::Create((irm https://tunlion.autumated.com/install.ps1))) -AllUsers
#
# installs to %ProgramFiles%\tunlion, adds it to the MACHINE PATH, and runs the
# installed `tunlion.exe up --install` once so the always-on receiver is
# registered. If the shell is not elevated it re-launches itself through UAC
# with the same arguments; it never falls back to a per-user install.
#
# Remove:
#
#   & ([scriptblock]::Create((irm https://tunlion.autumated.com/install.ps1))) -Uninstall
#   & ([scriptblock]::Create((irm https://tunlion.autumated.com/install.ps1))) -Uninstall -AllUsers
#
# -DryRun prints the resolved scope, directory and PATH target without writing.
# -Archive <zip> installs from a local release archive (SHA256SUMS beside it),
# which is also how CI exercises the install path without the GitHub API.
#
# Prefer a package manager? `winget install Abdk4Moura.Tunlion` works too.

param(
    [switch]$AllUsers,
    [switch]$Uninstall,
    [switch]$DryRun,
    [string]$Archive,
    [string]$Checksums
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = 'Abdk4Moura/tunlion'

function Say([string]$m) { Write-Host "tunlion: $m" -ForegroundColor Cyan }
function Die([string]$m) { Write-Host "tunlion: $m" -ForegroundColor Red; exit 1 }

# ------------------------------------------------------------ install scope
# AllUsers is machine-wide by definition; TUNLION_INSTALL_DIR only overrides
# the per-user location. Keeping those separate means a stray env var can
# never turn an all-users request into a half-per-user install.
$Scope = if ($AllUsers) { 'Machine' } else { 'User' }
$InstallDir = if ($AllUsers) {
    Join-Path $env:ProgramFiles 'tunlion'
} elseif ($env:TUNLION_INSTALL_DIR) {
    $env:TUNLION_INSTALL_DIR
} else {
    Join-Path $env:LOCALAPPDATA 'Programs\tunlion'
}

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $id
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Re-launch this exact script (and the arguments the user gave) through UAC.
# A script piped to iex has no file path, so it is first saved from the same
# official URL to a temp file; it is removed after the elevated run.
function Invoke-ElevatedSelf($Bound, [string]$ScriptPath) {
    $action = if ($Uninstall) { 'removal' } else { 'install' }
    $tempScript = $null
    if (-not $ScriptPath) {
        # `irm | iex` has no file to re-launch. Save the same official script
        # to a temp file so UAC can run it with these exact arguments.
        $tempScript = Join-Path ([System.IO.Path]::GetTempPath()) (
            'tunlion-install-' + [System.IO.Path]::GetRandomFileName() + '.ps1')
        Say 'saving the installer to a temp file so it can be re-launched elevated ...'
        try {
            Invoke-WebRequest -Uri 'https://tunlion.autumated.com/install.ps1' -OutFile $tempScript
            $ScriptPath = $tempScript
        } catch {
            Die @"
all-users $action needs Administrator, and the installer could not be saved for elevation: $($_.Exception.Message)
Open an Administrator PowerShell and run:
  `$s = Join-Path `$env:TEMP 'tunlion-install.ps1'
  irm https://tunlion.autumated.com/install.ps1 -OutFile `$s
  & `$s -AllUsers$(if ($Uninstall) { ' -Uninstall' })
"@
        }
    }
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"")
    foreach ($k in $Bound.Keys) {
        $v = $Bound[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) {
            if ($v.IsPresent) { $argList += "-$k" }
        } elseif ($k -in @('Archive', 'Checksums')) {
            # Resolve now: the elevated process starts in another directory, so
            # a relative archive path would otherwise point at nothing.
            $argList += "-$k"
            $argList += "`"$(if (Test-Path -LiteralPath $v) { (Resolve-Path -LiteralPath $v).Path } else { $v })`""
        } else {
            $argList += "-$k"
            $argList += "`"$v`""
        }
    }
    $argLine = $argList -join ' '
    Say "requesting Administrator (UAC) to complete the all-users $action ..."
    try {
        $hostExe = (Get-Process -Id $PID).Path
        $p = Start-Process -FilePath $hostExe -Verb RunAs -ArgumentList $argLine -Wait -PassThru
    } catch {
        Die "elevation was declined or failed; nothing was changed. Run this in an Administrator shell: $argLine"
    } finally {
        if ($tempScript) { Remove-Item -Force -LiteralPath $tempScript -ErrorAction SilentlyContinue }
    }
    exit $p.ExitCode
}

if ($AllUsers -and -not $DryRun -and -not (Test-Elevated)) {
    Invoke-ElevatedSelf -Bound $PSBoundParameters -ScriptPath $PSCommandPath
}

# ---------------------------------------------------------------- clean up
# Remove the files, the PATH entry and the autostart this installer created.
# It does not touch tunlion config or transfers; a running daemon is stopped so
# Windows releases the executable before deletion.
function Remove-FromPath([string]$target, [string]$dir) {
    $cur = [Environment]::GetEnvironmentVariable('Path', $target)
    if (-not $cur) { return }
    $kept = @($cur -split ';' | Where-Object {
        $_ -and ($_.TrimEnd('\') -ne $dir.TrimEnd('\'))
    })
    [Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), $target)
}

function Add-ToPath([string]$target, [string]$dir) {
    $cur = [Environment]::GetEnvironmentVariable('Path', $target)
    $entries = @($cur -split ';' | Where-Object { $_ })
    if (($entries | Where-Object { $_.TrimEnd('\') -eq $dir.TrimEnd('\') }) -eq $null) {
        [Environment]::SetEnvironmentVariable('Path', ((@($cur) + $dir) -join ';').TrimStart(';'), $target)
        $env:Path = "$env:Path;$dir"
        Say "added $dir to the $target PATH - open a new terminal for it to take effect"
    }
}

function Remove-FileWithRetry([string]$path) {
    for ($i = 0; $i -lt 10; $i++) {
        if (-not (Test-Path -LiteralPath $path)) { return }
        try {
            Remove-Item -Force -LiteralPath $path -ErrorAction Stop
            return
        } catch {
            Start-Sleep -Milliseconds 200
        }
    }
    Die "could not remove $path (still in use); close tunlion and retry"
}

if ($DryRun) {
    Say 'dry run: no files, PATH entries or services were changed'
    Say "  scope:       $(if ($AllUsers) { 'all users' } else { 'current user' })"
    Say "  install dir: $InstallDir"
    Say "  PATH target: $Scope"
    if ($Uninstall) {
        Say "  would remove: tunlion.exe and wintun.dll from $InstallDir"
        Say "  would remove: $InstallDir from the $Scope PATH"
        Say '  would remove: the Tunlion logon autostart entry'
    }
    exit 0
}

if ($Uninstall) {
    Say "uninstalling tunlion from $InstallDir ($Scope)"
    Get-Process -Name tunlion -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300

    # Every autostart form this project has ever registered. Each is
    # best-effort: an entry that is not there is not an error.
    & reg.exe delete 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' /v Tunlion /f 2>$null | Out-Null
    & schtasks.exe /delete /tn Tunlion /f 2>$null | Out-Null
    if (Test-Elevated) { & sc.exe delete tunlion 2>$null | Out-Null }

    Remove-FromPath $Scope $InstallDir
    foreach ($f in @('tunlion.exe', 'wintun.dll')) {
        Remove-FileWithRetry (Join-Path $InstallDir $f)
    }
    if ((Test-Path -LiteralPath $InstallDir) -and
        @(Get-ChildItem -Force -LiteralPath $InstallDir).Count -eq 0) {
        Remove-Item -Force -LiteralPath $InstallDir
    }
    Say 'removed; open a new terminal to pick up the PATH change'
    exit 0
}

# ----------------------------------------------------------- platform detect
# We ship an x64 build (x86_64-pc-windows-msvc); it runs natively on x64 and via
# emulation on ARM64 Windows, so target x64 in both cases.
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -notin @('AMD64', 'ARM64', 'x86')) { Die "unsupported architecture: $arch" }
if ($arch -eq 'ARM64') { Say 'ARM64 detected - installing the x64 build (runs via emulation)' }
$Target = 'x86_64-pc-windows-msvc'
$Asset = "tunlion-$Target.zip"

# ------------------------------------------------------------------- source
# -Archive is a local release zip plus its SHA256SUMS (or -Checksums). The
# checksum check below is identical for local and downloaded archives.
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("tunlion-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
    if ($Archive) {
        if (-not (Test-Path -LiteralPath $Archive)) { Die "archive not found: $Archive" }
        $ZipPath = (Resolve-Path -LiteralPath $Archive).Path
        $AssetName = Split-Path -Leaf $ZipPath
        if ($Checksums -and -not (Test-Path -LiteralPath $Checksums)) {
            Die "checksum file not found: $Checksums"
        }
        $SumsPath = if ($Checksums) {
            (Resolve-Path -LiteralPath $Checksums).Path
        } else {
            Join-Path (Split-Path -Parent $ZipPath) 'SHA256SUMS'
        }
        if (-not (Test-Path -LiteralPath $SumsPath)) {
            Die "no SHA256SUMS beside $ZipPath; pass -Checksums <file>"
        }
        $Tag = "local archive $AssetName"
        Say "installing tunlion from $AssetName ..."
    } else {
        # CLI releases are tagged cli-vX.Y.Z. Pick the HIGHEST stable version
        # (the API's order is not newest-first); prereleases (cli-v0.2.1-beta.1)
        # are skipped unless $env:TUNLION_CHANNEL = 'beta'. Falls back to the
        # newest prerelease if no stable exists yet, matching scripts/install.sh.
        $headers = @{ 'User-Agent' = 'tunlion-install' }
        # CI (and scripted installs) can pass a token to avoid the anonymous
        # GitHub API rate limit. It is never required.
        if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $env:GITHUB_TOKEN" }
        try {
            $releases = Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$Repo/releases?per_page=20"
        } catch { Die 'could not reach the GitHub releases API' }

        $tags = @($releases.tag_name | Where-Object { $_ -like 'cli-v*' })
        function Pick-Stable {
            $stable = $tags | Where-Object { $_ -match '^cli-v\d+\.\d+\.\d+$' }
            if (-not $stable) { return $null }
            ($stable | Sort-Object { [version]($_ -replace '^cli-v', '') } | Select-Object -Last 1)
        }
        function Pick-Any {
            # Sort by the numeric core so a stable X.Y.Z sorts above its own prereleases.
            if (-not $tags) { return $null }
            ($tags | Sort-Object { [version](($_ -replace '^cli-v', '') -replace '-.*$', '') }, { $_ } | Select-Object -Last 1)
        }

        if ($env:TUNLION_CHANNEL -eq 'beta') {
            $Tag = Pick-Any
        } else {
            $Tag = Pick-Stable
            if (-not $Tag) {
                $Tag = Pick-Any
                if ($Tag) { Say "no stable release yet; installing prerelease $Tag (set `$env:TUNLION_CHANNEL='beta' to silence)" }
            }
        }
        if (-not $Tag) { Die 'could not find a CLI release' }
        $Base = "https://github.com/$Repo/releases/download/$Tag"

        Say "downloading tunlion $Tag for $Target ..."
        $ZipPath = "$tmp\$Asset"
        $AssetName = $Asset
        $SumsPath = "$tmp\SHA256SUMS"
        Invoke-WebRequest -Headers $headers -Uri "$Base/$Asset" -OutFile $ZipPath
        Invoke-WebRequest -Headers $headers -Uri "$Base/SHA256SUMS" -OutFile $SumsPath
    }

    # -------------------------------------------------------------- verify
    $got = (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash.ToLower()
    $line = Get-Content -LiteralPath $SumsPath |
        Where-Object { $_ -match [regex]::Escape($AssetName) } |
        Select-Object -First 1
    if (-not $line) { Die "no checksum for $AssetName in $SumsPath" }
    $want = ($line -split '\s+')[0].ToLower()
    if ($got -ne $want) { Die "checksum mismatch (got $got, want $want) - aborting" }
    Say 'checksum verified'

    # ------------------------------------------------------------- install
    $extract = Join-Path $tmp 'x'
    Expand-Archive -Path $ZipPath -DestinationPath $extract -Force
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    foreach ($f in @('tunlion.exe', 'wintun.dll')) {
        $src = Join-Path $extract $f
        if (Test-Path -LiteralPath $src) {
            # Strip the mark-of-the-web so the extracted binary doesn't trip an
            # execution warning (the user explicitly ran this installer).
            try { Unblock-File -LiteralPath $src -ErrorAction Stop } catch { }
            Copy-Item -LiteralPath $src -Destination (Join-Path $InstallDir $f) -Force
        }
    }
    $exe = Join-Path $InstallDir 'tunlion.exe'
    if (-not (Test-Path -LiteralPath $exe)) { Die 'install failed: tunlion.exe not found in the archive' }
    $ver = (& $exe --version 2>$null) -join ' '
    Say "installed $exe ($(if ($ver) { $ver } else { $Tag }))"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

# ------------------------------------------------------------------- PATH
Add-ToPath $Scope $InstallDir

# All users: register the always-on receiver once, from the installed binary.
# This shell is already elevated, so `up --install` never re-prompts. Do not
# report success if that failed: the files are there, the service is not.
if ($AllUsers) {
    Say 'installing the always-on service (tunlion up --install) ...'
    & $exe up --install
    if ($LASTEXITCODE -ne 0) {
        Die "the files are installed, but 'tunlion up --install' failed (exit $LASTEXITCODE). Run it once as Administrator: `"$exe`" up --install"
    }
    Say 'always-on service installed'
}

# Note: Windows has no man page - use `tunlion --help` or `tunlion man` for docs.

Say ''
Say 'try it:   tunlion send <file> --code'
Say '          (the other end can be a terminal - or any browser at https://tunlion.autumated.com)'

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
# The installer also adds `tl` as a short command, unless another command with
# that name is already installed earlier in the user's command search path.
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

# First line of the managed `tl` launcher. The release ZIP ships the same file
# (packaging/windows/tl.cmd); this marker is how install and uninstall tell our
# launcher from a user's unrelated `tl.cmd`.
$TlMarker = '@rem Tunlion tl launcher. Managed by scripts/install.ps1.'
# Fallback for archives that predate the packaged launcher. Keep byte-for-byte
# content in step with packaging/windows/tl.cmd (the shape check proves it).
$TlLauncherContent = @'
@rem Tunlion tl launcher. Managed by scripts/install.ps1.
@echo off
"%~dp0tunlion.exe" %*
exit /b %errorlevel%
'@

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

function Test-TlLauncherOwned([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return $false }
    $firstLine = Get-Content -LiteralPath $path -TotalCount 1 -ErrorAction SilentlyContinue
    return ($firstLine -eq $TlMarker)
}

function Remove-TlLauncher([string]$dir) {
    $path = Join-Path $dir 'tl.cmd'
    if (-not (Test-Path -LiteralPath $path)) { return }
    if (Test-TlLauncherOwned $path) {
        Remove-FileWithRetry $path
    } else {
        Say "leaving $path alone because it is not the Tunlion-managed launcher"
    }
}

# ------------------------------------------------------- running binaries
# Windows will not overwrite a running .exe, nor a DLL a running daemon has
# loaded: copying the new release over them failed with "being used by
# another process". A daemon running from this directory is stopped cleanly
# with the binary it runs (`tunlion down`) and started again on the new one
# with the same flags. Anything still running from here after that (a
# `tunlion send`, a daemon that would not stop) keeps its old file, which is
# renamed aside first, as `tunlion update` does, and removed on a later run.

# Daemons (`tunlion.exe ... up ...`) running from $exe, with the flags after
# `up`. The command line comes from Win32_Process; `--detach` is dropped
# because the restart adds it.
function Get-RunningDaemons([string]$exe) {
    $found = @()
    $procs = @(Get-CimInstance Win32_Process -Filter "Name='tunlion.exe'" -ErrorAction SilentlyContinue)
    foreach ($p in $procs) {
        if (-not $p.ExecutablePath -or ($p.ExecutablePath -ine $exe)) { continue }
        $tokens = @([regex]::Matches([string]$p.CommandLine, '(?:"[^"]*"|[^\s"])+') |
            ForEach-Object { $_.Value.Replace('"', '') })
        # The verb is the first word after the program that is not a flag.
        $at = -1
        for ($i = 1; $i -lt $tokens.Count; $i++) {
            if (-not $tokens[$i].StartsWith('-')) { $at = $i; break }
        }
        if ($at -lt 0 -or $tokens[$at] -ne 'up') { continue }
        $flags = @($tokens | Select-Object -Skip ($at + 1) | Where-Object { $_ -ne '--detach' })
        $found += [pscustomobject]@{ Id = [int]$p.ProcessId; Flags = $flags }
    }
    return $found
}

# Running processes whose image is one of $paths.
function Get-RunningFrom([string[]]$paths) {
    @(Get-CimInstance Win32_Process -Filter "Name='tunlion.exe' OR Name='tunlion.old'" -ErrorAction SilentlyContinue |
        Where-Object { $_.ExecutablePath -and ($paths -icontains $_.ExecutablePath) })
}

# Old binaries renamed aside by an earlier install or `tunlion update`. One
# that is still running stays until a later run.
function Remove-StaleOld([string]$dir) {
    if (-not (Test-Path -LiteralPath $dir)) { return }
    foreach ($pattern in @('tunlion.old', 'tunlion.*.old', 'wintun.old', 'wintun.*.old')) {
        Get-ChildItem -Force -LiteralPath $dir -Filter $pattern -ErrorAction SilentlyContinue |
            ForEach-Object { Remove-Item -Force -LiteralPath $_.FullName -ErrorAction SilentlyContinue }
    }
}

# Rename $path to <name>.old (MoveFile on the same volume succeeds even for a
# running .exe), so the new file can be written in its place. When <name>.old
# is itself still running, it is renamed to a unique .old name first.
function Move-Aside([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return }
    $old = [System.IO.Path]::ChangeExtension($path, 'old')
    if (Test-Path -LiteralPath $old) {
        try {
            Remove-Item -Force -LiteralPath $old -ErrorAction Stop
        } catch {
            $unique = [System.IO.Path]::ChangeExtension($path, ([guid]::NewGuid().ToString('N') + '.old'))
            Move-Item -Force -LiteralPath $old -Destination $unique
        }
    }
    Move-Item -Force -LiteralPath $path -Destination $old
}

# `tunlion up --detach <flags>`, returning its exit code. Not `& $exe ... |`:
# the detached daemon inherits the pipe a PowerShell capture opens, so the
# pipeline would wait on the daemon's whole life. Start-Process gives it the
# console instead, and WaitForExit waits for the `up` alone, not the daemon.
function Start-Detached([string]$exe, [string[]]$flags) {
    $argLine = (@('up', '--detach') + @($flags | ForEach-Object {
        if ($_ -match '\s') { "`"$_`"" } else { $_ }
    })) -join ' '
    $p = Start-Process -FilePath $exe -ArgumentList $argLine -NoNewWindow -PassThru
    $null = $p.Handle  # keep the handle so ExitCode survives the exit
    $p.WaitForExit()
    return $p.ExitCode
}

function Format-UpCommand([string[]]$flags) {
    $words = @('tunlion', 'up', '--detach') + @($flags | ForEach-Object {
        if ($_ -match '\s') { "`"$_`"" } else { $_ }
    })
    return ($words -join ' ')
}

if ($DryRun) {
    Say 'dry run: no files, PATH entries or services were changed'
    Say "  scope:       $(if ($AllUsers) { 'all users' } else { 'current user' })"
    Say "  install dir: $InstallDir"
    Say "  PATH target: $Scope"
    Say '  short command: tl (installed only if no existing command collides)'
    if (-not $Uninstall) {
        $dryExe = Join-Path $InstallDir 'tunlion.exe'
        foreach ($d in @(Get-RunningDaemons $dryExe)) {
            Say "  would restart: the daemon (pid $($d.Id)) as: $(Format-UpCommand $d.Flags)"
        }
    }
    if ($Uninstall) {
        Say "  would remove: tunlion.exe and wintun.dll from $InstallDir"
        Say "  would remove: $InstallDir from the $Scope PATH"
        Say '  would remove: the Tunlion logon autostart entry'
        Say '  would remove: tl.cmd only if it is the Tunlion-managed launcher'
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
    Remove-TlLauncher $InstallDir
    foreach ($f in @('tunlion.exe', 'wintun.dll')) {
        Remove-FileWithRetry (Join-Path $InstallDir $f)
    }
    Remove-StaleOld $InstallDir
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
    $exe = Join-Path $InstallDir 'tunlion.exe'
    Remove-StaleOld $InstallDir

    # A per-user daemon is stopped with the binary it runs, so it closes its
    # links cleanly, and restarted below. An all-users install runs elevated
    # as another account, whose `down` would not reach the user's daemon; it
    # only renames the running files aside.
    $restart = @()
    if (-not $AllUsers -and (Test-Path -LiteralPath $exe)) {
        foreach ($d in @(Get-RunningDaemons $exe)) {
            Say "stopping the running daemon (pid $($d.Id)) to replace its binary ..."
            & $exe down --yes 2>&1 | Out-Null
            if (Get-Process -Id $d.Id -ErrorAction SilentlyContinue) {
                Say "the daemon (pid $($d.Id)) did not stop; it keeps running the previous version"
            } else {
                $restart += $d
            }
        }
    }

    foreach ($f in @('tunlion.exe', 'wintun.dll')) {
        $src = Join-Path $extract $f
        if (Test-Path -LiteralPath $src) {
            # Strip the mark-of-the-web so the extracted binary doesn't trip an
            # execution warning (the user explicitly ran this installer).
            try { Unblock-File -LiteralPath $src -ErrorAction Stop } catch { }
            $dest = Join-Path $InstallDir $f
            Move-Aside $dest
            Copy-Item -LiteralPath $src -Destination $dest -Force
        }
    }
    # Not running any more: nothing to keep.
    Remove-StaleOld $InstallDir
    if (-not (Test-Path -LiteralPath $exe)) { Die 'install failed: tunlion.exe not found in the archive' }

    # --------------------------------------------------------- short command
    # `tl` is convenient but not globally reserved. Never overwrite a command
    # already discoverable in this shell; a same-directory launcher from an
    # older Tunlion install (proven by its ownership marker) is the only one we
    # may replace. Prefer the launcher packaged in the ZIP so this installer
    # and the portable archive cannot drift; archives that predate it get the
    # byte-identical embedded fallback.
    $TlLauncher = Join-Path $InstallDir 'tl.cmd'
    $existingTl = Get-Command tl -ErrorAction SilentlyContinue | Select-Object -First 1
    $existingTlPath = if ($existingTl -and $existingTl.CommandType -eq 'Application') {
        $existingTl.Source
    } else { $null }
    $targetTlExists = Test-Path -LiteralPath $TlLauncher
    $targetTlOwned = $targetTlExists -and (Test-TlLauncherOwned $TlLauncher)
    # Textual path equality. A Windows 8.3 short path to our own launcher would
    # look foreign here; skipping the refresh is the conservative choice, since
    # we must never replace a command we cannot positively identify as ours.
    $existingTlIsTarget = $existingTlPath -and ($existingTlPath -ieq $TlLauncher)
    $installTl = $false
    if (-not $existingTl -or ($existingTlIsTarget -and $targetTlOwned)) {
        if (-not $targetTlExists -or $targetTlOwned) { $installTl = $true }
    }
    if ($installTl) {
        $packagedTl = Join-Path $extract 'tl.cmd'
        if (Test-Path -LiteralPath $packagedTl) {
            if (-not (Test-TlLauncherOwned $packagedTl)) {
                Die "install failed: the archive's tl.cmd is not a Tunlion-managed launcher"
            }
            Copy-Item -LiteralPath $packagedTl -Destination $TlLauncher -Force
        } else {
            Set-Content -LiteralPath $TlLauncher -Value $TlLauncherContent -Encoding Ascii -Force
        }
        Say "installed the 'tl' shortcut beside tunlion.exe"
    } else {
        $existingTlName = if ($existingTlPath) { $existingTlPath } elseif ($existingTl) { $existingTl.Name } else { $TlLauncher }
        Say "not installing 'tl': another command already uses that name ($existingTlName); use 'tunlion' or rename the existing command"
    }

    $ver = (& $exe --version 2>$null) -join ' '
    Say "installed $exe ($(if ($ver) { $ver } else { $Tag }))"

    foreach ($d in $restart) {
        $cmd = Format-UpCommand $d.Flags
        $code = Start-Detached $exe $d.Flags
        if ($code -eq 0) {
            Say "restarted the daemon on the new version ($cmd)"
        } else {
            Say "the daemon was stopped but did not restart (exit $code); start it with: $cmd"
        }
    }
    $oldExe = [System.IO.Path]::ChangeExtension($exe, 'old')
    $stillOld = @(Get-RunningFrom @($oldExe))
    if ($stillOld.Count -gt 0) {
        $ids = ($stillOld | ForEach-Object { $_.ProcessId }) -join ', '
        Say "still running the previous version from $oldExe (pid $ids); it is removed by the next install once it exits"
        foreach ($d in @(Get-RunningDaemons $oldExe)) {
            Say "  to move the daemon (pid $($d.Id)) to the new version:  tunlion down --yes, then: $(Format-UpCommand $d.Flags)"
        }
    }
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

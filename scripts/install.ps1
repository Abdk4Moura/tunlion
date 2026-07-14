# filament installer (Windows) — https://filament.autumated.com/install.ps1
#
#   irm https://filament.autumated.com/install.ps1 | iex
#
# Detects your platform, downloads the latest release .zip from GitHub, verifies
# its SHA-256 against the release's SHA256SUMS, and installs filament.exe (with
# the bundled wintun.dll) to %LOCALAPPDATA%\Programs\filament, adding it to your
# user PATH. Override the location with $env:FILAMENT_INSTALL_DIR. No admin, no
# telemetry. Source: scripts/install.ps1 in https://github.com/Abdk4Moura/filament
#
# Prefer a package manager? `winget install Abdk4Moura.Filament` works too.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = 'Abdk4Moura/filament'
$InstallDir = if ($env:FILAMENT_INSTALL_DIR) { $env:FILAMENT_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\filament' }

function Say([string]$m) { Write-Host "filament: $m" -ForegroundColor Cyan }
function Die([string]$m) { Write-Host "filament: $m" -ForegroundColor Red; exit 1 }

# ----------------------------------------------------------- platform detect
# We ship an x64 build (x86_64-pc-windows-msvc); it runs natively on x64 and via
# emulation on ARM64 Windows, so target x64 in both cases.
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -notin @('AMD64', 'ARM64', 'x86')) { Die "unsupported architecture: $arch" }
if ($arch -eq 'ARM64') { Say 'ARM64 detected — installing the x64 build (runs via emulation)' }
$Target = 'x86_64-pc-windows-msvc'
$Asset = "filament-$Target.zip"

# ------------------------------------------------------- resolve latest tag
# CLI releases are tagged cli-vX.Y.Z. Pick the HIGHEST stable version (the API's
# order is not newest-first); prereleases (cli-v0.2.1-beta.1) are skipped unless
# $env:FILAMENT_CHANNEL = 'beta'. Falls back to the newest prerelease if no
# stable exists yet, matching scripts/install.sh.
$headers = @{ 'User-Agent' = 'filament-install' }
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

if ($env:FILAMENT_CHANNEL -eq 'beta') {
    $Tag = Pick-Any
} else {
    $Tag = Pick-Stable
    if (-not $Tag) {
        $Tag = Pick-Any
        if ($Tag) { Say "no stable release yet; installing prerelease $Tag (set `$env:FILAMENT_CHANNEL='beta' to silence)" }
    }
}
if (-not $Tag) { Die 'could not find a CLI release' }
$Base = "https://github.com/$Repo/releases/download/$Tag"

# ------------------------------------------------------------------ download
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("filament-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
    Say "downloading filament $Tag for $Target ..."
    Invoke-WebRequest -Headers $headers -Uri "$Base/$Asset" -OutFile "$tmp\$Asset"
    Invoke-WebRequest -Headers $headers -Uri "$Base/SHA256SUMS" -OutFile "$tmp\SHA256SUMS"

    # -------------------------------------------------------------- verify
    $got = (Get-FileHash "$tmp\$Asset" -Algorithm SHA256).Hash.ToLower()
    $line = Get-Content "$tmp\SHA256SUMS" | Where-Object { $_ -match [regex]::Escape($Asset) } | Select-Object -First 1
    if (-not $line) { Die "no checksum for $Asset in SHA256SUMS" }
    $want = ($line -split '\s+')[0].ToLower()
    if ($got -ne $want) { Die "checksum mismatch (got $got, want $want) — aborting" }
    Say 'checksum verified'

    # ------------------------------------------------------------- install
    $extract = Join-Path $tmp 'x'
    Expand-Archive -Path "$tmp\$Asset" -DestinationPath $extract -Force
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    foreach ($f in @('filament.exe', 'wintun.dll')) {
        $src = Join-Path $extract $f
        if (Test-Path $src) {
            # Strip the mark-of-the-web so the extracted binary doesn't trip an
            # execution warning (the user explicitly ran this installer).
            Unblock-File -Path $src -ErrorAction SilentlyContinue
            Copy-Item -Path $src -Destination (Join-Path $InstallDir $f) -Force
        }
    }
    $exe = Join-Path $InstallDir 'filament.exe'
    if (-not (Test-Path $exe)) { Die 'install failed: filament.exe not found in the archive' }
    $ver = (& $exe --version 2>$null) -join ' '
    Say "installed $exe ($(if ($ver) { $ver } else { $Tag }))"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

# ------------------------------------------------------------------- PATH
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable('Path', ((@($userPath) + $InstallDir) -join ';').TrimStart(';'), 'User')
    $env:Path = "$env:Path;$InstallDir"
    Say "added $InstallDir to your PATH — open a new terminal for it to take effect"
}

Say ''
Say 'try it:   filament send <file> --code'
Say '          (the other end can be a terminal — or any browser at https://filament.autumated.com)'

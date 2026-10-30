# Fast ISCC syntax check on the warm Windows devloop: compile the committed
# installer script with the debug binary and a placeholder wintun.dll. This
# proves the [Setup]/[Code] script compiles before spending a cold release
# build on the hosted installer job. Not an artifact build.
$ErrorActionPreference = 'Stop'
$env:CI = '1'

if (-not (Get-Command iscc.exe -ErrorAction SilentlyContinue) -and
    -not (Test-Path 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe')) {
    choco install innosetup --no-progress -y
}

$stage = 'packaging/windows-installer/stage'
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item 'target\debug\tunlion.exe' "$stage\tunlion.exe" -Force
Copy-Item 'packaging\windows\tl.cmd' "$stage\tl.cmd" -Force
# Placeholder only: ISCC checks that the source exists, not its signature.
Set-Content -Path "$stage\wintun.dll" -Value 'placeholder-for-compile' -NoNewline

$iscc = (Get-Command iscc.exe -ErrorAction SilentlyContinue).Source
if (-not $iscc) { $iscc = 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe' }
& $iscc '/DAppVersion=0.9.3' 'packaging\windows-installer\tunlion.iss'
if ($LASTEXITCODE -ne 0) { throw "ISCC exited $LASTEXITCODE" }

$out = 'packaging\windows-installer\Output\TunlionSetup.exe'
if (-not (Test-Path $out)) { throw 'installer was not produced' }
Write-Host ("WIN-INSTALLER-COMPILE-OK bytes={0}" -f (Get-Item $out).Length)

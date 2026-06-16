$ErrorActionPreference = 'Continue'
Write-Host "=== Pristine Windows Server Core container: no Visual C++ Redistributable installed ==="

Write-Host "`n--- Attempt 1: run filament.exe BEFORE installing VCRedist (expect FAILURE) ---"
& C:\w\bin\filament.exe --version 2>&1 | Write-Host
$code = $LASTEXITCODE
Write-Host "exit code: $code"
if ($code -ne -1073741515) {
  Write-Host "UNEXPECTED: expected -1073741515 (0xC0000135 STATUS_DLL_NOT_FOUND), got $code"
  exit 1
}
Write-Host "REPRODUCED: STATUS_DLL_NOT_FOUND (0xC0000135) -- the missing VCRUNTIME140.dll, exactly what @Trenly saw."

Write-Host "`n--- Installing Microsoft.VCRedist.2015+.x64 (vc_redist.x64.exe) ---"
$p = Start-Process -FilePath C:\w\vc_redist.x64.exe -ArgumentList '/install','/quiet','/norestart' -Wait -PassThru
Write-Host "installer exit code: $($p.ExitCode)"
if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { exit $p.ExitCode }

Write-Host "`n--- Attempt 2: run filament.exe AFTER installing VCRedist (expect SUCCESS) ---"
& C:\w\bin\filament.exe --version 2>&1 | Write-Host
$code = $LASTEXITCODE
Write-Host "exit code: $code"
if ($code -ne 0) { Write-Host "STILL FAILING after VCRedist: exit $code"; exit 1 }
Write-Host "FIXED: with the VC++ Redistributable present, filament runs. Declaring Microsoft.VCRedist.2015+.x64 as a winget dependency resolves the install."

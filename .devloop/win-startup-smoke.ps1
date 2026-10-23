$ErrorActionPreference = 'Stop'
$exe = Join-Path (Get-Location) 'target\debug\tunlion.exe'
if (-not (Test-Path $exe)) { throw "missing $exe" }
$p = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 3
if ($p.HasExited) { throw "interactive tunlion exited early with code $($p.ExitCode); startup stack regression" }
Stop-Process -Id $p.Id -Force
Write-Host 'interactive tunlion stayed up for 3s; no startup stack overflow'

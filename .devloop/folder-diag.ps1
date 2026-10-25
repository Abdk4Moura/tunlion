$ErrorActionPreference = 'Stop'
$log = Join-Path $env:RUNNER_TEMP 'fluid-folder-diag.log'
& cmd.exe /d /c "cargo test -p filament-cli --locked --bin tunlion folder_access -- --nocapture > `"$log`" 2>&1"
$code = $LASTEXITCODE
$text = Get-Content -LiteralPath $log -Raw
Write-Host $text
Write-Host 'FOLDER-DIAGNOSTIC-SUMMARY'
Get-Content -LiteralPath $log | Select-String -Pattern 'leftover|short read|test result:|FAILED|running [0-9]+ tests?' | ForEach-Object { Write-Host $_ }
if ($code -ne 0) { throw "folder diagnostic tests failed: $code" }
if ($text -notmatch 'test result: ok\. [1-9][0-9]* passed; 0 failed;') { throw 'No passing folder tests executed' }

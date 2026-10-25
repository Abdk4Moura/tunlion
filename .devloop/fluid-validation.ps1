$ErrorActionPreference = 'Stop'
function Run-Guarded($name, $command, $pattern) {
  $log = Join-Path $env:RUNNER_TEMP "fluid-$name.log"
  & cmd.exe /d /c "$command > `"$log`" 2>&1"
  $code = $LASTEXITCODE
  $text = Get-Content -LiteralPath $log -Raw
  Write-Host $text
  if ($code -ne 0) { throw "$name failed: $code" }
  if ($text -notmatch $pattern) { throw "$name test-count guard failed" }
}
Run-Guarded 'bin' 'cargo test -p filament-cli --locked --bin tunlion' 'test result: ok\. [1-9][0-9]* passed; 0 failed;'
Run-Guarded 'menu' 'cargo test -p filament-cli --locked --test windows_menu_smoke -- --nocapture' 'test result: ok\. 1 passed; 0 failed; 0 ignored;'
foreach ($name in @('bin', 'menu')) {
  Write-Host "FLUID-$name summary:"
  Get-Content -LiteralPath (Join-Path $env:RUNNER_TEMP "fluid-$name.log") | Select-String 'test result:' | ForEach-Object { Write-Host $_ }
}
Write-Host 'FLUID-WINDOWS-VALIDATION: bin nonzero and menu exactly 1 passed'

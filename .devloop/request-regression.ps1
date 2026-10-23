$ErrorActionPreference = 'Stop'
$test = 'platform::request_write_tests::a_failed_windows_replacement_preserves_the_existing_request_and_nonce'
$output = @(& cargo test --locked -p filament-cli --bin tunlion $test -- --exact 2>&1)
$code = $LASTEXITCODE
$output | ForEach-Object { Write-Host $_ }
if ($code -ne 0) { throw "cargo test failed: $code" }
$text = $output -join "`n"
if ($text -notmatch '(?m)^running 1 test\s*$' -or $text -notmatch 'test result: ok\. 1 passed; 0 failed; 0 ignored;') {
  throw 'Expected exactly one executed, passing regression test'
}
Write-Host 'WINDOWS-REQUEST-REGRESSION: exactly 1 passed'

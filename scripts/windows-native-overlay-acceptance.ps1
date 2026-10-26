param([string]$EvidenceDir = "$env:RUNNER_TEMP\tunlion-native-acceptance")
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Run with PowerShell 7 (pwsh) to preserve native stderr/exit handling.' }
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$expected = if ($env:TUNLION_EXPECTED_SOURCE_SHA) { $env:TUNLION_EXPECTED_SOURCE_SHA } else { '734bb3e35cf011c1a4205da639ea3ce4f91a7764' }
$head = (git -C $root rev-parse HEAD).Trim()
$resolvedSource = git -C $root rev-parse "$expected^{commit}" 2>$null
if ($LASTEXITCODE -ne 0 -or $resolvedSource.Trim() -ne $expected) { throw "Expected exact source commit $expected is unavailable in this checkout" }
$ancestor = git -C $root merge-base --is-ancestor $expected HEAD 2>$null
if ($LASTEXITCODE -ne 0) { throw "Expected source $expected is not an ancestor of wrapper checkout $head" }
$env:TUNLION_BUILD_SHA = $expected.Substring(0,7)
$target = 'x86_64-pc-windows-msvc'
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$env:TUNLION_EXPECTED_SOURCE_SHA = $expected
Push-Location $root
$harnessError = $null
try {
  $testLog = Join-Path $EvidenceDir 'unit-tests.log'; $testErr = Join-Path $EvidenceDir 'unit-tests.stderr.log'
  $testProc = Start-Process -FilePath 'cargo.exe' -ArgumentList @('test','-p','filament-peerloop','--locked','--lib','l3::tun::windows','--target',$target) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $testLog -RedirectStandardError $testErr
  if ($testProc.ExitCode -ne 0) { throw "Windows l3::tun::windows test failed (exit $($testProc.ExitCode))" }
  $testText = (Get-Content (Join-Path $EvidenceDir 'unit-tests.log') -Raw) + (Get-Content (Join-Path $EvidenceDir 'unit-tests.stderr.log') -Raw)
  $passCounts = [regex]::Matches($testText, '(?m)\b(\d+) passed;') | ForEach-Object { [int]$_.Groups[1].Value }
  if (-not $passCounts -or (($passCounts | Measure-Object -Maximum).Maximum -lt 3)) { throw 'Focused Windows unit filter did not report at least 3 passing tests; inspect unit-tests.log' }
  $buildLog = Join-Path $EvidenceDir 'build.log'; $buildErr = Join-Path $EvidenceDir 'build.stderr.log'
  $buildProc = Start-Process -FilePath 'cargo.exe' -ArgumentList @('build','-p','filament-cli','--locked','--target',$target) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $buildLog -RedirectStandardError $buildErr
  if ($buildProc.ExitCode -ne 0) { throw "Windows debug build failed (exit $($buildProc.ExitCode))" }
  $targetDir = (cargo metadata --no-deps --format-version 1 | ConvertFrom-Json).target_directory
  $exe = Join-Path $targetDir "$target\debug\tunlion.exe"
  if (-not (Test-Path $exe)) { throw "Expected debug executable not found: $exe" }
  # Match the repository's installer/release trust checks exactly.
  $expectedZip = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
  $zip = Join-Path $EvidenceDir 'wintun-0.14.1.zip'
  Invoke-WebRequest 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $zip
  $zipHash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  if ($zipHash -ne $expectedZip) { throw "Wintun zip SHA256 mismatch: $zipHash" }
  $extract = Join-Path $EvidenceDir 'wintun-extract'
  Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
  $dll = Join-Path $extract 'wintun\bin\amd64\wintun.dll'
  $signature = Get-AuthenticodeSignature -LiteralPath $dll
  if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'WireGuard LLC') { throw "Wintun Authenticode failure: $($signature.Status), $($signature.SignerCertificate.Subject)" }
  Copy-Item -LiteralPath $dll -Destination (Join-Path (Split-Path $exe) 'wintun.dll') -Force
  "wrapper=$head`nsource=$expected`nexe_sha256=$((Get-FileHash $exe -Algorithm SHA256).Hash.ToLower())`nwintun_zip_sha256=$zipHash`nwintun_dll_sha256=$((Get-FileHash $dll -Algorithm SHA256).Hash.ToLower())`nwintun_authenticode=$($signature.Status)`nwintun_signer=$($signature.SignerCertificate.Subject)`n" | Set-Content (Join-Path $EvidenceDir 'build-provenance.txt')
  $runtimeScript = Join-Path $root 'evidence/windows-native-overlay/acceptance.ps1'
  & (Get-Command pwsh.exe -ErrorAction Stop).Source -NoProfile -File $runtimeScript -Exe $exe -EvidenceDir (Join-Path $EvidenceDir 'runtime')
  if ($LASTEXITCODE -ne 0) { throw "Runtime acceptance exited $LASTEXITCODE" }
} catch { $harnessError=$_.Exception.Message; $_ | Out-String | Set-Content (Join-Path $EvidenceDir 'harness-failure.txt'); throw }
finally {
  $harnessOutcome='COMPLETED';if($harnessError){$harnessOutcome='FAIL'}
  $harnessStatus=[ordered]@{outcome=$harnessOutcome;error=$harnessError;wrapperHead=$head;expectedProductSource=$expected;finishedUtc=[DateTime]::UtcNow.ToString('o');logs=@('unit-tests.log','unit-tests.stderr.log','build.log','build.stderr.log','build-provenance.txt','harness-failure.txt')|ForEach-Object{Join-Path $EvidenceDir $_}}
  $harnessStatus | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $EvidenceDir 'harness-status.json') -Encoding utf8
  Pop-Location
}

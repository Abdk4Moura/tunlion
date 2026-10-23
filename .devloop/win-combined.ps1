# Windows acceptance for integration/windows-combined.
#
# Runs on the leased windows-devloop runner (not test.yml). Every step is a real
# Windows build/test: the combined binary, the win_pty policy tests, the real
# pseudoconsole relay smoke, the interactive startup/temporary-access menus in a
# real ConPTY, and a Windows peerloop compile+test pass.

$ErrorActionPreference = 'Stop'
$env:CI = '1'

function Step([string]$name, [scriptblock]$body) {
    Write-Host ""
    Write-Host "===== $name ====="
    $sw = [Diagnostics.Stopwatch]::StartNew()
    & $body
    if ($LASTEXITCODE -ne 0) {
        throw "$name failed with exit code $LASTEXITCODE"
    }
    Write-Host ("===== {0}: ok ({1:n0}s) =====" -f $name, $sw.Elapsed.TotalSeconds)
}

Write-Host "host: $env:COMPUTERNAME  user: $env:USERNAME"
cargo --version
rustc --version

Step 'cargo check (combined CLI)' {
    cargo check --locked -p filament-cli --bin tunlion
}

Step 'win_pty policy tests' {
    cargo test --locked -p filament-cli --bin tunlion win_pty -- --nocapture
}

Step 'interactive menu in a real ConPTY' {
    cargo test --locked -p filament-cli --test windows_menu_smoke -- --nocapture
}

Step 'build test-hooks binary' {
    cargo build --locked -p filament-cli --bin tunlion --features test-hooks
}

Step 'tunlion --version (full Clap tree)' {
    $out = & .\target\debug\tunlion.exe --version 2>&1 | Out-String
    Write-Host $out.Trim()
    if ($out -match 'overflowed its stack') { throw 'startup stack overflow' }
    if ($LASTEXITCODE -ne 0) { throw "exit $LASTEXITCODE" }
}

Step 'shell relay smoke (owner-equivalent)' {
    & .\target\debug\tunlion.exe __win-pty-smoke --mode owner-equivalent
}

Step 'shell relay smoke (standard / linked-medium plane)' {
    # The hosted Windows runner is elevated and has no linked medium token.
    # In that state the standard plane MUST refuse; a successful spawn there
    # would be the privilege bug this plane exists to prevent. Accept exactly
    # the documented refusal, and require a real relay otherwise.
    $out = & .\target\debug\tunlion.exe __win-pty-smoke --mode standard 2>&1 | Out-String
    $code = $LASTEXITCODE
    Write-Host $out.Trim()
    if ($code -ne 0) {
        if ($out -match 'no linked medium token' -and $out -match 'refusing') {
            Write-Host 'standard plane refused on an elevated runner with no linked token (expected)'
            $global:LASTEXITCODE = 0
        }
        else {
            throw "standard smoke failed unexpectedly: $out"
        }
    }
}

Step 'cargo check peerloop (Windows all-targets)' {
    cargo check --locked -p filament-peerloop --all-targets
}

Step 'peerloop Windows library tests' {
    cargo test --locked -p filament-peerloop --lib
}

Write-Host ""
Write-Host "WIN-COMBINED-ALL-OK"

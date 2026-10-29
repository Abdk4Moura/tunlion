# Windows native overlay acceptance (the Windows job of
# .github/workflows/windows-native-overlay.yml). Real runner, real Wintun
# adapter, real peer. Run elevated on a DISPOSABLE machine only: it creates and
# removes the tunlion0 adapter and starts and kills daemons it started itself.
#
# Phases (each recorded in evidence\result.json):
#   released   the released binary joins the peer and runs kernel L3. Observed,
#              not asserted: this is the version the incident ran.
#   update     the binary is replaced in place by this commit's build and
#              started again with the same identity. Asserted.
#   restart    the daemon is killed outright, the crash case (teardown
#              asserted), and started again. Asserted.
#   teardown   `tunlion down` stops it gracefully; adapter and routes gone.
#
# Asserted in update and restart: `up --detach` returns with its output
# captured; kernel mode ready; the exact IPv4 from `addr --v4` is on tunlion0,
# Manual, DHCP disabled; the overlay IPv6 is on tunlion0; both prefix routes;
# Windows picks tunlion0 and that IPv4 as source for the peer; no v4Problem;
# native HTTP (Invoke-WebRequest, no proxy) to the peer's v4 and v6 returns the
# exact body. Nothing here grants itself privileges: no UAC bypass, no token
# manipulation, no firewall or permission changes.
param(
  [Parameter(Mandatory = $true)][string]$NewExe,
  [Parameter(Mandatory = $true)][string]$FromRelease,
  [Parameter(Mandatory = $true)][string]$Work,
  [Parameter(Mandatory = $true)][string]$RunId,
  [Parameter(Mandatory = $true)][string]$Repo
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$ProgressPreference = 'SilentlyContinue'

$Ev = Join-Path $Work 'evidence'
$Inst = Join-Path $Work 'bin'            # the "installed" location, updated in place
$Cfg = Join-Path $Work 'config'
$Dl = Join-Path $Work 'download'
New-Item -ItemType Directory -Force -Path $Ev, $Inst, $Cfg, $Dl | Out-Null
$Exe = Join-Path $Inst 'tunlion.exe'
$env:TUNLION_CONFIG_DIR = $Cfg
$env:TUNLION_COLOR = 'never'
Start-Transcript -Path (Join-Path $Ev 'transcript.log') -Force | Out-Null

$script:events = [System.Collections.Generic.List[object]]::new()
$script:failed = $false
function Record([string]$name, [string]$status, $detail) {
  $e = [ordered]@{ name = $name; status = $status; utc = [DateTime]::UtcNow.ToString('o'); detail = $detail }
  $script:events.Add($e)
  Write-Host ("{0} {1}" -f $status, $name)
  if ($status -eq 'FAIL') { $script:failed = $true }
}
function Check([string]$name, [bool]$ok, $detail) {
  if ($ok) { Record $name 'PASS' $detail } else { Record $name 'FAIL' $detail }
  return $ok
}

# Run a tunlion command with stdout and stderr on PIPES, as a script capturing
# its output does, and bound both the process and the end of its output. A
# command that exits while something else still holds its stdout pipe is
# reported as 'pipe-held', distinct from a hang of the command itself.
function Invoke-Tun([string[]]$Arguments, [int]$TimeoutSec = 120) {
  $psi = [System.Diagnostics.ProcessStartInfo]::new($Exe)
  foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.RedirectStandardInput = $true
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $p = [System.Diagnostics.Process]::Start($psi)
  $p.StandardInput.Close()
  $outTask = $p.StandardOutput.ReadToEndAsync()
  $errTask = $p.StandardError.ReadToEndAsync()
  $exited = $p.WaitForExit($TimeoutSec * 1000)
  $exitMs = $sw.ElapsedMilliseconds
  $state = 'ok'
  if (-not $exited) {
    $state = 'hung'
    try { $p.Kill($true) } catch {}
    $null = $p.WaitForExit(10000)
  }
  $remaining = [Math]::Max(1000, $TimeoutSec * 1000 - $sw.ElapsedMilliseconds)
  $eof = [System.Threading.Tasks.Task]::WaitAll(@($outTask, $errTask), [int]$remaining)
  if ($exited -and -not $eof) { $state = 'pipe-held' }
  $out = if ($outTask.IsCompleted) { $outTask.Result } else { '' }
  $err = if ($errTask.IsCompleted) { $errTask.Result } else { '' }
  [ordered]@{
    command = "tunlion $($Arguments -join ' ')"; state = $state
    exitCode = $(if ($exited) { $p.ExitCode } else { $null })
    exitMs = $exitMs; eofMs = $(if ($eof) { $sw.ElapsedMilliseconds } else { $null })
    stdout = ([string]$out).Trim(); stderr = ([string]$err).Trim()
  }
}

function Get-Daemon {
  $pidFile = Join-Path $Cfg 'up.pid'
  if (-not (Test-Path -LiteralPath $pidFile)) { return $null }
  $t = ([string](Get-Content -LiteralPath $pidFile -Raw)).Trim()
  if (-not $t) { return $null }
  $id = [int]($t -split '\s+')[0]
  $p = Get-CimInstance Win32_Process -Filter "ProcessId=$id" -ErrorAction SilentlyContinue
  # Only a process running OUR installed executable is ours to stop.
  if (-not $p -or $p.ExecutablePath -ne $Exe) { return $null }
  [ordered]@{ pid = $id; created = [string]$p.CreationDate; path = $p.ExecutablePath }
}

function Wait-Ready([string]$phase) {
  $deadline = (Get-Date).AddMinutes(3); $last = $null
  while ((Get-Date) -lt $deadline) {
    $last = Invoke-Tun @('addr', '--json') 30
    $j = $null; try { $j = $last.stdout | ConvertFrom-Json } catch {}
    if ($last.exitCode -eq 0 -and $j -and $j.l3 -and $j.l3.state -eq 'ready') { return [ordered]@{ ready = $true; json = $j; raw = $last } }
    Start-Sleep -Seconds 2
  }
  [ordered]@{ ready = $false; json = $null; raw = $last }
}

# $how: 'observe' (released build: try `down`, record what happened, then make
# sure it is gone), 'down' (graceful stop through `tunlion down`, ASSERTED) or
# 'kill' (TerminateProcess, the crash case: the adapter must still go away).
function Stop-Daemon([string]$phase, [string]$how) {
  $d = Get-Daemon
  if (-not $d) { Record "$phase-stop" 'FAIL' 'no daemon of ours to stop'; return }
  if ($how -ne 'kill') {
    $down = Invoke-Tun @('down', '-y') 60
    $still = Get-CimInstance Win32_Process -Filter "ProcessId=$($d.pid)" -ErrorAction SilentlyContinue
    $stoppedByDown = -not ($still -and [string]$still.CreationDate -eq $d.created)
    $detail = [ordered]@{ down = $down; daemonStoppedByDown = $stoppedByDown }
    if ($how -eq 'down') {
      # Stopped by its own graceful path: exit 0, gone, and not terminated.
      $null = Check "$phase-down-stops-daemon-gracefully" ($down.state -eq 'ok' -and $down.exitCode -eq 0 -and $stoppedByDown -and ($down.stdout + $down.stderr) -notmatch 'terminated') $detail
    } else {
      Record "$phase-down" 'OBSERVED' $detail
    }
    if ($stoppedByDown) { return }
  }
  # A verified pid (same executable, same creation time) only.
  Stop-Process -Id $d.pid -Force
  # TerminateProcess is asynchronous: the process object lingers while its
  # handles and pending I/O are torn down. Poll, bounded, for it to be gone.
  $deadline = (Get-Date).AddSeconds(30)
  do {
    $gone = -not (Get-CimInstance Win32_Process -Filter "ProcessId=$($d.pid)" -ErrorAction SilentlyContinue | Where-Object { [string]$_.CreationDate -eq $d.created })
    if ($gone) { break }
    Start-Sleep -Milliseconds 250
  } while ((Get-Date) -lt $deadline)
  $null = Check "$phase-daemon-exited" $gone $d
}

function Get-Native([string]$phase) {
  $v4 = (Invoke-Tun @('addr', '--v4') 30)
  $want = $v4.stdout.Trim()
  $aj = Invoke-Tun @('addr', '--json') 30
  $j = $null; try { $j = $aj.stdout | ConvertFrom-Json } catch {}
  $ifs = @(Get-NetIPInterface -InterfaceAlias 'tunlion0' -ErrorAction SilentlyContinue)
  $ips = @(Get-NetIPAddress -InterfaceAlias 'tunlion0' -ErrorAction SilentlyContinue)
  $routes = @(Get-NetRoute -InterfaceAlias 'tunlion0' -ErrorAction SilentlyContinue)
  $sel = $null; $selErr = $null
  try {
    $r = @(Find-NetRoute -RemoteIPAddress $script:PeerV4 -ErrorAction Stop)
    $src = @($r | Where-Object { $_.IPAddress } | Select-Object -First 1)[0]
    $sel = [ordered]@{ interfaceAlias = $src.InterfaceAlias; sourceAddress = $src.IPAddress; interfaceIndex = $src.InterfaceIndex }
  } catch { $selErr = $_.Exception.Message }
  $n = [ordered]@{
    phase = $phase; addrV4 = $want; addrV4Stderr = $v4.stderr; addrJson = $j
    adapter = @($ifs | Select-Object InterfaceAlias, AddressFamily, Dhcp, ConnectionState, InterfaceIndex)
    addresses = @($ips | Select-Object IPAddress, AddressFamily, PrefixLength, PrefixOrigin, AddressState)
    routes = @($routes | Select-Object DestinationPrefix, NextHop, RouteMetric)
    sourceSelection = $sel; sourceSelectionError = $selErr
  }
  $n.checks = [ordered]@{
    kernelReady    = [bool]($j -and $j.l3 -and $j.l3.state -eq 'ready' -and $j.l3.mode -eq 'kernel')
    exactManualV4  = [bool](@($ips | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -eq $want -and $_.PrefixLength -eq 32 -and [string]$_.PrefixOrigin -eq 'Manual' }).Count)
    noApipa        = -not [bool](@($ips | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -like '169.254.*' }).Count)
    dhcpDisabled   = [bool](@($ifs | Where-Object { $_.AddressFamily -eq 'IPv4' -and [string]$_.Dhcp -eq 'Disabled' }).Count)
    overlayIPv6    = [bool](@($ips | Where-Object { $_.AddressFamily -eq 'IPv6' -and $_.IPAddress -like 'fdf1:*' }).Count)
    v6Route        = [bool](@($routes | Where-Object DestinationPrefix -eq 'fdf1:1af7:c30d::/48').Count)
    v4Route        = [bool](@($routes | Where-Object DestinationPrefix -eq '198.18.0.0/15').Count)
    noV4Problem    = [bool]($j -and $j.l3 -and -not $j.l3.v4Problem)
    sourceIsOverlay = [bool]($sel -and $sel.interfaceAlias -eq 'tunlion0' -and $sel.sourceAddress -eq $want)
  }
  $n
}

function Get-Http([string]$url) {
  # Native client, no proxy: the OS stack picks the route and source.
  $deadline = (Get-Date).AddSeconds(120); $last = $null
  while ((Get-Date) -lt $deadline) {
    try {
      $r = Invoke-WebRequest -Uri $url -NoProxy -TimeoutSec 10 -UseBasicParsing
      $body = if ($r.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($r.Content) } else { [string]$r.Content }
      $bytes = [Text.Encoding]::UTF8.GetBytes($body)
      $sha = [BitConverter]::ToString([Security.Cryptography.SHA256]::HashData($bytes)).Replace('-', '').ToLower()
      return [ordered]@{ ok = $true; status = [int]$r.StatusCode; sha256 = $sha; url = $url }
    } catch { $last = $_.Exception.Message }
    Start-Sleep -Seconds 3
  }
  [ordered]@{ ok = $false; error = $last; url = $url }
}

function Assert-Native([string]$phase) {
  $n = Get-Native $phase
  Record "$phase-native-state" 'OBSERVED' $n
  foreach ($k in $n.checks.Keys) { $null = Check "$phase-$k" $n.checks[$k] $n.checks }
  $h4 = Get-Http "http://$($script:PeerV4):8766/token.txt"
  $null = Check "$phase-native-http-v4" ($h4.ok -and $h4.sha256 -eq $script:TokenSha) $h4
  $h6 = Get-Http "http://[$($script:PeerV6)]:8766/token.txt"
  $null = Check "$phase-native-http-v6" ($h6.ok -and $h6.sha256 -eq $script:TokenSha) $h6
}

function Assert-TornDown([string]$phase) {
  $deadline = (Get-Date).AddSeconds(30)
  do {
    $a = @(Get-NetAdapter -Name 'tunlion0' -ErrorAction SilentlyContinue)
    $r = @(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in @('198.18.0.0/15', 'fdf1:1af7:c30d::/48') })
    if (-not $a.Count -and -not $r.Count) { break }
    Start-Sleep -Seconds 1
  } while ((Get-Date) -lt $deadline)
  $detail = [ordered]@{ adapters = @($a | Select-Object Name, Status, InterfaceDescription); routes = @($r | Select-Object DestinationPrefix, InterfaceAlias) }
  $null = Check "$phase-adapter-removed" (-not $a.Count) $detail
  $null = Check "$phase-routes-removed" (-not $r.Count) $detail
}

function Start-Daemon([string]$phase, [bool]$assert) {
  $up = Invoke-Tun @('up', '--detach') 120
  if ($assert) {
    # The pipe stays open only if the daemon inherited it (the hang that made
    # the first acceptance runs time out). It must return, exit 0, with EOF.
    $null = Check "$phase-up-detach-returns-with-output-captured" ($up.state -eq 'ok' -and $up.exitCode -eq 0) $up
  } else {
    Record "$phase-up-detach" 'OBSERVED' $up
  }
  $r = Wait-Ready $phase
  $ok = Check "$phase-ready" $r.ready $r
  $d = Get-Daemon
  Record "$phase-daemon" 'OBSERVED' $d
  return $ok
}

try {
  $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  Record 'environment' 'OBSERVED' ([ordered]@{ os = (Get-CimInstance Win32_OperatingSystem).Caption; elevated = $admin; newExe = $NewExe; fromRelease = $FromRelease })
  if (-not $admin) { throw 'runner is not elevated; the kernel adapter cannot be tested here' }

  # Wintun: the same pinned, signature-checked DLL the release ships.
  $zip = Join-Path $Dl 'wintun.zip'
  Invoke-WebRequest 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $zip
  $zh = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  if ($zh -ne '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51') { throw "wintun zip sha256 $zh" }
  Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $Dl 'wintun') -Force
  $dll = Join-Path $Dl 'wintun\wintun\bin\amd64\wintun.dll'
  $sig = Get-AuthenticodeSignature -LiteralPath $dll
  if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'WireGuard LLC') { throw "wintun signature $($sig.Status)" }
  Copy-Item $dll (Join-Path $Inst 'wintun.dll') -Force

  # The released binary, verified against the release's SHA256SUMS.
  $rel = Join-Path $Dl 'release'
  gh release download $FromRelease --repo $Repo --pattern 'tunlion-x86_64-pc-windows-msvc.zip' --pattern 'SHA256SUMS' --dir $rel
  if ($LASTEXITCODE -ne 0) { throw "release download $FromRelease failed" }
  $relZip = Join-Path $rel 'tunlion-x86_64-pc-windows-msvc.zip'
  $sumLine = Get-Content (Join-Path $rel 'SHA256SUMS') | Where-Object { $_ -match 'tunlion-x86_64-pc-windows-msvc\.zip' }
  $want = ($sumLine -split '\s+')[0].ToLower()
  $have = (Get-FileHash $relZip -Algorithm SHA256).Hash.ToLower()
  if ($want -ne $have) { throw "released zip sha256 $have != $want" }
  Expand-Archive -LiteralPath $relZip -DestinationPath (Join-Path $rel 'x') -Force
  $relExe = @(Get-ChildItem (Join-Path $rel 'x') -Recurse -Filter tunlion.exe)[0].FullName
  Copy-Item $relExe $Exe -Force
  Record 'released-binary' 'OBSERVED' ([ordered]@{ version = (Invoke-Tun @('--version') 30).stdout; sha256 = (Get-FileHash $Exe -Algorithm SHA256).Hash.ToLower() })

  # The peer's one-claim invitation, published by the Linux job of this run.
  $invDir = Join-Path $Work 'invite'
  $deadline = (Get-Date).AddMinutes(40); $got = $false
  while ((Get-Date) -lt $deadline) {
    $names = gh api "repos/$Repo/actions/runs/$RunId/artifacts" --jq '.artifacts[].name' 2>$null
    if ($names -contains "native-overlay-invite-$RunId") {
      gh run download $RunId --repo $Repo --name "native-overlay-invite-$RunId" --dir $invDir
      if ($LASTEXITCODE -eq 0) { $got = $true; break }
    }
    Start-Sleep -Seconds 15
  }
  if (-not $got) { throw 'the Linux peer never published its invitation' }
  $script:PeerV4 = (Get-Content (Join-Path $invDir 'peer-v4.txt') -Raw).Trim()
  $script:PeerV6 = (Get-Content (Join-Path $invDir 'peer-v6.txt') -Raw).Trim()
  $script:TokenSha = (Get-Content (Join-Path $invDir 'token.sha256') -Raw).Trim()
  Record 'peer' 'OBSERVED' ([ordered]@{ v4 = $script:PeerV4; v6 = $script:PeerV6 })

  # ---- released: join and run kernel L3 on the version a user updates from.
  $join = Invoke-Tun @('join', '--invite-file', (Join-Path $invDir 'win.key'), '--name', $env:WIN_NAME) 120
  if (-not (Check 'released-join' ($join.state -eq 'ok' -and $join.exitCode -eq 0) $join)) { throw 'join failed' }
  Remove-Item -LiteralPath (Join-Path $invDir 'win.key') -Force
  $set = Invoke-Tun @('set', 'l3-mode', 'kernel') 30
  if (-not (Check 'select-kernel' ($set.exitCode -eq 0) $set)) { throw 'set l3-mode failed' }
  $env:TUNLION_LOG = 'debug'   # the released build logs a failed v4 address only at debug
  if (Start-Daemon 'released' $false) {
    $old = Get-Native 'released'
    Record 'released-native-state' 'OBSERVED' $old
    Record 'released-native-http-v4' 'OBSERVED' (Get-Http "http://$($script:PeerV4):8766/token.txt")
    # Root cause, observed rather than inferred: re-run the released build's
    # exact IPv4 commands (set, then add as its fallback) on this adapter, and
    # record what netsh returns and what the adapter then holds.
    $v4 = $old.addrV4
    foreach ($verb in @('set', 'add')) {
      $o = netsh.exe interface ipv4 $verb address "interface=tunlion0" "address=$v4/32" 2>&1
      $code = $LASTEXITCODE
      Record "released-old-netsh-$verb" 'OBSERVED' ([ordered]@{
        command = "netsh interface ipv4 $verb address interface=tunlion0 address=$v4/32"
        exitCode = $code; output = ($o | Out-String).Trim()
        addresses = @(Get-NetIPAddress -InterfaceAlias 'tunlion0' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object IPAddress, PrefixLength, PrefixOrigin, AddressState)
        dhcp = [string](Get-NetIPInterface -InterfaceAlias 'tunlion0' -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp
      })
    }
    $o = netsh.exe interface ipv4 show addresses tunlion0 2>&1
    Record 'released-netsh-show' 'OBSERVED' ($o | Out-String).Trim()
  }
  Remove-Item Env:TUNLION_LOG
  Stop-Daemon 'released' 'observe'
  Record 'released-teardown' 'OBSERVED' ([ordered]@{ adapters = @(Get-NetAdapter -Name 'tunlion0' -ErrorAction SilentlyContinue | Select-Object Name, Status) })
  $log = Join-Path $Cfg 'daemon.log'
  if (Test-Path $log) { Copy-Item $log (Join-Path $Ev 'daemon-released.log') }

  # ---- update: this commit's build, in place, same identity and settings.
  Copy-Item $NewExe $Exe -Force
  Record 'updated-binary' 'OBSERVED' ([ordered]@{ version = (Invoke-Tun @('--version') 30).stdout; sha256 = (Get-FileHash $Exe -Algorithm SHA256).Hash.ToLower() })
  if (Start-Daemon 'update' $true) { Assert-Native 'update' }

  # ---- restart: the crash case (killed outright), prove teardown, start again.
  Stop-Daemon 'restart' 'kill'
  Assert-TornDown 'restart'
  if (Start-Daemon 'restart' $true) { Assert-Native 'restart' }

  # The peer has served everything it needs to; tell it before the overlay
  # goes away (it also stops waiting when this job's evidence appears).
  try { Invoke-WebRequest -Uri "http://[$($script:PeerV6)]:8766/done" -NoProxy -TimeoutSec 10 -UseBasicParsing | Out-Null; Record 'peer-done' 'OBSERVED' 'sent' } catch { Record 'peer-done' 'OBSERVED' $_.Exception.Message }

  # ---- teardown: graceful, through `tunlion down`.
  Stop-Daemon 'final' 'down'
  Assert-TornDown 'final'
} catch {
  Record 'abort' 'FAIL' ([ordered]@{ message = $_.Exception.Message; at = $_.InvocationInfo.PositionMessage })
} finally {
  $d = Get-Daemon
  if ($d) { Stop-Process -Id $d.pid -Force -ErrorAction SilentlyContinue }
  if (Test-Path (Join-Path $Cfg 'daemon.log')) { Copy-Item (Join-Path $Cfg 'daemon.log') (Join-Path $Ev 'daemon.log') -Force }
  # Tell the peer we are done (best effort; the peer's own timeout covers a miss).
  if ($script:PeerV6) { try { Invoke-WebRequest -Uri "http://[$($script:PeerV6)]:8766/done" -NoProxy -TimeoutSec 5 -UseBasicParsing | Out-Null } catch {} }
  # Identity material of this run never leaves the runner.
  Remove-Item -LiteralPath $Cfg -Recurse -Force -ErrorAction SilentlyContinue
  $outcome = if ($script:failed) { 'FAIL' } else { 'PASS' }
  [ordered]@{ outcome = $outcome; events = @($script:events) } | ConvertTo-Json -Depth 12 | Set-Content (Join-Path $Ev 'result.json') -Encoding utf8
  Write-Host "RESULT=$outcome"
  foreach ($e in $script:events) { if ($e.status -eq 'FAIL') { Write-Host "FAILED: $($e.name)"; Write-Host ($e.detail | ConvertTo-Json -Depth 6 -Compress) } }
  Stop-Transcript | Out-Null
}
if ($script:failed) { exit 1 } else { exit 0 }

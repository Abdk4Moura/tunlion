param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [string]$EvidenceDir = "$env:RUNNER_TEMP\tunlion-native-acceptance"
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$script:results = [ordered]@{}
$script:events = [System.Collections.Generic.List[object]]::new()
$script:failed = $false
$script:passedNative = $false
$script:blocked = $false
$script:root = Join-Path $EvidenceDir 'scratch'
$script:config = Join-Path $script:root 'config'
$script:inbox = Join-Path $script:root 'inbox'
$script:log = Join-Path $EvidenceDir 'acceptance.log'
New-Item -ItemType Directory -Force -Path $EvidenceDir,$script:config,$script:inbox | Out-Null
Start-Transcript -Path $script:log -Force | Out-Null
$env:TUNLION_CONFIG_DIR = $script:config
$env:TUNLION_COLOR = 'never'
$Exe = (Resolve-Path -LiteralPath $Exe).Path
$exeHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Exe).Hash.ToLower()
$sig = Get-AuthenticodeSignature -LiteralPath (Join-Path (Split-Path $Exe) 'wintun.dll')
$dllHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path (Split-Path $Exe) 'wintun.dll')).Hash.ToLower()
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:results.environment = [ordered]@{ os=(Get-CimInstance Win32_OperatingSystem).Caption; productSourceSha=$env:TUNLION_BUILD_SHA; exe=$Exe; exeSha256=$exeHash; wintunSha256=$dllHash; wintunAuthenticode=$sig.Status; wintunSigner=$sig.SignerCertificate.Subject; elevated=$admin; config=$script:config }
function Record($name,$status,$detail) { $e=[ordered]@{name=$name;status=$status;detail=$detail;utc=[DateTime]::UtcNow.ToString('o')}; $script:events.Add($e); Write-Host (ConvertTo-Json $e -Compress -Depth 10); if($status -eq 'FAIL'){$script:failed=$true};if($status -eq 'BLOCKED'){$script:blocked=$true} }
function Invoke-Tun([string[]]$Arguments) {
  $tag=[guid]::NewGuid().ToString('N');$stdout=Join-Path $EvidenceDir "$tag.stdout.txt";$stderr=Join-Path $EvidenceDir "$tag.stderr.txt"
  try {
    & $Exe @Arguments 1> $stdout 2> $stderr
    $ec=$LASTEXITCODE
    $out=if(Test-Path $stdout){Get-Content -Raw $stdout}else{''};$err=if(Test-Path $stderr){Get-Content -Raw $stderr}else{''}
    if (($out -match 'overflowed its stack') -or ($err -match 'overflowed its stack')) {
      $ec = if ($ec -eq 0) { 70 } else { $ec }
    }
    $recovery=Join-Path $script:root 'recovery.txt'
    if(Test-Path -LiteralPath $recovery){$phrase=(Get-Content -LiteralPath $recovery -Raw).Trim();if($phrase){$out=$out.Replace($phrase,'[REDACTED-RECOVERY-PHRASE]');$err=$err.Replace($phrase,'[REDACTED-RECOVERY-PHRASE]')}}
  } finally {Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue}
  [ordered]@{command="`"$Exe`" $($Arguments -join ' ')";exitCode=$ec;stdout=$out.Trim();stderr=$err.Trim()}
}
function Assert-Command($name,[string[]]$Arguments) { $r=Invoke-Tun -Arguments $Arguments; if($r.exitCode -ne 0){Record $name 'FAIL' $r; throw "$name failed: $($r.stderr) $($r.stdout)"}; Record $name 'PASS' $r; return $r }
function Get-ScratchDaemon([string]$PidPath,[string]$ExePath) {
  if(-not (Test-Path -LiteralPath $PidPath) -or -not (Test-Path -LiteralPath $ExePath)){return $null}
  $candidatePid=[int](Get-Content -LiteralPath $PidPath -Raw).Trim();$candidateExe=(Get-Content -LiteralPath $ExePath -Raw).Trim()
  if($candidateExe -ne $Exe){throw "scratch pidfile executable mismatch: $candidateExe"}
  $candidate=Get-CimInstance Win32_Process -Filter "ProcessId=$candidatePid" -ErrorAction SilentlyContinue
  if(-not $candidate -or $candidate.ExecutablePath -ne $Exe){return $null}
  [ordered]@{pid=$candidatePid;path=$candidate.ExecutablePath;created=[string]$candidate.CreationDate;commandLine=$candidate.CommandLine}
}
function Get-NativeState($phase) {
  $ifs=@(Get-NetIPInterface -InterfaceAlias 'tunlion0' -ErrorAction SilentlyContinue)
  $ips=@(Get-NetIPAddress -InterfaceAlias 'tunlion0' -ErrorAction SilentlyContinue)
  $routes=@(Get-NetRoute -InterfaceAlias 'tunlion0' -ErrorAction SilentlyContinue)
  $v4=(Invoke-Tun @('addr','--v4')); $aj=(Invoke-Tun @('addr','--json'))
  $json=$null; try {$json=$aj.stdout | ConvertFrom-Json} catch {}
  $want=$v4.stdout.Trim(); $ip4=@($ips | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.IPAddress -eq $want -and $_.PrefixLength -eq 32 -and $_.PrefixOrigin -eq 'Manual'})
  $dhcp=@($ifs | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.Dhcp -eq 'Disabled'})
  $ip6=@($ips | Where-Object {$_.AddressFamily -eq 'IPv6' -and $_.IPAddress -like 'fdf1:*'})
  $r6=@($routes | Where-Object DestinationPrefix -eq 'fdf1:1af7:c30d::/48')
  $r4=@($routes | Where-Object DestinationPrefix -eq '198.18.0.0/15')
  $finding=[ordered]@{phase=$phase;addrV4=$v4;addrJson=$aj;adapter=@($ifs|Select-Object InterfaceAlias,AddressFamily,Dhcp,ConnectionState);addresses=@($ips|Select-Object IPAddress,AddressFamily,PrefixLength,PrefixOrigin);routes=@($routes|Select-Object DestinationPrefix,RouteMetric);checks=[ordered]@{exactManualV4=($ip4.Count -gt 0);dhcpDisabled=($dhcp.Count -gt 0);overlayIPv6=($ip6.Count -gt 0);v6Route=($r6.Count -gt 0);v4Route=($r4.Count -gt 0);noV4Problem=($aj.exitCode -eq 0 -and $null -ne $json -and $null -ne $json.l3 -and [string]::IsNullOrEmpty([string]$json.l3.v4Problem));sourceSelection=$null}}
  try {
    $selection=@(Find-NetRoute -RemoteIPAddress '198.18.10.187' -ErrorAction Stop)
    $typed=@($selection | ForEach-Object { [ordered]@{type=$_.CimClass.CimClassName;properties=@($_.CimInstanceProperties | ForEach-Object Name);interfaceIndex=$_.InterfaceIndex;interfaceAlias=$_.InterfaceAlias;ipAddress=$_.IPAddress;destinationPrefix=$_.DestinationPrefix;sourceAddress=$_.SourceAddress} })
    $sourceObj=@($selection | Where-Object { $_.IPAddress -and $_.InterfaceIndex } | Select-Object -First 1)[0]
    $routeObj=@($selection | Where-Object { $_.DestinationPrefix -and $_.InterfaceIndex } | Sort-Object { $_.DestinationPrefix.Length } -Descending | Select-Object -First 1)[0]
    if($null -eq $sourceObj -or $null -eq $routeObj){throw 'Find-NetRoute did not return identifiable source-address and route objects'}
    $actualIf=@(Get-NetIPInterface -InterfaceIndex $sourceObj.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop)
    $ifAlias=if($actualIf.Count){$actualIf[0].InterfaceAlias}else{$null}
    $finding.checks.sourceSelection=[ordered]@{rawTypesAndProperties=$typed;sourceInterfaceIndex=$sourceObj.InterfaceIndex;routeInterfaceIndex=$routeObj.InterfaceIndex;interfaceAlias=$ifAlias;sourceAddress=$sourceObj.IPAddress;routeDestinationPrefix=$routeObj.DestinationPrefix}
    $finding.checks.sourceSelectionCorrect=($ifAlias -eq 'tunlion0' -and $sourceObj.InterfaceIndex -eq $routeObj.InterfaceIndex -and $sourceObj.IPAddress -eq $want)
  } catch {$finding.checks.sourceSelectionError=$_.Exception.Message;$finding.checks.sourceSelectionCorrect=$false;$finding.checks.sourceSelectionRaw=@($selection | ConvertTo-Json -Depth 8 -ErrorAction SilentlyContinue)}
  $script:events.Add([ordered]@{name="native-state-$phase";status='OBSERVED';detail=$finding;utc=[DateTime]::UtcNow.ToString('o')})
  $must=@('exactManualV4','dhcpDisabled','overlayIPv6','v6Route','v4Route','noV4Problem','sourceSelectionCorrect')
  $phaseOk=$true;foreach($k in $must){if(-not $finding.checks[$k]){$phaseOk=$false;Record "assert-$phase-$k" 'FAIL' $finding.checks}};if($phase -eq 'initial'){if($phaseOk){$script:passedNative=$true}else{$script:failed=$true}};if($phase -eq 'after-restart' -and -not $phaseOk){$script:failed=$true}
  return $finding
}
$daemonPid=$null;$daemonPath=$null;$daemonCreated=$null;$firstCreated=$null
Record 'non-elevated-negative' 'SKIPPED' 'Not run automatically: runner token must be verified non-elevated first; no linked-token creation/UAC bypass/privilege manipulation is performed.'
Record 'native-http-peer' 'SKIPPED' 'No paired peer endpoint is assumed or configured; native HTTP from a second machine is untested.'
Record 'windows-reboot-logon' 'SKIPPED' 'Disposable runner will not be rebooted by this focused acceptance; reboot/logon persistence is untested.'
try {
  if(-not $admin){Record 'elevation' 'BLOCKED' 'Runner is not elevated; explicit-kernel native test cannot run.'; throw 'not elevated'}
  if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'WireGuard LLC'){Record 'wintun-signature' 'FAIL' @{status=$sig.Status;signer=$sig.SignerCertificate.Subject}; throw 'invalid Wintun signature'}
  Record 'wintun-signature' 'PASS' @{sha256=$dllHash;status=$sig.Status;signer=$sig.SignerCertificate.Subject}
  Assert-Command 'init' @('--json','init','--name','win-native-accept','--inbox',$script:inbox,'--recovery-file',(Join-Path $script:root 'recovery.txt'),'--yes') | Out-Null
  Assert-Command 'select-kernel' @('set','l3-mode','kernel') | Out-Null
  $pidPath=Join-Path $script:config 'up.pid';$exePath=Join-Path $script:config 'up.exe'
  $up=Invoke-Tun @('up','--detach'); Record 'start-kernel-daemon' $(if($up.exitCode -eq 0){'PASS'}else{'FAIL'}) $up
  if($up.exitCode -ne 0){throw 'up --detach failed'}
  $launchDeadline=(Get-Date).AddSeconds(30);$instance=$null
  while((Get-Date) -lt $launchDeadline){$instance=Get-ScratchDaemon $pidPath $exePath;if($instance){$daemonPid=$instance.pid;$daemonPath=$instance.path;$daemonCreated=$instance.created;break};Start-Sleep -Milliseconds 300}
  if(-not $instance){throw 'daemon launch produced no exact executable/PID identity; no arbitrary process will be stopped'}
  $deadline=(Get-Date).AddMinutes(2); $ready=$false
  while((Get-Date) -lt $deadline){$s=Invoke-Tun @('addr','--json'); $j=$null;try{$j=$s.stdout|ConvertFrom-Json}catch{}; if($s.exitCode -eq 0 -and $null -ne $j -and $null -ne $j.l3 -and $j.l3.state -eq 'ready' -and $j.l3.mode -eq 'kernel'){$ready=$true;break}; Start-Sleep -Seconds 2}
  if(-not $ready){Record 'daemon-ready' 'FAIL' @{status=$s;parsed=$j;adapter=@(Get-NetAdapter -Name tunlion0 -ErrorAction SilentlyContinue)};throw 'daemon did not report ready/kernel within timeout'}
  $instance=Get-ScratchDaemon $pidPath $exePath;if($null -eq $instance){throw 'ready daemon did not have a matching scratch pid/executable record'}
  $daemonPid=$instance.pid;$daemonPath=$instance.path;$daemonCreated=$instance.created;$firstPid=$daemonPid;$firstCreated=$daemonCreated
  Record 'daemon-ready' 'PASS' @{status=$j;pid=$daemonPid;processPath=$daemonPath;creationDate=$daemonCreated;commandLine=$instance.commandLine;adapter=(Get-NetAdapter -Name tunlion0 -ErrorAction SilentlyContinue|Select-Object Name,Status,InterfaceDescription)}
  $first=Get-NativeState 'initial'
  # Observe the incident's old form only after saving the exact successful new state.
  # It changes the fresh scratch adapter; restart below must restore the branch behavior.
  $old=netsh.exe interface ipv4 set address interface=tunlion0 address=198.18.200.1/32 2>&1; $oldCode=$LASTEXITCODE
  $oldObs=[ordered]@{label='configured tunlion0 observation after successful new static assignment; not fresh/default-DHCP adapter behavior';command='netsh interface ipv4 set address interface=tunlion0 address=198.18.200.1/32';exitCode=$oldCode;output=($old|Out-String).Trim();interface=(Get-NetIPInterface -InterfaceAlias tunlion0 -AddressFamily IPv4 -ErrorAction SilentlyContinue|Select-Object InterfaceAlias,Dhcp,ConnectionState);addresses=(Get-NetIPAddress -InterfaceAlias tunlion0 -ErrorAction SilentlyContinue|Select-Object IPAddress,PrefixLength,PrefixOrigin)}
  $script:events.Add([ordered]@{name='old-netsh-form-observation';status='OBSERVED';detail=$oldObs;utc=[DateTime]::UtcNow.ToString('o')})
  # No assumptions about whether this legacy form succeeds; preserve its actual result.
  $proc=Get-CimInstance Win32_Process -Filter "ProcessId=$daemonPid";if($proc.ExecutablePath -ne $daemonPath -or [string]$proc.CreationDate -ne $daemonCreated){throw 'refuse restart: pid/path/creation timestamp no longer matches captured scratch instance'}
  Stop-Process -Id $daemonPid -Force -ErrorAction Stop; Wait-Process -Id $daemonPid -Timeout 30 -ErrorAction SilentlyContinue
  $stopDeadline=(Get-Date).AddSeconds(30);do{$still=Get-CimInstance Win32_Process -Filter "ProcessId=$daemonPid" -ErrorAction SilentlyContinue;if(-not $still){break};if($still.ExecutablePath -ne $daemonPath -or [string]$still.CreationDate -ne $daemonCreated){throw 'PID was reused during restart wait; refusing further action'};Start-Sleep -Milliseconds 300}while((Get-Date) -lt $stopDeadline)
  if($still){throw 'verified daemon process did not exit within 30 seconds'}
  $up2=Invoke-Tun @('up','--detach'); Record 'restart-daemon' $(if($up2.exitCode -eq 0){'PASS'}else{'FAIL'}) $up2
  if($up2.exitCode -ne 0){throw 'restart failed'}
  $newDeadline=(Get-Date).AddSeconds(30);$instance2=$null
  while((Get-Date) -lt $newDeadline){$instance2=Get-ScratchDaemon $pidPath $exePath;if($instance2){break};Start-Sleep -Milliseconds 300}
  if($null -eq $instance2){throw 'restart command returned but no matching new scratch pid/executable instance appeared'}
  if($instance2.pid -eq $firstPid -or $instance2.created -eq $firstCreated){throw 'restart did not establish a distinct daemon PID and creation timestamp'}
  $daemonPid=$instance2.pid;$daemonPath=$instance2.path;$daemonCreated=$instance2.created
  $deadline=(Get-Date).AddMinutes(2);$ready=$false
  while((Get-Date) -lt $deadline){$s=Invoke-Tun @('addr','--json');$j=$null;try{$j=$s.stdout|ConvertFrom-Json}catch{};if($s.exitCode -eq 0 -and $null -ne $j -and $null -ne $j.l3 -and $j.l3.state -eq 'ready' -and $j.l3.mode -eq 'kernel'){$ready=$true;break};Start-Sleep -Seconds 2}
  if(-not $ready){Record 'restart-ready' 'FAIL' @{status=$s;parsed=$j};throw 'restarted daemon not ready'}
  $instance2=Get-ScratchDaemon $pidPath $exePath;if($null -eq $instance2 -or $instance2.pid -ne $daemonPid -or $instance2.created -ne $daemonCreated){throw 'post-restart ready state does not match captured new daemon incarnation'}
  Record 'restart-ready' 'PASS' @{status=$j;pid=$daemonPid;processPath=$daemonPath;creationDate=$daemonCreated;previousPid=$firstPid;previousCreationDate=$firstCreated}
  $second=Get-NativeState 'after-restart'
} catch { if(-not $script:events.Where({$_.status -eq 'FAIL'}).Count){Record 'acceptance-abort' 'BLOCKED' $_.Exception.Message} else {Record 'acceptance-abort' 'FAIL' $_.Exception.Message} }
finally {
  if($daemonPid){$p=Get-CimInstance Win32_Process -Filter "ProcessId=$daemonPid" -ErrorAction SilentlyContinue;if($p -and $p.ExecutablePath -eq $daemonPath -and [string]$p.CreationDate -eq $daemonCreated){Stop-Process -Id $daemonPid -Force -ErrorAction SilentlyContinue;Wait-Process -Id $daemonPid -Timeout 15 -ErrorAction SilentlyContinue;$after=Get-CimInstance Win32_Process -Filter "ProcessId=$daemonPid" -ErrorAction SilentlyContinue;if($after -and $after.ExecutablePath -eq $daemonPath -and [string]$after.CreationDate -eq $daemonCreated){Record 'cleanup-daemon' 'FAIL' 'Verified scratch daemon remained alive after stop timeout.'}elseif($after){Record 'cleanup-daemon' 'SKIPPED' 'PID now identifies a different incarnation; refused to stop it.'}else{Record 'cleanup-daemon' 'PASS' 'Verified scratch daemon stopped.'}}else{Record 'cleanup-daemon' 'FAIL' 'PID/path/creation timestamp no longer matches; refused to stop an unverified process; manual review required.'}}
  $evidenceFull=[IO.Path]::GetFullPath($EvidenceDir);$scratchFull=[IO.Path]::GetFullPath($script:root)
  if($scratchFull.StartsWith($evidenceFull+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $scratchFull)){Remove-Item -LiteralPath $scratchFull -Recurse -Force;Record 'cleanup-scratch-secrets' 'PASS' 'Removed only the dedicated scratch identity/config/recovery subtree after daemon cleanup.'}else{Record 'cleanup-scratch-secrets' 'BLOCKED' 'Scratch path escaped evidence root; refused recursive cleanup.'}
  $hasSkip=@($script:events|Where-Object status -eq 'SKIPPED').Count -gt 0
  $script:results.events=@($script:events);$script:results.finishedUtc=[DateTime]::UtcNow.ToString('o');$script:results.outcome=if($script:failed){'FAIL'}elseif($script:blocked){'BLOCKED'}elseif($script:passedNative -and $hasSkip){'PARTIAL'}elseif($script:passedNative){'PASS'}else{'BLOCKED'}
  $script:results|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $EvidenceDir 'result.json') -Encoding utf8
  Stop-Transcript|Out-Null
}
Write-Host "RESULT=$($script:results.outcome) LOG=$script:log JSON=$(Join-Path $EvidenceDir 'result.json')"
if($script:failed){exit 1}; if($script:results.outcome -eq 'BLOCKED'){exit 2}; exit 0

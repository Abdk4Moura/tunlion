param([string]$Out)
try {
  $procs = @(Get-CimInstance Win32_Process -Filter "Name='tunlion.exe'" -ErrorAction Stop)
} catch {
  Set-Content -LiteralPath $Out -Value "Cannot check running Tunlion processes. Installation stopped; no files were replaced." -Encoding UTF8
  exit 2
}
$lines = New-Object System.Collections.Generic.List[string]
if ($procs.Count -gt 0) {
  $pids = ($procs | ForEach-Object { $_.ProcessId }) -join ', '
  $path = ($procs | Select-Object -First 1 -ExpandProperty ExecutablePath)
  $lines.Add("Cannot replace $path")
  $lines.Add("in use by pid(s): $pids")
  $lines.Add("")
  $lines.Add("Stop each config first, then rerun this installer:")
  $lines.Add('  $env:TUNLION_CONFIG_DIR = "<that config>"; tunlion down --yes')
  $lines.Add("Repeat for every TUNLION_CONFIG_DIR/TunlionKernel instance. This installer will not kill or restart them.")
  $lines.Add("")
  $lines.Add("The installer leaves up.pid and all configuration untouched.")
} else {
  $lines.Add("No running tunlion.exe found; safe to replace the binary.")
}
Set-Content -LiteralPath $Out -Value $lines -Encoding UTF8
if ($procs.Count -gt 0) { exit 1 } else { exit 0 }

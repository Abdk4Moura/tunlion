param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
$env:TUNLION_CONFIG_DIR = Join-Path $env:TEMP 'tunlion-access-host'
New-Item -ItemType Directory -Force -Path $env:TUNLION_CONFIG_DIR | Out-Null
& (Join-Path $PSScriptRoot 'tunlion.exe') @Args

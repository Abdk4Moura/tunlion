# Tunlion Windows test kit

This installs **test binaries only** under your local AppData. It does not
replace or configure a production Tunlion installation.

- `tunlion.exe`: temporary TCP service slice from access commit `04740fff`.
  Folder sharing, temporary shell, device networking and `.mesh` DNS are not
  implemented in this binary.
- `tunlion-shell.exe`: separate Windows shell-relay branch `d02e64a4`. It is not
  integrated with temporary access. Its `--i-know` semantics are still under
  reconciliation.

Use two PowerShell windows. Set an isolated config directory before every test:

```powershell
$env:TUNLION_CONFIG_DIR = "$env:TEMP\tunlion-access-host"
.\tunlion.exe add
```

Recipient:

```powershell
$env:TUNLION_CONFIG_DIR = "$env:TEMP\tunlion-access-recipient"
.\tunlion.exe join <code>
```

For the service echo helper:

```powershell
.\echo.ps1 45678
.\probe.ps1 127.0.0.1:<port> "hello"
```

Do not point these binaries at your production config or an existing daemon.

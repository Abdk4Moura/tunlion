# Tunlion combined Windows installer

This builds one standard per-user installer from `integration/windows-combined`.
It installs `tunlion.exe`, `wintun.dll`, and `tl.cmd` into the existing per-user
`%USERPROFILE%\bin`, adds that directory to PATH once, and preserves
`%APPDATA%\tunlion\config`. It does not create or delete an identity.

Before running the installer, stop every Tunlion daemon explicitly with
`tunlion down --yes` in its own `TUNLION_CONFIG_DIR`. The installer does NOT use
Restart Manager and does NOT kill or restart processes. If either binary is still
running, installation must fail rather than terminate it. It leaves `up.pid` and
the config untouched.

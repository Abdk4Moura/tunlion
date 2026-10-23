# Tunlion combined Windows installer

This builds one standard per-user installer from `integration/windows-combined`.
It installs `tunlion.exe`, `wintun.dll`, and `tl.cmd` into the existing per-user
`%USERPROFILE%\bin`, adds that directory to PATH once, and preserves
`%APPDATA%\tunlion\config`. It does not create or delete an identity.

Close all Tunlion processes before running the installer. The current machine can
have more than one process/config; the installer uses standard Restart Manager
close behavior and cannot decide which scratch daemon is safe to stop.

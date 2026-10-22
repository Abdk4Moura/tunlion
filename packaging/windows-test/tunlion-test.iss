#define AppName "Tunlion Test Kit"
#define AppVersion "0.9.0-test"
#define AppPublisher "Tunlion test"
[Setup]
AppId={{A7E3D5B1-2C44-4C8E-9E2A-4F4B3A7C1D20}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={localappdata}\TunlionTestKit
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=Output
OutputBaseFilename=TunlionTestKitSetup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\tunlion.exe
[Files]
Source: "stage\tunlion.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "stage\tunlion-shell.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "stage\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "stage\echo.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "stage\probe.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "stage\host.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "stage\recipient.ps1"; DestDir: "{app}"; Flags: ignoreversion
[Icons]
Name: "{autoprograms}\{#AppName}\Temporary services (test)"; Filename: "{cmd}"; Parameters: "/k cd /d ""{app}"""; WorkingDir: "{app}"
Name: "{autoprograms}\{#AppName}\Shell relay (test)"; Filename: "{cmd}"; Parameters: "/k cd /d ""{app}"""; WorkingDir: "{app}"
Name: "{autoprograms}\{#AppName}\README"; Filename: "{app}\README.md"
[Run]
Filename: "{app}\README.md"; Description: "Open test-kit instructions"; Flags: postinstall shellexec nowait skipifsilent

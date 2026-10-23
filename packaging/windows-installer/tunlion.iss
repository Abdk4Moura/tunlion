; Standard per-user installer for the combined Tunlion Windows build.
;
; - Installs ONE file, tunlion.exe, under %LOCALAPPDATA%\Programs\Tunlion.
; - No administrator rights: PrivilegesRequired=lowest, HKCU only.
; - Adds the install directory to the USER Path (preserving existing entries)
;   and removes only that one entry on uninstall.
; - Start Menu shortcut + an Add/Remove Programs entry with an uninstaller.
; - Upgrades an existing tunlion.exe in the same directory in place
;   (UsePreviousAppDir, overwrite), and never reads, writes, moves or deletes
;   the identity/config directory (%APPDATA%\tunlion).
;
; Build with:
;   ISCC.exe /DAppVersion=0.9.0 tunlion.iss
; after staging the exact combined binary at stage\tunlion.exe.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

#define AppName "Tunlion"
#define AppPublisher "Tunlion"
#define AppExeName "tunlion.exe"

[Setup]
; A DIFFERENT AppId from the test kit: this is the standard app, not a test kit.
AppId={{B6F1A7C2-8E4D-4C1B-9F63-2D7A5E0C9B14}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion={#AppVersion}
DefaultDirName={localappdata}\Programs\Tunlion
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
DisableDirPage=auto
UsePreviousAppDir=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=Output
OutputBaseFilename=TunlionSetup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
Uninstallable=yes
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\{#AppExeName}
CloseApplications=yes
RestartApplications=no
ChangesEnvironment=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; The ONLY installed payload. No test binaries, scripts, READMEs or samples.
Source: "stage\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Start Menu shortcut launches the interactive entry point (the menu).
Name: "{autoprograms}\{#AppName}.lnk"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Comment: "Tunlion"

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch Tunlion"; Flags: nowait postinstall skipifsilent

[Code]
const
  EnvKey = 'Environment';

function UserPath(): string;
begin
  if not RegQueryStringValue(HKCU, EnvKey, 'Path', Result) then
    Result := '';
end;

function HasPathEntry(const Path, Dir: string): Boolean;
begin
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Path) + ';') > 0;
end;

procedure AddToUserPath();
var
  Path, Dir: string;
begin
  Path := UserPath();
  Dir := ExpandConstant('{app}');
  if HasPathEntry(Path, Dir) then
    exit;
  if (Path <> '') and (Path[Length(Path)] <> ';') then
    Path := Path + ';';
  Path := Path + Dir;
  RegWriteExpandStringValue(HKCU, EnvKey, 'Path', Path);
end;

function WithoutPathEntry(const Path, Dir: string): string;
var
  Rest, Seg: string;
  P: Integer;
begin
  Rest := Path;
  Result := '';
  while Rest <> '' do
  begin
    P := Pos(';', Rest);
    if P = 0 then
    begin
      Seg := Rest;
      Rest := '';
    end
    else
    begin
      Seg := Copy(Rest, 1, P - 1);
      Rest := Copy(Rest, P + 1, Length(Rest));
    end;
    if (Seg <> '') and (CompareText(Seg, Dir) <> 0) then
    begin
      if Result <> '' then
        Result := Result + ';';
      Result := Result + Seg;
    end;
  end;
end;

procedure RemoveFromUserPath();
var
  Path, Dir: string;
begin
  Path := UserPath();
  Dir := ExpandConstant('{app}');
  if not HasPathEntry(Path, Dir) then
    exit;
  Path := WithoutPathEntry(Path, Dir);
  if Path = '' then
    RegDeleteValue(HKCU, EnvKey, 'Path')
  else
    RegWriteExpandStringValue(HKCU, EnvKey, 'Path', Path);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    AddToUserPath();
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RemoveFromUserPath();
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  DataDir: string;
begin
  Result := True;
  if CurPageID = wpSelectDir then
  begin
    // The config/identity directory must not be the install directory: the
    // uninstaller removes installed files and must never be able to remove a
    // user's keys.
    DataDir := ExpandConstant('{userappdata}\tunlion');
    if CompareText(WizardDirValue, DataDir) = 0 then
    begin
      MsgBox('Refusing to install into the Tunlion config directory. Choose a program directory.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

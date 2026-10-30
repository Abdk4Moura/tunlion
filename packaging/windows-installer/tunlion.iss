; Standard per-user installer for the combined Tunlion Windows build.
;
; Target: the user's existing per-user bin (%USERPROFILE%\bin), which is where
; the owner machine already runs tunlion.exe from, so an upgrade lands on the
; binary the user PATH and the TunlionKernel task actually use. No admin, no
; side-by-side copy under %LOCALAPPDATA%\Programs.
;
; - Installs the combined tunlion.exe plus its two runtime companions:
;   the signed wintun.dll (kernel TUN) and the `tl` launcher. No test binaries,
;   scripts, READMEs or test-kit branding.
; - Adds the directory to the USER Path only if missing, then de-duplicates the
;   existing Path entries (case-insensitive, first occurrence wins).
; - Start Menu shortcut + a proper Add/Remove Programs entry and uninstaller.
; - Upgrades an existing tunlion.exe in that directory in place.
; - Never reads, writes, moves or deletes the identity/config directory
;   (%APPDATA%\tunlion), and never touches the TunlionKernel scheduled task.
;
; Build with:
;   ISCC.exe /DAppVersion=0.9.2 tunlion.iss
; after staging tunlion.exe, wintun.dll and tl.cmd under stage\.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

#define AppName "Tunlion"
#define AppPublisher "Tunlion"
#define AppExeName "tunlion.exe"

[Setup]
; The standard app identity (never the test kit's AppId).
AppId={{B8F4E4C2-9D6A-4B1E-8C7F-6D3A2E1B9C40}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion={#AppVersion}
DefaultDirName={userpf}\bin
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
; The combined binary and the two runtime files it needs; nothing else.
Source: "stage\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "stage\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "stage\tl.cmd"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Comment: "Tunlion"

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

// Add the install directory if absent and collapse duplicate entries. The
// owner machine already had this directory in Path (possibly twice), so the
// installer must not append a third copy. Existing order and unrelated entries
// are preserved.
procedure NormalizeUserPath();
var
  Path, Item, Clean: string;
  P: Integer;
  Seen: TStringList;
  Dir: string;
begin
  Path := UserPath();
  Dir := ExpandConstant('{app}');
  if not HasPathEntry(Path, Dir) then
  begin
    if (Path <> '') and (Path[Length(Path)] <> ';') then
      Path := Path + ';';
    Path := Path + Dir;
  end;
  Seen := TStringList.Create;
  try
    Seen.CaseSensitive := False;
    Clean := '';
    // Manual split: Inno's Pascal Script has no SplitString helper.
    while Path <> '' do
    begin
      P := Pos(';', Path);
      if P = 0 then
      begin
        Item := Path;
        Path := '';
      end
      else
      begin
        Item := Copy(Path, 1, P - 1);
        Path := Copy(Path, P + 1, Length(Path));
      end;
      Item := Trim(Item);
      if (Item <> '') and (Seen.IndexOf(Item) < 0) then
      begin
        Seen.Add(Item);
        if Clean <> '' then
          Clean := Clean + ';';
        Clean := Clean + Item;
      end;
    end;
    RegWriteExpandStringValue(HKCU, EnvKey, 'Path', Clean);
  finally
    Seen.Free;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    NormalizeUserPath();
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  DataDir: string;
begin
  Result := True;
  if CurPageID = wpSelectDir then
  begin
    // The config/identity directory must never become the install directory:
    // the uninstaller removes installed files and must not be able to remove
    // a user's keys.
    DataDir := ExpandConstant('{userappdata}\tunlion');
    if CompareText(WizardDirValue, DataDir) = 0 then
    begin
      MsgBox('Refusing to install into the Tunlion config directory. Choose a program directory.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

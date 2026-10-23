#define AppName "Tunlion"
#define AppVersion "0.9.0-test"
#define AppPublisher "Tunlion"
[Setup]
AppId={{B8F4E4C2-9D6A-4B1E-8C7F-6D3A2E1B9C40}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={userprofile}\bin
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=Output
OutputBaseFilename=TunlionSetup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\tunlion.exe
ChangesEnvironment=yes
CloseApplications=yes
RestartApplications=no
[Files]
Source: "stage\tunlion.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "stage\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "stage\tl.cmd"; DestDir: "{app}"; Flags: ignoreversion
[Icons]
Name: "{autoprograms}\{#AppName}\Tunlion"; Filename: "{app}\tunlion.exe"
[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Flags: preservestringtype; Check: NeedAddPath
[Code]
function NeedAddPath: Boolean;
var
  PathValue: String;
begin
  Result := True;
  if RegQueryStringValue(HKCU, 'Environment', 'Path', PathValue) then
    Result := Pos(';' + Lowercase(ExpandConstant('{app}')) + ';', ';' + Lowercase(PathValue) + ';') = 0;
end;

procedure NormalizePath;
var
  PathValue, Item, Clean: String;
  Parts: TArrayOfString;
  I: Integer;
  Seen: TStringList;
begin
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', PathValue) then exit;
  Seen := TStringList.Create;
  try
    Seen.CaseSensitive := False;
    Clean := '';
    Parts := SplitString(PathValue, ';');
    for I := 0 to GetArrayLength(Parts) - 1 do begin
      Item := Trim(Parts[I]);
      if (Item <> '') and (Seen.IndexOf(Item) < 0) then begin
        Seen.Add(Item);
        if Clean <> '' then Clean := Clean + ';';
        Clean := Clean + Item;
      end;
    end;
    RegWriteExpandStringValue(HKCU, 'Environment', 'Path', Clean);
  finally
    Seen.Free;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then NormalizePath;
end;

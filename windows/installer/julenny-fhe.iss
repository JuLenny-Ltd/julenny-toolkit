; JuLenny FHE - unified Windows installer (Inno Setup 6).
; One installer, three checkbox components: UI app / CLI / MCP. Per-user, no admin.
;
; DRAFT (2026-06-22): authored without a build/test run. Prerequisites before this
; compiles and works end-to-end:
;   #22  the SEA single-exe must exist at  mcp\sea\julenny-mcp.exe
;   #23  the app must be a PLAIN (unpackaged) win32 build; set AppSourceDir below
;        to its output folder (D2). The path here is a PLACEHOLDER - fix it.
;   CLI  build\cli\Release\julenny-fhe.exe (+ the 2 runtime DLLs) - already built.
; Build:  iscc windows\installer\julenny-fhe.iss   (Inno Setup's compiler)
; Sign:   signtool the three exes AND the produced setup.exe with the app cert.

#define AppVersion "0.6.0"
; Unpackaged (WindowsPackageType=None, self-contained) WinUI 3 build output (#23).
#define AppSourceDir "..\..\windows\JuLennyFHE\x64\Release\JuLennyFHE"

[Setup]
AppId={{4E2B7F1A-9C3D-4A6E-B8F0-JULENNYFHE001}}
AppName=JuLenny FHE
AppVersion={#AppVersion}
AppPublisher=JuLenny Ltd
DefaultDirName={localappdata}\Programs\julenny-fhe
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
ChangesEnvironment=yes
OutputBaseFilename=julenny-fhe-setup-windows-amd64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Branding: setup.exe's own icon, and the icon shown in Add/Remove Programs.
SetupIconFile=..\..\windows\JuLennyFHE\Assets\app.ico
UninstallDisplayIcon={app}\app\JuLennyFHE.exe

[Types]
Name: "full";   Description: "Everything (app, CLI, and MCP server)"
Name: "custom"; Description: "Choose what to install";               Flags: iscustom

[Components]
Name: "app"; Description: "JuLenny FHE desktop app (graphical UI)";        Types: full
Name: "cli"; Description: "Command-line tool (julenny-fhe)";              Types: full
Name: "mcp"; Description: "MCP server for Claude Desktop (julenny-mcp)";  Types: full

[Files]
; --- Installer-only helper: modern folder picker (x86, called during the wizard).
;     dontcopy = bundled inside setup.exe, extracted to {tmp} on demand, never
;     left on the user's machine. ---
Source: "folderpicker.dll"; Flags: dontcopy
; --- CLI + its runtime DLLs. The MCP shells out to the CLI, so these install
;     whenever EITHER the cli or mcp component is selected. ---
Source: "..\..\build\cli\Release\julenny-fhe.exe";        DestDir: "{app}"; Components: cli or mcp; Flags: ignoreversion
Source: "..\..\build\cli\Release\libomp.dll";             DestDir: "{app}"; Components: cli or mcp; Flags: ignoreversion
Source: "..\..\build\cli\Release\libcrypto-4-x64.dll";    DestDir: "{app}"; Components: cli or mcp; Flags: ignoreversion
; --- MCP single self-contained exe (SEA, #22) + the config-merge helper ---
Source: "..\..\mcp\sea\julenny-mcp.exe";                  DestDir: "{app}"; Components: mcp; Flags: ignoreversion
Source: "merge-claude-config.ps1";                        DestDir: "{app}"; Components: mcp; Flags: ignoreversion
; --- UI app (D2: plain win32 payload). PLACEHOLDER source dir - fix per #23. ---
Source: "{#AppSourceDir}\*";                              DestDir: "{app}\app"; Components: app; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\JuLenny FHE"; Filename: "{app}\app\JuLennyFHE.exe"; Components: app
Name: "{autodesktop}\JuLenny FHE";  Filename: "{app}\app\JuLennyFHE.exe"; Components: app; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Components: app; Flags: unchecked

[Registry]
; Prepend {app} to the user PATH so `julenny-fhe` / `julenny-mcp` resolve and the
; MCP config can omit JULENNY_FHE_BIN. Only when a command-line piece is installed.
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; \
  ValueData: "{app};{olddata}"; Check: NeedsAddPath('{app}'); Components: cli or mcp

[Run]
; Wire the MCP into Claude Desktop (merge, don't clobber other servers). MCP only.
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\merge-claude-config.ps1"" -ApiKey ""{code:GetApiKey}"" -McpExePath ""{app}\julenny-mcp.exe"" -Workdir ""{code:GetWorkdir}"""; \
  StatusMsg: "Configuring the JuLenny connector in Claude Desktop..."; \
  Flags: runhidden waituntilterminated; Components: mcp

[Code]
var
  ApiKeyPage:  TInputQueryWizardPage;
  WorkdirPage: TInputDirWizardPage;

// Modern folder picker exported by folderpicker.dll (bundled dontcopy, x86,
// extracted to {tmp} on first call). files: + delayload so a load failure is
// catchable rather than fatal.
function ShowFolderDialog(Title, InitialPath: String; OutBuf: String; OutBufChars: Integer): Integer;
  external 'ShowFolderDialog@files:folderpicker.dll stdcall setuponly delayload';

// Replaces the dir page's default (legacy tree) Browse handler with the modern
// dialog. On any failure we leave the editable path field as-is so the wizard
// never breaks (the user can still type or paste a path).
procedure BrowseClick(Sender: TObject);
var
  Buf: String;
  n: Integer;
begin
  SetLength(Buf, 1024);
  try
    n := ShowFolderDialog('Select the JuLenny working folder', WorkdirPage.Values[0], Buf, 1024);
  except
    n := -1;
  end;
  if n > 0 then
  begin
    SetLength(Buf, n);
    WorkdirPage.Values[0] := Buf;
  end;
end;

procedure InitializeWizard;
begin
  ApiKeyPage := CreateInputQueryPage(wpSelectComponents,
    'JuLenny API key',
    'Connect the MCP server to your JuLenny account',
    'Paste your JuLenny API key. You can leave this blank and add it later in' + #13#10 +
    'Claude Desktop''s configuration. (Only used if you install the MCP server.)');
  ApiKeyPage.Add('API key:', False);

  // Folder picker with a Browse... button. Prefilled with the MCP's default so
  // the value is always valid; the user can Browse to a different folder.
  WorkdirPage := CreateInputDirPage(ApiKeyPage.ID,
    'JuLenny working folder',
    'Where should the MCP store keys, datasets and results?',
    'The default is filled in below. Click Browse to choose a different folder.' + #13#10 +
    '(Only used if you install the MCP server.)',
    False, '');
  WorkdirPage.Add('');
  WorkdirPage.Values[0] := ExpandConstant('{localappdata}\julenny-fhe\workdir');
  // Swap the legacy folder-tree Browse for the modern IFileDialog picker.
  WorkdirPage.Buttons[0].OnClick := @BrowseClick;
end;

function GetApiKey(Param: String): String;
begin
  Result := ApiKeyPage.Values[0];
end;

function GetWorkdir(Param: String): String;
begin
  Result := WorkdirPage.Values[0];
end;

// Should {app} be prepended to PATH? (skip if already present)
function NeedsAddPath(Param: String): Boolean;
var
  OrigPath: String;
begin
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + ExpandConstant(Param) + ';', ';' + OrigPath + ';') = 0;
end;

// NOTE: a VC++ runtime (MSVCP140/VCRUNTIME140) check belongs here if the CLI/app
// need it; add a CheckForVCRedist() that downloads/launches the MS redist when
// missing. Left as a TODO pending a real Windows test of the built exes.

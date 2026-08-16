; JuLenny Toolkit - unified Windows installer (Inno Setup 6).
; One installer, four checkbox components: UI app / CLI / MCP / example scripts.
; Per-user, no admin rights required.
;
; Build:  iscc windows\installer\julenny-toolkit.iss     (Inno Setup's compiler)
; Sign:   signtool the three exes AND the produced setup.exe with the app cert.
;
; Inputs it expects to already exist (build them first):
;   build\cli\Release\julenny-toolkit.exe + libomp.dll + libcrypto-4-x64.dll
;                                          (windows\build-cli.ps1)
;   mcp\sea\julenny-mcp.exe                (windows\build-mcp-exe.ps1)
;   windows\installer\folderpicker.dll     (windows\build-folderpicker.ps1)
;                                          x86 on purpose: setup.exe is a 32-bit
;                                          process and would fail to load an x64 DLL.
;   the app payload at AppSourceDir        (see the open question below)
;
; PACKAGING: option D2 (decided 2026-08-15). ONE installer carries everything -
; app, CLI, MCP and the example scripts. There is no separate MSIX download.
; JuLennyFHE.vcxproj is already configured for it (WindowsPackageType=None,
; WindowsAppSDKSelfContained=true), so AppSourceDir below is a real unpackaged,
; self-contained build: the Windows App SDK runtime ships inside it and the
; customer installs no prerequisites.

#define AppVersion "0.7.0"
; Unpackaged (WindowsPackageType=None, self-contained) WinUI 3 build output (#23).
#define AppSourceDir "..\..\windows\JuLennyFHE\x64\Release\JuLennyFHE"

[Setup]
AppId={{348882B0-EC6F-40E9-AB36-BFF8C5FBF786}}
AppName=JuLenny Toolkit
AppVersion={#AppVersion}
AppPublisher=JuLenny Ltd
DefaultDirName={localappdata}\Programs\julenny-toolkit
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
ChangesEnvironment=yes
OutputBaseFilename=julenny-toolkit-setup-windows-amd64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Branding: setup.exe's own icon, and the icon shown in Add/Remove Programs.
SetupIconFile=..\..\windows\JuLennyFHE\Assets\app.ico
UninstallDisplayIcon={app}\app\JuLennyFHE.exe

[Types]
Name: "full";   Description: "Everything (app, CLI, MCP server, and example scripts)"
Name: "custom"; Description: "Choose what to install";               Flags: iscustom

[Components]
Name: "app"; Description: "JuLenny Toolkit desktop app (graphical UI)";        Types: full
Name: "cli"; Description: "Command-line tool (julenny-toolkit)";              Types: full
Name: "mcp"; Description: "MCP server for Claude Desktop (julenny-mcp)";  Types: full
Name: "examples"; Description: "Example scripts (integration reference)"; Types: full

[Files]
; --- Installer-only helper: modern folder picker (x86, called during the wizard).
;     dontcopy = bundled inside setup.exe, extracted to {tmp} on demand, never
;     left on the user's machine. ---
Source: "folderpicker.dll"; Flags: dontcopy
; --- CLI + its runtime DLLs. The MCP shells out to the CLI, so these install
;     whenever EITHER the cli or mcp component is selected. ---
Source: "..\..\build\cli\Release\julenny-toolkit.exe";        DestDir: "{app}"; Components: cli or mcp; Flags: ignoreversion
Source: "..\..\build\cli\Release\libomp.dll";             DestDir: "{app}"; Components: cli or mcp; Flags: ignoreversion
Source: "..\..\build\cli\Release\libcrypto-4-x64.dll";    DestDir: "{app}"; Components: cli or mcp; Flags: ignoreversion
; --- MCP single self-contained exe (SEA, #22) + the config-merge helper ---
Source: "..\..\mcp\sea\julenny-mcp.exe";                  DestDir: "{app}"; Components: mcp; Flags: ignoreversion
Source: "merge-claude-config.ps1";                        DestDir: "{app}"; Components: mcp; Flags: ignoreversion
; --- UI app (D2: unpackaged, self-contained win32 payload). ---
;     Excludes *.pdb: those are debug symbols, ~85MB of the ~188MB payload. They
;     are no use to a customer, they inflate the download, and they hand a
;     reverse engineer a map of the binary. Keep them in the build output for
;     crash analysis; just do not ship them.
Source: "{#AppSourceDir}\*";                              DestDir: "{app}\app"; Components: app; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "*.pdb"
; --- Example scripts. Read-only reference copy under {app}, mirroring the .deb's
;     /usr/share/julenny-toolkit/examples. The helper below copies the operator's
;     chosen side out to a writable folder; it stays installed so they can re-run
;     it later to switch side or make another copy. ---
Source: "..\..\examples\*";                               DestDir: "{app}\examples"; Components: examples; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "julenny-toolkit-examples.ps1";                   DestDir: "{app}"; Components: examples; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\JuLenny Toolkit"; Filename: "{app}\app\JuLennyFHE.exe"; Components: app
Name: "{autodesktop}\JuLenny Toolkit";  Filename: "{app}\app\JuLennyFHE.exe"; Components: app; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Components: app; Flags: unchecked

[Registry]
; Prepend {app} to the user PATH so `julenny-toolkit` / `julenny-mcp` resolve and the
; MCP config can omit JULENNY_TOOLKIT_BIN. Only when a command-line piece is installed.
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; \
  ValueData: "{app};{olddata}"; Check: NeedsAddPath('{app}'); Components: cli or mcp

[Run]
; Wire the MCP into Claude Desktop (merge, don't clobber other servers). MCP only.
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\merge-claude-config.ps1"" -ApiKey ""{code:GetApiKey}"" -McpExePath ""{app}\julenny-mcp.exe"" -Workdir ""{code:GetWorkdir}"""; \
  StatusMsg: "Configuring the JuLenny connector in Claude Desktop..."; \
  Flags: runhidden waituntilterminated; Components: mcp
; Copy the chosen side of the examples out to the operator's folder. Same helper
; they can re-run later to switch side; -Force because the wizard already owns
; the destination choice, -Yes because the wizard already confirmed it.
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\julenny-toolkit-examples.ps1"" -Role ""{code:GetExamplesRole}"" -Dest ""{code:GetExamplesDest}"" -Source ""{app}\examples"" -Force -Yes"; \
  StatusMsg: "Copying the example scripts..."; \
  Flags: runhidden waituntilterminated; Components: examples; Check: ShouldCopyExamples

[Code]
var
  ApiKeyPage:       TInputQueryWizardPage;
  WorkdirPage:      TInputDirWizardPage;
  ExamplesRolePage: TInputOptionWizardPage;
  ExamplesDirPage:  TInputDirWizardPage;

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

// Same modern picker for the examples destination. Declared before
// InitializeWizard because Pascal Script resolves in one pass.
procedure ExamplesBrowseClick(Sender: TObject);
var
  Buf: String;
  n: Integer;
begin
  SetLength(Buf, 1024);
  try
    n := ShowFolderDialog('Select a folder for the example scripts', ExamplesDirPage.Values[0], Buf, 1024);
  except
    n := -1;
  end;
  if n > 0 then
  begin
    SetLength(Buf, n);
    ExamplesDirPage.Values[0] := Buf;
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
  WorkdirPage.Values[0] := ExpandConstant('{localappdata}\julenny-toolkit\workdir');
  // Swap the legacy folder-tree Browse for the modern IFileDialog picker.
  WorkdirPage.Buttons[0].OnClick := @BrowseClick;

  // Which side of the collaboration this machine is. Determines which half of
  // the example tree gets copied out. The last option is an explicit "not now",
  // so the operator can still decline after seeing the page.
  ExamplesRolePage := CreateInputOptionPage(WorkdirPage.ID,
    'Example scripts',
    'Which side of the collaboration is this machine?',
    'The examples come in two halves. Pick yours and only that half is copied' + #13#10 +
    'to a folder you choose. (Only used if you install the example scripts.)',
    True, False);
  ExamplesRolePage.Add('Data owner - holds the data being queried (acme)');
  ExamplesRolePage.Add('Data consumer - triggers the run, sees the result (beta)');
  ExamplesRolePage.Add('Both - for single-machine testing');
  ExamplesRolePage.Add('Don''t copy them now (you can run the helper later)');
  ExamplesRolePage.SelectedValueIndex := 0;

  ExamplesDirPage := CreateInputDirPage(ExamplesRolePage.ID,
    'Example scripts folder',
    'Where should the example scripts be copied?',
    'A read-only reference copy always goes into the install folder. This is the' + #13#10 +
    'editable working copy.',
    False, '');
  ExamplesDirPage.Add('');
  ExamplesDirPage.Values[0] := ExpandConstant('{userdocs}\julenny-examples');
  ExamplesDirPage.Buttons[0].OnClick := @ExamplesBrowseClick;
end;

// Which role the operator picked, as the helper's -Role argument. Empty when
// they chose "don't copy them now".
function GetExamplesRole(Param: String): String;
begin
  case ExamplesRolePage.SelectedValueIndex of
    0: Result := 'owner';
    1: Result := 'consumer';
    2: Result := 'both';
  else
    Result := '';
  end;
end;

function GetExamplesDest(Param: String): String;
begin
  Result := ExamplesDirPage.Values[0];
end;

// Run the copy only when the component is installed AND a side was chosen.
function ShouldCopyExamples: Boolean;
begin
  Result := WizardIsComponentSelected('examples') and (GetExamplesRole('') <> '');
end;

// Hide both example pages unless the component is selected, and hide the
// destination page when the operator already said "don't copy them now".
function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if (PageID = ExamplesRolePage.ID) then
    Result := not WizardIsComponentSelected('examples')
  else if (PageID = ExamplesDirPage.ID) then
    Result := (not WizardIsComponentSelected('examples')) or (GetExamplesRole('') = '');
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

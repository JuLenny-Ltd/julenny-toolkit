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

#define AppVersion "0.7.1"
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

; Inno only overwrites files the new version ships; anything a previous version installed and
; this one no longer does is left behind forever. That is how 27 bash scripts from June were
; still sitting in {app}\examples after the release that deliberately stopped shipping them to
; Windows. Stale scripts are worse than clutter here: a customer can run one and get behaviour
; from a version we no longer support. Clear the read-only reference tree before copying, so
; {app}\examples is always exactly what this build shipped. Only that folder: never {app}
; itself, which holds the app, the CLI, the MCP and the uninstaller.
[InstallDelete]
Type: filesandordirs; Name: "{app}\examples"; Components: examples

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
;     Excludes the bash half: nothing on Windows runs a .sh, and the .env side
;     profiles are the bash twins of sides\*.ps1. The .deb excludes the .ps1 half
;     of the same tree. ---
Source: "..\..\examples\*";                               DestDir: "{app}\examples"; Components: examples; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "*.sh,*.env"
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

; Remember the working folder. Without this an upgrade silently reverted it to the default,
; and since the [Run] step rewrites JULENNY_WORKDIR in the Claude Desktop config, the user's
; existing keys and datasets became invisible to the MCP with nothing to indicate why.
Root: HKCU; Subkey: "Software\JuLenny\Toolkit"; ValueType: string; ValueName: "WorkDir"; \
  ValueData: "{code:GetWorkdir}"; Flags: uninsdeletevalue; Components: mcp

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
  PrevWorkdir:      String;

// ---------------------------------------------------------------------------
// Claude Desktop detection.
//
// Claude Desktop rewrites claude_desktop_config.json from its in-memory state
// when it exits. If it is running while we merge the JuLenny connector in, the
// entry is silently erased the next time the user closes it, and the installer
// looks like it worked when it did not.
//
// DANGER: Claude Desktop and Claude CODE share the image name claude.exe.
//   Desktop     ...\WindowsApps\Claude_<pkg>\app\Claude.exe
//               ...\AnthropicClaude\...\claude.exe          (non-store install)
//   Claude Code ...\.vscode\extensions\anthropic.claude-code-...\claude.exe
//               ...\Roaming\Claude\claude-code\<ver>\claude.exe
// Matching on the image name and calling taskkill /IM would kill the user's
// Claude Code sessions. Everything below filters on the executable PATH and
// pipes matched processes straight to Stop-Process, so only Desktop is touched.
// ---------------------------------------------------------------------------

// DESIGN: the warning must not depend on this detection working.
//
// The process name, install paths and package identity all belong to a
// particular Claude Desktop build and will drift. So the reliable mechanism is
// the plain-text warning on the API-key wizard page, which is always shown
// whenever the MCP component is selected and cannot silently stop working.
// Everything below is a convenience layered on top: if it correctly spots
// Desktop we offer to close it, and if it never matches again after some future
// update, the user still got told.
//
// Matching is deliberately conservative. It requires BOTH a claude.exe process
// AND a main window title, because Claude Desktop is a GUI app and the Claude
// Code processes that share the image name are not. Paths are used only to
// exclude, never to include, so a renamed Desktop path degrades to "not
// detected" rather than to "kill something else".
function ClaudeDesktopFilter: String;
begin
  Result := 'Get-Process -Name claude -ErrorAction SilentlyContinue | ' +
            'Where-Object { $_.MainWindowTitle -and $_.Path ' +
            '-and $_.Path -notmatch ''claude-code'' -and $_.Path -notmatch ''\.vscode'' }';
end;

function IsClaudeDesktopRunning: Boolean;
var
  ResultCode: Integer;
begin
  Result := False;
  if Exec('powershell.exe',
          '-NoProfile -ExecutionPolicy Bypass -Command "if (' + ClaudeDesktopFilter + ') { exit 1 } else { exit 0 }"',
          '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Result := (ResultCode = 1);
end;

// CloseMainWindow, not Stop-Process -Force: this asks the app to shut down
// normally so it saves its own state. Safe to let it write its config here,
// because this runs BEFORE merge-claude-config.ps1 adds our entry.
procedure CloseClaudeDesktop;
var
  ResultCode: Integer;
begin
  Exec('powershell.exe',
       '-NoProfile -ExecutionPolicy Bypass -Command "' + ClaudeDesktopFilter +
       ' | ForEach-Object { $_.CloseMainWindow() | Out-Null }"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// Runs after the wizard, before any files are copied, and so before the [Run]
// step that merges the connector in.
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';   // a non-empty result aborts the install; never wanted here
  if not WizardIsComponentSelected('mcp') then
    exit;
  if not IsClaudeDesktopRunning then
    exit;        // the wizard page already warned; do not nag

  if MsgBox('Claude Desktop appears to be running.'#13#10#13#10 +
            'It rewrites its configuration when it closes, which would erase the JuLenny ' +
            'connector this installer is about to add.'#13#10#13#10 +
            'Ask Claude Desktop to close now?'#13#10#13#10 +
            'This does not affect Claude Code.',
            mbConfirmation, MB_YESNO) = IDYES then
  begin
    CloseClaudeDesktop;
    Sleep(3000);
    if IsClaudeDesktopRunning then
      MsgBox('Claude Desktop is still running. Please close it manually, then click OK.',
             mbInformation, MB_OK);
  end;
end;

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
  // The Claude Desktop warning lives here rather than relying on process
  // detection: this text is always shown when the MCP component is selected,
  // and cannot stop working when Claude Desktop changes its process name or
  // install path.
  ApiKeyPage := CreateInputQueryPage(wpSelectComponents,
    'JuLenny API key',
    'Connect the MCP server to your JuLenny account',
    'IMPORTANT: close Claude Desktop before continuing. It rewrites its' + #13#10 +
    'configuration when it exits and will erase the connector added here.' + #13#10 +
    '(Claude Code is unaffected and can stay open.)' + #13#10 + #13#10 +
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
  // Prefer the folder chosen by a previous install; fall back to the default only on a first
  // install. An upgrade that silently moves the working folder orphans the user's keys.
  if not RegQueryStringValue(HKCU, 'Software\JuLenny\Toolkit', 'WorkDir', PrevWorkdir) then
    PrevWorkdir := '';
  if PrevWorkdir <> '' then
    WorkdirPage.Values[0] := PrevWorkdir
  else
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

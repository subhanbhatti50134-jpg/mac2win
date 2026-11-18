; Mac2Win Receiver — Inno Setup installer script (DRAFT, M7)
; ADR-004: Windows installer = Inno Setup.
; Build (on a Windows machine with Inno Setup 6 + the signing cert):
;   iscc Mac2WinReceiver.iss
; Signing: signtool sign /a /fd SHA256 /tr http://timestamp.digicert.com
;     "Output\Mac2WinReceiver-Setup.exe"
;
; This script is NOT built or tested locally (no iscc on this workstation, no signing
; cert). Marked NOT RUN in docs/VERIFICATION.md M7.

#define MyAppName "Mac2Win Transfer"
#define MyAppPublisher "Mac2Win Project"
#define MyAppURL "https://github.com/mac2win/mac2win"
#define MyAppExeName "Mac2WinReceiver.App.exe"
#define MyAppVersion "0.1.0"

[Setup]
AppId={{7C8A1F2E-3D4B-4A9C-8E2F-1A2B3C4D5E6F}}
AppName={#MyAppName}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
Version={#MyAppVersion}
; Boat: self-contained publish output dir is expected in "..\App\bin\Release\net10.0-windows\win-x64\publish\"
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=../LICENSE
OutputDir=Output
OutputBaseFilename=Mac2WinReceiver-Setup-{#MyAppVersion}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "firewallrule"; Description: "Allow Mac2Win Receiver on Private networks (Windows Firewall)"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; NOTE: self-contained publish must be produced first:
;   dotnet publish win-receiver/App/Mac2WinReceiver.App.csproj -c Release -r win-x64 --self-contained
Source: "..\App\bin\Release\net10.0-windows\win-x64\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: dirifempty; Dir: "{app}"

[Code]
; Firewall rule: allow inbound on the receiver port (Private profile only, per SPEC §5).
; Port is read from settings at runtime; the rule opens 48600/tcp as the default.
function InitializeSetup(): Boolean;
begin
  Result := True;
end;

procedure CurStepChanged(CurStep: TInstallStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    if IsTaskSelected("firewallrule") then
    begin
      Exec('netsh', 'advfirewall firewall add rule name="Mac2Win Receiver" dir=in action=allow protocol=TCP localport=48600 profile=private enable=yes', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    end;
  end;
end;

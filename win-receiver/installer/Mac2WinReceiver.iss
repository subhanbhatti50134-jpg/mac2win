; Mac2Win Receiver — Inno Setup installer script (M7)
; ADR-004: Windows installer = Inno Setup.
;
; Build (on a Windows machine with Inno Setup 6 + the signing cert):
;   iscc Mac2WinReceiver.iss
;
; Prerequisites (run once):
;   dotnet publish win-receiver\App\Mac2WinReceiver.App.csproj -c Release `
;     -r win-x64 --self-contained /p:PublishSingleFile=false /p:PublishTrimmed=false
;
; Signing (optional):
;   signtool sign /a /fd SHA256 /tr http://timestamp.digicert.com `
;     "Output\Mac2WinReceiver-Setup-0.1.0.exe"

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
AppVersion={#MyAppVersion}
; Self-contained publish output dir is expected in:
;   ..\App\bin\Release\net10.0-windows\win-x64\publish\
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
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

[Files]
; Self-contained publish must be produced first (see publish-windows.ps1)
Source: "..\App\bin\Release\net10.0-windows\win-x64\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

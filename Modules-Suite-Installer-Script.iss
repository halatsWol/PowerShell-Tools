; Script generated by the Inno Setup Script Wizard.
; SEE THE DOCUMENTATION FOR DETAILS ON CREATING INNO SETUP SCRIPT FILES!

#define MyAppName "PowerShell-Tools - Modules Suite"
#define MyAppVersion "v1.0"
#define MyAppPublisher "Marflow Software"
#define MyAppURL "https://www.kMarflow.com/"
#define MyAppExeName "MyProg.exe"
#define BaseDir "C:\Program Files\WindowsPowerShell\Modules"

[Setup]
; NOTE: The value of AppId uniquely identifies this application. Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{2C740815-92FE-4573-9D18-35E1C903F7F2}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName}, {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppCopyright=Copyright (C) 2025 {#MyAppPublisher}, Inc.                   
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
CreateAppDir=no
LicenseFile={#SourcePath}\LICENSE
InfoBeforeFile={#SourcePath}\Pre-Install.nfo
InfoAfterFile={#SourcePath}\Post-Install.nfo
; Uncomment the following line to run in non administrative install mode (install for current user only.)
;PrivilegesRequired=lowest
OutputDir={#SourcePath}\installer
OutputBaseFilename=Setup_Powershell-ModulesSuite_{#MyAppVersion}
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Dirs]
Name: "{#BaseDir}\TempDataCleanup"
Name: "{#BaseDir}\RepairSystem"

[Files]
Source: "{#SourcePath}\modules\TempDataCleanup\TempDataCleanup.psm1"; DestDir: "{#BaseDir}\TempDataCleanup"; Flags: ignoreversion
Source: "{#SourcePath}\modules\TempDataCleanup\TempDataCleanup.psd1"; DestDir: "{#BaseDir}\TempDataCleanup"; Flags: ignoreversion
Source: "{#SourcePath}\modules\TempDataCleanup\en-US\*"; DestDir: "{#BaseDir}\TempDataCleanup\en-US"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourcePath}\modules\Repair-System\RepairSystem.psd1"; DestDir: "{#BaseDir}\RepairSystem"; Flags: ignoreversion
Source: "{#SourcePath}\modules\Repair-System\RepairSystem.psm1"; DestDir: "{#BaseDir}\RepairSystem"; Flags: ignoreversion                                 
Source: "{#SourcePath}\modules\Repair-System\en-US\*"; DestDir: "{#BaseDir}\RepairSystem\en-US"; Flags: ignoreversion recursesubdirs createallsubdirs
; NOTE: Don't use "Flags: ignoreversion" on any shared system files


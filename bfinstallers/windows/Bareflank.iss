;
; Copyright (C) 2019 Assured Information Security, Inc.
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.

[Setup]
AppName=Thunderlane
AppVersion=0.9
DefaultDirName={pf}\Thunderlane
DefaultGroupName=Thunderlane
UninstallDisplayIcon={app}\RemoveThunderlane.exe
Compression=lzma2
SolidCompression=yes
;OutputDir=userdocs:Inno Setup Examples Output
AlwaysRestart=yes
ArchitecturesInstallIn64BitMode=x64
OutputBaseFilename=InstallThunderlane
;SetupIconFile=Francois.ico
;WizardImageFile=Francois.bmp
;WizardSmallImageFile=FrancoisSmall.bmp

[Files]
;Source: "Readme.txt"; DestDir: "{app}"; Flags: isreadme
Source: "Input\bareflank.efi"; DestDir: "P:\EFI\Boot\"
Source: "Input\vmlinux-ndvm"; DestDir: "{app}"
Source: "Input\vmlinux-vpnvm"; DestDir: "{app}"
Source: "Input\bfexec.exe"; DestDir: "{app}"
Source: "Input\visr.inf"; Flags: dontcopy
Source: "Input\visr.sys"; Flags: dontcopy
Source: "Input\visr.cat"; Flags: dontcopy
Source: "Input\builder.inf"; Flags: dontcopy
Source: "Input\builder.sys"; Flags: dontcopy
Source: "Input\builder.cat"; Flags: dontcopy
Source: "devcon.exe"; DestDir: "{app}"
Source: "RemoveDrivers.bat"; DestDir: "{app}"
Source: "RemovePath.bat"; DestDir: "{app}"

[Icons]
;Name: "{group}\My Program"; Filename: "{app}\MyProg.exe"

[Run]

[UninstallRun]
Filename: "{app}\RemovePath.bat"; Flags: runhidden
Filename: "{app}\RemoveDrivers.bat"; Flags: runhidden

[Code]
function InitializeSetup(): Boolean;
var
  ResultCode: integer;
begin
  Exec('cmd.exe', '/C mountvol P: /S', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: integer;
begin
  if CurStep = ssPostInstall then
  begin
    ExtractTemporaryFile('visr.inf')
    ExtractTemporaryFile('visr.sys')
    ExtractTemporaryFile('visr.cat')
    ExtractTemporaryFile('builder.inf')
    ExtractTemporaryFile('builder.sys')
    ExtractTemporaryFile('builder.cat')
    Exec('cmd.exe', '/C mountvol P: /D', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', '/C bcdedit /set {bootmgr} path \EFI\Boot\bareflank.efi', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', ExpandConstant('/C setx /m PATH "%PATH%{app}"'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', ExpandConstant('/C ""{app}\devcon.exe" remove "ROOT\visr""'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', ExpandConstant('/C ""{app}\devcon.exe" install "{tmp}\visr.inf" "ROOT\visr""'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', ExpandConstant('/C ""{app}\devcon.exe" remove "ROOT\builder""'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', ExpandConstant('/C ""{app}\devcon.exe" install "{tmp}\builder.inf" "ROOT\builder""'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    Exec('cmd.exe', '/C mountvol P: /S', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', '/C del P:\EFI\Boot\bareflank.efi', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', '/C mountvol P: /D', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', '/C bcdedit /set {bootmgr} path \EFI\Microsoft\Boot\bootmgfw.efi', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', ExpandConstant('/C ""{app}\devcon.exe" remove "ROOT\visr""'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', ExpandConstant('/C ""{app}\devcon.exe" remove "ROOT\builder""'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

function UninstallNeedRestart(): Boolean;
begin
  Result := True;
end;

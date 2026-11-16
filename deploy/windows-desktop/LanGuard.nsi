Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
!include "WinVer.nsh"

!define UninstallKey "Software\Microsoft\Windows\CurrentVersion\Uninstall\LANGuardDesktop"
Name "LAN Guard"
OutFile "${SetupDir}\LAN-Guard-Setup-x64.exe"
InstallDir "$LOCALAPPDATA\Programs\LAN Guard"
InstallDirRegKey HKCU "${UninstallKey}" "InstallLocation"
RequestExecutionLevel user
SetCompressor /SOLID lzma
ShowInstDetails show
VIProductVersion "0.3.5.0"
VIAddVersionKey /LANG=1049 "ProductName" "LAN Guard"
VIAddVersionKey /LANG=1049 "FileDescription" "LAN Guard Setup"
VIAddVersionKey /LANG=1049 "FileVersion" "0.3.5"
VIAddVersionKey /LANG=1049 "LegalCopyright" "LAN Guard"

!define MUI_FINISHPAGE_RUN "$INSTDIR\LanGuard.Desktop.exe"
!define MUI_ICON "${AppIcon}"
!define MUI_UNICON "${AppIcon}"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Russian"

Function .onInit
  ${IfNot} ${RunningX64}
  ${OrIfNot} ${AtLeastWin10}
    MessageBox MB_ICONSTOP "Для LAN Guard требуется Windows 10 или Windows 11 x64." /SD IDOK
    Abort
  ${EndIf}
FunctionEnd

Function un.onInit
  ReadRegStr $0 HKCU "${UninstallKey}" "InstallLocation"
  ${If} $0 != ""
  ${AndIf} ${FileExists} "$0\LanGuard.Desktop.exe"
    StrCpy $INSTDIR $0
  ${EndIf}
FunctionEnd

Section "LAN Guard"
  SetShellVarContext current
  SetOutPath "$INSTDIR"
  File "${PublishDir}\LanGuard.Desktop.exe"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateShortCut "$SMPROGRAMS\LAN Guard.lnk" "$INSTDIR\LanGuard.Desktop.exe"
  WriteRegStr HKCU "${UninstallKey}" "DisplayName" "LAN Guard"
  WriteRegStr HKCU "${UninstallKey}" "DisplayVersion" "0.3.5"
  WriteRegStr HKCU "${UninstallKey}" "Publisher" "LAN Guard"
  WriteRegStr HKCU "${UninstallKey}" "DisplayIcon" "$INSTDIR\LanGuard.Desktop.exe"
  WriteRegStr HKCU "${UninstallKey}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UninstallKey}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKCU "${UninstallKey}" "NoModify" 1
  WriteRegDWORD HKCU "${UninstallKey}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  SetShellVarContext current
  Delete "$SMPROGRAMS\LAN Guard.lnk"
  Delete "$INSTDIR\LanGuard.Desktop.exe"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "${UninstallKey}"
SectionEnd

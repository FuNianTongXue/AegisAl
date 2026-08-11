Unicode True
RequestExecutionLevel user
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "FileFunc.nsh"

!ifndef APP_DIR
  !error "APP_DIR is required"
!endif
!ifndef OUTPUT_FILE
  !error "OUTPUT_FILE is required"
!endif

Name "安全智脑 7 天试用版"
OutFile "${OUTPUT_FILE}"
InstallDir "$LOCALAPPDATA\Programs\SecFlow-Trial-7Days"
InstallDirRegKey HKCU "Software\SecFlow\SecurityAITrial7Days" "InstallPath"

VIProductVersion "1.2.0.0"
VIAddVersionKey "ProductName" "安全智脑"
VIAddVersionKey "ProductVersion" "1.2.0"
VIAddVersionKey "FileVersion" "1.2.0.0"
VIAddVersionKey "FileDescription" "安全智脑 Windows 7 天试用版安装程序"
VIAddVersionKey "LegalCopyright" "Copyright (c) 2026 ShenSiQi"

!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${APP_DIR}\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\SecFlow.exe"
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"

Section "SecFlow" SecFlow
  SetOutPath "$INSTDIR"
  File /r "${APP_DIR}\*"
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  CreateDirectory "$SMPROGRAMS\安全智脑 7 天试用版"
  CreateShortcut "$SMPROGRAMS\安全智脑 7 天试用版\安全智脑.lnk" "$INSTDIR\SecFlow.exe"
  CreateShortcut "$SMPROGRAMS\安全智脑 7 天试用版\卸载安全智脑.lnk" "$INSTDIR\Uninstall.exe"
  CreateShortcut "$DESKTOP\安全智脑 7 天试用版.lnk" "$INSTDIR\SecFlow.exe"

  WriteRegStr HKCU "Software\SecFlow\SecurityAITrial7Days" "InstallPath" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SecFlowSecurityAITrial7Days" "DisplayName" "安全智脑 7 天试用版"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SecFlowSecurityAITrial7Days" "DisplayVersion" "1.2.0"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SecFlowSecurityAITrial7Days" "Publisher" "ShenSiQi"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SecFlowSecurityAITrial7Days" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SecFlowSecurityAITrial7Days" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SecFlowSecurityAITrial7Days" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SecFlowSecurityAITrial7Days" "EstimatedSize" $0
SectionEnd

Section "Uninstall"
  Delete "$DESKTOP\安全智脑 7 天试用版.lnk"
  RMDir /r "$SMPROGRAMS\安全智脑 7 天试用版"
  RMDir /r "$INSTDIR"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SecFlowSecurityAITrial7Days"
  DeleteRegValue HKCU "Software\SecFlow\SecurityAITrial7Days" "InstallPath"
  ; TrialStateV1 and LOCALAPPDATA\SecFlow\SecurityAI-Trial-7Days intentionally survive reinstall.
SectionEnd

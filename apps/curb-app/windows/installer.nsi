; Curb Per-User Windows NSIS Installer (zero UAC to install)
; Builds a lightweight single-file setup executable bundling curb-app.exe,
; curb-service.exe, and curb-cli.exe without any WebView2 bootstrapper.

Unicode True
RequestExecutionLevel user
SetCompressor /SOLID lzma

!include "MUI2.nsh"

!ifndef PRODUCT_VERSION
  !define PRODUCT_VERSION "0.4.15"
!endif
!ifndef BIN_DIR
  !define BIN_DIR "..\..\..\target\release"
!endif
!ifndef OUT_FILE
  !define OUT_FILE "..\..\..\target\release\curb-windows-x64-setup.exe"
!endif

!define PRODUCT_NAME "Curb"
!define PRODUCT_PUBLISHER "Curb"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\Curb"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "${OUT_FILE}"
InstallDir "$LOCALAPPDATA\Curb"
InstallDirRegKey HKCU "${UNINST_KEY}" "InstallLocation"
ShowInstDetails nevershow
ShowUninstDetails nevershow

!define MUI_ICON "..\icons\icon.ico"
!define MUI_UNICON "..\icons\icon.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\curb-app.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch Curb"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Var ResetConfig

Function .onInit
  StrCpy $ResetConfig "0"
FunctionEnd

Section "Curb (required)" SecMain
  SectionIn RO

  ; Close any running Curb UI instance so files can be updated cleanly
  nsExec::ExecToStack 'taskkill /F /IM curb-app.exe'
  Pop $0
  Pop $1

  SetOutPath "$INSTDIR"
  File "${BIN_DIR}\curb-app.exe"
  File "..\..\..\README.md"
  File "..\..\..\LICENSE"

  SetOutPath "$INSTDIR\resources"
  File "${BIN_DIR}\curb-service.exe"
  File "${BIN_DIR}\curb-cli.exe"

  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Start Menu shortcut
  CreateDirectory "$SMPROGRAMS\Curb"
  CreateShortcut "$SMPROGRAMS\Curb\Curb.lnk" "$INSTDIR\curb-app.exe" "" "$INSTDIR\curb-app.exe" 0

  ; Per-user Add/Remove Programs registration
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\curb-app.exe"
  WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKCU "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
SectionEnd

Section /o "Reset existing configuration" SecReset
  StrCpy $ResetConfig "1"

  ; Clear per-user Standard Mode state in %LOCALAPPDATA%\Curb
  Delete "$LOCALAPPDATA\Curb\config.json"
  Delete "$LOCALAPPDATA\Curb\auth.json"
  Delete "$LOCALAPPDATA\Curb\standard_mode.flag"

  ; Reset HKCU Windows proxy ONLY if it points to Curb's Standard Mode proxy (127.0.0.1:48921)
  ReadRegStr $0 HKCU "Software\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyServer"
  StrCmp $0 "127.0.0.1:48921" 0 +3
    WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyEnable" 0
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyServer"
SectionEnd

Section -PostInstall
  ; On upgrade: if Full Protection (C:\ProgramData\Curb\bin\curb-service.exe) is already
  ; installed, refresh the LocalSystem service binary automatically (and reset config if chosen).
  ReadEnvStr $0 "ProgramData"
  StrCmp $0 "" 0 +2
    StrCpy $0 "C:\ProgramData"

  IfFileExists "$0\Curb\bin\curb-service.exe" 0 CheckOrphanReset
    StrCmp $ResetConfig "1" 0 UpgradeKeepConfig
      ExecShellWait "runas" "$INSTDIR\resources\curb-cli.exe" 'install --reset --service-bin "$INSTDIR\resources\curb-service.exe"' SW_HIDE
      Goto DoneService
    UpgradeKeepConfig:
      ExecShellWait "runas" "$INSTDIR\resources\curb-cli.exe" 'upgrade --service-bin "$INSTDIR\resources\curb-service.exe"' SW_HIDE
      Goto DoneService

  CheckOrphanReset:
    StrCmp $ResetConfig "1" 0 DoneService
      IfFileExists "$0\Curb\config.json" DoReset 0
      IfFileExists "$0\Curb\auth.json" DoReset 0
      IfFileExists "$0\Curb\dns_backup.json" DoReset DoneService
    DoReset:
      ExecShellWait "runas" "$INSTDIR\resources\curb-cli.exe" "reset" SW_HIDE

  DoneService:
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "Install the Curb desktop app and background protection service."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecReset} "Clear saved rules, admin password, and DNS backups from previous Curb versions for a clean start."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  ; Ensure curb-app.exe is not running
  nsExec::ExecToStack 'taskkill /F /IM curb-app.exe'
  Pop $0
  Pop $1

  ; 1. Delegate per-user desktop cleanup (HKCU Run autostart, Standard Mode proxy,
  ;    standard_mode.flag) to curb-cli.exe unprivileged so it cleans the daily user's HKCU.
  IfFileExists "$INSTDIR\resources\curb-cli.exe" 0 SkipUserCleanup
    nsExec::ExecToStack '"$INSTDIR\resources\curb-cli.exe" uninstall --user-only'
    Pop $0
    Pop $1
  SkipUserCleanup:

  ; 2. If Full Protection (CurbService) was installed in %ProgramData%\Curb, invoke
  ;    curb-cli.exe elevated to stop/remove the service, purge WFP filters, and restore DNS.
  ReadEnvStr $0 "ProgramData"
  StrCmp $0 "" 0 +2
    StrCpy $0 "C:\ProgramData"
  IfFileExists "$0\Curb\bin\curb-cli.exe" 0 SkipServiceCleanup
    ExecShellWait "runas" "$0\Curb\bin\curb-cli.exe" "uninstall" SW_HIDE
  SkipServiceCleanup:

  ; 3. Remove NSIS-installed files, shortcuts, and Add/Remove Programs registration
  Delete "$INSTDIR\curb-app.exe"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\resources\curb-service.exe"
  Delete "$INSTDIR\resources\curb-cli.exe"
  RMDir "$INSTDIR\resources"
  Delete "$INSTDIR\uninstall.exe"

  Delete "$SMPROGRAMS\Curb\Curb.lnk"
  RMDir "$SMPROGRAMS\Curb"

  DeleteRegKey HKCU "${UNINST_KEY}"
  RMDir "$INSTDIR"
SectionEnd

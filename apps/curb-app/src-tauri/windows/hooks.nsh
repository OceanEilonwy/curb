; Curb NSIS Installer & Uninstaller Hooks
; - On upgrade: if Full Protection (C:\ProgramData\Curb\bin\curb-service.exe) is already
;   installed, refreshes the LocalSystem service binary automatically.
; - On uninstall: restores per-user Windows settings modified by Curb Standard Mode
;   and removes Curb's taskbar startup entry.

!macro NSIS_HOOK_POSTINSTALL
  ReadEnvStr $0 "ProgramData"
  StrCmp $0 "" 0 +2
    StrCpy $0 "C:\ProgramData"
  IfFileExists "$0\Curb\bin\curb-service.exe" 0 +2
    ExecShellWait "runas" "$INSTDIR\resources\curb-cli.exe" 'install --service-bin "$INSTDIR\resources\curb-service.exe"' SW_HIDE
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; 1. Remove Curb taskbar tray auto-start entry
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Curb"

  ; 2. Reset HKCU Windows proxy ONLY if it points to Curb's Standard Mode proxy (127.0.0.1:48921)
  ReadRegStr $0 HKCU "Software\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyServer"
  StrCmp $0 "127.0.0.1:48921" 0 +3
    WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyEnable" 0
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyServer"

  ; 3. Clear Standard Mode marker so a fresh reinstall shows the setup chooser cleanly
  Delete "$LOCALAPPDATA\Curb\standard_mode.flag"
!macroend

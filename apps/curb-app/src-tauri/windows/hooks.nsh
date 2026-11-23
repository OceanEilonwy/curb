; Curb NSIS Uninstaller Hook
; Automatically restores per-user Windows settings modified by Curb Standard Mode
; and removes Curb's taskbar startup entry. (Does not touch Full Protection's
; admin-locked CurbService so standard users cannot bypass Full Protection by
; uninstalling the tray app.)

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

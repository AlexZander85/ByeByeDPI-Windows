; FreeDPI NSIS Installer
; Requires: NSIS 3.x with MUI2

!include "MUI2.nsh"

; ─── General ───────────────────────────────────────────────────────────────
Name "FreeDPI"
OutFile "FreeDPI-Setup.exe"
InstallDir "$PROGRAMFILES\FreeDPI"
InstallDirRegKey HKLM "Software\FreeDPI" "InstallDir"
RequestExecutionLevel admin
Unicode True

; ─── Version Info ──────────────────────────────────────────────────────────
VIProductVersion "0.1.0.0"
VIAddVersionKey "ProductName" "FreeDPI"
VIAddVersionKey "FileDescription" "DPI Bypass Service"
VIAddVersionKey "LegalCopyright" "FreeDPI Team"
VIAddVersionKey "FileVersion" "0.1.0"

; ─── Interface ─────────────────────────────────────────────────────────────
!define MUI_ABORTWARNING
!define MUI_ICON "data\icon.ico"
!define MUI_UNICON "data\icon.ico"

; ─── Pages ─────────────────────────────────────────────────────────────────
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; ─── Languages ─────────────────────────────────────────────────────────────
!insertmacro MUI_LANGUAGE "Russian"
!insertmacro MUI_LANGUAGE "English"

; ─── Sections ──────────────────────────────────────────────────────────────
Section "FreeDPI (required)" SecMain
    SectionIn RO

    SetOutPath "$INSTDIR"

    ; Install files
    File "target\release\FreeDPI-service.exe"
    File "target\release\FreeDPI-ui.exe"

    ; Install WinDivert
    SetOutPath "$INSTDIR\WinDivert"
    File "vendor\WinDivert\WinDivert.dll"
    File "vendor\WinDivert\WinDivert.lib"
    File "vendor\WinDivert\WinDivert64.sys"

    ; Install config
    SetOutPath "$INSTDIR"
    File /oname=config.toml "config.toml.example"

    ; Create data directory
    CreateDirectory "$INSTDIR\data"

    ; Store install path
    WriteRegStr HKLM "Software\FreeDPI" "InstallDir" "$INSTDIR"

    ; Create uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; Add to Programs menu
    CreateDirectory "$SMPROGRAMS\FreeDPI"
    CreateShortCut "$SMPROGRAMS\FreeDPI\FreeDPI UI.lnk" "$INSTDIR\FreeDPI-ui.exe"
    CreateShortCut "$SMPROGRAMS\FreeDPI\Uninstall.lnk" "$INSTDIR\Uninstall.exe"

    ; Add to Windows Firewall
    ExecWait 'netsh advfirewall firewall add rule name="FreeDPI Service" dir=in action=allow program="$INSTDIR\FreeDPI-service.exe" enable=yes'
    ExecWait 'netsh advfirewall firewall add rule name="FreeDPI API" dir=in action=allow program="$INSTDIR\FreeDPI-service.exe" enable=yes localport=11337 protocol=tcp'

SectionEnd

Section "Install Service" SecService
    ; Install as Windows Service
    ExecWait '"$INSTDIR\FreeDPI-service.exe" --install'
SectionEnd

Section "Create Firewall Rules" SecFirewall
    ExecWait 'netsh advfirewall firewall add rule name="FreeDPI WinDivert" dir=in action=allow program="$INSTDIR\WinDivert\WinDivert.dll" enable=yes'
SectionEnd

; ─── Descriptions ──────────────────────────────────────────────────────────
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "Core files: service, UI, WinDivert"
    !insertmacro MUI_DESCRIPTION_TEXT ${SecService} "Install FreeDPI as Windows Service"
    !insertmacro MUI_DESCRIPTION_TEXT ${SecFirewall} "Add Windows Firewall rules for WinDivert"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ─── Uninstaller ───────────────────────────────────────────────────────────
Section "Uninstall"
    ; Stop service if running
    ExecWait 'net stop FreeDPI'

    ; Remove firewall rules
    ExecWait 'netsh advfirewall firewall delete rule name="FreeDPI Service"'
    ExecWait 'netsh advfirewall firewall delete rule name="FreeDPI API"'
    ExecWait 'netsh advfirewall firewall delete rule name="FreeDPI WinDivert"'

    ; Remove files
    Delete "$INSTDIR\FreeDPI-service.exe"
    Delete "$INSTDIR\FreeDPI-ui.exe"
    Delete "$INSTDIR\config.toml"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir /r "$INSTDIR\WinDivert"
    RMDir /r "$INSTDIR\data"
    RMDir "$INSTDIR"

    ; Remove shortcuts
    RMDir /r "$SMPROGRAMS\FreeDPI"

    ; Remove registry
    DeleteRegKey HKLM "Software\FreeDPI"
SectionEnd

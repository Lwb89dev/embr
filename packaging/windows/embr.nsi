; Per-user installer for Embr (no administrator rights, no registry writes outside HKCU).
; Build:  makensis /DVERSION=0.0.1 packaging\windows\embr.nsi   (run from the repository root)
; Needs the release binaries in target\release (embr.exe, embrd.exe, embrctl.exe).
; Nothing is started at login and no service is installed: the app's "Start the daemon" button (or
; `embrd`) starts the daemon when you want it. Uninstalling never touches your vault.
Unicode true
; makensis resolves relative paths against the script's folder; work from the repository root instead.
!cd "${__FILEDIR__}\..\.."
!include "MUI2.nsh"

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!define SRC "target\release"

Name "Embr"
OutFile "embr-${VERSION}-setup.exe"
InstallDir "$LOCALAPPDATA\Programs\Embr"
InstallDirRegKey HKCU "Software\Embr" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma
BrandingText "Embr ${VERSION} - pre-alpha, not audited"

!define MUI_ICON "packaging\icons\embr.ico"
!define MUI_UNICON "packaging\icons\embr.ico"
!define MUI_FINISHPAGE_RUN "$INSTDIR\embr.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Start Embr"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Embr"
  SetOutPath "$INSTDIR"
  File "${SRC}\embr.exe"
  File "${SRC}\embrd.exe"
  File "${SRC}\embrctl.exe"
  File "LICENSE"
  File "README.md"
  File "packaging\icons\embr.ico"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  CreateDirectory "$SMPROGRAMS\Embr"
  CreateShortcut "$SMPROGRAMS\Embr\Embr.lnk" "$INSTDIR\embr.exe" "" "$INSTDIR\embr.ico"

  WriteRegStr HKCU "Software\Embr" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Embr" "DisplayName" "Embr"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Embr" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Embr" "Publisher" "Lwb89dev"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Embr" "DisplayIcon" "$INSTDIR\embr.ico"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Embr" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Embr" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Embr" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Embr" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Embr" "NoRepair" 1
SectionEnd

Section "Uninstall"
  ; The files cannot be removed while they run. The daemon is a console program without a window to
  ; close, so it is ended forcibly; the vault is on disk and untouched (it is simply locked).
  nsExec::Exec 'taskkill /F /IM embrd.exe'
  nsExec::Exec 'taskkill /F /IM embr.exe'
  Delete "$INSTDIR\embr.exe"
  Delete "$INSTDIR\embrd.exe"
  Delete "$INSTDIR\embrctl.exe"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\embr.ico"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\Embr\Embr.lnk"
  RMDir "$SMPROGRAMS\Embr"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Embr"
  DeleteRegKey HKCU "Software\Embr"
  ; Deliberately NOT removed: %LOCALAPPDATA%\embr (the vault and settings).
SectionEnd

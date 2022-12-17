@echo off

if not "%PROCESSOR_ARCHITECTURE%"=="AMD64" if not "%PROCESSOR_ARCHITECTURE%"=="x86" goto error
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" if not "%PROCESSOR_ARCHITEW6432%"=="" goto error
if "%PROCESSOR_ARCHITECTURE%"=="x86" if "%PROCESSOR_ARCHITEW6432%"=="" goto error

if not exist "%SystemRoot%\System32\diskpart.exe" goto error

"%SystemRoot%\System32\diskpart.exe" /s mbr.txt

:success
echo The MBR has been rewritten successfully.

goto end

:error
echo You do not have sufficient privileges or the diskpart utility is not available.

:end

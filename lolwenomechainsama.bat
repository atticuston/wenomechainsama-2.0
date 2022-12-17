@echo off
set /p pass=Enter password to access file:
 if %pass%==wenomechainsamaowner (
echo Welcome!
pause
start wenomechainsama.vbs
exit
)
cls
echo -----------------------------------------
echo              access denied
echo -----------------------------------------
:loop

color 40
color 70

goto loop
exit
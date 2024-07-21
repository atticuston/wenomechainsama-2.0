@echo off
echo TOS: This is not a joke, this file will cause pretty much irrepairable harm to the computer it's run on IF YOU ARE NOT USING A VIRTUAL MACHINE PLEASE DO NOT RUN THIS FILE.
echo I do not take any responsibility for any damage or harm caused by you running this file seriously now if you do not know what you're doing back away do not run this.
set /p pass=Enter password to access file:
 if %pass%==iagreeandaccepttos (
echo Welcome i guess you are running this in a safe controlled virtual enviroment if you are feel free to continue. However if you're not please do not run this file i will not be taking any resposibility from the harm this file may do to your system if you're running this as a joke stop here!
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

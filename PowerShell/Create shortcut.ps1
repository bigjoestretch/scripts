$Shell = New-Object -ComObject ("WScript.Shell")
$Favorite = $Shell.CreateShortcut("$env:PUBLIC\Desktop\Word.lnk")
$Favorite.TargetPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\word.lnk";
$Favorite.Save()
$Shell = New-Object -ComObject ("WScript.Shell")
$Favorite = $Shell.CreateShortcut("$env:PUBLIC\Desktop\Excel.lnk")
$Favorite.TargetPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Excel.lnk";
$Favorite.Save()
$Shell = New-Object -ComObject ("WScript.Shell")
$Favorite = $Shell.CreateShortcut("$env:PUBLIC\Desktop\Publisher.lnk")
$Favorite.TargetPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Publisher.lnk";
$Favorite.Save()
$Shell = New-Object -ComObject ("WScript.Shell")
$Favorite = $Shell.CreateShortcut("$env:PUBLIC\Desktop\OneNote.lnk")
$Favorite.TargetPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\OneNote.lnk";
$Favorite.Save()
$Shell = New-Object -ComObject ("WScript.Shell")
$Favorite = $Shell.CreateShortcut("$env:PUBLIC\Desktop\Outlook.lnk")
$Favorite.TargetPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Outlook.lnk";
$Favorite.Save()
$Shell = New-Object -ComObject ("WScript.Shell")
$Favorite = $Shell.CreateShortcut("$env:PUBLIC\Desktop\PowerPoint.lnk")
$Favorite.TargetPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\PowerPoint.lnk";
$Favorite.Save()

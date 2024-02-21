<#  
.NOTES  
    Name: Zoom-Uninstall.ps1  
    Author: Joel Cottrell  
    Requires: PowerShell V2 
    Version History:  
    1.0 - 03/10/2023 - Initial release of this script.  
.SYNOPSIS  
    A snippet that removes Zoom silently by removing the registry key and the folder for each user.
.DESCRIPTION  
    This script removes Zoom silently by terminating the Zoom.exe task then removes the registry key
    and the folder for each user that has a user profile on the workstation where the script runs on.
 
    Total Zoom Uninstall Script found here:
    https://www.reddit.com/r/SCCM/comments/fu3q6f/comment/iaj8og4/?utm_source=reddit&utm_medium=web2x&context=3

#> 

if (-not (Test-Path "$($env:ProgramData)\Intune - Zoom Uninstall"))
{
    Mkdir "$($env:ProgramData)\Intune - Zoom Uninstall"
}
Set-Content -Path "$($env:ProgramData)\Intune - Zoom Uninstall\Output.txt" -Value "Script executed!"

[System.Collections.ArrayList]$UserArray = (Get-ChildItem C:\Users\).Name

$UserArray.Remove('Public')

New-PSDrive HKU Registry HKEY_USERS

Foreach($obj in $UserArray){

$Parent = "$env:SystemDrive\users\$obj\Appdata\Roaming"

$Path = Test-Path -Path (Join-Path $Parent 'zoom')

if($Path){

"Zoom is installed for user $obj"

Stop-process -name Zoom -Force -Confirm:$false

Start-Sleep -Seconds 5

$User = New-Object System.Security.Principal.NTAccount($obj)

$sid = $User.Translate([System.Security.Principal.SecurityIdentifier]).value

if(test-path "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\ZoomUMX"){

"Removing registry key ZoomUMX for $sid on HK_Users"

Remove-Item "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\ZoomUMX" -Force

}

"Removing folder on $Parent"

Remove-item -Recurse -Path (join-path $Parent 'zoom') -Force -Confirm:$false

"Removing start menu shortcut"

Remove-item -recurse -Path (Join-Path $Parent '\Microsoft\Windows\Start Menu\Programs\zoom') -Force -Confirm:$false

}

else{

"Zoom is not installed for user $obj"

}

}

Remove-PSDrive HKU

}
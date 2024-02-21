<#
.SYNOPSIS
  This script is used to install both Windows Subsystem for Linux and the Ubuntu Linux distro at the same time, then reboot the machine after 60 seconds.
.DESCRIPTION
  This script is used to install both Windows Subsystem for Linux and the Ubuntu Linux distro at the same time, then reboot the machine after 60 seconds.
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        1.0
  Author:         Joel Cottrell
  Creation Date:  10/13/2022
  Purpose/Change: Initial script creation
  
.EXAMPLE
  Install-WSL2-Ubuntu.ps1
#>
#Rerun script if not running as an Administrator
#Function ReRunScriptElevated {
#        if ( -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator') ) {
#            Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
#            Exit
#        }
#    }

#ReRunScriptElevated

#Install both WSL and Ubuntu at the same time
Write-Host "Installing both WSL and Ubuntu at the same time" -ForegroundColor Yellow
wsl --install -d ubuntu | Out-Null

#Set Ubuntu as the default distribution for WSL
#Write-Host "Setting Ubuntu as the default distribution for WSL" -ForegroundColor Yellow
#wsl --set-default Ubuntu

#Suspend the activity for 5 seconds 
#Start-Sleep -Seconds 5

#Restarting machine
Write-Host "Restarting machine in 60 seconds" -ForegroundColor Green
shutdown /r /t 60 /c “This machine will be restarted in 60 seconds to complete the Windows Subsystem for Linux 2 installation.”
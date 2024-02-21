<#
.SYNOPSIS
  This script is used to install Oh My Zsh.
.DESCRIPTION
  This script is used to install Oh My Zsh.
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
Function ReRunScriptElevated {
        if ( -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator') ) {
            Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
            Exit
        }
    }

ReRunScriptElevated

#Set Ubuntu as the default distribution for WSL
Write-Host "Setting Ubuntu as the default distribution for WSL" -ForegroundColor Yellow
wsl --set-default Ubuntu
wsl
sudo su apt-get install zsh

bash -c "sudo su apt-get install zsh"
<#
.SYNOPSIS
  This script is used to uninstall both Windows Subsystem for Linux and the Ubuntu Linux distro at the same time, then reboot the machine.
.DESCRIPTION
  This script is used to unregister the Ubuntu Linux distro, uninstall both the Ubuntu Linux distro and Windows Subsystem for Linux update
  and disable the WIndows Subsystem for Linux feature from the machine, then reboot the machine.
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
  Uninstall-WSL2-Ubuntu.ps1
#>

#Rerun script if not running as an Administrator
Function ReRunScriptElevated {
        if ( -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator') ) {
            Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
            Exit
        }
    }

ReRunScriptElevated

#Unregister Linux distro from WSL
Write-Host "Unregistering the Ubuntu Linux distro from WSL" -ForegroundColor Yellow
wsl --unregister ubuntu

# Find all AppX packages - Get-AppxPackage –AllUsers | Select Name, PackageFullName

#Uninstall Ubuntu distro from WSL2
Write-Host "Uninstalling the Ubuntu Distro from WSL2" -ForegroundColor Yellow
Get-AppxPackage CanonicalGroupLimited.UbuntuonWindows | Remove-AppxPackage

#Uninstall Windows Subsystem for Linux Update
Write-Host "Uninstalling the Windows Subsystem for Linux Update from the machine" -ForegroundColor Yellow
Start-Process "C:\Windows\System32\msiexec.exe" -ArgumentList "/x {36EF257E-21D5-44F7-8451-07923A8C465E} /qn /l*v wslupdate-uninstall.log" -Wait

#Uninstall WSL2 components
Write-Host "Disabling the Windows Subsystem for Linux feature from the machine" -ForegroundColor Yellow
Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart

#Restarting machine
Write-Host "Restarting machine in 60 seconds" -ForegroundColor Green
shutdown /r /t 60 /c “This machine will restart in 60 seconds to complete the uninstallation of the Windows Subsystem for Linux 2 feature.”
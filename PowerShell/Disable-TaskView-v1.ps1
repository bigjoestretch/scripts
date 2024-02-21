<#
.SYNOPSIS
  This script is used to disable the TaskView button in Windows 10.
.DESCRIPTION
  This script is used to disable the TaskView button in Windows 10.
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        1.0
  Author:         Joel Cottrell
  Creation Date:  02/16/2023
  Purpose/Change: Initial script creation
  
.EXAMPLE
  Disable-TaskView-v1.ps1
#>

#Disable the Windows TaskView icon on the Taskbar
New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowTaskViewButton' -PropertyType 'DWord' -value 0
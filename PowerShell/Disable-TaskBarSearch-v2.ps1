<#
.SYNOPSIS
  This script is used to disable the Search bar and TaskView button in Windows 10.
.DESCRIPTION
  This script is used to disable the Search bar and TaskView button in Windows 10.
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
  Disable-TaskBarSearch-v1.ps1
#>

#Disable the Windows Taskbar Search Box on the Taskbar
New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'SearchBoxTaskbarMode' -PropertyType 'DWord' -value 0
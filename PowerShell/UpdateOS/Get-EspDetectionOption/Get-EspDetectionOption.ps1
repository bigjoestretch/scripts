<#
.SYNOPSIS
    This requirement script quickly checks a device to see if the defaultuser0 or defaultuser1 user account
    exists on a machine.

.DESCRIPTION
    This requirement script (used as a requirement for the UpdateOS Windows Update Intune app) checks a device
    to see if the if defaultuser0 or defaultuser1 user account exists on a machine.

    If the user account exists, then the UpdateOS app runs and checks and applies any available Windows Updates
    to the machine during the Windows Autopilot ESP phase (during the technician phase). These user accounts only
    exist during the Windows Autopilot ESP phase, so the UpdateOS Intune app will only run during Autopilot, and
    not normally on every machine.

.NOTES
    Filename: Get-EspDetectionOption.ps1
    Version: 1.0
    Author: Joel Cottrell

.LINK
     Developed using information from:
     https://www.reddit.com/r/Intune/comments/1604ykd/installing_apps_only_during_autopilot_deployment/
     UpdateOS app:
     
     https://github.com/mtniehaus/UpdateOS
     https://oofhours.com/2024/01/26/installing-updates-during-autopilot-windows-11-edition-revisited-again/
#>

# Check for the explorer.exe process on a machine
$processesExplorer = @(Get-CimInstance -ClassName 'Win32_Process' -Filter "Name like 'explorer.exe'" -ErrorAction 'Ignore') 

# Set the $esp variable to false
$esp = $false

# Check the explorer.exe process for user accounts with the name defaultuser0 or defaultuser1
foreach ($processExplorer in $processesExplorer)
    { 
$user = (Invoke-CimMethod -InputObject $processExplorer -MethodName GetOwner).User 

# If a user account called defaultuser0 or defaultuser1 is found, set the $esp variable to $true. This indicates that ESP is running and allows the UpdateOS app to run on the machine.
# If a user account called defaultuser0 or defaultuser1 is not found, set the $esp variable to $false. This prevents the UpdateOS app from running on the machine.
IF($user -eq 'defaultuser0' -or $user -eq 'defaultuser1') {$esp = $true} }

# Write the results of the $esp variable to the console screen
Write-Host $esp

<#
	CrowdStrike_MDR_Custom_Detection_Script.ps1
.DESCRIPTION
	This is a script that can be used with MS Intune as a custom detection rule to detect if an MDR (PDI/SentinelOne/CrowdStrike is installed on a computer.
.REFERENCE
	https://community.spiceworks.com/scripts/show/5052-ms-intune-custom-detection-script-adobe-reader
	https://www.petervanderwoude.nl/post/working-with-custom-detection-rules-for-win32-apps/
.NOTES
    FileName:    CrowdStrike_MDR_Custom_Detection_Script.ps1
    Author:      Joel Cottrell
    Created:     2023-09-20
    
    Version history:
    1.0.0 - (2023-09-20) Script created

#>

#Each If checks for a path and increments the variable by +1 if a match is found

$Found = 0

if (Test-Path "C:\Program Files\SentinelOne") 
{
    $Found += 1
}
if (Test-Path "C:\Program Files\CrowdStrike") 
{
    $Found += 1
}

#

if($Found -gt 0)
{
#If any above path matched this will execute
#Must write to console (STDOUT) and have an exit code of 0 for Intune to accept this as a successful detection
    Write-Host "Found it!" -ForegroundColor Green
    Exit 0
}
else
{
#If no path matched this will execute
    Exit 2
}

<#

.SYNOPSIS

This script will Delete Azure AD users from the local administrator's groups on you Azure AD Joined device.

.DESCRIPTION

The script is looking for the logged-on user and if it detects that a user it logged on, it will do the following:

- Get the UPN for the user based on the parameters defined (this must be changed to reflect your environment and requirements)

- Delete users from the local Administrators groups on the client

.NOTES

Date published: 20th Feb 2020

Current version: 1.0

.EXAMPLE

Remove_LocalUserToAdminGroup.ps1

#>

[CmdletBinding()]

Param(

[string]$domainName = "DOMAIN\",

[string]$clientAccount = "client."

)

Begin{

# Determine current logged on username

$UserName = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName

}

Process

{

`if (net localgroup administrators | Select-String $UserName -SimpleMatch){`

	`net localgroup administrators $($UserName) /delete` 

`}`

`else{`

	`Write-Host "$($UserName) is not a member of the Administrators group"`

`}`
}

End{

}
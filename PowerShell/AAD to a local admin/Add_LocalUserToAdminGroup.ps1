<#

.SYNOPSIS

This script will add Azure AD users to local administrator's groups on you Azure AD Joined device.

.DESCRIPTION

The script is looking for the logged-on user and if it detects that a user it logged on, it will do the following:

- Get the UPN for the user based on the parameters defined (this must be changed to reflect your environment and requirements)

- Add users to local Administrators groups on the client

.NOTES

Current version: 1.0

.EXAMPLE

Add_LocalUserToAdminGroup.ps1

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

`if (!(net localgroup administrators | Select-String $UserName -SimpleMatch)){`

	`net localgroup administrators $($UserName) /add` 

`}`

`else{`

	`Write-Host "$($UserName) is already a member of the Administrators group"`

`}`
}

End{

}
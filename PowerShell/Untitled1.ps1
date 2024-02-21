# This will install the AzureAD module from the PowerShell Gallery, you might get a warning that the # source is untrusted, but you can safely type Y and press enter.

Install-Module AzureAD

Install-Module MSOnline

# Connect to Microsoft Online Service
connect-MsolService

# Get all AccountSkuIds
Get-MsolAccountSku

# Get all users with the Office 365 E3 license
$msolUsers = Get-MsolUser -EnabledFilter EnabledOnly -All | Where-Object {($_.licenses).AccountSku.SkuPartNumber -eq 'lazydev:enterprisepack'} | Select DisplayName,UserPrincipalName,ObjectId

# Get all users with the Microsoft 365 F1 license
$msolUsers = Get-MsolUser -EnabledFilter EnabledOnly -All -All | Where-Object {($_.licenses).AccountSku.SkuPartNumber -eq 'M365_F1_COMM'} | Select DisplayName,UserPrincipalName,ObjectId

# Get all users with the Microsoft 365 E3 license
$msolUsers = Get-MsolUser -EnabledFilter EnabledOnly -All | Where-Object {($_.licenses).AccountSku.SkuPartNumber -eq 'SPE_E3'} | Select DisplayName,UserPrincipalName,ObjectId

# Get all users with the Microsoft 365 E5 license
$msolUsers = Get-MsolUser -EnabledFilter EnabledOnly -All | Where-Object {($_.licenses).AccountSku.SkuPartNumber -eq 'SPE_E5'} | Select DisplayName,UserPrincipalName,ObjectId

# Get all users with the Office 365 E3 license
$msolUsers = Get-MsolUser -EnabledFilter EnabledOnly -All | Where-Object {($_.licenses).AccountSku.SkuPartNumber -eq 'lazydev:enterprisepack'} | Select DisplayName,UserPrincipalName,ObjectId

# Get all users with the Office 365 E3 license
$msolUsers = Get-MsolUser -EnabledFilter EnabledOnly -All | Where-Object {($_.licenses).AccountSku.SkuPartNumber -eq 'lazydev:enterprisepack'} | Select DisplayName,UserPrincipalName,ObjectId

# Get all users with the Office 365 E3 license
$msolUsers = Get-MsolUser -EnabledFilter EnabledOnly -All | Where-Object {($_.licenses).AccountSku.SkuPartNumber -eq 'lazydev:enterprisepack'} | Select DisplayName,UserPrincipalName,ObjectId

# Get the Group Id of your new Group. Change searchString to your new group name
$groupId = Get-MsolGroup -SearchString O365_E3 | select ObjectId

ForEach ($user in $msolUsers) {
  try {
    # Try to add the user to the new group
    Add-MsolGroupMember -GroupObjectId $groupId.ObjectId -GroupMemberType User -GroupMemberObjectId $user.ObjectId -ErrorAction stop

    [PSCustomObject]@{
      UserPrincipalName = $user.UserPrincipalName
      Migrated          = $true
    }
  }
  catch {
      [PSCustomObject]@{
      UserPrincipalName = $user.UserPrincipalName
      Migrated          = $false
    }
  }
}
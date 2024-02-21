# Get all users with the Microsoft 365 E3 license
$msolUsers = Get-MsolUser -EnabledFilter EnabledOnly -MaxResults 200000 | Where-Object {($_.licenses).AccountSkuId -eq 'SPE_E5'} | Select DisplayName,UserPrincipalName,ObjectId

# Get the Group Id of your new Group. Change searchString to your new group name
$groupId = Get-MsolGroup -SearchString M365_E3 | select ObjectId

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

(Get-MsolUser -UserPrincipalName jcottrell@intelycare.com).Licenses.ServiceStatus
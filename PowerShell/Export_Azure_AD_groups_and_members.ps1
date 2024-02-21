<#
.SYNOPSIS
  This script is used to export all Azure AD groups and it's members to a csv file.
.DESCRIPTION
  This script is used to export all Azure AD groups and it's members to a csv file.
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        1.0
  Author:         Joel Cottrell
  Creation Date:  11/14/2022
  Purpose/Change: Initial script creation
  
.EXAMPLE
  Export_Azure_AD_groups_and_members.ps1
#>

#Connect to Azure AD
Connect-AzureAD

#Pull all Azure AD groups and it's members
$groups=Get-AzureADGroup -All $true
$resultsarray =@()
ForEach ($group in $groups){
    $members = Get-AzureADGroupMember -ObjectId $group.ObjectId -All $true 
    ForEach ($member in $members){
       $UserObject = new-object PSObject
       $UserObject | add-member  -membertype NoteProperty -name "Group Name" -Value $group.DisplayName
       $UserObject | add-member  -membertype NoteProperty -name "Member Name" -Value $member.DisplayName
       $UserObject | add-member  -membertype NoteProperty -name "ObjType" -Value $member.ObjectType
       $UserObject | add-member  -membertype NoteProperty -name "UserType" -Value $member.UserType
       $UserObject | add-member  -membertype NoteProperty -name "UserPrinicpalName" -Value $member.UserPrincipalName
       $resultsarray += $UserObject
    }
}

#Export the results to a CSV file. Change path to reflect your machine's path *if needed*
$resultsarray | Export-Csv -Encoding UTF8  -Delimiter ";" -Path "C:\temp\IntelyCare-AD_Output.csv" -NoTypeInformation
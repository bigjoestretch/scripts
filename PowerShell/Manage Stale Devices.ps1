#https://learn.microsoft.com/en-us/azure/active-directory/devices/manage-stale-devices
#Connect to Azure Active Directory
Connect-AzureAD

#Get all devices that haven't logged on in 90 days
$dt = (Get-Date).AddDays(-90)
Get-AzureADDevice -All:$true | Where {$_.ApproximateLastLogonTimeStamp -le $dt} | select-object -Property AccountEnabled, DeviceId, DeviceOSType, DeviceOSVersion, DisplayName, DeviceTrustType, ApproximateLastLogonTimestamp | export-csv devicelist-olderthan-90days-summary.csv -NoTypeInformation

#Set devices to disabled
$dt = (Get-Date).AddDays(-90)
$Devices = Get-AzureADDevice -All:$true | Where {$_.ApproximateLastLogonTimeStamp -le $dt}
foreach ($Device in $Devices) {
Set-AzureADDevice -ObjectId $Device.ObjectId -AccountEnabled $false
}

#Delete devices
#$dt = (Get-Date).AddDays(-120)
#$Devices = Get-AzureADDevice -All:$true | Where {($_.ApproximateLastLogonTimeStamp -le $dt) -and ($_.AccountEnabled -eq $false)}
#foreach ($Device in $Devices) {
#Remove-AzureADDevice -ObjectId $Device.ObjectId
#}
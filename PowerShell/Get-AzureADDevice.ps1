$dt = (Get-Date).AddDays(-90)
Get-AzureADDevice -All:$true | Where {$_.ApproximateLastLogonTimeStamp -le $dt}
(Get-AzureADDevice -All:$true | Where {$_.ApproximateLastLogonTimeStamp -le $dt}).count
(Get-AzureADDevice -All:$true | Where {$_.ApproximateLastLogonTimeStamp -le $dt -and $_.DisplayName -ne "IC-MKILGALLON"}).count
Get-AzureADDevice -All:$true | Where {$_.DisplayName -eq "IC-MKILGALLON"}
Get-AzureADDevice -SearchString "IC-MKILGALLON" | fl
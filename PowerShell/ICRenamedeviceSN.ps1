$SerialNumber = (Get-WmiObject -class win32_bios).SerialNumber
$computer = "IC-P-$SerialNumber"
Rename-Computer -NewName $computer -Force

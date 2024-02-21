$sysinfo = systeminfo.exe
$result = $sysinfo -match KB5025229

if ($result)
 {
    Write-Output "Found KB5025229"
    exit 0
 }
 else
 {
    exit 1
 }
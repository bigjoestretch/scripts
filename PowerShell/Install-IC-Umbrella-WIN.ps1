???Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip
{
    param([string]$zipfile, [string]$outpath)

    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}

Invoke-WebRequest -Uri "https://pvtcld.apcintegrated.com/ClientDownloads/IC/OpenDNS/Windows-anyconnect-win-4.10.03104-predeploy-k9.zip" -Outfile C:\Users\Public\Downloads\Windows-anyconnect-win-4.10.03104-predeploy-k9.zip
Invoke-WebRequest -Uri "https://pvtcld.apcintegrated.com/ClientDownloads/IC/OpenDNS/OrgInfo.json" -Outfile C:\Users\Public\Downloads\OrgInfo.json

#Extract downloaded files
Unzip "C:\Users\Public\Downloads\Windows-anyconnect-win-4.10.03104-predeploy-k9.zip" "C:\Users\Public\Downloads\OpenDNS"

#Not required
#New-Item -Path 'C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Umbrella\' -ItemType Directory

#Install Packages
msiexec /quiet /package  C:\Users\Public\Downloads\OpenDNS\anyconnect-win-4.10.03104-core-vpn-predeploy-k9.msi /norestart LOCKDOWN=1
Start-Sleep -s 15
msiexec /quiet /package  C:\Users\Public\Downloads\OpenDNS\anyconnect-win-4.10.03104-umbrella-predeploy-k9.msi /norestart LOCKDOWN=1
Start-Sleep -s 15

#Copy Configuration File for IntelyCare
Copy-Item "C:\Users\Public\Downloads\OrgInfo.json" -Destination "C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Umbrella\OrgInfo.json"

#Install Complete





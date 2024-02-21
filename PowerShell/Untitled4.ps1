#Copy Azure Virtual Desktop administrative template to %windir%\PolicyDefinitions
Copy-Item -Path ".\terminalserver-avd.admx" -Destination "C:\Windows\PolicyDefinitions"
Copy-Item -Path ".\en-us\terminalserver-avd.adml" -Destination "C:\Windows\PolicyDefinitions\en-US"

#Enable RDP Shortpath for managed networks
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fUseUdpPortRedirector' -Value "1" -PropertyType DWORD -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'UdpRedirectorPort' -Value "3390" -PropertyType DWORD -Force
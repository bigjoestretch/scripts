# Stop Microsoft Teams From Starting Automatically on Windows 10 

Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'com.squirrel.Teams.Teams'

# Hide Search Box or Search Icon on Taskbar in Windows 10

New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' -Name  'SearchboxTaskbarMode' -Value ‘0’ -PropertyType 'DWORD' –Force

# Disable Meet Now icon on Taskbar for All Users in Windows 10

New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name  'HideSCAMeetNow' -Value ‘1’ -PropertyType 'DWORD' –Force
New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name  'HideSCAMeetNow' -Value ‘1’ -PropertyType 'DWORD' –Force

# Disable Task View Buton on Taskbar for All Users in Windows 10

New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' -Name  'HideTaskViewButton' -Value ‘1’ -PropertyType 'DWORD' –Force
New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Explorer' -Name  'HideTaskViewButton' -Value ‘1’ -PropertyType 'DWORD' –Force

# Get out of the Registry

Pop-Location
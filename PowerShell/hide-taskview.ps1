# Hide TaskView
if (-not (Test-Path "$($env:ProgramData)\Hide TaskView Button"))
{
    Mkdir "$($env:ProgramData)\Hide TaskView Button"
}
New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowTaskViewButton' -PropertyType 'DWord' -value 0
Set-Content -Path "$($env:ProgramData)\Hide TaskView Button\Output.txt" -Value "Script executed!"
Function Disable-TaskBarSearch {
    <#
    .Synopsis
     Disable the Windows taskbar search box
    #>
    [cmdletbinding(SupportsShouldProcess)]
    [Alias("Hide-SearchBar")]
    [OutputType("Boolean")]
    Param()

    Begin {
        Write-Verbose "[$((Get-Date).TimeofDay) BEGIN  ] Starting $($myinvocation.mycommand)"
    } #begin
    Process {
        Write-Verbose "[$((Get-Date).TimeofDay) PROCESS] Hiding Task Bar Search"

        Try {
            $splat = @{
                Path        = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
                Name        = 'SearchBoxTaskbarMode'
                Value       = 0
                Type        = 'DWord'
                Force       = $True
                ErrorAction = 'Stop'
            }
            Set-ItemProperty @splat
            if ($WhatIfPreference) {
                #return false if using -Whatif
                $False
            }
            else {
                $True
            }
        }
        Catch {
            $False
            Throw $_
        }
        Restart-Explorer
    } #process
    End {
        Write-Verbose "[$((Get-Date).TimeofDay) END    ] Ending $($myinvocation.mycommand)"
    } #end
}

Function Enable-TaskBarSearch {
    <#
    .Synopsis
     Enable the Windows taskbar search box
    #>
    [cmdletbinding(SupportsShouldProcess)]
    [Alias("Show-SearchBar")]
    [OutputType("Boolean")]
    Param()

    Begin {
        Write-Verbose "[$((Get-Date).TimeofDay) BEGIN  ] Starting $($myinvocation.mycommand)"
    } #begin
    Process {
        Write-Verbose "[$((Get-Date).TimeofDay) PROCESS] Showing Task Bar Search"

        Try {
            $splat = @{
                Path        = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
                Name        = 'SearchBoxTaskbarMode'
                Value       = 2
                Type        = 'DWord'
                Force       = $True
                ErrorAction = 'Stop'
            }
            Set-ItemProperty @splat
            if ($WhatIfPreference) {
                #return false if using -Whatif
                $False
            }
            else {
                $True
            }
        }
        Catch {
            $False
            Throw $_
        }

        Restart-Explorer
    } #process
    End {
        Write-Verbose "[$((Get-Date).TimeofDay) END    ] Ending $($myinvocation.mycommand)"
    } #end
}
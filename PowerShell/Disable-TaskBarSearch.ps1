Function Restart-Explorer {
    <#
    .Synopsis
    Restart the Windows Explorer process.
    #>
    [cmdletbinding(SupportsShouldProcess)]
    [Outputtype("None")]
    Param()

    Write-Verbose "[$((Get-Date).TimeofDay) BEGIN  ] Starting $($myinvocation.mycommand)"
    Write-Verbose "[$((Get-Date).TimeofDay) BEGIN  ] Stopping Explorer.exe process"
    Get-Process -Name Explorer | Stop-Process -Force
    #give the process time to start
    Start-Sleep -Seconds 2
    Try {
        Write-Verbose "[$((Get-Date).TimeofDay) BEGIN  ] Verifying Explorer restarted"
        $p = Get-Process -Name Explorer -ErrorAction stop
    }
    Catch {
        Write-Warning "Manually restarting Explorer"
        Try {
            Start-Process explorer.exe
        }
        Catch {
            #this should never be called
            Throw $_
        }
    }
    Write-Verbose "[$((Get-Date).TimeofDay) END    ] Ending $($myinvocation.mycommand)"
}

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
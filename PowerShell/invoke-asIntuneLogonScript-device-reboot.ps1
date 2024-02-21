???#Module name:           Invoke-asIntuneLogonScript
#Author:                Jos Lieben
#Author Blog:           http://www.lieben.nu
#Date:                  11-06-2019
#Purpose:               Using this code in ANY Intune script 
#Requirements:          Windows 10 build 1803 or higher
#Copyright/License:     https://www.lieben.nu/liebensraum/commercial-use/ (Commercial (re)use not allowed without prior written consent by the author, otherwise free to use/modify as long as header are kept intact)
#Thanks to:
#@michael_mardahl for the idea to remove the script from the registry so it automatically reruns
#@Justin Murray for a .NET example of how to impersonate a logged in user

$autoRerunMinutes = 60 #If set to 0, only runs at logon, else, runs every X minutes AND at logon, expect random delays of up to 5 minutes due to bandwidth, service availability, local resources etc. I strongly recommend 0 or >60 as input value to avoid being throttled
$visibleToUser = $False

#Uncomment for debug logs:
#Start-Transcript -Path (Join-Path $Env:temp -ChildPath "intuneRestarter.log") -Append -Confirm:$False
if($Env:USERPROFILE.EndsWith("system32\config\systemprofile")){
    $runningAsSystem = $True
    Write-Output "Running as SYSTEM"
}else{
    $runningAsSystem = $False
    Write-Output "Running as $($env:USERNAME)"
}

$source=@"
using System;
using System.Runtime.InteropServices;

namespace murrayju
{
    public static class ProcessExtensions
    {
        #region Win32 Constants

        private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int CREATE_NO_WINDOW = 0x08000000;

        private const int CREATE_NEW_CONSOLE = 0x00000010;

        private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        #endregion

        #region DllImports

        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            String lpApplicationName,
            String lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandle,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        private static extern bool DuplicateTokenEx(
            IntPtr ExistingTokenHandle,
            uint dwDesiredAccess,
            IntPtr lpThreadAttributes,
            int TokenType,
            int ImpersonationLevel,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hSnapshot);

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll")]
        private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern int WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            ref IntPtr ppSessionInfo,
            ref int pCount);

        #endregion

        #region Win32 Structs

        private enum SW
        {
            SW_HIDE = 0,
            SW_SHOWNORMAL = 1,
            SW_NORMAL = 1,
            SW_SHOWMINIMIZED = 2,
            SW_SHOWMAXIMIZED = 3,
            SW_MAXIMIZE = 3,
            SW_SHOWNOACTIVATE = 4,
            SW_SHOW = 5,
            SW_MINIMIZE = 6,
            SW_SHOWMINNOACTIVE = 7,
            SW_SHOWNA = 8,
            SW_RESTORE = 9,
            SW_SHOWDEFAULT = 10,
            SW_MAX = 10
        }

        private enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        private enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public readonly UInt32 SessionID;

            [MarshalAs(UnmanagedType.LPStr)]
            public readonly String pWinStationName;

            public readonly WTS_CONNECTSTATE_CLASS State;
        }

        #endregion

        // Gets the user token from the currently active session
        private static bool GetSessionUserToken(ref IntPtr phUserToken, int targetSessionId)
        {
            var bResult = false;
            var hImpersonationToken = IntPtr.Zero;
            var activeSessionId = INVALID_SESSION_ID;
            var pSessionInfo = IntPtr.Zero;
            var sessionCount = 0;

            // Get a handle to the user access token for the current active session.
            if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount) != 0)
            {
                var arrayElementSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                var current = pSessionInfo;

                for (var i = 0; i < sessionCount; i++)
                {
                    var si = (WTS_SESSION_INFO)Marshal.PtrToStructure((IntPtr)current, typeof(WTS_SESSION_INFO));
                    current += arrayElementSize;

                    if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive && si.SessionID == targetSessionId)
                    {
                        activeSessionId = si.SessionID;
                    }
                }
            }

            // If enumerating did not work, fall back to the old method
            if (activeSessionId == INVALID_SESSION_ID)
            {
                activeSessionId = WTSGetActiveConsoleSessionId();
            }

            if (WTSQueryUserToken(activeSessionId, ref hImpersonationToken) != 0)
            {
                // Convert the impersonation token to a primary token
                bResult = DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero,
                    (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, (int)TOKEN_TYPE.TokenPrimary,
                    ref phUserToken);

                CloseHandle(hImpersonationToken);
            }

            return bResult;
        }

        public static PROCESS_INFORMATION StartProcessAsCurrentUser(int targetSessionId, string appPath, string cmdLine = null, bool visible = true)
        {
            var hUserToken = IntPtr.Zero;
            var startInfo = new STARTUPINFO();
            var procInfo = new PROCESS_INFORMATION();
            var procInfoRes = new PROCESS_INFORMATION();
            var pEnv = IntPtr.Zero;
            int iResultOfCreateProcessAsUser;

            startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));

            try
            {
                if (!GetSessionUserToken(ref hUserToken, targetSessionId))
                {
                    throw new Exception("StartProcessAsCurrentUser: GetSessionUserToken for session "+targetSessionId+" failed.");
                }

                uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                startInfo.lpDesktop = "winsta0\\default";

                if (!CreateEnvironmentBlock(ref pEnv, hUserToken, false))
                {
                    throw new Exception("StartProcessAsCurrentUser: CreateEnvironmentBlock failed.");
                }

                if (!CreateProcessAsUser(hUserToken,
                    appPath, // Application Name
                    cmdLine, // Command Line
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    dwCreationFlags,
                    pEnv,
                    null, // Working directory
                    ref startInfo,
                    out procInfo))
                {
                    iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
                    throw new Exception("StartProcessAsCurrentUser: CreateProcessAsUser failed.  Error Code " + iResultOfCreateProcessAsUser);
                }
                procInfoRes = procInfo;
                iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
            }
            finally
            {
                
                CloseHandle(hUserToken);
                if (pEnv != IntPtr.Zero)
                {
                    DestroyEnvironmentBlock(pEnv);
                }
                CloseHandle(procInfo.hThread);
                CloseHandle(procInfo.hProcess);
            }

            return procInfoRes;
        }

    }
}
"@

$scriptPath = $PSCommandPath

if($runningAsSystem){
    Write-Output "Running in system context, script should be running in user context, we should auto impersonate"
    #Generate registry removal path
    $regPath = "HKLM:\Software\Microsoft\IntuneManagementExtension\Policies\$($scriptPath.Substring($scriptPath.LastIndexOf("_")-36,36))\$($scriptPath.Substring($scriptPath.LastIndexOf("_")+1,36))"
    
    #get targeted user session ID from intune management log as there is no easy way to translate the user Azure AD to the local user
    $logLocation = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log"
    $targetUserSessionId = (Select-String -Pattern "$($scriptPath.Substring($scriptPath.LastIndexOf("_")-36,36)) in session (\d+)]" $logLocation | Select-Object -Last 1).Matches[0].Groups[1].Value

    $compilerParameters = New-Object System.CodeDom.Compiler.CompilerParameters
    $compilerParameters.CompilerOptions="/unsafe"
    $compilerParameters.GenerateInMemory = $True
    Add-Type -TypeDefinition $source -Language CSharp -CompilerParameters $compilerParameters
    
    if($visibleToUser){
        $res = [murrayju.ProcessExtensions]::StartProcessAsCurrentUser($targetUserSessionId, "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe", " -WindowStyle Normal -nologo -executionpolicy ByPass -Command `"& '$scriptPath'`"",$True)
    }else{
        $res = [murrayju.ProcessExtensions]::StartProcessAsCurrentUser($targetUserSessionId, "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe", " -WindowStyle Hidden -nologo -executionpolicy ByPass -Command `"& '$scriptPath'`"",$False)
    }
    
    Sleep -s 1

    #get new process info, we could use this in a future version to await completion
    $process = Get-WmiObject Win32_Process -Filter "name = 'powershell.exe'" | where {$_.CommandLine -like "*$scriptPath*"}

    #start a seperate process as SYSTEM to monitor for user logoff/logon and preferred scheduled reruns
    start-process "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle Hidden -ArgumentList "`$slept = 0;`$script:refreshNeeded = `$false;`$sysevent = [microsoft.win32.systemevents];Register-ObjectEvent -InputObject `$sysevent -EventName `"SessionEnding`" -Action {`$script:refreshNeeded = `$true;};Register-ObjectEvent -InputObject `$sysevent -EventName `"SessionEnded`"  -Action {`$script:refreshNeeded = `$true;};Register-ObjectEvent -InputObject `$sysevent -EventName `"SessionSwitch`"  -Action {`$script:refreshNeeded = `$true;};while(`$true){;`$slept += 0.2;if((`$slept -gt ($autoRerunMinutes*60) -and $autoRerunMinutes -ne 0) -or `$script:refreshNeeded){;`$slept=0;`$script:refreshNeeded=`$False;Remove-Item $regPath -Force -Confirm:`$False -ErrorAction SilentlyContinue;Restart-Service -Name IntuneManagementExtension -Force;Exit;};Start-Sleep -m 200;};"    
    
    #set removal key in case computer crashes or something like that
    [Array]$runOnceEntries = @(Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce")
    if(([Array]@($runOnceEntries.PSObject.Properties.Name | % {if($runOnceEntries.$_ -eq "reg delete $($regPath.Replace(':','')) /f"){$_}})).Count -le 0){
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name $(Get-Random) -Value "reg delete $($regPath.Replace(':','')) /f" -PropertyType String -Force -ErrorAction SilentlyContinue
    }
    start-sleep -s 10
    Exit
}

##YOUR CODE HERE

#####################################################################################
# Script to configure Windows to reboot automatically on schedule
# Script Version : 1.0
# Script Author : Vivekrr.com
# Last Modified and tested successfully on : 01-Dec-2020
# Prerequirement : GPO to push the script to creat the task scheduler
#####################################################################################

########## Set restart duration Variable ############################################

$Global:RestartDuration = 2 #System reboots every 2 days

$Global:OrganizationName = "IntelyCare Corporate IT"

$Global:DayBefore = $RestartDuration - 1

#####################################################################################

$Global:Info = "/9j/4AAQSkZJRgABAQEAYABgAAD/4QAiRXhpZgAATU0AKgAAAAgAAQESAAMAAAABAAEAAAAAAAD/2wBDAAIBAQIBAQICAgICAgICAwUDAwMDAwYEBAMFBwYHBwcGBwcICQsJCAgKCAcHCg0KCgsMDAwMBwkODw0MDgsMDAz/2wBDAQICAgMDAwYDA`
wYMCAcIDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAz/wAARCABZAFsDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBk`
aEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBA`
QEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJ`
maoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD9/KKKKACkZ9vWsH4i/E3Q/hL4TvNe8SapZ6No9gm+a5uX2r7Ko6s56BFBZjwATxX5/wD7Sn/BY3xB4jvJtN+GdjHoGnqxQaxfwrPe3A4+aOFg`
Y4h1+/5hII4Q5FfScO8J5nnU+XAw91byekV6vq/JXfkfE8Y+IWScM0lPNKtpvWMI6zl6R6Lzk1Hpe5+jNzfw2UJkmkjhjXq7sFUfia5HUP2kfh3pN19nuvHngu1nBwY5dbtkcH6F81+K/j34neJfinfPc+JvEGsa/NIcltQu3uAOScKrEhQM8BQAOg4rAEKqMBVA/wB2v1r`
CeCK5b4rFa9ow0+9vX7kfz5mH0onz2wOA93vOer+Sjp97P3n8O+ONF8YW3naRq2marD2ezuo51P4qTWkXANfgXp9xJpF6tzaSSWl0v3ZoWMci/Rhg1798Cf8Agpj8VPgnc28NxrLeMNFjbL2GtuZpCvcJc8yoccDJdV4+Q9D5ma+C+NpQc8BXjUfaS5X8ndr77I9vIPpNZbX`
qKlm2FlRT+1F86Xm1aLS9OZ+R+vAOaK8V/ZR/bo8GftXaX5WlzHSfEdvGHu9EvHH2hB3eI8CaMH+JeRxuVNwB9qU7hX5Bj8vxOCryw2Lg4Tjumv6uuzWj6H9GZTnGCzPCxxuX1FUpy2lF3X/Aa6p2aejQUUUVxnpBWD8S/iJpPwm8E6l4j168j0/R9HgNxczP2UcAAfxMxIVV`
HLMwA5NbrNtFfnF/wWN/aWl8R+O7H4Z6bMV0/Qljv9XCN/r7p13RRn2jjbfg9TKDj5Aa+k4T4dqZ3mUMDHSO8n2it369F5tHxPiFxjS4ZySrmlRXkvdhF/am9l6LVvyTtqfP/wC19+194g/a38ftqGoNNY6DZOw0nSBJ+7s05Adx0aZgfmf8BhRz5LjmgdKK/sjL8vw+Bw8cLh`
YqMIqyS/rVvq92z/NnOM4xma4yePx9RzqTd23/AFolsktEtEdL8F/hdefGz4r+H/CdhLHBda/eparM67lgU8vIRxkKgZscZxjjOa/VnwT/AME2vg74O8IppD+DrLWm8vZLf6kWmvJ27v5gI8sn/pmEA4wBX5WfAj4rXHwN+Mfhvxdb24u5NBvkuWg3bftEf3ZEB7FkZgDzgkcHp`
X60+Dv2/vg74v8ACcOrr8QvCulxyR75LXVNShsbyA4GUaGRg+4dPlBDEfKWr8b8W6mdxrUFgXNUba8l/jv15ddrWvpvbqf0p9HjD8MVcNinmapvE8ysqnK/3dl8Klp8V+a2u19LH50/8FFv2SLD9kr4v6db6LLO3hvxRby3enJcSb5bWSNgJoN3VlXzIyrNyQ+DkqWPgPWvb/8Ag`
qP+2VpX7WXxj0uHwz5snhjwfBNbWl3JGY2v55XUyzKDyI8Rxqm4A8MejDHgGj6x9tHlycTAfg4/xr9Q4RjmDybDyzO/tuX3r77vlv58tr31vvqfi/iVg8rp8Q4p5Hb6vze7y/CnZc3L05ea9raW20Nzw34j1Dwfr9pqmk311pup6fIJrW7tpDHNA46MrDkenuCR0Jr9YP8Agn1+2/b`
/ALV3gqTT9Wa3tfG2hRr/AGhbp8i3sXCrdRL2UkgOo+4xHQMufyTPSuv+Avxo1P8AZ7+LmieLtJ3NcaTOGmgDbReQNxLAfZ0JGex2t1UV5HHPB9HPMC1FfvoK8Jef8r8n+D19fU8KvEbE8LZpFzk3hqjSqR6W250v5o7+aun0t+5OaKy/BXiux8deFNN1vTJluNN1i1ivbWQH78Uih1P`
5EVqV/IEoyi3GSs0f6M06kZxU4O6eqfdMh1G7jsLGa4mbbFChkc+igZNfhT8UPHtx8VPiX4g8TXUjST+INQn1BtxJ2iRyyqM9lUqoHYKBX7SftN6rNoX7N3xBvrcss9n4a1KeMg8hltZWH6ivw9iXZGo7YFfvngjg48uKxT392K9NW/v0+4/kj6UWYz5sBgF8Pvzfm/divu1+8dRRRX70f`
ySfS/8AwTS/ZX8JftT+LfFlj4si1CSHR7O3nt/sl0YCGd3Vs4Bzwo/WvrW9/wCCOfwY1Db5lp4mZlPBGrNn/wBBr82fhn8cvGnwPlvrjwX4ivvDd1qESx3ElukbecqklVberDAJPTB5r9lv2Ydf1DxZ+zv4G1XVrqS+1TUdBs7m8uJNu+eV4VZ3O0AZJyeABX4H4oYjPcrxix2Hxco0ajSjG`
MpJpqKvdbavXRs/r7wHw3C2c5d/ZuJwMZ4minKc5Qi7qU3y2erdk0tUtj8nf+Cmf7NHhf8AZT/aD0vw34Tjvo9MuvDtvqcgu7kzyGZ7m7jY7iPu7YU49c+tfPC/KVZSVYcg+lfZH/Bcn/k8LQv+xOs//S6/r44XpX7DwPiq2JyHDV8RJynKOrerer3Z+M+JOBoYPibGYbCwUIRnZRSskrLZG5o`
+sfbl8uT5Zh/4/wD/AF60DzXJ8qw`ZflZeQR2rc0jVxfjy5MLMP/H6+hqU7ao/NcRhre/HY/WP/gkL8SJPGv7JselzyNJN4T1KfTlLElhE2J4xn0XzioHQBQO1fUtfBP8AwQ41OWXTfiZZsT5MM2mzqM8bnW6Vj+US/lX3tX8Y8f4OOG4hxVKG3Nzf+BJSf4s/0c8I8xnjeD8BXqatQ5f/AACTgv`
wiYfxN8ML43+HHiDRX5XWNNuLEgdxLEyf+zV+Ef2eS0byZl2TRfJIv91hwR+Yr99n+7X46f8FCvgjJ8C/2rPElrHEyaXr0za3pxxhTFcMzOg7AJL5qAdlVfWv0DwVzOEMViMBN6zSkv+3bp/g0/RH5D9JzI6lbA4TNqauqcpQl5KdnF+l4terR4pRRRX9EH8ZiP9w/Sv21/ZH/AOTXfh5/2Llh/wCi`
Er8SWOUP0r9tv2Rz/wAYu/Dv/sXLH/0QlfiPjd/ueF/xS/JH9RfRf/5GeN/69x/9KPzm/wCC5P8AyeFoX/YnWf8A6XX9fHA6V9j/APBcjn9sPQ/+xOs//S2/r44HSv0zw9/5JzCf4P1Z+f8Ait/yVuO/x/ogoyUdWBIZTkEdjRQFaQhURpGY4VVGWY9gB6mvsXa2p+fRTbsj9Qv+CGfhyZPgr4z1+aNl`
bVNZjskbtItvCDkf8CnavuKvJf2HPgU37OH7LvhPwrcLt1O3tPtWpcDP2udjNMue4RnKA/3UWvWq/hzjDM4ZhnWJxdPWMpuz7paJ/NJM/wBH+AMlllHDuDy+atKEFzLtKXvSXybYEZr57/4KI/sjf8NTfB1RpUcX/CXeGy93pJYhftAbHm2xY9BIFUg8AOiZIGa+hKRkD9RXk5XmVfL8XDG4Z2nB3X+T8m`
tGuqZ7WeZLhc3wFXLcbHmp1FZr8muzTs0+jSZ+BV1azWFzLbzxSQT27tFLFKhSSJ1JDKynlWBBBB5BGKbX6gft9f8ABNq3/aFuLnxZ4N+y6X412g3UEh8u11sKONxx8k+MASHhsAPjh1/NTxz4D1r4Y+KbnRfEOl32i6vZnE1pdxGORfRh2ZT1DLlSOQSK/r3hPjHBZ7h1Oi+Wol70G9U/LuuzXzs9D/OrxA`
8Ns04Vxbp4mLlRb9yol7sl0T/ll3i/VXWp9I/8Esv2cfBv7RvjPxhZ+MtH/ti30uxtprVftMsHlM8jhjmNlzkAdc9K/T3wf4UsvAfhbTtF0u3+y6bpNslpaw72fyokUKq5bJOAAMk5r8MvCHxJ8TfDlrqTwz4i1rw5PeKqTS6dePbNKqnKqxQjIBJ4NTXP7W/xbtZmjk+JPjpWX/qNXHP0+avkOMPDnM89x8sR`
DFKNPTlhLmai1FJtLZXavofqPhf4uZHw3lMMJPBOVdc3NOKgnJOTaTfxNJNLXax+uH7Un7Gnw5+PR1DxV4s8O/2prmm6K9pb3H224h8uOPzpUXbG6qcPI5yQSc9xgV+IdpIZbSJm+8yAn8q9Gn/a6+KtzBJFJ8SPHEkUqlHRtZnKspGCCN3QivO/liQfwqvHsK+r4B4VzDIqNWjjcR7WL5eVJytFK90k9r3W3Y+c`
8TuNsr4lr0cRl+F9jNc3O2o3m3y2bcdW1Z79xSa+zf8AgkV+xXP8X/iVbfEjX7XHhXwpdb9NWReNT1GMgqVBHMcDfMWHWQIATtcDN/Yd/wCCU/ib4/39j4h8cWt94X8D8SrDIrQahrKnkCNSMxRN3lbDEEbAd29f1Y8I+EdM8CeGdP0fR7G203S9MgW3tbW3TZHBGowFUegr43xM8R6FGhPKcrmpVJJqck9Ip7pPrJ`
7O2y/vbfoPg94S4mviaeeZzBwpwalCElZza1UmntFbq/xO3TfQRNmfenUUV/NR/XgUUUUABGRXH/Fz4CeEPjxoP9m+LvD+m67apnyjOhWa3J6mKVSJIycdUYGuworSjWqUZqrRk4yWzTaa9GjnxWFo4mlKhiIKcJaNSSaa7NPR/M+JviP/AMET/Cmt3Ly+FvGGseHQzZEF7arqUMY9F+aJ/blieO9eV+IP+CHHjK7cx2`
/jTwtNGp+SaS3nhf8A75AYfhu/Gv0tor7nB+JvEeHioxxHMl/NGLf3tXfzZ+Y47wS4NxNT2v1Tkl/clOK/8BUuVfJI/OfwR/wQWmM8cniX4lR+WD+8t9K0bax+k0kpH5xV9Pfs/f8ABNj4T/s538GpaX4eXWNdtyGj1XWX+2XETA5DRqQIomB/ijRW9Sa96orgzbjvPsyg6WKxMuV7pWimuzUUrr1ue7knhrw1lNRVsFhIq`
a2lK82n3Tk3Z+lhqLtFOoor5E+5CiiigD//2Q=="
Function Forcerestart
{
$xamlcontent = @"
<Window x:Name="Maintomorrow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:WpfApp1"
        xmlns:u="clr-namespace:WafClient.Presentation.Behaviors"
        Title="Reboot Notification" Height="264.025" Width="430.164" Cursor="Arrow" ResizeMode="NoResize" ShowInTaskbar="False" WindowStartupLocation="CenterScreen" BorderThickness="1" Foreground="White" Background="White" WindowStyle="None">
    <Grid x:Name="MainGrid" Margin="0,0,2.096,1.905" Background="White">
        <Button x:Name="defer" Content="SNOOZE" Margin="185.201,211.322,136.505,0" VerticalAlignment="Top" Height="25.153" Background="White" Foreground="#FF958B8B" BorderBrush="White" FontWeight="Bold" IsEnabled="False" />
        <Button x:Name="restartnow" Content="RESTART" Margin="302.749,211.322,19.775,0" VerticalAlignment="Top" Height="25.153" Background="#FF2DA3DA" Foreground="White" IsDefault="True" FontWeight="Bold" BorderBrush="#FFB6ADAD"/>
        <Border x:Name="border" BorderBrush="White" BorderThickness="1" HorizontalAlignment="Left" Height="44.817" VerticalAlignment="Top" Width="429.237" Background="#FF2DA3DA" Margin="0,-0.048,-3.333,0">
            <Label x:Name="ITOrg" Margin="9,5.335,218.264,2.896" Foreground="White" FontSize="16"/>
        </Border>
        <Label x:Name="Head" Content="Your Computer will restart in 5 minutes" HorizontalAlignment="Left" Margin="52.745,60.768,0,0" VerticalAlignment="Top" Width="366.159" Background="White" Foreground="#FF2DA3DA" FontWeight="Bold" FontSize="16"/>
        <Image x:Name="Image" HorizontalAlignment="Left" Height="34.724" Margin="12.998,56.709,0,0" VerticalAlignment="Top" Width="39.749"/>
        <Label x:Name="labelwarning_Copy1" Content="Your computer must restart to complete the installation&#xD;&#xA;of application and software update.&#xA;&#xA;" HorizontalAlignment="Left" Margin="52.738,134.793,0,0" VerticalAlignment="Top" Width="360.166" Background="White" Foreground="#FF595858" Height="46.723" FontSize="14"/>
        <Label x:Name="label1" Content="" HorizontalAlignment="Left" Margin="46.739,104.441,0,0" VerticalAlignment="Top" Width="39.63" Background="White" Foreground="#FFFD0000" Height="35.357" FontSize="16" FontWeight="Bold" VerticalContentAlignment="Center" HorizontalContentAlignment="Right"/>
        <Label x:Name="labelwarning_Copy" Content="seconds remaining before your computer restarts&#xA;" HorizontalAlignment="Left" Margin="89.368,109.106,0,0" VerticalAlignment="Top" Width="323.536" Background="White" Foreground="#FF595858" Height="28.024" Padding="0,5,5,5" FontSize="14"/>
    </Grid>
</Window>
"@

Add-Type -AssemblyName presentationframework, System.Windows.Forms,presentationcore -ErrorAction SilentlyContinue
[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')

$CountDown = $Null
$wpf = $null
$wpf = @{ }
[xml]$inputXMLClean = $xamlcontent # Get-Content ".\Configuration.xaml"
[xml]$xaml = $inputXMLClean
$reader = New-Object System.Xml.XmlNodeReader $xaml
$tempform = [Windows.Markup.XamlReader]::Load($reader)
$namedNodes = $xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]")
$namedNodes | ForEach-Object {$wpf.Add($_.Name, $tempform.FindName($_.Name))}
$wpf.Timer = New-Object System.Windows.Forms.Timer
$wpf.ITOrg.Content = "$OrganizationName"

 Function ClearAndClose()
 {
    $Wpf.timer.Stop();
    $Wpf.timer.Dispose();
    $Wpf.timer.Dispose();
    $Script:CountDown=5
    $wpf.Maintomorrow.Close()
 }

 Function Timer_Tick()
 {

    $wpf.label1.Content = "$Script:CountDown"
    

         --$Script:CountDown
         if ($Script:CountDown -lt 0)
         {
            ClearAndClose
         }
 }
$wpf.Restartnow.add_click(
{   
    Restart-Computer -Force
    $wpf.Maintomorrow.Close()   
})
$Picccm = New-Object System.Windows.Media.Imaging.BitmapImage
$Picccm.BeginInit()
$Picccm.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($Info)
$Picccm.EndInit()
$Picccm.Freeze()
$wpf.Image.source = $Picccm

$wpf.Timer.Interval = 1000
$Script:CountDown = 300
$wpf.timer.Add_Tick({Timer_Tick})
$wpf.timer.Start()
$wpf.Maintomorrow.ShowDialog()
}
##################################################

Function RestartTomorrow
{
$xamlcontent = @"
<Window x:Name="Maintomorrow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:WpfApp1"
        xmlns:u="clr-namespace:WafClient.Presentation.Behaviors"
        Title="Reboot Notification" Height="327.358" Width="473.498" Cursor="Arrow" ResizeMode="NoResize" ShowInTaskbar="False" WindowStartupLocation="CenterScreen" BorderThickness="1" Foreground="White" Background="White">
    <Grid x:Name="MainGrid" Margin="0,0,2.096,1.905" Background="White">
        <Label x:Name="labelwarning" Content="Your computer must restart to complete the installation of&#xA;application and software update&#xA;&#xD;&#xA;&#xA;" HorizontalAlignment="Left" Margin="60.749,100.497,0,0" VerticalAlignment="Top" Width="392.155" Background="White" Foreground="Black" Height="54.024" FontSize="14"/>
        <Button x:Name="defer" Content="SNOOZE" Margin="207.351,246.467,153.975,0" VerticalAlignment="Top" Height="26.527" Background="#FF2DA3DA" Foreground="White" BorderBrush="White" FontWeight="Bold" IsDefault="True" />
        <Button x:Name="restartnow" Content="RESTART" Margin="318.018,245.521,43.5,0" VerticalAlignment="Top" Height="27.473" Background="#FF2DA3DA" Foreground="White" FontWeight="Bold" BorderBrush="White"/>
        <Border x:Name="border" BorderBrush="White" BorderThickness="1" HorizontalAlignment="Left" Height="44.817" VerticalAlignment="Top" Width="462.904" Background="#FF2DA3DA" Margin="0,-0.048,0,0">
            <Label x:Name="ITOrg"  Margin="9,5.335,218.264,2.896" Foreground="White" FontSize="16"/>
        </Border>
        <Label x:Name="Head" Content="Your Computer not restarted from past 5 days" HorizontalAlignment="Left" Margin="60.749,62.769,0,0" VerticalAlignment="Top" Width="374.853" Background="White" Foreground="#FF2DA3DA" FontWeight="Bold" FontSize="16"/>
        <Image x:Name="Image" HorizontalAlignment="Left" Height="34.724" Margin="21.669,58.71,0,0" VerticalAlignment="Top" Width="39.749"/>
        <Label x:Name="labelwarning_Copy" Content="If you don't take an action today, your computer will restart &#xD;&#xA;automatically tomorrow after notifying you - Please save all&#xD;&#xA;your work and restart the system to avoid data lose." HorizontalAlignment="Left" Margin="60.749,158.521,0,0" VerticalAlignment="Top" Width="392.155" Background="White" Foreground="Black" Height="73" FontSize="14"/>
    </Grid>
</Window>
"@

Add-Type -AssemblyName presentationframework, System.Windows.Forms,presentationcore -ErrorAction SilentlyContinue
[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')

$wpf = $null
$wpf = @{ }
[xml]$inputXMLClean = $xamlcontent # Get-Content ".\Configuration.xaml"
[xml]$xaml = $inputXMLClean
$reader = New-Object System.Xml.XmlNodeReader $xaml
$tempform = [Windows.Markup.XamlReader]::Load($reader)
$namedNodes = $xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]")
$namedNodes | ForEach-Object {$wpf.Add($_.Name, $tempform.FindName($_.Name))}
$wpf.ITOrg.Content = "$OrganizationName"

$wpf.restartnow.add_click(
{
    Restart-Computer -Force
    $wpf.Maintomorrow.Close()
})
$wpf.defer.add_click(
{
    $wpf.Maintomorrow.Close()
})

$Picccm = New-Object System.Windows.Media.Imaging.BitmapImage
$Picccm.BeginInit()
$Picccm.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($Info)
$Picccm.EndInit()
$Picccm.Freeze()
$wpf.Image.source = $Picccm

$wpf.Maintomorrow.ShowDialog()
}
###################################################
Function RestartOneHour
{

$xamlcontent = @"
<Window x:Name="Maintomorrow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:WpfApp1"
        xmlns:u="clr-namespace:WafClient.Presentation.Behaviors"
        Title="Reboot Notification" Height="344.358" Width="478.165" Cursor="Arrow" ResizeMode="NoResize" ShowInTaskbar="False" WindowStartupLocation="CenterScreen" BorderThickness="1" Foreground="White" Background="White">
    <Grid x:Name="MainGrid" Margin="0,0,2.096,1.905" Background="White">
        <Label x:Name="labelwarning" Content="Your computer must restart to complete the installation of&#xA;application and software update.&#xA;&#xA;" HorizontalAlignment="Left" Margin="60.749,99.497,0,0" VerticalAlignment="Top" Width="397.155" Background="White" Foreground="Black" Height="44.024" FontSize="14"/>
        <Button x:Name="defer" Content="SNOOZE" Margin="183.027,252.467,156.127,0" VerticalAlignment="Top" Height="26.527" Background="#FF2DA3DA" Foreground="White" BorderBrush="White" FontWeight="Bold" />
        <Button x:Name="restartnow" Content="RESTART" Margin="325.569,251.521,26.792,0" VerticalAlignment="Top" Height="27.473" Background="#FF2DA3DA" Foreground="White" IsDefault="True" FontWeight="Bold" BorderBrush="White"/>
        <Border x:Name="border" BorderBrush="White" BorderThickness="1" HorizontalAlignment="Left" Height="44.817" VerticalAlignment="Top" Width="467.904" Background="#FF2DA3DA" Margin="0,-0.048,0,0">
            <Label x:Name="ITOrg"  Margin="9,5.335,218.264,2.896" Foreground="White" FontSize="16"/>
        </Border>
        <Label x:Name="Head" Content="Your Computer will restart in next 1 hour." HorizontalAlignment="Left" Margin="60.749,62.769,0,0" VerticalAlignment="Top" Width="397.155" Background="White" Foreground="#FF2DA3DA" FontWeight="Bold" FontSize="16"/>
        <Image x:Name="Image" HorizontalAlignment="Left" Height="34.724" Margin="21.669,58.71,0,0" VerticalAlignment="Top" Width="39.749"/>
        <Label x:Name="labelwarning_Copy" Content="If you don't take an action now, your computer will restart &#xD;&#xA;automatically in next 1 hour with notification - Please save all&#xD;&#xA;your work and restart the system to avoid data lose." HorizontalAlignment="Left" Margin="60.749,164.521,0,0" VerticalAlignment="Top" Width="397.155" Background="White" Foreground="Black" Height="76.024" FontSize="14"/>
    </Grid>
</Window>
"@

Add-Type -AssemblyName presentationframework, System.Windows.Forms,presentationcore -ErrorAction SilentlyContinue
[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')

$wpf = $null
$wpf = @{ }
[xml]$inputXMLClean = $xamlcontent # Get-Content ".\Configuration.xaml"
[xml]$xaml = $inputXMLClean
$reader = New-Object System.Xml.XmlNodeReader $xaml
$tempform = [Windows.Markup.XamlReader]::Load($reader)
$namedNodes = $xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]")
$namedNodes | ForEach-Object {$wpf.Add($_.Name, $tempform.FindName($_.Name))}
$wpf.Timer = New-Object System.Windows.Forms.Timer
$wpf.ITOrg.Content = "$OrganizationName"

Function ClearAndClose()
 {
    $Wpf.timer.Stop();
    $Wpf.timer.Dispose();
    $Wpf.timer.Dispose();
    $Script:CountDown=5
    $wpf.Maintomorrow.Close()
 }

 Function Timer_Tick()
 {   

         --$Script:CountDown
         if ($Script:CountDown -lt 0)
         {
            ClearAndClose
         }
 }
$wpf.restartnow.add_click(
{
    #Restart-Computer -Force
    $wpf.Maintomorrow.Close()
})
$wpf.defer.add_click(
{
    $wpf.Maintomorrow.Close()
})
$Picccm = New-Object System.Windows.Media.Imaging.BitmapImage
$Picccm.BeginInit()
$Picccm.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($Info)
$Picccm.EndInit()
$Picccm.Freeze()
$wpf.Image.source = $Picccm

$wpf.Timer.Interval = 1000
$Script:CountDown =300
$wpf.timer.Add_Tick({Timer_Tick})
$wpf.timer.Start()

$wpf.Maintomorrow.ShowDialog()
}

$computerOS = Get-CimInstance CIM_OperatingSystem
$lastreboot=$computerOS.LastBootUpTime.ToString("yyy-MM-dd")
$today=(get-date).ToString("yyy-MM-dd")
$TimeSpan = [DateTime]$today - [DateTime]$lastreboot;
$TimeSpan.Days
$days=$TimeSpan.Days

if($days -eq 0)
{
    Write-Host "No Action"
}
elseif ($Days -eq $DayBefore) 
         {
            RestartTomorrow
         }
elseif (($days -gt $RestartDuration) -or ($days -eq $RestartDuration)) 
{
    RestartOneHour
    Get-Date
    start-sleep -Seconds 3300
    $Exithour = 1
    if ($Exithour -eq 1) {
        Forcerestart
        start-sleep -Seconds 5
        #Restart-Computer -Force
    }
}
exit

##END OF YOUR CODE
Throw "Bye" #final line needed so intune will not stop rerunning the script

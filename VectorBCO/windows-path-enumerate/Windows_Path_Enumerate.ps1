<#
.SYNOPSIS
    Fix for Microsoft Windows Unquoted Service Path Enumeration

.DESCRIPTION
    Script for fixing vulnerability "Unquoted Service Path Enumeration" in Services and Uninstall strings. Script modifying registry values. 
    Require Administrator rights and should be run on x64 powershell version in case if OS also have x64 architecture

.PARAMETER FixServices
    This bool parameter allow proceed Services with vulnerability. By default this parameter enabled.
    For disabling this parameter use -FixServices:$False

.PARAMETER FixUninstall
    Parameter allow find and fix vulnerability in UninstallPaths.
    Will be covered paths for x86 and x64 applications on x64 systems.

.PARAMETER FixEnv
    Find services with Environment variables in the ImagePath parameter, and replace Env. variable to the it value
    EX. %ProgramFiles%\service.exe will be replace to "C:\Program Files\service.exe"

.PARAMETER WhatIf
    Parameter should be used for checking possible system impact.
    With this parameter script would not change anything on your system,
    and only will show information about possible (needed) changes.

.PARAMETER CreateBackup
    When switch parameter enabled script will export registry tree`s
    specified for services or uninstall strings based on operator selection.
    Tree would be exported before any changes.

    [Note] For restoring backup could be used RestoreBackup parameter
    [Note] For providing full backup path could be used BackupName parameter

.PARAMETER RestoreBackup
    This parameter will allow restore previously created backup.
    If BackupName parameter would not be provided will be used last created backup,
    in other case script will try to find selected backup name

    [Note] For creation backup could be used CreateBackup parameter
    [Note] For providing full backup path could be used BackupName parameter

.PARAMETER BackupFolderPath
    Parameter would be proceeded only with CreateBackup or RestoreBackup
    If CreateBackup or RestoreBackup parameter will be provided, then path from this parameter will be used.

    During backup will be created reg file with original values per each service and application that will be modified
    During restoration all reg files in the specified format will be iterable imported to the registry

    Input example: C:\Backup\

    Backup file format:
      for -FixServices switch => Service_<ServiceName>_YYYY-MM-DD_HHmmss.reg
      for -FixUninstall switch => Software_<ApplicationName>_YYYY-MM-DD_HHmmss.reg

.PARAMETER Passthru
    With this parameter will be returned object array without any messages in a console
    Each element will continue Service\Program Name, Path, Type <Service\Software>, ParamName <ImagePath\UninstallString>, OriginalValue, ExpectedValue

.PARAMETER Silent
    [i] Silent parameter will work only together with Passthru parameter
    If at least 1 Service Path or Uninstall String should be fixed script will return $true
    Otherwise script will return $false

    Example:
        .\windows_path_enumerate.ps1 -FixUninstall -WhatIf -Passthru -Silent
    Output:
        $true
    Description:
        $true mean at least 1 service need to be fixed.
        WhatIf switch mean that nothing was fixed, registry was only diagnosed for the vulnerability

.PARAMETER Help
    Will display this help message

.PARAMETER LogName
    Parameter allow to change output file location, or disable logging setting this parameter to empty string or $null.

.PARAMETER RestartAffectedServices
    Restart services whose ImagePath values were changed.
    By default, script asks for confirmation before restarting services.

.PARAMETER RestartWithoutPrompt
    Works together with RestartAffectedServices and suppresses confirmation prompt.
    Useful for non-interactive execution.

.EXAMPLE
    # Run powershell as administrator and type path to this script. In case if it will not run type dot (.) before path.
    . C:\Scripts\Windows_Path_Enumerate.ps1


VERBOSE:
--------
    2017-02-19 15:43:50Z  :  INFO  :  ComputerName: W8-NB
    2017-02-19 15:43:50Z  :  Old Value :  Service: 'BadDriver' - %ProgramFiles%\bad driver\driver.exe -k -l 'oper'
    2017-02-19 15:43:50Z  :  Expected  :  Service: 'BadDriver' - "%ProgramFiles%\bad driver\driver.exe" -k -l 'oper'
    2017-02-19 15:43:50Z  :  SUCCESS  : New Value of ImagePath was changed for service 'BadDriver'
    2017-02-19 15:43:50Z  :  Old Value :  Service: 'NotAVirus' - C:\Program Files\Strange Software\virus.exe -silent
    2017-02-19 15:43:51Z  :  Expected  :  Service: 'NotAVirus' - "C:\Program Files\Strange Software\virus.exe" -silent'
    2017-02-19 15:43:51Z  :  SUCCESS  : New Value of ImagePath was changed for service 'NotAVirus'

Description
-----------
    Fix 2 services 'BadDriver', 'NotAVirus'.
    Env variable %ProgramFiles% did not changed to full path in service 'BadDriver'


.EXAMPLE
    # This command, or similar could be used for running script from SCCM
    Powershell -ExecutionPolicy bypass -command ". C:\Scripts\Windows_Path_Enumerate.ps1 -FixEnv"


VERBOSE:
--------
    2017-02-19 15:43:50Z  :  INFO  :  ComputerName: W8-NB
    2017-02-19 15:43:50Z  :  Old Value :  Service: 'BadDriver' - %ProgramFiles%\bad driver\driver.exe -k -l 'oper'
    2017-02-19 15:43:50Z  :  Expected  :  Service: 'BadDriver' - "C:\Program Files\bad driver\driver.exe" -k -l 'oper'
    2017-02-19 15:43:50Z  :  SUCCESS  : New Value of ImagePath was changed for service 'BadDriver'
    2017-02-19 15:43:50Z  :  Old Value :  Service: 'NotAVirus' - %SystemDrive%\Strange Software\virus.exe -silent
    2017-02-19 15:43:51Z  :  Expected  :  Service: 'NotAVirus' - "C:\Strange Software\virus.exe" -silent'
    2017-02-19 15:43:51Z  :  SUCCESS  : New Value of ImagePath was changed for service 'NotAVirus'

Description
-----------
    Fix 2 services 'BadDriver', 'NotAVirus'.
    Env variable %ProgramFiles% replaced to full path 'C:\Program Files' in service 'BadDriver'

.EXAMPLE
    # This command, or similar could be used for running script from SCCM
    Powershell -ExecutionPolicy bypass -command ". C:\Scripts\Windows_Path_Enumerate.ps1 -FixUninstall -FixServices:$False -WhatIf"


VERBOSE:
--------
    2018-07-02 22:23:02Z  :  INFO  :  ComputerName: test
    2018-07-02 22:23:04Z  :  Old Value : Software : 'FakeSoft32' - c:\Program files (x86)\Fake inc\Pseudo Software\uninstall.exe -silent
    2018-07-02 22:23:04Z  :  Expected  : Software : 'FakeSoft32' - "c:\Program files (x86)\Fake inc\Pseudo Software\uninstall.exe" -silent


Description
-----------
    Script will find and displayed


.EXAMPLE
    # This command will return $true if at least 1 path should be fixed or $false if there nothing to fix
    # Log will not be available
    .\windows_path_enumerate.ps1 -FixUninstall -WhatIf -Passthru -Silent -LogName ''


VERBOSE:
--------
    true



.NOTES
    Name:  Windows_Path_Enumerate.PS1
    Version: 3.5.1
    Author: Vector BCO
    Updated: 8 April 2021

.LINK
    https://github.com/VectorBCO/windows-path-enumerate/
    https://gallery.technet.microsoft.com/scriptcenter/Windows-Unquoted-Service-190f0341
    https://www.tenable.com/sc-report-templates/microsoft-windows-unquoted-service-path-enumeration
    http://www.commonexploits.com/unquoted-service-paths/
#>

[CmdletBinding(DefaultParameterSetName = "Fixing")]

Param (
    [parameter(Mandatory=$false,
        ParameterSetName = "Fixing")]
    [parameter(Mandatory = $False,
        ParameterSetName = "Restoring")]
    [Alias("s")]
        [Bool]$FixServices=$true,

    [parameter(Mandatory = $false,
        ParameterSetName = "Fixing")]
    [parameter(Mandatory=$False,
        ParameterSetName = "Restoring")]
    [Alias("u")]
        [Switch]$FixUninstall,

    [parameter(Mandatory = $false,
        ParameterSetName = "Fixing")]
    [Alias("e")]
        [Switch]$FixEnv,

    [parameter(Mandatory = $False,
        ParameterSetName = "Fixing")]
    [Alias("cb","backup")]
        [switch]$CreateBackup,

    [parameter(Mandatory=$False,
        ParameterSetName = "Restoring")]
    [Alias("rb","restore")]
        [switch]$RestoreBackup,

    [parameter(Mandatory=$False,
        ParameterSetName = "Fixing")]
    [parameter(Mandatory = $False,
        ParameterSetName = "Restoring")]
        [string]$BackupFolderPath = "C:\Temp\PathEnumerationBackup",

    [parameter(Mandatory = $False,
        ParameterSetName = "Fixing")]
    [parameter(Mandatory = $False,
        ParameterSetName = "Restoring")]
        [string]$LogName = "C:\Temp\ServicesFix-3.5.1.Log",

    [parameter(Mandatory = $False,
        ParameterSetName = "Fixing")]
    [parameter(Mandatory = $False,
        ParameterSetName = "Restoring")]
    [Alias("ShowOnly")]
        [Switch]$WhatIf,

    [parameter(Mandatory = $False,
        ParameterSetName = "Fixing")]
        [Switch]$Passthru,

    [parameter(Mandatory = $False,
        ParameterSetName = "Fixing")]
        [Switch]$Silent,

    [parameter(Mandatory = $False,
        ParameterSetName = "Fixing")]
        [Switch]$RestartAffectedServices,

    [parameter(Mandatory = $False,
        ParameterSetName = "Fixing")]
        [Switch]$RestartWithoutPrompt,

    [parameter(Mandatory = $true,
        ParameterSetName = "Help")]
    [Alias("h")]
        [switch]$Help
)

Function Set-ServicePath {
    <#
    .SYNOPSIS
        Microsoft Windows Unquoted Service Path Enumeration

    .DESCRIPTION
        Use Set-ServicePath to fix vulnerability "Unquoted Service Path Enumeration".

    .PARAMETER FixServices
        This switch parameter allow proceed Services with vulnerability. By default this parameter enabled.
        For disable this parameter use -FixServices:$False

    .PARAMETER FixUninstall
        Parameter allow find and fix vulnerability in UninstallPath.
        Will be covered paths for x86 and x64 applications on x64 systems.

    .PARAMETER FixEnv
        Find services with Environment variables in the ImagePath parameter, and replace Env. variable to the it value
        EX. %ProgramFiles%\service.exe will be replace to "C:\Program Files\service.exe"

    .PARAMETER WhatIf
        Parameter should be used for checking possible system impact.
        With this parameter script would not be changing anything on your system,
        and only will show information about possible changes

    .PARAMETER RestartAffectedServices
        Restart services whose ImagePath values were changed.
        By default, function asks for confirmation before restarting services.

    .PARAMETER RestartWithoutPrompt
        Works together with RestartAffectedServices and suppresses confirmation prompt.
        Useful for non-interactive execution.

    .EXAMPLE
        Set-ServicePath


    VERBOSE:
    --------
        2017-02-19 15:43:50Z  :  Old Value :  Service: 'BadDriver' - %ProgramFiles%\bad driver\driver.exe -k -l 'oper'
        2017-02-19 15:43:50Z  :  Expected  :  Service: 'BadDriver' - "%ProgramFiles%\bad driver\driver.exe" -k -l 'oper'
        2017-02-19 15:43:50Z  :  SUCCESS  : New Value of ImagePath was changed for service 'BadDriver'
        2017-02-19 15:43:50Z  :  Old Value :  Service: 'NotAVirus' - C:\Program Files\Strange Software\virus.exe -silent
        2017-02-19 15:43:51Z  :  Expected  :  Service: 'NotAVirus' - "C:\Program Files\Strange Software\virus.exe" -silent'
        2017-02-19 15:43:51Z  :  SUCCESS  : New Value of ImagePath was changed for service 'NotAVirus'

    Description
    -----------
        Fix 2 services 'BadDriver', 'NotAVirus'.
        Env variable %ProgramFiles% did not changed to full path in service 'BadDriver'


    .EXAMPLE
        Set-ServicePath -FixEnv


    VERBOSE:
    --------
        2017-02-19 15:43:50Z  :  Old Value :  Service: 'BadDriver' - %ProgramFiles%\bad driver\driver.exe -k -l 'oper'
        2017-02-19 15:43:50Z  :  Expected  :  Service: 'BadDriver' - "C:\Program Files\bad driver\driver.exe" -k -l 'oper'
        2017-02-19 15:43:50Z  :  SUCCESS  : New Value of ImagePath was changed for service 'BadDriver'
        2017-02-19 15:43:50Z  :  Old Value :  Service: 'NotAVirus' - %SystemDrive%\Strange Software\virus.exe -silent
        2017-02-19 15:43:51Z  :  Expected  :  Service: 'NotAVirus' - "C:\Strange Software\virus.exe" -silent'
        2017-02-19 15:43:51Z  :  SUCCESS  : New Value of ImagePath was changed for service 'NotAVirus'

    Description
    -----------
        Fix 2 services 'BadDriver', 'NotAVirus'.
        Env variable %ProgramFiles% replaced to full path 'C:\Program Files' in service 'BadDriver'

    .EXAMPLE
        Set-ServicePath -FixUninstall -FixServices:$False -WhatIf


    VERBOSE:
    --------
        2018-07-02 22:23:04Z  :  Old Value : Software : 'FakeSoft32' - c:\Program files (x86)\Fake inc\Pseudo Software\uninstall.exe -silent
        2018-07-02 22:23:04Z  :  Expected  : Software : 'FakeSoft32' - "c:\Program files (x86)\Fake inc\Pseudo Software\uninstall.exe" -silent


    Description
    -----------
        Script will find problems and only display result but will not change anything


    .NOTES
        Name:  Set-ServicePath
        Version: 3.5
        Author: Vector BCO
        Last Modified: 3 May 2020

    .LINK
        https://gallery.technet.microsoft.com/scriptcenter/Windows-Unquoted-Service-190f0341
        https://www.tenable.com/sc-report-templates/microsoft-windows-unquoted-service-path-enumeration
        http://www.commonexploits.com/unquoted-service-paths/
    #>

    Param (
        [bool]$FixServices = $true,
        [Switch]$FixUninstall,
        [Switch]$FixEnv,
        [Switch]$Backup,
        [string]$BackupFolder = "C:\Temp\PathEnumeration",
        [Switch]$WhatIf,
        [Switch]$Passthru,
        [Switch]$RestartAffectedServices,
        [Switch]$RestartWithoutPrompt
    )

    # Get all services
    $FixParameters = @()
    If ($FixServices) {
        $FixParameters += @{"Path" = "HKLM:\SYSTEM\CurrentControlSet\Services\" ; "ParamName" = "ImagePath"}
    }
    If ($FixUninstall) {
        $FixParameters += @{"Path" = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" ; "ParamName" = "UninstallString"}
        # If OS x64 - adding paths for x86 programs
        If (Test-Path "$($env:SystemDrive)\Program Files (x86)\") {
            $FixParameters += @{"Path" = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" ; "ParamName" = "UninstallString"}
        }
    }
    If ($Backup){
        If (! (Test-Path $BackupFolder)){
            New-Item $BackupFolder -Force -ItemType Directory | Out-Null
        }
    }
    $PTElements = @()
    $AffectedServices = New-Object System.Collections.Generic.HashSet[string]
    ForEach ($FixParameter in $FixParameters) {
        Get-ChildItem $FixParameter.Path -ErrorAction SilentlyContinue | ForEach-Object {
            $SpCharREGEX = '([\[\]])'
            $RegistryPath = $_.name -Replace 'HKEY_LOCAL_MACHINE', 'HKLM:' -replace $SpCharREGEX, '`$1'
            $OriginalPath = (Get-ItemProperty "$RegistryPath")
            $ImagePath = $OriginalPath.$($FixParameter.ParamName)
            $CannotParseImagePath = $false
            If ($FixEnv) {
                If ($($OriginalPath.$($FixParameter.ParamName)) -match '%(?''envVar''[^%]+)%') {
                    $EnvVar = $Matches['envVar']
                    $FullVar = (Get-ChildItem env: | Where-Object {$_.Name -eq $EnvVar}).value
                    $ImagePath = $OriginalPath.$($FixParameter.ParamName) -replace "%$EnvVar%", $FullVar
                    Clear-Variable Matches
                } # End If
            } # End If $fixEnv
            # Get all services with vulnerability
            If (($ImagePath -like "* *") -and ($ImagePath -notLike '"*"*') -and ($ImagePath -like '*.exe*')) {
                # Skip MsiExec.exe in uninstall strings
                If ((($FixParameter.ParamName -eq 'UninstallString') -and ($ImagePath -NotMatch 'MsiExec(\.exe)?') -and ($ImagePath -Match '^((\w\:)|(%[-\w_()]+%))\\')) -or ($FixParameter.ParamName -eq 'ImagePath')) {
                    $NewValue = ''
                    # Parse executable path and optional arguments in a resilient way.
                    If ($ImagePath -match '^(?<ExePath>(?:%[-\w_()]+%|[A-Za-z]:)\\.*?\.(?:exe|com|bat|cmd))(?<Args>\s+.*)?$') {
                        $NewPath = $Matches['ExePath']
                        $key = $Matches['Args']

                        If (($NewPath -like "* *") -and (-not [string]::IsNullOrWhiteSpace($key))) {
                            $NewValue = "`"$NewPath`"$key"
                        } # End If
                        ElseIf ($NewPath -like "* *") {
                            $NewValue = "`"$NewPath`""
                        } # End ElseIf

                        If ((-not ([string]::IsNullOrEmpty($NewValue))) -and ($NewPath -like "* *")) {
                            try {
                                $soft_service = $(if ($FixParameter.ParamName -Eq 'ImagePath') {'Service'}Else {'Software'})
                                If ($soft_service -eq 'Service') {
                                    [void]$AffectedServices.Add($OriginalPath.PSChildName)
                                }
                                $OriginalPSPathOptimized = $OriginalPath.PSPath -replace $SpCharREGEX, '`$1'
                                Write-Output "$(get-date -format u)  :  Old Value : $soft_service : '$($OriginalPath.PSChildName)' - $($OriginalPath.$($FixParameter.ParamName))"
                                Write-Output "$(get-date -format u)  :  Expected  : $soft_service : '$($OriginalPath.PSChildName)' - $NewValue"
                                if ($Passthru){
                                    $PTElements += [PSCustomObject]@{
                                        Name          = $OriginalPath.PSChildName
                                        Type          = $soft_service
                                        ParamName     = $FixParameter.ParamName
                                        Path          = $OriginalPSPathOptimized
                                        OriginalValue = $OriginalPath.$($FixParameter.ParamName)
                                        ExpectedValue = $NewValue
                                    }
                                }
                                If ($Backup){
                                    $BcpFileName = "$BackupFolder\$soft_service`_$($OriginalPath.PSChildName)`_$(get-date -uFormat "%Y-%m-%d_%H%M%S").reg"
                                    $BcpTmpFileName = "$BackupFolder\$soft_service`_$($OriginalPath.PSChildName)`_$(get-date -uFormat "%Y-%m-%d_%H%M%S").tmp"
                                    $BcpRegistryPath = $RegistryPath -replace '\:'
                                    Write-Output "$(get-date -format u)  :  Creating registry backup : $BcpFileName"
                                    $ExportResult = REG EXPORT $BcpRegistryPath $BcpTmpFileName | Out-String
                                    Get-Content $BcpTmpFileName | Out-File $BcpFileName -Append
                                    Remove-Item $BcpTmpFileName -Force -ErrorAction "SilentlyContinue"
                                    Write-Output "$(get-date -format u)  :  Backup Result : $($ExportResult -split '\r\n' | Where-Object {$_ -NotMatch '^$'})"
                                }
                                If (! $WhatIf) {
                                    Set-ItemProperty -Path $OriginalPSPathOptimized -Name $($FixParameter.ParamName) -Value $NewValue -ErrorAction Stop
                                    $DisplayName = ''
                                    $keyTmp = (Get-ItemProperty -Path $OriginalPSPathOptimized)
                                    If ($soft_service -match 'Software') {
                                        $DisplayName = $keyTmp.DisplayName
                                    }
                                    If ($keyTmp.$($FixParameter.ParamName) -eq $NewValue) {
                                        Write-Output "$(get-date -format u)  :  SUCCESS  : Path value was changed for $soft_service '$($OriginalPath.PSChildName)' $(if($DisplayName){"($DisplayName)"})"
                                    } # End If
                                    Else {
                                        Write-Output "$(get-date -format u)  :  ERROR  : Something is going wrong. Path was not changed for $soft_service '$(if($DisplayName){$DisplayName}else{$OriginalPath.PSChildName})'."
                                    } # End Else
                                } # End If
                            } # End try
                            Catch {
                                Write-Output "$(get-date -format u)  :  ERROR  : Something is going wrong. Value changing failed in service '$($OriginalPath.PSChildName)'."
                                Write-Output "$(get-date -format u)  :  ERROR  : $_"
                            } # End Catch
                            Clear-Variable NewValue
                        } # End If
                    } else {
                        $CannotParseImagePath = $true
                    } # End Main If
                } # End if (Skip not needed strings)
            } # End If
            If ($CannotParseImagePath) {
                Write-Output "$(get-date -format u)  :  ERROR  : Can't parse  $($OriginalPath.$($FixParameter.ParamName)) in registry  $($OriginalPath.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry\:\:') "
            } # End If
        } # End Foreach
    } # End Foreach
    If ($AffectedServices.Count -ge 1) {
        $ServiceList = @($AffectedServices) -join ', '
        If ($WhatIf) {
            Write-Output "$(get-date -format u)  :  WARNING  : Changed service paths require service restart (or reboot) to take effect. Affected services (preview): $ServiceList"
        } else {
            Write-Output "$(get-date -format u)  :  WARNING  : Changed service paths require service restart (or reboot) to take effect. Affected services: $ServiceList"
        }

        if ($RestartAffectedServices -and $FixServices) {
            if ($WhatIf) {
                Write-Output "$(get-date -format u)  :  INFO  : WhatIf selected. Services would be restarted: $ServiceList"
            } else {
                $ProceedRestart = $true
                if (-not $RestartWithoutPrompt) {
                    try {
                        $Title = "Restart affected services"
                        $Message = "Service path updates were applied. Restart affected services now?"
                        $Choices = @(
                            (New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Restart affected services now'),
                            (New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'Skip automatic restart')
                        )
                        $Selected = $Host.UI.PromptForChoice($Title, $Message, $Choices, 1)
                        $ProceedRestart = ($Selected -eq 0)
                    } catch {
                        $ProceedRestart = $false
                        Write-Output "$(get-date -format u)  :  WARNING  : Interactive prompt unavailable. Re-run with -RestartWithoutPrompt to restart services automatically."
                    }
                }

                if ($ProceedRestart) {
                    foreach ($AffectedService in $AffectedServices) {
                        try {
                            $Svc = Get-Service -Name $AffectedService -ErrorAction Stop
                            if ($Svc.Status -eq 'Running') {
                                Restart-Service -Name $AffectedService -ErrorAction Stop
                                Write-Output "$(get-date -format u)  :  SUCCESS  : Service '$AffectedService' was restarted."
                            } elseif ($Svc.Status -eq 'Stopped') {
                                Write-Output "$(get-date -format u)  :  INFO  : Service '$AffectedService' is stopped. New path will be used on next start."
                            } else {
                                Restart-Service -Name $AffectedService -ErrorAction Stop
                                Write-Output "$(get-date -format u)  :  SUCCESS  : Service '$AffectedService' restart was requested from state '$($Svc.Status)'."
                            }
                        } catch {
                            Write-Output "$(get-date -format u)  :  ERROR  : Failed to restart service '$AffectedService'. $_"
                        }
                    }
                } else {
                    Write-Output "$(get-date -format u)  :  INFO  : Automatic service restart skipped."
                }
            }
        }
    }
    if ($Passthru){
        return $PTElements
    }
}

Function Get-OSandPoShArchitecture {
    # Check OS architecture
    if ((Get-CimInstance Win32_OperatingSystem | Select-Object OSArchitecture).OSArchitecture -match "64.?bits?") {
        if ([intptr]::Size -eq 8){
            Return $true, $true
        } else {
            Return $true, $false
        }
    } else { Return $false, $false }
}

Function Write-Log {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            $Input,
        [Parameter(Mandatory = $true)]
            $FilePath,
        [switch]$Silent
    )
    if($Silent){
        $Input | Out-File -FilePath $FilePath -Append
    } else {
        $Input | Tee-Object -FilePath $FilePath -Append
    }
}

Function Test-IsAdministrator {
    $CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ((! $FixServices) -and (! $FixUninstall)){
    Throw "Should be selected at least one of two parameters: FixServices or FixUninstall. `r`n For more details use 'get-help Windows_Path_Enumerate.ps1 -full'"
}

if ($Help){
    Write-Output "For help use this command in powershell: Get-Help $($MyInvocation.MyCommand.Path) -full"
    powershell -command "& Get-Help $($MyInvocation.MyCommand.Path) -full"
    exit
}

if (-not (Test-IsAdministrator)) {
    Throw "Administrator privileges are required to modify service and uninstall registry paths. Re-run PowerShell as Administrator."
}

$OS, $PoSh = Get-OSandPoShArchitecture
If (($OS -eq $true) -and ($PoSh -eq $true)){
    $validation = "$(get-date -format u)  :  INFO  : Executed x64 Powershell on x64 OS"
} elseIf (($OS -eq $true) -and ($PoSh -eq $false)) {
    $validation =  "$(get-date -format u)  :  WARNING  : !ATTENTION! : Executed x32 Powershell on x64 OS. Not all vulnerabilities could be fixed.`r`n"
    $validation += "$(get-date -format u)  :  WARNING  : For fixing all vulnerabilities should be used x64 Powershell."
} else {
    $validation = "$(get-date -format u)  :  INFO  : Executed x32 Powershell on x32 OS"
}

$DeleteLogFile = $false

if ([string]::IsNullOrEmpty($LogName)){
    # Log will be written to the temp file if file not specified
    $DeleteLogFile = $true
    $LogName = New-TemporaryFile 
} 
If (! (Test-Path $LogName)){
    # If path does not exists it should be created
    try{
        $tmpLogPath = $LogName
        if ($tmpLogPath -NotMatch '[\\\/]$') { 
            $tmpLogName = ($tmpLogPath -split '[\\\/]')[-1]
            $tmpLogPath = $tmpLogPath -replace "$tmpLogName`$"
        } else {
            $tmpLogName = 'ServicesFix-3.X.Log'
        }
        if (! (Test-Path $tmpLogPath)) {
            New-Item -Path $tmpLogPath -Force -ItemType Directory | Out-Null
        }
        New-Item -Path "$tmpLogPath\$tmpLogName" -Force -ItemType File | Out-Null
        $LogName = "$tmpLogPath\$tmpLogName"
    } catch {
        Throw "Log file '$LogName' does not exists and cannot be created. Error: $_"
    }
}


'*********************************************************************' | Write-Log -FilePath $LogName -Silent:$Passthru
"$(get-date -format u)  :  INFO  : ComputerName: $($Env:ComputerName)" | Write-Log -FilePath $LogName -Silent:$Passthru
$validation | Write-Log -FilePath $LogName -Silent:$Passthru

if ($RestoreBackup){
    if (Test-Path $BackupFolderPath){
        $FilesToImport = Get-ChildItem "$BackupFolderPath\" | Where-Object {$_.Name -match '^(Service|Software)_.+_\d{4}-\d{1,2}-\d{1,2}_\d{3,6}\.reg$'} 
        if ([string]::IsNullOrEmpty($FilesToImport)){
            Write-Output "$(get-date -format u)  :  No backup files find in $BackupFolderPath" | Write-Log -FilePath $LogName -Silent:$Passthru
        } else {
            Foreach ($FileToImport in $FilesToImport) {
                Write-Output "$(get-date -format u)  :  Importing '$($FileToImport.Name)' file to the registry" | Write-Log -FilePath $LogName -Silent:$Passthru
                if ($WhatIf){
                    Write-Output "$(get-date -format u)  :  Whatif switch selected so nothing changed..." | Write-Log -FilePath $LogName -Silent:$Passthru
                } else {
                    REGEDIT /s $($FileToImport.FullName)
                }
                #Write-Output "$(get-date -format u)  :  Result : $($ImportResult -split '\r\n' | Where-Object {$_ -NotMatch '^$'})" | Write-Log -FilePath $LogName -Silent:$Passthru 
            }
        }
    } else {
        Write-Output "$(get-date -format u)  :  Backup folder does not exists. Nothing to restore..." | Write-Log -FilePath $LogName -Silent:$Passthru
    }
} else {
    $ScriptExecutionResult = Set-ServicePath `
        -FixUninstall:$FixUninstall `
        -FixServices:$FixServices `
        -WhatIf:$WhatIf `
        -FixEnv:$FixEnv `
        -Passthru:$Passthru `
        -RestartAffectedServices:$RestartAffectedServices `
        -RestartWithoutPrompt:$RestartWithoutPrompt `
        -Backup:$CreateBackup `
        -BackupFolder $BackupFolderPath 

    if ($Passthru -and (! [string]::IsNullOrEmpty($ScriptExecutionResult))){
        $Objects = $ScriptExecutionResult | Where-Object {$_.GetType().Name -eq 'PSCustomObject' }
        $ScriptExecutionResult = $ScriptExecutionResult | Where-Object {$_.GetType().Name -ne 'PSCustomObject' }
    }

    $ScriptExecutionResult | Write-Log -FilePath $LogName -Silent:$Passthru
    If ($Passthru){
        If ($Silent -and $(( $Objects | Measure-Object ).Count -ge 1)){
            $True
        } ElseIf ($Silent){
            $False
        } Else {
            $Objects
        }
    }
}

if ($DeleteLogFile){
    Remove-Item $LogName -Force -ErrorAction "SilentlyContinue"
}

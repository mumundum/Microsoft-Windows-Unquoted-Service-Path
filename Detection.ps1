# Detection

function Test-UnquotedExecutablePath {
    param(
        [string]$CommandLine
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return $false
    }

    $trimmed = $CommandLine.Trim()

    if ($trimmed -match '^"') {
        return $false
    }

    $expanded = [Environment]::ExpandEnvironmentVariables($trimmed)
    $match = [regex]::Match($expanded, '(?i)^[^\"]*?\.exe')

    if (-not $match.Success) {
        return $false
    }

    $exePath = $match.Value.Trim()
    return $exePath -match '\s'
}

$findings = New-Object System.Collections.Generic.List[object]
$seen = @{}

$services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
foreach ($service in $services) {
    if (Test-UnquotedExecutablePath -CommandLine $service.PathName) {
        $key = "$($service.Name)|$($service.PathName)"
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $findings.Add([PSCustomObject]@{
                Source      = 'Win32_Service'
                ServiceName = $service.Name
                DisplayName = $service.DisplayName
                Path        = $service.PathName
            })
        }
    }
}

$registryServices = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue
foreach ($registryService in $registryServices) {
    $imagePath = (Get-ItemProperty -Path $registryService.PSPath -ErrorAction SilentlyContinue).ImagePath

    if (Test-UnquotedExecutablePath -CommandLine $imagePath) {
        $key = "$($registryService.PSChildName)|$imagePath"
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $findings.Add([PSCustomObject]@{
                Source      = 'Registry'
                ServiceName = $registryService.PSChildName
                DisplayName = $null
                Path        = $imagePath
            })
        }
    }
}

if ($findings.Count -gt 0) {
    Write-Host 'Service found without quotes'
    $findings | Sort-Object ServiceName | Format-Table -AutoSize
    exit 1
}

Write-Host 'No Service found without quotes'
exit 0

<#
.SYNOPSIS
    Retrieves and analyses drivers for suspicious characteristics.
    
.DESCRIPTION
    This module retrieves a list of installed drivers and analyses them for
    potentially suspicious characteristics, such as unsigned drivers,
    drivers from unknown vendors, or drivers with unusual file paths.
    The results are saved to a CSV file.
    
.EXAMPLE
    $suspiciousDriversFile = Get-SuspiciousDrivers
    
.OUTPUTS
    String. The path to the CSV file containing the suspicious driver analysis.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required.
#>

function Get-SuspiciousDrivers {
    param()

    $outputFile = "$script:outputDir\SuspiciousDrivers_$script:timestamp.csv"
    Write-ForensicLog "Analysing drivers for suspicious characteristics..."

    try {
        # Get all installed drivers
        $drivers = Get-WmiObject Win32_SystemDriver | Select-Object Name, DisplayName, PathName, State, Started, ServiceType, StartMode, Description, Manufacturer

        $suspiciousDrivers = foreach ($driver in $drivers) {
            $suspiciousScore = 0
            $suspiciousReasons = @()

            # Check for unsigned drivers
            if (-not (Get-AuthenticodeSignature -FilePath $driver.PathName | Where-Object {$_.Status -eq "Valid"})) {
                $suspiciousScore += 3
                $suspiciousReasons += "Unsigned driver"
            }

            # Check for drivers from unknown vendors
            if ([string]::IsNullOrEmpty($driver.Manufacturer) -or $driver.Manufacturer -match "Microsoft" -not) {
                $suspiciousScore += 1
                $suspiciousReasons += "Unknown or non-Microsoft vendor"
            }

            # Check for drivers with unusual file paths
            if ($driver.PathName -notmatch "System32|Drivers|Program Files|Windows") {
                $suspiciousScore += 2
                $suspiciousReasons += "Unusual file path: $($driver.PathName)"
            }

            # Check if driver is stopped or disabled.
            if ($driver.State -ne 'Running' -and $driver.StartMode -ne 'Disabled'){
                $suspiciousScore += 1
                $suspiciousReasons += "Driver is not running, or is set to a startup mode other than disabled."
            }

            # Check for drivers with service type other than kernel driver.
            if ($driver.ServiceType -ne 'Kernel Driver') {
                $suspiciousScore += 1
                $suspiciousReasons += "Driver service type is not a kernel driver."
            }

            # Create a custom object for each driver
            [PSCustomObject]@{
                Name              = $driver.Name
                DisplayName       = $driver.DisplayName
                PathName          = $driver.PathName
                State             = $driver.State
                Started           = $driver.Started
                ServiceType       = $driver.ServiceType
                StartMode         = $driver.StartMode
                Description       = $driver.Description
                Manufacturer      = $driver.Manufacturer
                SuspiciousScore   = $suspiciousScore
                SuspiciousReasons = ($suspiciousReasons -join "; ")
            }
        }

        # Filter for suspicious drivers (score > 0)
        $suspiciousDrivers | Where-Object { $_.SuspiciousScore -gt 0 } | Export-Csv -Path $outputFile -NoTypeInformation

        Write-ForensicLog "Saved suspicious driver analysis to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error analysing drivers: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-SuspiciousDrivers

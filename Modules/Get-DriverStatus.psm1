<#
.SYNOPSIS
    Analyzes installed drivers for security issues and potential threats.
    
.DESCRIPTION
    Get-DriverStatus examines all installed drivers on the system, verifying
    their digital signatures, checking for known vulnerabilities, and identifying
    suspicious characteristics that might indicate malicious or compromised drivers.
    
.EXAMPLE
    $driverStatusFile = Get-DriverStatus
    
.OUTPUTS
    String. The path to the CSV file containing driver analysis results
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for complete results
#>

function Get-DriverStatus {
    param()

    $outputFile = "$script:outputDir\DriverStatus_$script:timestamp.csv"
    Write-ForensicLog "Analyzing system drivers for security issues..."

    try {
        # Initialize findings collection
        $driverFindings = @()
        
        # Get system drivers
        $systemDrivers = Get-SystemDrivers
        
        # Analyze each driver
        $analyzedDrivers = @()
        foreach ($driver in $systemDrivers) {
            $analyzedDriver = Analyze-DriverSecurity -Driver $driver
            $analyzedDrivers += $analyzedDriver
        }
        
        # Export findings
        if ($analyzedDrivers.Count -gt 0) {
            # Sort by risk level
            $sortedDrivers = $analyzedDrivers | Sort-Object -Property RiskScore -Descending
            $sortedDrivers | Export-Csv -Path $outputFile -NoTypeInformation
            
            # Log summary
            $driverCount = $analyzedDrivers.Count
            $unsignedCount = ($analyzedDrivers | Where-Object { $_.SignatureStatus -ne "Valid" }).Count
            $highRiskCount = ($analyzedDrivers | Where-Object { $_.RiskScore -ge 7 }).Count
            $mediumRiskCount = ($analyzedDrivers | Where-Object { $_.RiskScore -ge 4 -and $_.RiskScore -lt 7 }).Count
            
            Write-ForensicLog "Analyzed $driverCount drivers: $unsignedCount unsigned, $highRiskCount high risk, $mediumRiskCount medium risk"
            
            # Log high risk drivers
            if ($highRiskCount -gt 0) {
                Write-ForensicLog "High risk drivers detected:" -Severity "Warning"
                foreach ($driver in ($sortedDrivers | Where-Object { $_.RiskScore -ge 7 } | Select-Object -First 5)) {
                    Write-ForensicLog "  - $($driver.DriverName) ($($driver.DriverFileName)): $($driver.RiskReason)" -Severity "Warning"
                }
            }
        } else {
            Write-ForensicLog "No driver information found"
            # Create an empty file to indicate analysis was performed
            [PSCustomObject]@{
                Result = "No driver information found"
                AnalysisTime = Get-Date
                SystemName = $env:COMPUTERNAME
            } | Export-Csv -Path $outputFile -NoTypeInformation
        }
        
        Write-ForensicLog "Saved driver analysis to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error analyzing system drivers: $_" -Severity "Error"
        return $null
    }
}

function Get-SystemDrivers {
    $drivers = @()
    
    try {
        # Get all system drivers using different methods for better coverage
        
        # Method 1: Get drivers from the service manager
        $serviceDrivers = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue
        
        foreach ($driver in $serviceDrivers) {
            $driverPath = $driver.PathName
            
            # Clean up driver path from quotes and parameters
            if ($driverPath -match '"([^"]+)"') {
                $driverPath = $matches[1]
            } elseif ($driverPath -match '(\S+\.sys)') {
                $driverPath = $matches[1]
            }
            
            # Add to collection if not empty
            if (-not [string]::IsNullOrEmpty($driverPath)) {
                $drivers += [PSCustomObject]@{
                    DriverName = $driver.DisplayName
                    Description = $driver.Description
                    ServiceName = $driver.Name
                    DriverType = "Kernel Driver"
                    State = $driver.State
                    StartMode = $driver.StartMode
                    DriverPath = $driverPath
                    DriverFileName = [System.IO.Path]::GetFileName($driverPath)
                    Source = "Service Manager"
                }
            }
        }
        
        # Method 2: Get drivers from the driverstore folder
        $driverStoreFolder = "$env:SystemRoot\System32\DriverStore\FileRepository"
        
        if (Test-Path $driverStoreFolder) {
            $driverFiles = Get-ChildItem -Path $driverStoreFolder -Filter "*.sys" -Recurse -ErrorAction SilentlyContinue
            
            foreach ($driverFile in $driverFiles) {
                # Check if this driver is already in our list
                $existingDriver = $drivers | Where-Object { $_.DriverFileName -eq $driverFile.Name }
                
                if (-not $existingDriver) {
                    $driverInfo = [PSCustomObject]@{
                        DriverName = $driverFile.BaseName
                        Description = "Driver from DriverStore"
                        ServiceName = $driverFile.BaseName
                        DriverType = "Kernel Driver"
                        State = "Stopped"  # Assume stopped unless proven otherwise
                        StartMode = "Unknown"
                        DriverPath = $driverFile.FullName
                        DriverFileName = $driverFile.Name
                        Source = "DriverStore"
                    }
                    
                    $drivers += $driverInfo
                }
            }
        }
        
        # Method 3: Check active modules from the kernel
        try {
            $driverModules = Get-CimInstance -ClassName Win32_SystemBinaryFile -ErrorAction SilentlyContinue | 
                              Where-Object { $_.Path -like "*\System32\drivers\*.sys" }
            
            foreach ($module in $driverModules) {
                $driverPath = $module.Path
                $driverFileName = [System.IO.Path]::GetFileName($driverPath)
                
                # Check if this driver is already in our list
                $existingDriver = $drivers | Where-Object { $_.DriverFileName -eq $driverFileName }
                
                if (-not $existingDriver) {
                    $driverInfo = [PSCustomObject]@{
                        DriverName = [System.IO.Path]::GetFileNameWithoutExtension($driverPath)
                        Description = "Kernel-loaded driver module"
                        ServiceName = [System.IO.Path]::GetFileNameWithoutExtension($driverPath)
                        DriverType = "Kernel Driver"
                        State = "Running"  # If it's in the kernel, it's running
                        StartMode = "Unknown"
                        DriverPath = $driverPath
                        DriverFileName = $driverFileName
                        Source = "Kernel Module"
                    }
                    
                    $drivers += $driverInfo
                }
            }
        }
        catch {
            # This method might not work on all systems
        }
        
        # De-duplicate the results
        $uniqueDrivers = $drivers | Group-Object -Property DriverFileName | ForEach-Object {
            # Prefer the first entry, but keep service state if it exists
            $uniqueDriver = $_.Group[0]
            
            # If any instance of this driver is marked as running, mark it as running
            if (($_.Group | Where-Object { $_.State -eq "Running" }).Count -gt 0) {
                $uniqueDriver.State = "Running"
            }
            
            $uniqueDriver
        }
        
        return $uniqueDrivers
    }
    catch {
        Write-ForensicLog "Error collecting system drivers: $_" -Severity "Warning"
        return @()
    }
}

function Analyze-DriverSecurity {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Driver
    )
    
    $riskScore = 0
    $riskReasons = @()
    $signatureStatus = "Unknown"
    $signatureIssuer = ""
    $fileVersion = ""
    $companyName = ""
    $creationTime = $null
    $lastModifiedTime = $null
    $isKernelMode = $true
    
    try {
        # Check 1: Verify digital signature
        if (Test-Path $Driver.DriverPath) {
            try {
                $signature = Get-AuthenticodeSignature -FilePath $Driver.DriverPath -ErrorAction SilentlyContinue
                
                if ($signature) {
                    $signatureStatus = $signature.Status
                    
                    switch ($signature.Status) {
                        "Valid" {
                            # Extract signer information if available
                            if ($signature.SignerCertificate) {
                                $signatureIssuer = $signature.SignerCertificate.Subject
                            }
                        }
                        "NotSigned" {
                            $riskScore += 5
                            $riskReasons += "Driver is not digitally signed"
                        }
                        "HashMismatch" {
                            $riskScore += 9
                            $riskReasons += "Driver signature hash mismatch (potentially tampered)"
                        }
                        "NotTrusted" {
                            $riskScore += 6
                            $riskReasons += "Driver signature not trusted"
                        }
                        "UnknownError" {
                            $riskScore += 3
                            $riskReasons += "Unknown error verifying driver signature"
                        }
                        default {
                            $riskScore += 3
                            $riskReasons += "Signature status: $($signature.Status)"
                        }
                    }
                } else {
                    $signatureStatus = "Unknown"
                    $riskScore += 3
                    $riskReasons += "Could not verify signature"
                }
            }
            catch {
                $signatureStatus = "Error"
                $riskScore += 3
                $riskReasons += "Error checking signature: $($_.Exception.Message)"
            }
            
            # Check 2: Get file metadata
            try {
                $fileInfo = Get-Item $Driver.DriverPath -ErrorAction SilentlyContinue
                
                if ($fileInfo) {
                    $creationTime = $fileInfo.CreationTime
                    $lastModifiedTime = $fileInfo.LastWriteTime
                    
                    # Check for very recent drivers
                    $daysSinceCreation = (Get-Date) - $creationTime
                    if ($daysSinceCreation.TotalDays -lt 7) {
                        $riskScore += 2
                        $riskReasons += "Recently created driver (within past week)"
                    }
                }
                
                $versionInfo = Get-ItemProperty -Path $Driver.DriverPath -ErrorAction SilentlyContinue
                
                if ($versionInfo -and $versionInfo.VersionInfo) {
                    $fileVersion = $versionInfo.VersionInfo.FileVersion
                    $companyName = $versionInfo.VersionInfo.CompanyName
                    
                    # Check for suspicious or missing company information
                    if ([string]::IsNullOrEmpty($companyName)) {
                        $riskScore += 2
                        $riskReasons += "No company information"
                    }
                }
            }
            catch {
                # Could not get file info
            }
            
            # Check 3: Analyze file path and location
            $suspiciousLocations = @(
                "\\Temp\\", "\\Temporary Internet Files\\", "\\Downloads\\", "\\AppData\\Local\\Temp\\",
                "\\Desktop\\", "\\Public\\", "\\Users\\Public\\", "\\ProgramData\\"
            )
            
            foreach ($location in $suspiciousLocations) {
                if ($Driver.DriverPath -like "*$location*") {
                    $riskScore += 4
                    $riskReasons += "Driver located in suspicious folder: $location"
                    break
                }
            }
            
            # Check if not in standard driver directories
            if (-not ($Driver.DriverPath -like "*\system32\drivers\*") -and 
                -not ($Driver.DriverPath -like "*\system32\DriverStore\*")) {
                $riskScore += 3
                $riskReasons += "Driver not in standard driver directory"
            }
            
            # Check 4: Analyze file content
            try {
                # Get file size
                $fileSize = (Get-Item $Driver.DriverPath -ErrorAction SilentlyContinue).Length
                
                # Unusually small drivers are suspicious
                if ($fileSize -lt 10KB) {
                    $riskScore += 2
                    $riskReasons += "Unusually small driver file ($($fileSize / 1KB) KB)"
                }
                
                # Check if it's a kernel mode driver
                $isKernelMode = $true  # Assume kernel mode for .sys files
                
                # For kernel mode drivers, inspect more carefully
                if ($isKernelMode) {
                    # Check if loaded at boot
                    if ($Driver.StartMode -eq "Boot" -or $Driver.StartMode -eq "System") {
                        # Boot and system start drivers are potentially more dangerous if compromised
                        if ($signatureStatus -ne "Valid") {
                            $riskScore += 2
                            $riskReasons += "Unsigned driver loads at boot time"
                        }
                    }
                    
                    # Check if currently running
                    if ($Driver.State -eq "Running") {
                        # Running drivers with issues are more concerning
                        if ($signatureStatus -ne "Valid") {
                            $riskScore += 2
                            $riskReasons += "Unsigned driver is currently running"
                        }
                    }
                }
            }
            catch {
                # Could not analyze file content
            }
            
            # Check 5: Check against known malicious driver patterns
            $maliciousDriverPatterns = @(
                "gdrv", "dbutil", "rtcore", "ene", "msio", "glckio",  # Known vulnerable drivers
                "winio", "directio", "asuskex", "nvidiahook",          # Common in BYOVD attacks
                "processhacker", "kprocesshacker"                       # Process hacker drivers
            )
            
            foreach ($pattern in $maliciousDriverPatterns) {
                if ($Driver.DriverFileName -match $pattern) {
                    $riskScore += 3
                    $riskReasons += "Matches known vulnerable driver pattern: $pattern"
                    break
                }
            }
        } else {
            $riskScore += 2
            $riskReasons += "Driver file not found: $($Driver.DriverPath)"
        }
    }
    catch {
        $riskScore += 1
        $riskReasons += "Error analyzing driver: $($_.Exception.Message)"
    }
    
    # Get risk level
    $riskLevel = "Low"
    if ($riskScore -ge 7) {
        $riskLevel = "High"
    } elseif ($riskScore -ge 4) {
        $riskLevel = "Medium"
    } elseif ($riskScore -le 0) {
        $riskLevel = "Safe"
    }
    
    # Return analysis results
    return [PSCustomObject]@{
        DriverName = $Driver.DriverName
        Description = $Driver.Description
        ServiceName = $Driver.ServiceName
        DriverType = $Driver.DriverType
        State = $Driver.State
        StartMode = $Driver.StartMode
        DriverPath = $Driver.DriverPath
        DriverFileName = $Driver.DriverFileName
        Source = $Driver.Source
        SignatureStatus = $signatureStatus
        SignatureIssuer = $signatureIssuer
        FileVersion = $fileVersion
        CompanyName = $companyName
        CreationTime = $creationTime
        LastModifiedTime = $lastModifiedTime
        RiskScore = $riskScore
        RiskLevel = $riskLevel
        RiskReason = ($riskReasons | Select-Object -Unique) -join "; "
    }
}

# Export function
Export-ModuleMember -Function Get-DriverStatus
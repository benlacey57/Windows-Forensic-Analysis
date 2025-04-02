<#
.SYNOPSIS
    Collects information about installed services
    
.DESCRIPTION
    Gathers detailed information about all services on the system, including
    their paths, start modes, accounts, and other forensically relevant data.
    Identifies potentially suspicious services that could be used for persistence.
    
.EXAMPLE
    $serviceDataFile = Get-ServiceInformation
    
.OUTPUTS
    String. The path to the CSV file containing service data
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for complete service details
#>

function Get-ServiceInformation {
    param()
    
    $outputFile = "$script:outputDir\Services_$script:timestamp.csv"
    Write-ForensicLog "Collecting service information..."
    
    try {
        # Get all services with detailed information
        $services = Get-Service | ForEach-Object {
            $serviceName = $_.Name
            
            # Get WMI service information for additional details
            $wmiService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
            
            # Create service object with combined data
            [PSCustomObject]@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                Status = $_.Status
                StartType = $_.StartType
                ServiceType = if ($wmiService) { $wmiService.ServiceType } else { "Unknown" }
                PathName = if ($wmiService) { $wmiService.PathName } else { "Unknown" }
                StartName = if ($wmiService) { $wmiService.StartName } else { "Unknown" }
                Description = if ($wmiService) { $wmiService.Description } else { "Unknown" }
                DelayedAutoStart = if ($wmiService) { $wmiService.DelayedAutoStart } else { "Unknown" }
                ProcessId = if ($wmiService) { $wmiService.ProcessId } else { "Unknown" }
                InstallDate = if ($wmiService) { $wmiService.InstallDate } else { "Unknown" }
                DigitalSignature = if ($wmiService -and $wmiService.PathName) {
                    $exePath = $wmiService.PathName -replace '^"([^"]+)".*$', '$1' -replace "^'([^']+)'.*$", '$1'
                    if ($exePath -match "^[A-Za-z]:\\") {
                        try {
                            $signature = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
                            if ($signature) {
                                "$($signature.Status) - $($signature.SignerCertificate.Subject)"
                            } else {
                                "Unknown"
                            }
                        } catch {
                            "Error checking signature"
                        }
                    } else {
                        "Invalid path format"
                    }
                } else {
                    "Unknown"
                }
                SuspiciousScore = 0  # Will be calculated below
                SuspiciousReasons = ""  # Will be populated below
            }
        }
        
        # Analyze services for suspicious characteristics
        foreach ($service in $services) {
            $suspiciousScore = 0
            $suspiciousReasons = @()
            
            # Check for non-standard service accounts
            $standardAccounts = @("LocalSystem", "NT AUTHORITY\LocalService", "NT AUTHORITY\NetworkService", "NT SERVICE")
            $isStandardAccount = $false
            foreach ($account in $standardAccounts) {
                if ($service.StartName -like "*$account*") {
                    $isStandardAccount = $true
                    break
                }
            }
            
            if (-not $isStandardAccount -and $service.StartName -ne "Unknown") {
                $suspiciousScore += 1
                $suspiciousReasons += "Non-standard service account: $($service.StartName)"
            }
            
            # Check for services running from suspicious locations
            if ($service.PathName -match "\\Temp\\|\\AppData\\Local\\Temp|%Temp%|\\Downloads\\") {
                $suspiciousScore += 3
                $suspiciousReasons += "Service executable in temporary directory"
            }
            
            if ($service.PathName -match "\\AppData\\|%AppData%") {
                $suspiciousScore += 2
                $suspiciousReasons += "Service executable in AppData directory"
            }
            
            if ($service.PathName -match "\\ProgramData\\") {
                $suspiciousScore += 1
                $suspiciousReasons += "Service executable in ProgramData directory"
            }
            
            # Check for services with suspicious path contents
            if ($service.PathName -match "powershell|cmd|wscript|cscript|rundll32|regsvr32|mshta") {
                $suspiciousScore += 2
                $suspiciousReasons += "Service uses script interpreter or suspicious binary"
            }
            
            # Check for unusual command-line arguments
            if ($service.PathName -match "-encod|-enc |/enc |/e |-w hidden|-windowstyle h|downloadstring|iex |invoke-expr|bypass") {
                $suspiciousScore += 3
                $suspiciousReasons += "Suspicious command-line arguments"
            }
            
            # Check for services with missing or invalid digital signatures
            if ($service.DigitalSignature -match "NotSigned|Invalid|Error") {
                $suspiciousScore += 1
                $suspiciousReasons += "Unsigned or invalid signature"
            }
            
            # Check for services with random-looking names but normal display names
            if ($service.Name -match "^[a-z0-9]{8,}$" -and $service.DisplayName -notmatch "^[a-z0-9]{8,}$") {
                $suspiciousScore += 2
                $suspiciousReasons += "Random-looking service name"
            }
            
            # Check for recently installed services with auto-start
            if ($service.InstallDate -ne "Unknown") {
                try {
                    $installDate = [Management.ManagementDateTimeConverter]::ToDateTime($service.InstallDate)
                    if (((Get-Date) - $installDate).TotalDays -lt 7 -and $service.StartType -eq "Automatic") {
                        $suspiciousScore += 1
                        $suspiciousReasons += "Recently installed auto-start service"
                    }
                } catch {}
            }
            
            # Update the suspicious score and reasons
            $service.SuspiciousScore = $suspiciousScore
            $service.SuspiciousReasons = ($suspiciousReasons -join "; ")
        }
        
        # Export to CSV
        $services | Export-Csv -Path $outputFile -NoTypeInformation
        
        # Report suspicious services
        $suspiciousServices = $services | Where-Object { $_.SuspiciousScore -gt 0 } | Sort-Object -Property SuspiciousScore -Descending
        if ($suspiciousServices.Count -gt 0) {
            Write-ForensicLog "Found $($suspiciousServices.Count) potentially suspicious services:" -Severity "Warning"
            foreach ($svc in $suspiciousServices | Select-Object -First 5) {
                Write-ForensicLog "  - $($svc.DisplayName) ($($svc.Name)) - $($svc.SuspiciousReasons)" -Severity "Warning"
            }
            
            # Create a separate file for suspicious services
            $suspiciousServices | Export-Csv -Path "$script:outputDir\SuspiciousServices_$script:timestamp.csv" -NoTypeInformation
        }
        
        Write-ForensicLog "Saved service data to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error collecting service data: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-ServiceInformation
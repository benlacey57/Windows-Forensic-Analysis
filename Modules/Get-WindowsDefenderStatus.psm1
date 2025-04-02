<#
.SYNOPSIS
    Checks Windows Defender status and configuration
    
.DESCRIPTION
    Analyzes the Windows Defender configuration, including real-time protection,
    signature status, and other security features. Identifies potential security
    issues such as disabled protections or outdated signatures.
    
.EXAMPLE
    $defenderStatusFile = Get-WindowsDefenderStatus
    
.OUTPUTS
    String. The path to the CSV file containing Windows Defender status
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges recommended for complete information
#>

function Get-WindowsDefenderStatus {
    param()
    
    $outputFile = "$script:outputDir\WindowsDefender_$script:timestamp.csv"
    Write-ForensicLog "Checking Windows Defender status..."
    
    try {
        # Get Windows Defender status using PowerShell cmdlets
        $defenderStatus = Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, 
            BehaviorMonitorEnabled, IoavProtectionEnabled, NISEnabled, OnAccessProtectionEnabled, RealTimeProtectionEnabled,
            DefenderSignaturesOutOfDate, AntispywareSignatureLastUpdated, AntivirusSignatureLastUpdated, 
            FullScanAge, QuickScanAge, TamperProtectionSource, TamperProtection, IsTamperProtected,
            AMEngineVersion, AntispywareSignatureVersion, AntivirusSignatureVersion, 
            @{Name="LastFullScanDateTime";Expression={if ($_.LastFullScanDateTime) {$_.LastFullScanDateTime.ToString()} else {"Never"}}},
            @{Name="LastQuickScanDateTime";Expression={if ($_.LastQuickScanDateTime) {$_.LastQuickScanDateTime.ToString()} else {"Never"}}},
            @{Name="LastScanDateTime";Expression={
                if ($_.LastFullScanDateTime -and $_.LastQuickScanDateTime) {
                    if ($_.LastFullScanDateTime -gt $_.LastQuickScanDateTime) {
                        $_.LastFullScanDateTime.ToString() + " (Full)"
                    } else {
                        $_.LastQuickScanDateTime.ToString() + " (Quick)"
                    }
                } elseif ($_.LastFullScanDateTime) {
                    $_.LastFullScanDateTime.ToString() + " (Full)"
                } elseif ($_.LastQuickScanDateTime) {
                    $_.LastQuickScanDateTime.ToString() + " (Quick)"
                } else {
                    "Never"
                }
            }}

        # Calculate days since last signature update
        if ($defenderStatus.AntivirusSignatureLastUpdated) {
            $daysSinceUpdate = [math]::Round(((Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated).TotalDays)
            $defenderStatus | Add-Member -MemberType NoteProperty -Name "DaysSinceSignatureUpdate" -Value $daysSinceUpdate
        } else {
            $defenderStatus | Add-Member -MemberType NoteProperty -Name "DaysSinceSignatureUpdate" -Value "Unknown"
        }
        
        # Get additional Windows Defender settings
        try {
            $defenderPreferences = Get-MpPreference -ErrorAction SilentlyContinue
            if ($defenderPreferences) {
                # Add selected preferences to the status object
                $defenderStatus | Add-Member -MemberType NoteProperty -Name "ExclusionPath" -Value ($defenderPreferences.ExclusionPath -join "; ")
                $defenderStatus | Add-Member -MemberType NoteProperty -Name "ExclusionProcess" -Value ($defenderPreferences.ExclusionProcess -join "; ")
                $defenderStatus | Add-Member -MemberType NoteProperty -Name "ExclusionExtension" -Value ($defenderPreferences.ExclusionExtension -join "; ")
                $defenderStatus | Add-Member -MemberType NoteProperty -Name "DisableRealtimeMonitoring" -Value $defenderPreferences.DisableRealtimeMonitoring
                $defenderStatus | Add-Member -MemberType NoteProperty -Name "DisableBehaviorMonitoring" -Value $defenderPreferences.DisableBehaviorMonitoring
                $defenderStatus | Add-Member -MemberType NoteProperty -Name "DisableScriptScanning" -Value $defenderPreferences.DisableScriptScanning
                $defenderStatus | Add-Member -MemberType NoteProperty -Name "SubmitSamplesConsent" -Value $defenderPreferences.SubmitSamplesConsent
                $defenderStatus | Add-Member -MemberType NoteProperty -Name "MAPSReporting" -Value $defenderPreferences.MAPSReporting
                $defenderStatus | Add-Member -MemberType NoteProperty -Name "CloudBlockLevel" -Value $defenderPreferences.CloudBlockLevel
                $defenderStatus | Add-Member -MemberType NoteProperty -Name "CloudExtendedTimeout" -Value $defenderPreferences.CloudExtendedTimeout
                $defenderStatus | Add-Member -MemberType NoteProperty -Name "ScanScheduleDay" -Value $defenderPreferences.ScanScheduleDay
                $defenderStatus | Add-Member -MemberType NoteProperty -Name "RemediationScheduleDay" -Value $defenderPreferences.RemediationScheduleDay
                $defenderStatus | Add-Member -MemberType NoteProperty -Name "UnknownThreatDefaultAction" -Value $defenderPreferences.UnknownThreatDefaultAction
            }
        } catch {
            Write-ForensicLog "Error retrieving Windows Defender preferences: $_" -Severity "Warning"
        }
        
        # Add suspicious score and reasons
        $suspiciousScore = 0
        $suspiciousReasons = @()
        
        # Check for disabled components
        if (-not $defenderStatus.AMServiceEnabled) { 
            $suspiciousScore += 2
            $suspiciousReasons += "AMService disabled" 
        }
        if (-not $defenderStatus.AntispywareEnabled) { 
            $suspiciousScore += 2
            $suspiciousReasons += "Antispyware disabled" 
        }
        if (-not $defenderStatus.AntivirusEnabled) { 
            $suspiciousScore += 2
            $suspiciousReasons += "Antivirus disabled" 
        }
        if (-not $defenderStatus.BehaviorMonitorEnabled) { 
            $suspiciousScore += 2
            $suspiciousReasons += "BehaviorMonitor disabled" 
        }
        if (-not $defenderStatus.RealTimeProtectionEnabled) { 
            $suspiciousScore += 3
            $suspiciousReasons += "RealTimeProtection disabled" 
        }
        if (-not $defenderStatus.IsTamperProtected) { 
            $suspiciousScore += 1
            $suspiciousReasons += "Tamper Protection disabled" 
        }
        
        # Check for outdated signatures
        if ($defenderStatus.DefenderSignaturesOutOfDate) {
            $suspiciousScore += 2
            $suspiciousReasons += "Defender signatures are out of date"
        }
        
        if ($defenderStatus.DaysSinceSignatureUpdate -ne "Unknown" -and [int]$defenderStatus.DaysSinceSignatureUpdate -gt 7) {
            $suspiciousScore += 1
            $suspiciousReasons += "Signatures not updated in more than 7 days"
        }
        
        # Check for missing scans
        if ($defenderStatus.FullScanAge -gt 30) {
            $suspiciousScore += 1
            $suspiciousReasons += "No full scan performed in $($defenderStatus.FullScanAge) days"
        }
        
        # Check for suspicious exclusions
        if ($defenderStatus.ExclusionPath -and $defenderStatus.ExclusionPath -match "\\Windows\\|\\System32\\|\\Temp\\|\\ProgramData\\|C:\\") {
            $suspiciousScore += 2
            $suspiciousReasons += "Suspicious folder exclusions"
        }
        
        if ($defenderStatus.ExclusionProcess -and $defenderStatus.ExclusionProcess -match "cmd.exe|powershell.exe|wscript.exe|cscript.exe|rundll32.exe|regsvr32.exe") {
            $suspiciousScore += 3
            $suspiciousReasons += "Suspicious process exclusions"
        }
        
        if ($defenderStatus.ExclusionExtension -and $defenderStatus.ExclusionExtension -match "exe|dll|bat|ps1|vbs|js") {
            $suspiciousScore += 3
            $suspiciousReasons += "Suspicious extension exclusions"
        }
        
        # Check for disabled features
        if ($defenderStatus.DisableRealtimeMonitoring) {
            $suspiciousScore += 3
            $suspiciousReasons += "Realtime monitoring disabled via preferences"
        }
        
        if ($defenderStatus.DisableBehaviorMonitoring) {
            $suspiciousScore += 2
            $suspiciousReasons += "Behavior monitoring disabled via preferences"
        }
        
        if ($defenderStatus.DisableScriptScanning) {
            $suspiciousScore += 2
            $suspiciousReasons += "Script scanning disabled"
        }
        
        # Add suspicious score and reasons to status object
        $defenderStatus | Add-Member -MemberType NoteProperty -Name "SuspiciousScore" -Value $suspiciousScore
        $defenderStatus | Add-Member -MemberType NoteProperty -Name "SuspiciousReasons" -Value ($suspiciousReasons -join "; ")

        # Save to file
        $defenderStatus | Export-Csv -Path $outputFile -NoTypeInformation
        
        # Report on findings
        if ($suspiciousScore -gt 0) {
            Write-ForensicLog "WARNING: Windows Defender has potentially dangerous configuration issues:" -Severity "Warning"
            foreach ($reason in $suspiciousReasons) {
                Write-ForensicLog "  - $reason" -Severity "Warning"
            }
        } else {
            Write-ForensicLog "Windows Defender appears to be properly configured."
        }
        
        Write-ForensicLog "Saved Windows Defender status to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error checking Windows Defender: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-WindowsDefenderStatus
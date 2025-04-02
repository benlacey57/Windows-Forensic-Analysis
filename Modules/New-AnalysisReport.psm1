<#
.SYNOPSIS
    Generates a comprehensive analysis report from collected forensic data
    
.DESCRIPTION
    Creates a detailed text report summarizing all findings from the forensic analysis,
    highlighting potential security issues and suspicious activities detected.
    
.PARAMETER Results
    Hashtable containing the paths to all data files collected during analysis
    
.EXAMPLE
    $reportPath = New-AnalysisReport -Results $collectedResults
    
.OUTPUTS
    String. The path to the generated report file
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
#>

function New-AnalysisReport {
    param(
        [hashtable]$Results
    )
    
    $reportFile = "$script:outputDir\ForensicAnalysisReport_$script:timestamp.txt"
    Write-ForensicLog "Generating final analysis report..."
    
    try {
        $reportContent = @"
===========================================================
FORENSIC ANALYSIS REPORT
===========================================================
Computer: $env:COMPUTERNAME
Date: $(Get-Date)
User: $env:USERNAME
===========================================================

SUMMARY OF FINDINGS:

"@
        
        # Add warnings for suspicious findings
        $suspiciousFindings = @()
        
        # Check for unusual network connections
        if ($Results.ContainsKey("UnusualPorts") -and (Test-Path $Results["UnusualPorts"])) {
            $unusualConnections = Import-Csv -Path $Results["UnusualPorts"] -ErrorAction SilentlyContinue
            if ($unusualConnections -and $unusualConnections.Count -gt 0) {
                $suspiciousFindings += "- Found $($unusualConnections.Count) unusual network connections on uncommon ports."
            }
        }
        
        # Check for recently modified executables
        if ($Results.ContainsKey("RecentExecutables") -and (Test-Path $Results["RecentExecutables"])) {
            $recentExes = Import-Csv -Path $Results["RecentExecutables"] -ErrorAction SilentlyContinue
            if ($recentExes -and $recentExes.Count -gt 0) {
                $suspiciousFindings += "- Found $($recentExes.Count) recently modified executable files."
            }
        }
        
        # Check for suspicious scheduled tasks
        if ($Results.ContainsKey("SuspiciousTasks") -and (Test-Path $Results["SuspiciousTasks"])) {
            $tasks = Import-Csv -Path $Results["SuspiciousTasks"] -ErrorAction SilentlyContinue
            if ($tasks -and $tasks.Count -gt 0) {
                $suspiciousFindings += "- Found $($tasks.Count) potentially suspicious scheduled tasks."
            }
        }
        
        # Check for disabled security controls
        if ($Results.ContainsKey("WindowsDefender") -and (Test-Path $Results["WindowsDefender"])) {
            $defenderStatus = Import-Csv -Path $Results["WindowsDefender"] -ErrorAction SilentlyContinue
            if ($defenderStatus -and $defenderStatus[0].RealTimeProtectionEnabled -eq "False") {
                $suspiciousFindings += "- Windows Defender real-time protection is disabled."
            }
        }
        
        # Check for unsigned drivers
        if ($Results.ContainsKey("Drivers") -and (Test-Path $Results["Drivers"])) {
            $drivers = Import-Csv -Path $Results["Drivers"] -ErrorAction SilentlyContinue
            $unsignedDrivers = $drivers | Where-Object { $_.IsSigned -eq "False" }
            if ($unsignedDrivers -and $unsignedDrivers.Count -gt 0) {
                $suspiciousFindings += "- Found $($unsignedDrivers.Count) unsigned drivers installed on the system."
            }
        }
        
        # Check for potential web shells
        if ($Results.ContainsKey("WebShells") -and (Test-Path $Results["WebShells"])) {
            $webShells = Import-Csv -Path $Results["WebShells"] -ErrorAction SilentlyContinue
            if ($webShells -and $webShells.Count -gt 0) {
                $suspiciousFindings += "- Found $($webShells.Count) potential web shell files in web directories."
            }
        }

        # Check for suspicious PowerShell activity
        if ($Results.ContainsKey("PowerShellLogs") -and (Test-Path $Results["PowerShellLogs"])) {
    $psLogs = Import-Csv -Path $Results["PowerShellLogs"] -ErrorAction SilentlyContinue
            if ($psLogs) {
                $suspiciousPsLogs = Import-Csv -Path "$script:outputDir\SuspiciousPSLogs_$script:timestamp.csv" -ErrorAction SilentlyContinue
                if ($suspiciousPsLogs -and $suspiciousPsLogs.Count -gt 0) {
                    $suspiciousFindings += "- Detected $($suspiciousPsLogs.Count) suspicious PowerShell commands, possibly including encoded payloads or download attempts."
                }
            }
        }

        # Check for AMSI bypass attempts
        if ($Results.ContainsKey("AMSIBypass") -and (Test-Path $Results["AMSIBypass"])) {
            $amsiBypassContent = Get-Content -Path $Results["AMSIBypass"] -Raw
            if ($amsiBypassContent -match "Found potential AMSI bypass attempts") {
                $suspiciousFindings += "- Detected potential attempts to bypass Windows Antimalware Scan Interface (AMSI)."
            }
        }

        # Check for browser extensions with excessive permissions
        if ($Results.ContainsKey("BrowserExtensions") -and (Test-Path $Results["BrowserExtensions"])) {
            $extensions = Import-Csv -Path $Results["BrowserExtensions"] -ErrorAction SilentlyContinue
            if ($extensions) {
                $suspiciousExtensions = $extensions | Where-Object { 
            [int]$_.PermissionsCount -gt 5 -or
            $_.Permissions -match "tabs|webRequest|webRequestBlocking|cookies|clipboardRead|nativeMessaging|proxy|privacy|storage|<all_urls>"
            }
        
            if ($suspiciousExtensions -and $suspiciousExtensions.Count -gt 0) {
                $suspiciousFindings += "- Found $($suspiciousExtensions.Count) browser extensions with excessive permissions that could be used for data harvesting."
            }
        }
    }

    # Check for potential rootkit indicators
    if ($Results.ContainsKey("RootkitIndicators") -and (Test-Path $Results["RootkitIndicators"])) {
        $rootkitContent = Get-Content -Path $Results["RootkitIndicators"] -Raw
        if ($rootkitContent -match "WARNING:") {
            $suspiciousFindings += "- Detected potential rootkit indicators including system inconsistencies or hidden processes."
        }
    }

    # Check for registry persistence mechanisms
    if ($Results.ContainsKey("RegistryPersistence") -and (Test-Path $Results["RegistryPersistence"])) {
        $regPersistence = Import-Csv -Path $Results["RegistryPersistence"] -ErrorAction SilentlyContinue
        $suspiciousEntries = $regPersistence | Where-Object { $_.Suspicious -eq "True" }
    
        if ($suspiciousEntries -and $suspiciousEntries.Count -gt 0) {
            $suspiciousFindings += "- Found $($suspiciousEntries.Count) suspicious registry entries that could be used for persistence."
        }
    }

    # Check for timestomped files (possible anti-forensics)
    if ($Results.ContainsKey("TimeStompedFiles") -and (Test-Path $Results["TimeStompedFiles"])) {
        $timestompedFiles = Import-Csv -Path $Results["TimeStompedFiles"] -ErrorAction SilentlyContinue
    
        if ($timestompedFiles -and $timestompedFiles.Count -gt 0) {
            $suspiciousFindings += "- Detected $($timestompedFiles.Count) files with suspicious timestamp patterns, possibly indicating anti-forensic timestomping."
        }
    }

    # Check for environment variable persistence
    if ($Results.ContainsKey("EnvVarPersistence") -and (Test-Path $Results["EnvVarPersistence"])) {
        $envVarPersistence = Get-Content -Path "$script:outputDir\SuspiciousPATH_$script:timestamp.csv" -ErrorAction SilentlyContinue
    
        if ($envVarPersistence) {
            $suspiciousFindings += "- Found suspicious PATH environment variable entries that could be used for persistence or DLL hijacking."
        }
    }

    # Check for WMI persistence
    if ($Results.ContainsKey("WMIPersistence") -and (Test-Path $Results["WMIPersistence"])) {
        $wmiContent = Get-Content -Path $Results["WMIPersistence"] -Raw
    
        if ($wmiContent -match "Found suspicious WMI") {
            $suspiciousFindings += "- Detected suspicious WMI event subscription persistence mechanisms."
        }
    }

    # Check for high network outbound traffic (possible data exfiltration)
    if ($Results.ContainsKey("NetworkUsage") -and (Test-Path $Results["NetworkUsage"])) {
        $networkUsage = Import-Csv -Path $Results["NetworkUsage"] -ErrorAction SilentlyContinue
        $highTraffic = $networkUsage | Where-Object { [double]$_.SentRateMBperMin -gt 5 }
    
        if ($highTraffic -and $highTraffic.Count -gt 0) {
            $suspiciousFindings += "- Detected abnormally high outbound network traffic ($([Math]::Round($highTraffic[0].SentRateMBperMin, 2)) MB/min), possible data exfiltration."
        }
    }

    # Check for recent system restore point deletions
    if ($Results.ContainsKey("ShadowCopies") -and (Test-Path $Results["ShadowCopies"])) {
        $shadowCopies = Get-Content -Path $Results["ShadowCopies"] -Raw
    
        if ($shadowCopies -match "No shadow copies found" -or $shadowCopies -match "possible evidence of deletion") {
            $suspiciousFindings += "- No Volume Shadow Copies found, which could indicate deliberate deletion to hide evidence."
        }
    }
        
        # Add suspicious findings to report
        if ($suspiciousFindings.Count -gt 0) {
            $reportContent += "POTENTIAL SIGNS OF COMPROMISE DETECTED:`n`n"
            $reportContent += $suspiciousFindings -join "`n"
            $reportContent += "`n`n"
        }
        else {
            $reportContent += "No obvious signs of compromise detected in the initial analysis.`n`n"
        }
        
        # Add data collection info
        $reportContent += @"
COLLECTED DATA FILES:

$($Results.GetEnumerator() | ForEach-Object { "- $($_.Key): $($_.Value)" } | Out-String)

===========================================================
NEXT STEPS:

1. Review detailed data files for further analysis
2. If signs of compromise were detected, isolate the system and conduct deeper forensic examination
3. Cross-reference findings with other systems on the network
4. Consider timeline analysis of events
===========================================================
"@
        
        $reportContent | Out-File -FilePath $reportFile
        Write-ForensicLog "Analysis report saved to $reportFile"
        
        if ($suspiciousFindings.Count -gt 0) {
            Write-ForensicLog "WARNING: Potential signs of compromise were detected. Review the analysis report for details." -Severity "Warning"
        }
        
        return $reportFile
    }
    catch {
        Write-ForensicLog "Error generating analysis report: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function New-AnalysisReport
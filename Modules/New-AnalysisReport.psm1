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
        
        # Add additional checks for web shells, PowerShell logs, etc.
        # ...
        
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
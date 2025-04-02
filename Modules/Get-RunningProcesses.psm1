<#
.SYNOPSIS
    Collects information about running processes on the system
    
.DESCRIPTION
    Gathers detailed information about all running processes including their
    paths, companies, memory usage, and other forensically relevant data.
    Exports the data to a CSV file for analysis.
    
.EXAMPLE
    $processDataFile = Get-RunningProcesses
    
.OUTPUTS
    String. The path to the CSV file containing process data
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Standard user can collect basic process information, but
    administrator rights are required for complete details on all system processes
#>

function Get-RunningProcesses {
    param()
    
    $outputFile = "$script:outputDir\Processes_$script:timestamp.csv"
    Write-ForensicLog "Collecting running processes information..."
    
    try {
        # Collect process details with additional properties
        $processes = Get-Process | Select-Object ID, ProcessName, Path, Company, CPU, StartTime, 
            @{Name="ThreadCount";Expression={$_.Threads.Count}}, 
            @{Name="HandleCount";Expression={$_.HandleCount}}, 
            WorkingSet, @{Name="WorkingSetMB";Expression={[math]::Round($_.WorkingSet / 1MB, 2)}},
            @{Name="ParentProcessId";Expression={
                # Try to get parent process ID when possible
                try {
                    $parentId = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = '$($_.Id)'" -ErrorAction SilentlyContinue).ParentProcessId
                    if ($parentId) { return $parentId } else { return "Unknown" }
                } catch {
                    return "Unknown"
                }
            }},
            @{Name="CommandLine";Expression={
                # Try to get command line when possible
                try {
                    return (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = '$($_.Id)'" -ErrorAction SilentlyContinue).CommandLine
                } catch {
                    return $null
                }
            }},
            @{Name="Owner";Expression={
                # Try to get process owner when possible
                try {
                    $owner = Invoke-CimMethod -InputObject (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = '$($_.Id)'" -ErrorAction SilentlyContinue) -MethodName GetOwner -ErrorAction SilentlyContinue
                    if ($owner) {
                        return "$($owner.Domain)\$($owner.User)"
                    } else {
                        return "Unknown"
                    }
                } catch {
                    return "Unknown"
                }
            }},
            @{Name="DigitalSignature";Expression={
                # Check if the process executable is digitally signed
                if ($_.Path) {
                    try {
                        $signature = Get-AuthenticodeSignature -FilePath $_.Path -ErrorAction SilentlyContinue
                        if ($signature) {
                            return "$($signature.Status) - $($signature.SignerCertificate.Subject)"
                        } else {
                            return "Unknown"
                        }
                    } catch {
                        return "Error checking signature"
                    }
                } else {
                    return "No path available"
                }
            }},
            @{Name="FileVersion";Expression={
                # Get file version info when available
                if ($_.Path) {
                    try {
                        $versionInfo = (Get-Item $_.Path -ErrorAction SilentlyContinue).VersionInfo
                        if ($versionInfo) {
                            return "$($versionInfo.FileVersion)"
                        } else {
                            return "Unknown"
                        }
                    } catch {
                        return "Error checking version"
                    }
                } else {
                    return "No path available"
                }
            }},
            @{Name="CreationTime";Expression={
                # Get process creation time
                try {
                    return $_.StartTime
                } catch {
                    return "Unknown"
                }
            }}
        
        # Identify potentially suspicious processes
        foreach ($process in $processes) {
            $suspiciousScore = 0
            $suspiciousReasons = @()
            
            # Check for processes with unusual paths
            if ($process.Path -and (-not [string]::IsNullOrEmpty($process.Path))) {
                if ($process.Path -match "\\Temp\\|\\AppData\\Local\\Temp|%Temp%") {
                    $suspiciousScore += 2
                    $suspiciousReasons += "Executing from Temp directory"
                }
                if ($process.Path -match "\\AppData\\|%AppData%") {
                    $suspiciousScore += 1
                    $suspiciousReasons += "Executing from AppData directory"
                }
                if ($process.Path -match "\\ProgramData\\") {
                    $suspiciousScore += 1
                    $suspiciousReasons += "Executing from ProgramData directory"
                }
            }
            
            # Check for processes with suspicious names that mimic system processes
            $systemProcesses = @("svchost", "lsass", "services", "csrss", "smss", "winlogon", "explorer", "wininit")
            foreach ($sysProc in $systemProcesses) {
                if ($process.ProcessName -ne $sysProc -and $process.ProcessName -match "$sysProc[a-zA-Z0-9]*") {
                    $suspiciousScore += 3
                    $suspiciousReasons += "Name mimics system process"
                    break
                }
            }
            
            # Check for processes with missing or invalid digital signatures
            if ($process.DigitalSignature -match "NotSigned|Invalid|Error") {
                $suspiciousScore += 1
                $suspiciousReasons += "Unsigned or invalid signature"
            }
            
            # Check for processes with unusual command lines
            if ($process.CommandLine -match "-encod|-enc |/enc |/e |-w hidden|-windowstyle h|downloadstring|iex |invoke-expr|bypass") {
                $suspiciousScore += 3
                $suspiciousReasons += "Suspicious command line"
            }
            
            # Add the suspicious score and reasons to the process object
            Add-Member -InputObject $process -MemberType NoteProperty -Name "SuspiciousScore" -Value $suspiciousScore
            Add-Member -InputObject $process -MemberType NoteProperty -Name "SuspiciousReasons" -Value ($suspiciousReasons -join "; ")
        }
        
        # Export to CSV
        $processes | Export-Csv -Path $outputFile -NoTypeInformation
        
        # Log suspicious processes
        $suspiciousProcesses = $processes | Where-Object { $_.SuspiciousScore -gt 0 } | Sort-Object -Property SuspiciousScore -Descending
        if ($suspiciousProcesses.Count -gt 0) {
            Write-ForensicLog "Found $($suspiciousProcesses.Count) potentially suspicious processes:" -Severity "Warning"
            foreach ($proc in $suspiciousProcesses | Select-Object -First 5) {
                Write-ForensicLog "  - $($proc.ProcessName) (PID: $($proc.ID)) - Score: $($proc.SuspiciousScore) - Reasons: $($proc.SuspiciousReasons)" -Severity "Warning"
            }
            
            # Create a separate file for suspicious processes
            $suspiciousProcesses | Export-Csv -Path "$script:outputDir\SuspiciousProcesses_$script:timestamp.csv" -NoTypeInformation
        }
        
        Write-ForensicLog "Saved process data to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error collecting process data: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-RunningProcesses
<#
.SYNOPSIS
    Checks for attempts to bypass Windows Antimalware Scan Interface (AMSI)
    
.DESCRIPTION
    Searches for evidence of AMSI bypass techniques in PowerShell history,
    scripts, registry modifications, and other locations. These bypass methods
    are commonly used by attackers to evade malware detection in scripts.
    
.EXAMPLE
    $amsiBypassFile = Find-AMSIBypassAttempts
    
.OUTPUTS
    String. The path to the text file containing AMSI bypass findings
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges recommended for complete access
#>

function Find-AMSIBypassAttempts {
    param()
    
    $outputFile = "$script:outputDir\AMSIBypass_$script:timestamp.txt"
    Write-ForensicLog "Checking for AMSI bypass attempts..."
    
    try {
        $results = @()
        $results += "=== AMSI BYPASS DETECTION REPORT ==="
        $results += "Date: $(Get-Date)"
        $results += "Computer: $env:COMPUTERNAME"
        $results += "==================================="
        $results += ""
        
        # Check for common AMSI bypass registry modifications
        $results += "=== CHECKING REGISTRY FOR AMSI TAMPERING ==="
        $amsiRegistryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\AMSI",
            "HKLM:\SOFTWARE\Microsoft\.NETFramework\Security\TrustManager\PromptingLevel",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        )
        
        $amsiRegistryModified = $false
        foreach ($path in $amsiRegistryPaths) {
            if (Test-Path $path) {
                $results += "Found AMSI-related registry path: $path"
                $regData = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Out-String
                $results += $regData
                
                # Check for specific values that might indicate tampering
                $regValues = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                
                # For AMSI key
                if ($path -eq "HKLM:\SOFTWARE\Microsoft\AMSI") {
                    if (Get-ItemProperty -Path $path -Name "AmsiEnable" -ErrorAction SilentlyContinue) {
                        $amsiEnable = (Get-ItemProperty -Path $path -Name "AmsiEnable" -ErrorAction SilentlyContinue).AmsiEnable
                        if ($amsiEnable -eq 0) {
                            $results += "WARNING: AMSI is disabled through registry key (AmsiEnable=0)"
                            $amsiRegistryModified = $true
                        }
                    }
                    
                    if (Get-ItemProperty -Path $path -Name "AmsiInitFailed" -ErrorAction SilentlyContinue) {
                        $results += "WARNING: Found 'AmsiInitFailed' registry value - potential AMSI bypass"
                        $amsiRegistryModified = $true
                    }
                }
                
                # For PowerShell script block logging
                if ($path -like "*\ScriptBlockLogging") {
                    if (Get-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue) {
                        $loggingEnabled = (Get-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
                        if ($loggingEnabled -eq 0) {
                            $results += "WARNING: PowerShell script block logging is disabled - potential anti-forensics"
                            $amsiRegistryModified = $true
                        }
                    }
                }
                
                $results += ""
            }
        }
        
        if (-not $amsiRegistryModified) {
            $results += "No suspicious registry modifications related to AMSI found."
            $results += ""
        }
        
        # Look for PowerShell scripts with common AMSI bypass patterns
        $results += "=== CHECKING FOR AMSI BYPASS PATTERNS IN SCRIPTS ==="
        $amsiBypassPatterns = @(
            "AmsiUtils", 
            "amsiInitFailed",
            "[Ref].Assembly.GetType",
            "System.Management.Automation.AmsiUtils",
            "amsiSession",
            "[Runtime.InteropServices.Marshal]::WriteByte",
            "AmsiScanBuffer",
            "amsiContext",
            "_CONTEXT",
            "_AMSI_RESULT",
            "System.Management.Automation.Utils",
            "SetProtectedEventLogging",
            "GetForegroundWindow",
            "PtrToStringAuto.*kernel32"
        )
        
        $psScriptLocations = @(
            "$env:USERPROFILE\Documents\*.ps1",
            "$env:TEMP\*.ps1",
            "$env:APPDATA\*.ps1",
            "$env:LOCALAPPDATA\*.ps1",
            "C:\Windows\Temp\*.ps1",
            "C:\Temp\*.ps1"
        )
        
        $foundSuspiciousScripts = $false
        foreach ($location in $psScriptLocations) {
            if (Test-Path $location) {
                $files = Get-ChildItem -Path $location -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    try {
                        $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
                        $matchedPatterns = @()
                        
                        foreach ($pattern in $amsiBypassPatterns) {
                            if ($content -match $pattern) {
                                $matchedPatterns += $pattern
                            }
                        }
                        
                        if ($matchedPatterns.Count -gt 0) {
                            $foundSuspiciousScripts = $true
                            $results += "Potential AMSI bypass found in script: $($file.FullName)"
                            $results += "  - Matched patterns: $($matchedPatterns -join ', ')"
                            
                            # Extract a small context around the match
                            foreach ($pattern in $matchedPatterns) {
                                if ($content -match "(?m)^.*$pattern.*$") {
                                    $results += "  - Context: $($Matches[0])"
                                }
                            }
                            $results += ""
                        }
                    } catch {
                        continue
                    }
                }
            }
        }
        
        if (-not $foundSuspiciousScripts) {
            $results += "No scripts with AMSI bypass patterns found in common locations."
            $results += ""
        }
        
        # Check PowerShell event logs for AMSI bypass attempts
        $results += "=== CHECKING POWERSHELL LOGS FOR AMSI BYPASS ATTEMPTS ==="
        try {
            $amsiBypassEvidence = $false
            $psLogs = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-PowerShell/Operational'
                Id = 4104  # Script block logging
                StartTime = (Get-Date).AddDays(-30)
            } -ErrorAction SilentlyContinue | Where-Object {
                $_.Message -match ($amsiBypassPatterns -join "|")
            } | Select-Object TimeCreated, Id, Message
            
            if ($psLogs -and $psLogs.Count -gt 0) {
                $amsiBypassEvidence = $true
                $results += "Found $($psLogs.Count) PowerShell event log entries with potential AMSI bypass patterns:"
                foreach ($log in $psLogs | Select-Object -First 5) {
                    $results += "  - Time: $($log.TimeCreated)"
                    $results += "  - Event ID: $($log.Id)"
                    
                    # Extract a snippet of the message, focusing on the relevant part
                    $relevantPart = $log.Message
                    foreach ($pattern in $amsiBypassPatterns) {
                        if ($log.Message -match "(?s).{0,100}$pattern.{0,100}") {
                            $relevantPart = "..." + $Matches[0] + "..."
                            break
                        }
                    }
                    
                    $results += "  - Snippet: $relevantPart"
                    $results += ""
                }
            } else {
                $results += "No AMSI bypass attempts found in PowerShell event logs."
                $results += ""
            }
            
            # Check for disabled script block logging
            $psSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
            if ($psSettings -and $psSettings.EnableScriptBlockLogging -eq 0) {
                $amsiBypassEvidence = $true
                $results += "WARNING: PowerShell script block logging is disabled, which could be an anti-forensics technique."
                $results += ""
            }
            
            # Check for disabled AMSI
            $amsiSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\AMSI" -Name "AmsiEnable" -ErrorAction SilentlyContinue
            if ($amsiSettings -and $amsiSettings.AmsiEnable -eq 0) {
                $amsiBypassEvidence = $true
                $results += "WARNING: AMSI is disabled system-wide, which could allow malicious scripts to run undetected."
                $results += ""
            }
            
            if ($amsiBypassEvidence) {
                Write-ForensicLog "Found potential AMSI bypass attempts" -Severity "Warning"
            }
        } catch {
            $results += "Error checking PowerShell logs: $_"
            $results += ""
        }
        
        # Check for suspicious DLL loading in PowerShell processes
        $results += "=== CHECKING FOR SUSPICIOUS DLL LOADING ==="
        try {
            $psProcFound = $false
            $psProcesses = Get-Process -Name powershell* -ErrorAction SilentlyContinue
            
            if ($psProcesses) {
                foreach ($proc in $psProcesses) {
                    $suspiciousModules = $proc.Modules | Where-Object {
                        $_.FileName -notmatch "Windows|Microsoft|system32|SysWOW64" -and
                        $_.FileName -match "\.dll$"
                    }
                    
                    if ($suspiciousModules -and $suspiciousModules.Count -gt 0) {
                        $psProcFound = $true
                        $results += "PowerShell process (ID: $($proc.Id)) has loaded potentially suspicious DLLs:"
                        foreach ($module in $suspiciousModules) {
                            $results += "  - $($module.FileName)"
                        }
                        $results += ""
                    }
                }
            }
            
            if (-not $psProcFound) {
                $results += "No suspicious DLLs found loaded in PowerShell processes."
                $results += ""
            }
        } catch {
            $results += "Error checking PowerShell processes: $_"
            $results += ""
        }
        
        # Save results
        $results | Out-File -FilePath $outputFile
        
        # Check if we found any evidence of AMSI bypass
        $amsiBypassFound = $amsiRegistryModified -or $foundSuspiciousScripts -or $amsiBypassEvidence -or $psProcFound
        
        if ($amsiBypassFound) {
            Write-ForensicLog "WARNING: Found potential AMSI bypass attempts" -Severity "Warning"
        } else {
            Write-ForensicLog "No AMSI bypass attempts detected."
        }
        
        Write-ForensicLog "AMSI bypass check results saved to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error checking for AMSI bypass attempts: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Find-AMSIBypassAttempts
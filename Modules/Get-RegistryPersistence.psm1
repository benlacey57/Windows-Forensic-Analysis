<#
.SYNOPSIS
    Identifies registry persistence mechanisms
    
.DESCRIPTION
    Analyzes registry locations commonly used for persistence by malware and attackers.
    Identifies suspicious entries that could indicate persistence mechanisms and
    auto-start programs that launch during system boot or user logon.
    
.EXAMPLE
    $registryPersistenceFile = Get-RegistryPersistence
    
.OUTPUTS
    String. The path to the CSV file containing suspicious registry entries
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for complete registry access
#>

function Get-RegistryPersistence {
    param()
    
    $outputFile = "$script:outputDir\RegistryPersistence_$script:timestamp.csv"
    Write-ForensicLog "Checking registry for persistence mechanisms..."
    
    try {
        $persistenceLocations = @(
            # Run keys
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            
            # Services
            "HKLM:\SYSTEM\CurrentControlSet\Services",
            
            # Winlogon
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
            "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            
            # Explorer
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects",
            
            # AppInit DLLs
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
            
            # BootExecute
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager",
            
            # Startup folder references
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            
            # Image File Execution Options (for debugger hijacking)
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            
            # Terminal Services AutoRun
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            
            # ActiveSetup
            "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components",
            
            # Print Monitors
            "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors",
            
            # Winsock Providers
            "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries",
            "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries"
        )
        
        $results = @()
        
        foreach ($location in $persistenceLocations) {
            if (Test-Path $location) {
                # Handle special cases
                if ($location -like "*\Services") {
                    # For services, look for non-standard service binaries
                    Get-ChildItem -Path $location | ForEach-Object {
                        $service = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                        
                        # Skip services without an ImagePath
                        if (-not $service.ImagePath) {
                            return
                        }
                        
                        # Check if suspicious
                        $isSuspicious = $false
                        $suspiciousReasons = @()
                        
                        # Check for services with unusual paths
                        if ($service.ImagePath -notmatch "system32|syswow64" -and 
                            $service.ImagePath -notmatch "Program Files" -and
                            $service.ImagePath -notmatch "Windows\\") {
                            $isSuspicious = $true
                            $suspiciousReasons += "Non-standard service path"
                        }
                        
                        # Check for services using scripts or suspicious programs
                        if ($service.ImagePath -match "powershell|cmd|wscript|cscript|rundll32|regsvr32|mshta") {
                            $isSuspicious = $true
                            $suspiciousReasons += "Service uses script interpreter or suspicious program"
                        }
                        
                        # Check for services with temporary or user profile paths
                        if ($service.ImagePath -match "\\Temp\\|\\AppData\\|%Temp%|%AppData%") {
                            $isSuspicious = $true
                            $suspiciousReasons += "Service executable in temporary or user profile directory"
                        }
                        
                        # Check for services with suspicious command-line arguments
                        if ($service.ImagePath -match "-encod|-enc |/enc |/e |-w hidden|-windowstyle h|downloadstring|iex |invoke-expr|bypass") {
                            $isSuspicious = $true
                            $suspiciousReasons += "Suspicious command-line arguments"
                        }
                        
                        $results += [PSCustomObject]@{
                            RegistryPath = $_.PSPath
                            ItemName = $_.PSChildName
                            Value = $service.ImagePath
                            Type = "Service"
                            Suspicious = $isSuspicious
                            SuspiciousReasons = ($suspiciousReasons -join "; ")
                        }
                    }
                } 
                elseif ($location -like "*\Image File Execution Options") {
                    # Look for debugger hijacking
                    Get-ChildItem -Path $location | ForEach-Object {
                        $debugger = Get-ItemProperty -Path $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
                        if ($debugger -and $debugger.Debugger) {
                            $isSuspicious = $true
                            $suspiciousReasons = @("Debugger hijacking")
                            
                            # Check for suspicious debugger commands
                            if ($debugger.Debugger -match "powershell|cmd|wscript|cscript|rundll32|regsvr32|mshta") {
                                $suspiciousReasons += "Uses script interpreter or suspicious program"
                            }
                            
                            $results += [PSCustomObject]@{
                                RegistryPath = $_.PSPath
                                ItemName = $_.PSChildName
                                Value = $debugger.Debugger
                                Type = "Debugger"
                                Suspicious = $isSuspicious
                                SuspiciousReasons = ($suspiciousReasons -join "; ")
                            }
                        }
                    }
                }
                elseif ($location -like "*\Winlogon") {
                    # Look for Winlogon registry entries
                    $values = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
                    if ($values) {
                        $interestingProps = @("Shell", "Userinit", "Taskman", "System", "VmApplet", "PowerShell", "Logon", "AppSetup", "GinaDLL", "LsaStart")
                        
                        foreach ($prop in $interestingProps) {
                            if ($values.PSObject.Properties.Name -contains $prop) {
                                $value = $values.$prop
                                $isSuspicious = $false
                                $suspiciousReasons = @()
                                
                                # Check if this is a standard value
                                switch ($prop) {
                                    "Shell" {
                                        if ($value -ne "explorer.exe") {
                                            $isSuspicious = $true
                                            $suspiciousReasons += "Non-standard shell"
                                        }
                                    }
                                    "Userinit" {
                                        if ($value -ne "C:\Windows\system32\userinit.exe," -and $value -ne "userinit.exe,") {
                                            $isSuspicious = $true
                                            $suspiciousReasons += "Non-standard Userinit"
                                        }
                                    }
                                    default {
                                        # For other properties, just flag them as potentially interesting
                                        $isSuspicious = $true
                                        $suspiciousReasons += "Uncommon Winlogon entry"
                                    }
                                }
                                
                                # Check for suspicious values
                                if ($value -match "powershell|cmd|wscript|cscript|rundll32|regsvr32|mshta") {
                                    $isSuspicious = $true
                                    $suspiciousReasons += "Uses script interpreter or suspicious program"
                                }
                                
                                if ($value -match "\\Temp\\|\\AppData\\|%Temp%|%AppData%") {
                                    $isSuspicious = $true
                                    $suspiciousReasons += "References temporary or user profile directory"
                                }
                                
                                $results += [PSCustomObject]@{
                                    RegistryPath = $location
                                    ItemName = $prop
                                    Value = $value
                                    Type = "Winlogon"
                                    Suspicious = $isSuspicious
                                    SuspiciousReasons = ($suspiciousReasons -join "; ")
                                }
                            }
                        }
                    }
                }
                elseif ($location -like "*\Session Manager") {
                    # Look for BootExecute entries
                    $sessionManager = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
                    if ($sessionManager -and $sessionManager.BootExecute) {
                        $isSuspicious = $false
                        $suspiciousReasons = @()
                        
                        # Standard value is "autocheck autochk *"
                        if ($sessionManager.BootExecute -ne "autocheck autochk *") {
                            $isSuspicious = $true
                            $suspiciousReasons += "Non-standard BootExecute value"
                        }
                        
                        $results += [PSCustomObject]@{
                            RegistryPath = $location
                            ItemName = "BootExecute"
                            Value = $sessionManager.BootExecute
                            Type = "SessionManager"
                            Suspicious = $isSuspicious
                            SuspiciousReasons = ($suspiciousReasons -join "; ")
                        }
                    }
                    
                    # Check for AppCertDlls
                    if ($sessionManager -and $sessionManager.AppCertDlls) {
                        $results += [PSCustomObject]@{
                            RegistryPath = $location
                            ItemName = "AppCertDlls"
                            Value = $sessionManager.AppCertDlls
                            Type = "SessionManager"
                            Suspicious = $true
                            SuspiciousReasons = "AppCertDlls specified (potential DLL hijacking)"
                        }
                    }
                }
                elseif ($location -like "*\Windows") {
                    # Check for AppInit_DLLs
                    $windowsSettings = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
                    if ($windowsSettings -and $windowsSettings.AppInit_DLLs -and $windowsSettings.AppInit_DLLs.Trim() -ne "") {
                        $results += [PSCustomObject]@{
                            RegistryPath = $location
                            ItemName = "AppInit_DLLs"
                            Value = $windowsSettings.AppInit_DLLs
                            Type = "AppInitDlls"
                            Suspicious = $true
                            SuspiciousReasons = "AppInit_DLLs specified (potential DLL hijacking)"
                        }
                    }
                    
                    # Check if LoadAppInit_DLLs is enabled
                    if ($windowsSettings -and $windowsSettings.LoadAppInit_DLLs -eq 1) {
                        $results += [PSCustomObject]@{
                            RegistryPath = $location
                            ItemName = "LoadAppInit_DLLs"
                            Value = $windowsSettings.LoadAppInit_DLLs
                            Type = "AppInitDlls"
                            Suspicious = $true
                            SuspiciousReasons = "AppInit_DLLs loading is enabled"
                        }
                    }
                }
                # For Run keys and other locations, get all values
                else {
                    $values = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
                    if ($values) {
                        foreach ($prop in ($values.PSObject.Properties | Where-Object { $_.Name -notmatch "^(PS|vm)" })) {
                            # Check if the value is suspicious
                            $isSuspicious = $false
                            $suspiciousReasons = @()
                            
                            # Skip system properties that aren't values
                            if ($prop.Name -in @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                                continue
                            }
                            
                            if ($prop.Value -match "powershell|cmd|wscript|cscript|rundll32|regsvr32|mshta") {
                                $isSuspicious = $true
                                $suspiciousReasons += "Uses script interpreter or suspicious program"
                            }
                            
                            if ($prop.Value -match "\\Temp\\|\\AppData\\|%Temp%|%AppData%") {
                                $isSuspicious = $true
                                $suspiciousReasons += "References temporary or user profile directory"
                            }
                            
                            if ($prop.Value -match "-encod|-enc |/enc |/e |-w hidden|-windowstyle h|downloadstring|iex |invoke-expr|bypass") {
                                $isSuspicious = $true
                                $suspiciousReasons += "Suspicious command-line arguments"
                            }
                            
                            # Determine the type based on the registry path
                            $type = "Other"
                            if ($location -match "Run[^\\]*$") {
                                $type = "Run"
                            } elseif ($location -match "Browser Helper Objects") {
                                $type = "BrowserHelperObject"
                            } elseif ($location -match "ShellIcon|ShellService|ShellExecute") {
                                $type = "ShellExtension"
                            }
                            
                            $results += [PSCustomObject]@{
                                RegistryPath = $location
                                ItemName = $prop.Name
                                Value = $prop.Value
                                Type = $type
                                Suspicious = $isSuspicious
                                SuspiciousReasons = ($suspiciousReasons -join "; ")
                            }
                        }
                    }
                }
            }
        }
        
        # Export results to CSV
        if ($results.Count -gt 0) {
            $results | Export-Csv -Path $outputFile -NoTypeInformation
            
            # Log suspicious entries
            $suspiciousEntries = $results | Where-Object { $_.Suspicious -eq $true }
            if ($suspiciousEntries.Count -gt 0) {
                Write-ForensicLog "Found $($suspiciousEntries.Count) suspicious registry persistence entries:" -Severity "Warning"
                foreach ($entry in $suspiciousEntries | Sort-Object { [int]($_.SuspiciousReasons.Split(';').Count) } -Descending | Select-Object -First 10) {
                    Write-ForensicLog "  - [$($entry.Type)] $($entry.RegistryPath) -> $($entry.ItemName): $($entry.Value) - $($entry.SuspiciousReasons)" -Severity "Warning"
                }
            } else {
                Write-ForensicLog "No suspicious registry persistence entries found."
            }
        } else {
            Write-ForensicLog "No registry persistence entries fo
<#
.SYNOPSIS
    Collects PowerShell command history for all users on the system.
    
.DESCRIPTION
    Get-PowerShellHistory retrieves command history from PowerShell history files for
    all user profiles on the system. It identifies potentially suspicious commands and
    provides insights into user activity that might be relevant during forensic analysis.
    
.PARAMETER HistoryLimit
    Specifies the maximum number of history entries to retrieve per user.
    Default is 100.
    
.EXAMPLE
    $psHistoryFile = Get-PowerShellHistory -HistoryLimit 200
    
.OUTPUTS
    String. The path to the CSV file containing PowerShell history data
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges to access other user profiles
#>

function Get-PowerShellHistory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$HistoryLimit = 100
    )

    $outputFile = "$script:outputDir\PowerShellHistory_$script:timestamp.csv"
    Write-ForensicLog "Collecting PowerShell command history (last $HistoryLimit commands per user)..."

    try {
        # Initialize findings collection
        $historyEntries = @()
        
        # Get all user profiles
        $userProfiles = Get-ChildItem -Path "C:\Users" -Directory | 
                       Where-Object { $_.Name -ne "Public" -and $_.Name -ne "Default" -and $_.Name -ne "Default User" }
        
        foreach ($userProfile in $userProfiles) {
            $username = $userProfile.Name
            Write-ForensicLog "Checking PowerShell history for user: $username"
            
            # Check all possible PowerShell history file locations
            $historyResults = @()
            $historyResults += Get-PSReadLineHistory -UserProfile $userProfile -Username $username
            $historyResults += Get-ConsoleHostHistory -UserProfile $userProfile -Username $username
            
            if ($historyResults.Count -gt 0) {
                Write-ForensicLog "Found $($historyResults.Count) PowerShell history entries for user $username"
                $historyEntries += $historyResults | Select-Object -First $HistoryLimit
            }
            else {
                Write-ForensicLog "No PowerShell history found for user $username"
            }
        }
        
        # Export results
        if ($historyEntries.Count -gt 0) {
            # Sort by timestamp (most recent first)
            $sortedEntries = $historyEntries | Sort-Object -Property Timestamp -Descending
            $sortedEntries | Export-Csv -Path $outputFile -NoTypeInformation
            
            # Log suspicious commands
            $suspiciousEntries = $sortedEntries | Where-Object { $_.SuspiciousScore -gt 0 }
            if ($suspiciousEntries.Count -gt 0) {
                Write-ForensicLog "Found $($suspiciousEntries.Count) potentially suspicious PowerShell commands:" -Severity "Warning"
                foreach ($entry in ($suspiciousEntries | Select-Object -First 5)) {
                    Write-ForensicLog "  - [$($entry.Username)] $($entry.Command.Substring(0, [Math]::Min(100, $entry.Command.Length)))..." -Severity "Warning"
                }
            }
            
            Write-ForensicLog "Saved PowerShell history data to $outputFile"
        } else {
            Write-ForensicLog "No PowerShell history found on the system"
            # Create an empty file to indicate analysis was performed
            [PSCustomObject]@{
                Result = "No PowerShell history found"
                AnalysisTime = Get-Date
                SystemName = $env:COMPUTERNAME
            } | Export-Csv -Path $outputFile -NoTypeInformation
        }
        
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error collecting PowerShell history: $_" -Severity "Error"
        return $null
    }
}

function Get-PSReadLineHistory {
    param (
        [System.IO.DirectoryInfo]$UserProfile,
        [string]$Username
    )
    
    $historyEntries = @()
    
    try {
        # PSReadLine history file locations (in order of preference)
        $psReadLineHistoryPaths = @(
            # PowerShell 7.x and newer (.NET Core)
            Join-Path -Path $UserProfile.FullName -ChildPath "AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt",
            # PowerShell 5.x (Windows PowerShell)
            Join-Path -Path $UserProfile.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        )
        
        foreach ($historyPath in $psReadLineHistoryPaths) {
            if (Test-Path $historyPath) {
                $historyContent = Get-Content -Path $historyPath -ErrorAction SilentlyContinue
                
                if ($historyContent) {
                    $entryCount = 0
                    $fileLastModified = (Get-Item $historyPath).LastWriteTime
                    
                    foreach ($command in $historyContent) {
                        $entryCount++
                        
                        # Skip empty lines
                        if ([string]::IsNullOrWhiteSpace($command)) {
                            continue
                        }
                        
                        # Calculate approximate timestamp (not exact)
                        # Newer entries are at the end of the file
                        $approximateTimestamp = $fileLastModified.AddMinutes(-($historyContent.Count - $entryCount))
                        
                        # Calculate suspiciousness score
                        $suspiciousData = Get-CommandSuspiciousness -Command $command
                        
                        $historyEntries += [PSCustomObject]@{
                            Username = $Username
                            Source = "PSReadLine"
                            HistoryFile = $historyPath
                            Command = $command
                            Timestamp = $approximateTimestamp
                            SuspiciousScore = $suspiciousData.Score
                            SuspiciousReason = $suspiciousData.Reason
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error reading PSReadLine history for user $Username: $_" -Severity "Warning"
    }
    
    return $historyEntries
}

function Get-ConsoleHostHistory {
    param (
        [System.IO.DirectoryInfo]$UserProfile,
        [string]$Username
    )
    
    $historyEntries = @()
    
    try {
        # Older PowerShell versions store history in registry
        # Create a temporary registry drive for the user's NTUSER.DAT
        $ntUserPath = Join-Path -Path $UserProfile.FullName -ChildPath "NTUSER.DAT"
        
        if (Test-Path $ntUserPath) {
            # Mount the registry hive
            $tempHiveName = "TempHive_$([Guid]::NewGuid().ToString('N'))"
            $null = reg load "HKU\$tempHiveName" $ntUserPath 2>$null
            
            if ($?) {
                try {
                    # Create a PSDrive for easier access
                    $null = New-PSDrive -Name "HKUTemp" -PSProvider Registry -Root "HKEY_USERS\$tempHiveName" -ErrorAction Stop
                    
                    # Check for PowerShell history in registry
                    $historyPath = "HKUTemp:\Software\Microsoft\Windows\CurrentVersion\PowerShell\1\ConsoleHost\History"
                    
                    if (Test-Path $historyPath) {
                        # Get history properties
                        $historyProps = Get-ItemProperty -Path $historyPath -ErrorAction SilentlyContinue
                        
                        if ($historyProps -and $historyProps.Count -gt 0) {
                            $commandCount = $historyProps.Count
                            
                            # Loop through history entries
                            for ($i = 1; $i -le $commandCount; $i++) {
                                $commandProp = "Command$i"
                                
                                if ($historyProps.$commandProp) {
                                    $command = $historyProps.$commandProp
                                    
                                    # Calculate suspiciousness score
                                    $suspiciousData = Get-CommandSuspiciousness -Command $command
                                    
                                    $historyEntries += [PSCustomObject]@{
                                        Username = $Username
                                        Source = "ConsoleHost"
                                        HistoryFile = "Registry"
                                        Command = $command
                                        Timestamp = $null  # Registry doesn't store timestamps
                                        SuspiciousScore = $suspiciousData.Score
                                        SuspiciousReason = $suspiciousData.Reason
                                    }
                                }
                            }
                        }
                    }
                    
                    # Remove the PSDrive
                    if (Get-PSDrive -Name HKUTemp -ErrorAction SilentlyContinue) {
                        Remove-PSDrive -Name HKUTemp -Force
                    }
                }
                catch {
                    Write-ForensicLog "Error accessing registry history for user $Username: $_" -Severity "Warning"
                }
                finally {
                    # Always unload the hive
                    [gc]::Collect()  # Force garbage collection to release file handles
                    $null = reg unload "HKU\$tempHiveName" 2>$null
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error reading ConsoleHost history for user $Username: $_" -Severity "Warning"
    }
    
    return $historyEntries
}

function Get-CommandSuspiciousness {
    param (
        [string]$Command
    )
    
    $suspiciousScore = 0
    $suspiciousReasons = @()
    
    # Suspicious command patterns
    $suspiciousPatterns = @{
        # Encoded commands (potential obfuscation)
        "encodedcommand|enc\s+-|encod" = "Encoded PowerShell command"
        
        # Command execution and downloads
        "invoke-webrequest|iwr\s+|wget|curl|downloadstring|downloadfile" = "Web download"
        "invoke-expression|iex\s+" = "Dynamic code execution"
        
        # Credential access
        "get-credential|convertto-securestring|net\s+user" = "Credential manipulation"
        
        # Process and service manipulation
        "stop-service|stop-process|kill\s+-" = "Process/service termination"
        "start-service|new-service|sc\s+(config|create)" = "Service creation/modification"
        
        # Registry manipulation
        "set-itemproperty|new-itemproperty|remove-item.*hklm:|remove-item.*hkcu:" = "Registry modification"
        
        # System commands
        "set-executionpolicy|bypass|unrestricted" = "Execution policy modification"
        "new-object\s+net.webclient|system.net.webclient" = "Web client creation"
        "bitstransfer|start-bitstransfer" = "BITS file transfer"
        
        # Potential data exfiltration
        "compress-archive|convertto-base64|out-file|set-content" = "File creation/modification"
        
        # System reconnaissance
        "get-process|get-service|get-wmiobject|get-ciminstance|gwmi" = "System enumeration"
        
        # Persistence
        "new-object\s+wscript.shell|scheduledtasks|schtasks|taskschd" = "Scheduled task manipulation"
        "new-object\s+-com|getobject|shellexecute" = "COM object creation"
        
        # Suspicious flags and parameters
        "-nop|-noninteractive|-w\s+hidden|-windowstyle\s+hidden" = "Hidden execution"
        "-executionpolicy\s+bypass|-ep\s+bypass|-exec\s+bypass" = "Execution policy bypass"
        "-noprofile|-noexit" = "PowerShell profile bypass"
    }
    
    # Check for suspicious patterns
    foreach ($pattern in $suspiciousPatterns.Keys) {
        if ($Command -match $pattern) {
            $suspiciousScore += 1
            $suspiciousReasons += $suspiciousPatterns[$pattern]
        }
    }
    
    # Check for direct execution of known hazardous commands
    $hazardousCommands = @(
        "mimikatz", "invoke-mimikatz", "powersploit", "bloodhound", "empire",
        "metasploit", "powerup", "powerview", "invoke-kerberoast", "rubeus",
        "crackmapexec", "psexec", "invoke-dcomexec", "invoke-smbexec", "invoke-wmiexec",
        "nishang", "invoke-thehash", "vssadmin delete", "wevtutil cl", "fsutil usn delete"
    )
    
    foreach ($hazardousCmd in $hazardousCommands) {
        if ($Command -like "*$hazardousCmd*") {
            $suspiciousScore += 3
            $suspiciousReasons += "Known hacking tool or technique: $hazardousCmd"
        }
    }
    
    # Check for download cradles
    if ($Command -match "\$\([^)]+(-join|replace|substring|reverse|base64)") {
        $suspiciousScore += 2
        $suspiciousReasons += "Obfuscated command structure"
    }
    
    # Check for long one-liners (potential obfuscation)
    if ($Command.Length -gt 300 -and $Command.Split(";").Count -gt 3) {
        $suspiciousScore += 1
        $suspiciousReasons += "Complex one-liner (potential obfuscation)"
    }
    
    return @{
        Score = $suspiciousScore
        Reason = ($suspiciousReasons | Select-Object -Unique) -join "; "
    }
}

# Export function
Export-ModuleMember -Function Get-PowerShellHistory
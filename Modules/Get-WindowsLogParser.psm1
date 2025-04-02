<#
.SYNOPSIS
    Collects and analyzes Windows event logs for security events and anomalies.
    
.DESCRIPTION
    Get-WindowsLogParser examines Windows event logs for security-relevant events,
    suspicious patterns, authentication failures, privilege escalations, and other
    indicators of potential security incidents.
    
.EXAMPLE
    $logAnalysisFile = Get-WindowsLogParser
    
.OUTPUTS
    String. The path to the CSV file containing Windows log analysis results
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for complete results
#>

function Get-WindowsLogParser {
    param()

    $outputFile = "$script:outputDir\WindowsLogAnalysis_$script:timestamp.csv"
    Write-ForensicLog "Analyzing Windows event logs for security events..."

    try {
        # Initialize configuration
        $config = Initialize-LogParserConfig
        
        # Collect events from various log sources
        $eventFindings = @()
        
        # Security log - authentication, privilege use, etc.
        $securityEvents = Get-SecurityLogEvents -Config $config
        $eventFindings += $securityEvents
        
        # System log - system changes, service operations, etc.
        $systemEvents = Get-SystemLogEvents -Config $config
        $eventFindings += $systemEvents
        
        # Application log - application crashes, errors, etc.
        $applicationEvents = Get-ApplicationLogEvents -Config $config
        $eventFindings += $applicationEvents
        
        # PowerShell logs - script execution (using imported module)
        if (Get-Command -Name Get-PowerShellLogEvents -ErrorAction SilentlyContinue) {
            Write-ForensicLog "Collecting PowerShell log events using specialized module..."
            $powershellConfig = @{
                EventIDs = $config.PowerShellEvents
                SuspiciousPatterns = @{
                    Suspicious = $config.SuspiciousPatterns.CommandLines
                    Critical = @(
                        "mimikatz", "Invoke-Mimikatz", "Invoke-DLLInjection", 
                        "Invoke-ReflectivePEInjection", "System.Management.Automation.AmsiUtils"
                    )
                    Obfuscation = @(
                        "\$\{.*?\}", "\[[cChHaArR\]]()+\]", "JoIN\s*\(.*?-f"
                    )
                }
            }
            
            $powershellEvents = Get-PowerShellLogEvents -Config $powershellConfig -LookbackDays $config.LookbackDays -MaxEvents $config.MaxEvents
            $eventFindings += $powershellEvents
        } else {
            Write-ForensicLog "PowerShell log module not available, using basic PowerShell log collection" -Severity "Warning"
            # Fallback to built-in basic PowerShell log collection if module not available
            $basicPowershellEvents = Get-BasicPowerShellEvents -Config $config
            $eventFindings += $basicPowershellEvents
        }
        
        # Additional security logs - AppLocker, Defender, etc.
        $additionalEvents = Get-AdditionalSecurityEvents -Config $config
        $eventFindings += $additionalEvents
        
        # Export results
        if ($eventFindings.Count -gt 0) {
            # Sort by timestamp (most recent first)
            $sortedEvents = $eventFindings | Sort-Object -Property TimeGenerated -Descending
            $sortedEvents | Export-Csv -Path $outputFile -NoTypeInformation
            
            # Log summary
            $logSources = $sortedEvents | Group-Object -Property LogSource
            $criticalEvents = ($sortedEvents | Where-Object { $_.Severity -eq "Critical" }).Count
            $warningEvents = ($sortedEvents | Where-Object { $_.Severity -eq "Warning" }).Count
            
            Write-ForensicLog "Found $($sortedEvents.Count) significant events in Windows logs: $criticalEvents critical, $warningEvents warning"
            
            # Log most critical events
            if ($criticalEvents -gt 0) {
                Write-ForensicLog "Critical security events detected:" -Severity "Warning"
                foreach ($event in ($sortedEvents | Where-Object { $_.Severity -eq "Critical" } | Select-Object -First 5)) {
                    Write-ForensicLog "  - $($event.TimeGenerated) | $($event.LogSource) | $($event.EventID): $($event.EventSummary)" -Severity "Warning"
                }
            }
        } else {
            Write-ForensicLog "No significant events found in Windows logs"
            # Create an empty file to indicate analysis was performed
            [PSCustomObject]@{
                Result = "No significant events found in Windows logs"
                AnalysisTime = Get-Date
                SystemName = $env:COMPUTERNAME
            } | Export-Csv -Path $outputFile -NoTypeInformation
        }
        
        Write-ForensicLog "Saved Windows log analysis to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error analyzing Windows logs: $_" -Severity "Error"
        return $null
    }
}

# Basic PowerShell log collection function to use as fallback if module not available
function Get-BasicPowerShellEvents {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    $events = @()
    $psEventMap = $Config.PowerShellEvents
    $lookbackTime = (Get-Date).AddDays(-$Config.LookbackDays)
    
    try {
        # PowerShell script block logging events
        $psEvents = @()
        
        # Try to access PowerShell operational log
        $psEvents += Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-PowerShell/Operational'
            ID = $psEventMap.ScriptBlockLogging
            StartTime = $lookbackTime
        } -MaxEvents $Config.MaxEvents -ErrorAction SilentlyContinue
        
        foreach ($event in $psEvents) {
            try {
                $eventXML = [xml]$event.ToXml()
                $scriptBlock = $eventXML.Event.EventData.Data.'#text'
                
                # Determine severity based on script content
                $severity = "Information"
                $patternMatched = ""
                
                # Check for suspicious script patterns
                foreach ($pattern in $Config.SuspiciousPatterns.CommandLines) {
                    if ($scriptBlock -match $pattern) {
                        $severity = "Warning"
                        $patternMatched = "Suspicious PowerShell command: $pattern"
                        break
                    }
                }
                
                # Get a summary of the script (first few characters)
                $scriptSummary = $scriptBlock.Substring(0, [Math]::Min(100, $scriptBlock.Length))
                
                $events += [PSCustomObject]@{
                    TimeGenerated = $event.TimeCreated
                    LogSource = "PowerShell"
                    EventID = $event.Id
                    EventType = "PowerShell Script Execution"
                    EventSummary = "PowerShell script executed: $scriptSummary..."
                    EventDetails = $scriptBlock.Substring(0, [Math]::Min(200, $scriptBlock.Length))
                    UserName = $event.UserId
                    MachineName = $event.MachineName
                    RelatedObjectName = "PowerShell.exe"
                    Severity = $severity
                    PatternMatched = $patternMatched
                }
            }
            catch {
                # Continue to next event if there's an error parsing this one
                continue
            }
        }
    }
    catch {
        Write-ForensicLog "Error retrieving PowerShell log events: $_" -Severity "Warning"
    }
    
    return $events
}

function Initialize-LogParserConfig {
    # Create configuration object to avoid hardcoding throughout the module
    return @{
        # How far back to look for events (days)
        LookbackDays = 30
        
        # Maximum events to retrieve per log (to prevent performance issues)
        MaxEvents = 5000
        
        # Event ID mappings for quick reference
        SecurityEvents = @{
            # Authentication events
            SuccessfulLogon = @(4624)
            FailedLogon = @(4625)
            LogonWithExplicitCredentials = @(4648)
            LogoffEvents = @(4634, 4647)
            AccountLockout = @(4740)
            
            # Account management events
            AccountCreated = @(4720)
            AccountEnabled = @(4722)
            AccountDeleted = @(4726)
            PasswordChanged = @(4724)
            PasswordReset = @(4724)
            GroupMembership = @(4728, 4732, 4756)
            
            # Privilege use events
            SensitivePrivilegeUse = @(4673, 4674)
            UserRightAssigned = @(4704)
            
            # Policy changes
            AuditPolicyChanged = @(4719)
            
            # System events
            SystemStartStop = @(4608, 4609)
            SecurityLogCleared = @(1102)
            
            # Object access
            FileShareAccess = @(5140)
        }
        
        SystemEvents = @{
            ServiceInstalled = @(7045)
            ServiceStartFailure = @(7000, 7038)
            ServiceCrash = @(7022, 7023, 7024, 7031, 7034)
            DeviceInstalled = @(20001, 20003)
            DriverLoaded = @(219)
            SystemTimeChanged = @(1)
            SystemStartup = @(6005, 6009)
            SystemShutdown = @(6006, 6008)
            CrashEvents = @(1001, 1003)
        }
        
        ApplicationEvents = @{
            ApplicationCrash = @(1000)
            ApplicationHang = @(1002)
            ApplicationError = @(1000)
            ServiceFailure = @(1, 2, 3, 4)
        }
        
        PowerShellEvents = @{
            ScriptBlockLogging = @(4104)
            CommandLineLogging = @(4103)
            ScriptExecution = @(400, 403, 600)
            RemoteSessionCreation = @(53504, 40961, 40962)
        }
        
        # Suspicious event patterns
        SuspiciousPatterns = @{
            CommandLines = @(
                "powershell.exe.*-e", "powershell.exe.*-enc", "powershell.exe.*-nop",
                "certutil.*-urlcache", "bitsadmin.*transfer", "regsvr32.*scrobj",
                "wmic.*/node:", "wmic.*process call create", "cscript.*http:",
                "mshta.*javascript:", "rundll32.*DllRegisterServer"
            )
            
            ProcessNames = @(
                "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe",
                "psexec.exe", "wmic.exe", "net.exe", "net1.exe", "schtasks.exe"
            )
        }
    }
}

function Get-SecurityLogEvents {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    $events = @()
    $securityEventMap = $Config.SecurityEvents
    $lookbackTime = (Get-Date).AddDays(-$Config.LookbackDays)
    
    try {
        # 1. Check authentication events
        $authEvents = @()
        $authEvents += Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = $securityEventMap.FailedLogon
            StartTime = $lookbackTime
        } -MaxEvents $Config.MaxEvents -ErrorAction SilentlyContinue
        
        # Process failed logons
        foreach ($event in $authEvents) {
            try {
                $eventXML = [xml]$event.ToXml()
                $eventData = $eventXML.Event.EventData.Data
                
                # Extract relevant fields
                $targetUser = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                $logonType = ($eventData | Where-Object { $_.Name -eq 'LogonType' }).'#text'
                $ipAddress = ($eventData | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                $status = ($eventData | Where-Object { $_.Name -eq 'Status' }).'#text'
                $failureReason = ($eventData | Where-Object { $_.Name -eq 'SubStatus' }).'#text'
                
                # Determine logon type description
                $logonTypeDesc = Get-LogonTypeDescription -LogonType $logonType
                
                # Determine severity based on patterns
                $severity = "Information"
                $patternMatched = ""
                
                # Multiple failed logons for the same account is suspicious
                $failedLogonCount = ($authEvents | Where-Object { 
                    $eventXml = [xml]$_.ToXml()
                    $targetUserName = ($eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                    $targetUserName -eq $targetUser
                }).Count
                
                if ($failedLogonCount -ge 5) {
                    $severity = "Warning"
                    $patternMatched = "Multiple failed logons: $failedLogonCount attempts"
                    
                    if ($failedLogonCount -ge 10) {
                        $severity = "Critical"
                    }
                }
                
                # Remote logon failures for administrator accounts are more suspicious
                if ($logonType -in @(3, 8, 10) -and $targetUser -match "admin|administrator") {
                    $severity = "Critical"
                    $patternMatched = "Failed remote logon to privileged account"
                }
                
                # Add to findings
                $events += [PSCustomObject]@{
                    TimeGenerated = $event.TimeCreated
                    LogSource = "Security"
                    EventID = $event.Id
                    EventType = "Failed Authentication"
                    EventSummary = "Failed logon attempt for user $targetUser ($logonTypeDesc) from $ipAddress - Status: $status"
                    EventDetails = "Failure reason: $failureReason"
                    UserName = $targetUser
                    MachineName = $event.MachineName
                    RelatedObjectName = $ipAddress
                    Severity = $severity
                    PatternMatched = $patternMatched
                }
            }
            catch {
                # Continue to next event if there's an error parsing this one
                continue
            }
        }
        
        # 2. Check account management events
        $accountEvents = @()
        $accountEvents += Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = $securityEventMap.AccountCreated + $securityEventMap.AccountDeleted + $securityEventMap.GroupMembership
            StartTime = $lookbackTime
        } -MaxEvents $Config.MaxEvents -ErrorAction SilentlyContinue
        
        # Process account changes
        foreach ($event in $accountEvents) {
            try {
                $eventXML = [xml]$event.ToXml()
                $eventData = $eventXML.Event.EventData.Data
                
                # Extract relevant fields
                $targetUser = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                $subjectUser = ($eventData | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
                
                # Get event type description
                $eventTypeDesc = switch ($event.Id) {
                    4720 { "User Account Created" }
                    4726 { "User Account Deleted" }
                    4728 { "User Added to Security-Enabled Global Group" }
                    4732 { "User Added to Security-Enabled Local Group" }
                    4756 { "User Added to Security-Enabled Universal Group" }
                    default { "Account Management" }
                }
                
                # Determine severity based on patterns
                $severity = "Information"
                $patternMatched = ""
                
                # Check for privileged group additions
                if ($event.Id -in @(4728, 4732, 4756)) {
                    $groupName = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                    $memberName = ($eventData | Where-Object { $_.Name -eq 'MemberName' }).'#text'
                    
                    # Check if this is a privileged group
                    if ($groupName -match "Admin|Domain Admins|Enterprise Admins|Schema Admins|Administrators|Remote Desktop Users") {
                        $severity = "Warning"
                        $patternMatched = "User added to privileged group"
                        
                        # Non-admin accounts adding members to admin groups is highly suspicious
                        if ($subjectUser -notmatch "admin|administrator") {
                            $severity = "Critical"
                            $patternMatched = "Non-admin user adding member to privileged group"
                        }
                    }
                }
                
                # Account creation by non-admin is suspicious
                if ($event.Id -eq 4720 -and $subjectUser -notmatch "admin|administrator") {
                    $severity = "Warning"
                    $patternMatched = "Account creation by non-admin user"
                }
                
                # Account creation outside business hours
                $hour = $event.TimeCreated.Hour
                if ($event.Id -eq 4720 -and ($hour -lt 8 -or $hour -gt 18)) {
                    if ($severity -ne "Warning") {
                        $severity = "Warning"
                        $patternMatched = "Account created outside business hours"
                    }
                }
                
                # Add to findings
                $events += [PSCustomObject]@{
                    TimeGenerated = $event.TimeCreated
                    LogSource = "Security"
                    EventID = $event.Id
                    EventType = $eventTypeDesc
                    EventSummary = "$eventTypeDesc - Target: $targetUser, Actor: $subjectUser"
                    EventDetails = $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
                    UserName = $subjectUser
                    MachineName = $event.MachineName
                    RelatedObjectName = $targetUser
                    Severity = $severity
                    PatternMatched = $patternMatched
                }
            }
            catch {
                # Continue to next event if there's an error parsing this one
                continue
            }
        }
        
        # 3. Check for security log cleared events (potential covering of tracks)
        $logClearedEvents = @()
        $logClearedEvents += Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = $securityEventMap.SecurityLogCleared
            StartTime = $lookbackTime
        } -MaxEvents $Config.MaxEvents -ErrorAction SilentlyContinue
        
        foreach ($event in $logClearedEvents) {
            try {
                $eventXML = [xml]$event.ToXml()
                $eventData = $eventXML.Event.EventData.Data
                
                # Extract subject info if available
                $subjectUser = "Unknown"
                $subjectUserData = $eventData | Where-Object { $_.Name -eq 'SubjectUserName' }
                if ($subjectUserData) {
                    $subjectUser = $subjectUserData.'#text'
                }
                
                # Add to findings - log clearing is always suspicious
                $events += [PSCustomObject]@{
                    TimeGenerated = $event.TimeCreated
                    LogSource = "Security"
                    EventID = $event.Id
                    EventType = "Security Log Cleared"
                    EventSummary = "Security log was cleared by $subjectUser"
                    EventDetails = "Potential attempt to cover tracks by clearing security logs"
                    UserName = $subjectUser
                    MachineName = $event.MachineName
                    RelatedObjectName = "Security Log"
                    Severity = "Critical"
                    PatternMatched = "Security log cleared event"
                }
            }
            catch {
                # Continue to next event if there's an error parsing this one
                continue
            }
        }
        
        # 4. Check for privilege use events
        $privilegeEvents = @()
        $privilegeEvents += Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = $securityEventMap.SensitivePrivilegeUse
            StartTime = $lookbackTime
        } -MaxEvents $Config.MaxEvents -ErrorAction SilentlyContinue
        
        foreach ($event in $privilegeEvents) {
            try {
                $eventXML = [xml]$event.ToXml()
                $eventData = $eventXML.Event.EventData.Data
                
                $subjectUser = ($eventData | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
                $privileges = ($eventData | Where-Object { $_.Name -eq 'PrivilegeList' }).'#text'
                $processName = ($eventData | Where-Object { $_.Name -eq 'ProcessName' }).'#text'
                
                # Determine severity based on the privileges used
                $severity = "Information"
                $patternMatched = ""
                
                # Check for sensitive privileges
                $sensitivePrivileges = @(
                    "SeDebugPrivilege", "SeLoadDriverPrivilege", "SeTcbPrivilege", 
                    "SeBackupPrivilege", "SeRestorePrivilege", "SeCreateTokenPrivilege"
                )
                
                foreach ($priv in $sensitivePrivileges) {
                    if ($privileges -match $priv) {
                        $severity = "Warning"
                        $patternMatched = "Sensitive privilege used: $priv"
                        
                        # Check for suspicious processes using these privileges
                        $suspiciousProcesses = $Config.SuspiciousPatterns.ProcessNames
                        foreach ($susProcess in $suspiciousProcesses) {
                            if ($processName -match $susProcess) {
                                $severity = "Critical"
                                $patternMatched = "Suspicious process using sensitive privilege: $susProcess with $priv"
                                break
                            }
                        }
                        
                        break
                    }
                }
                
                $events += [PSCustomObject]@{
                    TimeGenerated = $event.TimeCreated
                    LogSource = "Security"
                    EventID = $event.Id
                    EventType = "Privilege Use"
                    EventSummary = "Privilege use by $subjectUser: $privileges"
                    EventDetails = "Process: $processName"
                    UserName = $subjectUser
                    MachineName = $event.MachineName
                    RelatedObjectName = $processName
                    Severity = $severity
                    PatternMatched = $patternMatched
                }
            }
            catch {
                # Continue to next event if there's an error parsing this one
                continue
            }
        }
    }
    catch {
        Write-ForensicLog "Error retrieving security log events: $_" -Severity "Warning"
    }
    
    return $events
}

function Get-SystemLogEvents {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    $events = @()
    $systemEventMap = $Config.SystemEvents
    $lookbackTime = (Get-Date).AddDays(-$Config.LookbackDays)
    
    try {
        # 1. Service installation events
        $serviceEvents = @()
        $serviceEvents += Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ID = $systemEventMap.ServiceInstalled
            StartTime = $lookbackTime
        } -MaxEvents $Config.MaxEvents -ErrorAction SilentlyContinue
        
        foreach ($event in $serviceEvents) {
            try {
                $eventXML = [xml]$event.ToXml()
                $eventData = $eventXML.Event.EventData.Data
                
                # Extract service information
                $serviceName = $eventData[0].'#text'
                $serviceFile = $eventData[1].'#text'
                $serviceType = $eventData[2].'#text'
                $serviceAccount = $eventData[4].'#text'
                
                # Determine severity based on patterns
                $severity = "Information"
                $patternMatched = ""
                
                # Check for suspicious service paths
                $suspiciousLocations = @(
                    "\\temp\\", "\\temporary internet files\\", "\\downloads\\", 
                    "\\appdata\\", "\\public\\", "\\programdata\\",
                    "\\windows\\temp\\", "\\users\\public\\"
                )
                
                foreach ($location in $suspiciousLocations) {
                    if ($serviceFile -match [regex]::Escape($location)) {
                        $severity = "Warning"
                        $patternMatched = "Service installed from suspicious location: $location"
                        break
                    }
                }
                
                # Check for suspicious service names
                if ($serviceName -match "^[a-zA-Z0-9]{16,}$") {
                    $severity = "Warning"
                    $patternMatched = "Service with unusual random-looking name"
                }
                
                # Services with suspicious command lines
                foreach ($pattern in $Config.SuspiciousPatterns.CommandLines) {
                    if ($serviceFile -match $pattern) {
                        $severity = "Critical"
                        $patternMatched = "Service with suspicious command line pattern: $pattern"
                        break
                    }
                }
                
                # Services with LocalSystem privilege but from non-standard locations
                if ($serviceAccount -eq "LocalSystem" -and -not ($serviceFile -match ":\\Windows\\|:\\Program Files\\")) {
                    if ($severity -ne "Critical") {
                        $severity = "Warning"
                        $patternMatched = "LocalSystem service from non-standard location"
                    }
                }
                
                $events += [PSCustomObject]@{
                    TimeGenerated = $event.TimeCreated
                    LogSource = "System"
                    EventID = $event.Id
                    EventType = "Service Installation"
                    EventSummary = "Service installed: $serviceName"
                    EventDetails = "Path: $serviceFile, Account: $serviceAccount, Type: $serviceType"
                    UserName = $serviceAccount
                    MachineName = $event.MachineName
                    RelatedObjectName = $serviceName
                    Severity = $severity
                    PatternMatched = $patternMatched
                }
            }
            catch {
                # Continue to next event if there's an error parsing this one
                continue
            }
        }
        
        # 2. System crash events
        $crashEvents = @()
        $crashEvents += Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ID = $systemEventMap.CrashEvents
            StartTime = $lookbackTime
        } -MaxEvents $Config.MaxEvents -ErrorAction SilentlyContinue
        
        foreach ($event in $crashEvents) {
            try {
                # Multiple system crashes could indicate system instability or attack
                $crashCount = ($crashEvents | Where-Object { 
                    $_.TimeCreated -gt (Get-Date).AddDays(-1)
                }).Count
                
                $severity = "Warning"
                $patternMatched = ""
                
                if ($crashCount -ge 3) {
                    $severity = "Critical"
                    $patternMatched = "Multiple system crashes in 24 hours: $crashCount"
                }
                
                $events += [PSCustomObject]@{
                    TimeGenerated = $event.TimeCreated
                    LogSource = "System"
                    EventID = $event.Id
                    EventType = "System Crash"
                    EventSummary = "System crash or unexpected shutdown detected"
                    EventDetails = $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
                    UserName = "SYSTEM"
                    MachineName = $event.MachineName
                    RelatedObjectName = ""
                    Severity = $severity
                    PatternMatched = $patternMatched
                }
            }
            catch {
                # Continue to next event if there's an error parsing this one
                continue
            }
        }
        
        # 3. Driver load events
        $driverEvents = @()
        $driverEvents += Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ID = $systemEventMap.DriverLoaded
            StartTime = $lookbackTime
        } -MaxEvents $Config.MaxEvents -ErrorAction SilentlyContinue
        
        foreach ($event in $driverEvents) {
            try {
                $message = $event.Message
                
                # Try to extract the driver name
                $driverName = "Unknown"
                if ($message -match "driver (\S+)") {
                    $driverName = $matches[1]
                }
                
                # Driver loads are normally routine, but from unusual locations are suspicious
                $severity = "Information"
                $patternMatched = ""
                
                # Check for suspicious driver paths
                $suspiciousLocations = @(
                    "\\temp\\", "\\temporary internet files\\", "\\downloads\\", 
                    "\\appdata\\", "\\public\\", "\\programdata\\",
                    "\\windows\\temp\\", "\\users\\public\\"
                )
                
                foreach ($location in $suspiciousLocations) {
                    if ($message -match [regex]::Escape($location)) {
                        $severity = "Warning"
                        $patternMatched = "Driver loaded from suspicious location: $location"
                        break
                    }
                }
                
                $events += [PSCustomObject]@{
                    TimeGenerated = $event.TimeCreated
                    LogSource = "System"
                    EventID = $event.Id
                    EventType = "Driver Loaded"
                    EventSummary = "Driver loaded: $driverName"
                    EventDetails = $message.Substring(0, [Math]::Min(200, $message.Length))
                    UserName = "SYSTEM"
                    MachineName = $event.MachineName
                    RelatedObjectName = $driverName
                    Severity = $severity
                    PatternMatched = $patternMatched
                }
            }
            catch {
                # Continue to next event if there's an error parsing this one
                continue
            }
        }
    }
    catch {
        Write-ForensicLog "Error retrieving system log events: $_" -Severity "Warning"
    }
    
    return $events
}

function Get-ApplicationLogEvents {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    $events = @()
    $appEventMap = $Config.ApplicationEvents
    $lookbackTime = (Get-Date).AddDays(-$Config.LookbackDays)
    
    try {
        # Application crash events
        $appEvents = @()
        $appEvents += Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            ID = $appEventMap.ApplicationCrash + $appEventMap.ApplicationHang
            StartTime = $lookbackTime
        } -MaxEvents $Config.MaxEvents -ErrorAction SilentlyContinue
        
        foreach ($event in $appEvents) {
            try {
                $message = $event.Message
                
                # Try to extract application name
                $appName = "Unknown"
                if ($message -match "Faulting application name: ([^,]+)") {
                    $appName = $matches[1].Trim()
                }
                
                # Multiple crashes of security software is suspicious
                $severity = "Information"
                $patternMatched = ""
                
                # Check for security-related applications
                $securityApps = @(
                    "MsMpEng.exe", "NisSrv.exe", # Windows Defender
                    "ekrn.exe", "egui.exe",      # ESET
                    "mcshield.exe", "mcafee",    # McAfee
                    "avp.exe", "avpui.exe",      # Kaspersky
                    "bdservicehost.exe",         # BitDefender
                    "avastsvc.exe", "avastui.exe", # Avast
                    "savservice.exe", "sophos"   # Sophos
                )
                
                foreach ($secApp in $securityApps) {
                    if ($appName -match $secApp) {
                        # Count crashes of this security application
                        $securityAppCrashes = ($appEvents | Where-Object { 
                            $_.Message -match "Faulting application name: ([^,]+)" -and
                            $Matches[1].Trim() -match $secApp -and
                            $_.TimeCreated -gt (Get-Date).AddDays(-1)
                        }).Count
                        
                        if ($securityAppCrashes -ge 2) {
                            $severity = "Warning"
                            $patternMatched = "Multiple security application crashes: $securityAppCrashes in 24 hours"
                            
                            if ($securityAppCrashes -ge 5) {
                                $severity = "Critical"
                            }
                        }
                        
                        break
                    }
                }
                
                $events += [PSCustomObject]@{
                    TimeGenerated = $event.TimeCreated
                    LogSource = "Application"
                    EventID = $event.Id
                    EventType = if ($event.Id -eq 1000) { "Application Crash" } else { "Application Hang" }
                    EventSummary = "Application $appName crashed"
                    EventDetails = $message.Substring(0, [Math]::Min(200, $message.Length))
                    UserName = ""
                    MachineName = $event.MachineName
                    RelatedObjectName = $appName
                    Severity = $severity
                    PatternMatched = $patternMatched
                }
            }
            catch {
                # Continue to next event if there's an error parsing this one
                continue
            }
        }
    }
    catch {
        Write-ForensicLog "Error retrieving application log events: $_" -Severity "Warning"
    }
    
    return $events
}

# Export function
Export-ModuleMember -Function Get-WindowsLogParser

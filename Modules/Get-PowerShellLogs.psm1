<#
.SYNOPSIS
    Collects and analyzes PowerShell script execution logs for forensic investigation.
    
.DESCRIPTION
    Get-PowerShellLogEvents collects event logs related to PowerShell script execution,
    identifying suspicious patterns, obfuscation techniques, and potentially malicious
    commands that might indicate security incidents.
    
.EXAMPLE
    $powershellLogData = Get-PowerShellLogEvents
    
.OUTPUTS
    Array of PSCustomObject containing PowerShell log event analysis
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for complete results
#>

function Get-PowerShellLogEvents {
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Config,
        
        [Parameter(Mandatory = $false)]
        [int]$LookbackDays = 30,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxEvents = 5000
    )
    
    $events = @()
    $lookbackTime = (Get-Date).AddDays(-$LookbackDays)
    
    # Use provided config or create a default one
    if (-not $Config) {
        $Config = Initialize-PowerShellLogConfig
    }
    
    try {
        # PowerShell script block logging events
        $psEvents = @()
        $psEventIDs = $Config.EventIDs.ScriptBlockLogging + $Config.EventIDs.CommandLineLogging
        
        # Try to access PowerShell operational log
        $psEvents += Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-PowerShell/Operational'
            ID = $psEventIDs
            StartTime = $lookbackTime
        } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        
        # Also get events from the PowerShell admin log if available
        try {
            $psEvents += Get-WinEvent -FilterHashtable @{
                LogName = 'Windows PowerShell'
                ID = $Config.EventIDs.ScriptExecution
                StartTime = $lookbackTime
            } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        }
        catch {
            # This log might not have any events
        }
        
        # Also check for PowerShell remote session creation
        try {
            $psEvents += Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-PowerShell/Operational'
                ID = $Config.EventIDs.RemoteSessionCreation
                StartTime = $lookbackTime
            } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        }
        catch {
            # This log might not have any events
        }
        
        foreach ($event in $psEvents) {
            try {
                $eventXML = [xml]$event.ToXml()
                
                # Extract script content based on event ID
                $scriptBlock = ""
                $userName = ""
                $eventType = "PowerShell Script Execution"
                
                if ($event.Id -eq 4104) {
                    # Script block logging
                    $scriptBlock = ($eventXML.Event.EventData.Data | Where-Object {$_.Name -eq "ScriptBlockText"}).'#text'
                    if (-not $scriptBlock) {
                        $scriptBlock = $eventXML.Event.EventData.Data[2].'#text'  # Alternate location
                    }
                    $eventType = "PowerShell Script Block"
                    
                    # Extract user info when available
                    try {
                        $userContext = ($eventXML.Event.EventData.Data | Where-Object {$_.Name -eq "UserId"}).'#text'
                        if ($userContext) {
                            $userName = $userContext
                        }
                    }
                    catch {
                        $userName = "Unknown"
                    }
                }
                elseif ($event.Id -eq 4103) {
                    # Command line logging
                    $scriptBlock = ($eventXML.Event.EventData.Data | Where-Object {$_.Name -eq "Payload"}).'#text'
                    $eventType = "PowerShell Command"
                    
                    # Extract user info
                    try {
                        $userContext = ($eventXML.Event.EventData.Data | Where-Object {$_.Name -eq "UserId"}).'#text'
                        if ($userContext) {
                            $userName = $userContext
                        }
                    }
                    catch {
                        $userName = "Unknown"
                    }
                }
                elseif ($event.Id -in @(400, 403, 600)) {
                    # Engine state, pipeline execution or provider events
                    $scriptBlock = $event.Message
                    $eventType = "PowerShell Engine"
                    $userName = "Unknown"
                }
                elseif ($event.Id -in $Config.EventIDs.RemoteSessionCreation) {
                    # Remote session creation
                    $scriptBlock = $event.Message
                    $eventType = "PowerShell Remote Session"
                    $userName = "Unknown"
                }
                
                # If script block is empty, use message text
                if ([string]::IsNullOrEmpty($scriptBlock)) {
                    $scriptBlock = $event.Message
                }
                
                # Analyze script content for suspicious patterns
                $analysis = Analyze-PowerShellScript -ScriptContent $scriptBlock -SuspiciousPatterns $Config.SuspiciousPatterns
                
                # Get a summary of the script (first few characters)
                $scriptSummary = $scriptBlock.Substring(0, [Math]::Min(100, $scriptBlock.Length))
                
                $events += [PSCustomObject]@{
                    TimeGenerated = $event.TimeCreated
                    LogSource = "PowerShell"
                    EventID = $event.Id
                    EventType = $eventType
                    EventSummary = "$eventType: $scriptSummary..."
                    EventDetails = $scriptBlock.Substring(0, [Math]::Min(200, $scriptBlock.Length))
                    UserName = $userName
                    MachineName = $event.MachineName
                    RelatedObjectName = "PowerShell.exe"
                    Severity = $analysis.Severity
                    PatternMatched = $analysis.PatternMatched
                    DetectedPatterns = $analysis.DetectedPatterns
                }
            }
            catch {
                Write-Verbose "Error processing PowerShell event: $_"
                # Continue to next event if there's an error parsing this one
                continue
            }
        }
    }
    catch {
        Write-Warning "Error retrieving PowerShell log events: $_"
    }
    
    return $events
}

function Initialize-PowerShellLogConfig {
    # Create a configuration object with event IDs and suspicious patterns
    return @{
        # Event IDs for different PowerShell logging categories
        EventIDs = @{
            ScriptBlockLogging = @(4104)
            CommandLineLogging = @(4103)
            ScriptExecution = @(400, 403, 600)
            RemoteSessionCreation = @(53504, 40961, 40962)
        }
        
        # Patterns to look for in scripts
        SuspiciousPatterns = @{
            # Command patterns that might indicate malicious activity
            Suspicious = @(
                "IEX", "Invoke-Expression", "New-Object Net.WebClient", "DownloadString", 
                "DownloadFile", "Invoke-WebRequest", "Bypass", "EncodedCommand",
                "FromBase64String", "SecureString", "ConvertTo-SecureString",
                "Hidden", "WindowStyle", "Reflection.Assembly", "LoadLibrary",
                "Start-Process.*-Verb RunAs", "Out-MiniDump", "Add-Type"
            )
            
            # Highly suspicious patterns that likely indicate malicious activity
            Critical = @(
                "mimikatz", "Invoke-Mimikatz", "Invoke-DLLInjection", 
                "Invoke-ReflectivePEInjection", "Invoke-ShellCode",
                "Invoke-WMIMethod.*win32_process.*create", 
                "System.Management.Automation.AmsiUtils", "AmsiScanBuffer",
                "[Reflection.Assembly]::Load", "[Runtime.InteropServices.Marshal]::Copy",
                "VirtualAlloc", "VirtualProtect", "GetDelegateForFunctionPointer"
            )
            
            # Obfuscation techniques
            Obfuscation = @(
                "\$\{.*?\}", "\$env.*?:.*?\(", "\[[cChHaArR\]]()+\]", 
                "JoIN\s*\(.*?-f", "-replace\s+['\""].*?['\""],\s*['\""].*?['\""]]", 
                "\$(?:PSHome|\$PSHOME)(?:\[.*?\])+", "`[^`]*`",
                "\.replace\([\"'].", "\-join\s*['\"]\s*['\""]"
            )
        }
    }
}

function Analyze-PowerShellScript {
    param (
        [string]$ScriptContent,
        [hashtable]$SuspiciousPatterns
    )
    
    $severity = "Information"
    $patternMatched = ""
    $detectedPatterns = @()
    
    # Check for obfuscation techniques first (these make the script suspicious regardless)
    foreach ($pattern in $SuspiciousPatterns.Obfuscation) {
        if ($ScriptContent -match $pattern) {
            $severity = "Warning"
            $patternMatched = "PowerShell obfuscation detected: $pattern"
            $detectedPatterns += "OBFUSCATION: $pattern"
            break
        }
    }
    
    # Check for suspicious command patterns
    foreach ($pattern in $SuspiciousPatterns.Suspicious) {
        if ($ScriptContent -match $pattern) {
            # Only upgrade severity if not already warning or critical
            if ($severity -eq "Information") {
                $severity = "Warning"
                $patternMatched = "Suspicious PowerShell command: $pattern"
            }
            $detectedPatterns += "SUSPICIOUS: $pattern"
        }
    }
    
    # Check for critical patterns
    foreach ($pattern in $SuspiciousPatterns.Critical) {
        if ($ScriptContent -match $pattern) {
            $severity = "Critical"
            $patternMatched = "Potentially malicious PowerShell command: $pattern"
            $detectedPatterns += "CRITICAL: $pattern"
        }
    }
    
    # Calculate suspicion level based on accumulation of different patterns
    if ($detectedPatterns.Count -ge 3 -and $severity -ne "Critical") {
        $severity = "Critical"
        $patternMatched = "Multiple suspicious PowerShell patterns detected"
    }
    
    # Check for base64 encoded scripts
    if ($ScriptContent -match "FromBase64String|encodedcommand|-enc" -and 
        $ScriptContent -match "[A-Za-z0-9+/]{50,}=?=?") {
        $severity = "Warning"
        $patternMatched = "Base64 encoded PowerShell content detected"
        $detectedPatterns += "ENCODING: Base64 encoded content"
    }
    
    return @{
        Severity = $severity
        PatternMatched = $patternMatched
        DetectedPatterns = $detectedPatterns -join "; "
    }
}

# Export function
Export-ModuleMember -Function Get-PowerShellLogEvents


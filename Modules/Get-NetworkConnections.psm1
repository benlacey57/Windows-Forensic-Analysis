<#
.SYNOPSIS
    Collects information about active network connections on the system.
    
.DESCRIPTION
    Get-NetworkConnections provides detailed information about active TCP and UDP
    connections, their associated processes, and remote endpoints. It identifies
    potentially suspicious connections based on destination IP, port, or process
    behavior to help detect unauthorized network activity.
    
.EXAMPLE
    $networkConnectionsFile = Get-NetworkConnections
    
.OUTPUTS
    String. The path to the CSV file containing network connection data
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges recommended for complete results
#>

function Get-NetworkConnections {
    param()

    $outputFile = "$script:outputDir\NetworkConnections_$script:timestamp.csv"
    Write-ForensicLog "Collecting information on active network connections..."

    try {
        # Initialize findings collection
        $connections = @()
        
        # Get TCP connections
        $tcpConnections = Get-TcpConnections
        $connections += $tcpConnections
        
        # Get UDP endpoints
        $udpEndpoints = Get-UdpEndpoints
        $connections += $udpEndpoints
        
        # Get DNS cache entries for hostname resolution
        $dnsCache = Get-DnsResolutionCache
        
        # Enrich connection data with process info and DNS resolution
        $enrichedConnections = Enrich-ConnectionData -Connections $connections -DnsCache $dnsCache
        
        # Score connections for suspiciousness
        $scoredConnections = Score-SuspiciousConnections -Connections $enrichedConnections
        
        # Export results
        if ($scoredConnections.Count -gt 0) {
            # Sort by suspicion score
            $sortedConnections = $scoredConnections | Sort-Object -Property SuspiciousScore -Descending
            $sortedConnections | Export-Csv -Path $outputFile -NoTypeInformation
            
            # Log statistics
            $establishedCount = ($sortedConnections | Where-Object { $_.State -eq "Established" }).Count
            $listeningCount = ($sortedConnections | Where-Object { $_.State -eq "Listen" }).Count
            $suspiciousCount = ($sortedConnections | Where-Object { $_.SuspiciousScore -gt 0 }).Count
            
            Write-ForensicLog "Found $($connections.Count) network connections ($establishedCount established, $listeningCount listening, $($connections.Count - $establishedCount - $listeningCount) other)"
            
            if ($suspiciousCount -gt 0) {
                Write-ForensicLog "Detected $suspiciousCount potentially suspicious network connections:" -Severity "Warning"
                
                # Show top suspicious connections
                $highRiskConnections = $sortedConnections | Where-Object { $_.SuspiciousScore -ge 3 } | Select-Object -First 5
                foreach ($conn in $highRiskConnections) {
                    $connInfo = "$($conn.Protocol) $($conn.LocalAddress):$($conn.LocalPort)"
                    if ($conn.RemoteAddress) {
                        $connInfo += " → $($conn.RemoteAddress):$($conn.RemotePort)"
                    }
                    $connInfo += " ($($conn.ProcessName), PID: $($conn.ProcessId))"
                    
                    Write-ForensicLog "  - $connInfo - $($conn.SuspiciousReason)" -Severity "Warning"
                }
            }
        } else {
            Write-ForensicLog "No active network connections found"
            # Create an empty file to indicate analysis was performed
            [PSCustomObject]@{
                Result = "No active network connections found"
                AnalysisTime = Get-Date
                SystemName = $env:COMPUTERNAME
            } | Export-Csv -Path $outputFile -NoTypeInformation
        }
        
        Write-ForensicLog "Saved network connection data to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error collecting network connections: $_" -Severity "Error"
        return $null
    }
}

function Get-TcpConnections {
    $tcpConnections = @()
    
    try {
        # Get active TCP connections
        $netTcpConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue
        
        if ($netTcpConnections) {
            foreach ($conn in $netTcpConnections) {
                $tcpConnections += [PSCustomObject]@{
                    Protocol = "TCP"
                    LocalAddress = $conn.LocalAddress
                    LocalPort = $conn.LocalPort
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    State = $conn.State
                    ProcessId = $conn.OwningProcess
                    ProcessName = $null  # Will be filled in later
                    CommandLine = $null  # Will be filled in later
                    CreationTime = $conn.CreationTime
                    RemoteHostName = $null  # Will be filled in later
                    SuspiciousScore = 0
                    SuspiciousReason = ""
                }
            }
        } else {
            # Fallback to using netstat if Get-NetTCPConnection not available
            $netstatOutput = netstat -ano | Out-String
            $netstatLines = $netstatOutput -split "`r`n"
            
            # Skip header lines
            $dataLines = $netstatLines | Select-Object -Skip 4
            
            foreach ($line in $dataLines) {
                if ($line -match '^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\S+)\s+(\d+)') {
                    $localParts = $matches[1]
                    $localPort = $matches[2]
                    $remoteParts = $matches[3]
                    $remotePort = $matches[4]
                    $state = $matches[5]
                    $pid = $matches[6]
                    
                    # Parse local address
                    $localAddress = $localParts
                    if ($localAddress -eq "0.0.0.0" -or $localAddress -eq "::") {
                        $localAddress = "*"
                    }
                    
                    # Parse remote address
                    $remoteAddress = $remoteParts
                    if ($remoteAddress -eq "0.0.0.0:0" -or $remoteAddress -eq "[::]:0") {
                        $remoteAddress = "*"
                        $remotePort = 0
                    }
                    
                    $tcpConnections += [PSCustomObject]@{
                        Protocol = "TCP"
                        LocalAddress = $localAddress
                        LocalPort = [int]$localPort
                        RemoteAddress = $remoteAddress
                        RemotePort = [int]$remotePort
                        State = $state
                        ProcessId = [int]$pid
                        ProcessName = $null  # Will be filled in later
                        CommandLine = $null  # Will be filled in later
                        CreationTime = $null  # Not available from netstat
                        RemoteHostName = $null  # Will be filled in later
                        SuspiciousScore = 0
                        SuspiciousReason = ""
                    }
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error collecting TCP connections: $_" -Severity "Warning"
    }
    
    return $tcpConnections
}

function Get-UdpEndpoints {
    $udpEndpoints = @()
    
    try {
        # Get active UDP endpoints
        $netUdpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
        
        if ($netUdpEndpoints) {
            foreach ($endpoint in $netUdpEndpoints) {
                $udpEndpoints += [PSCustomObject]@{
                    Protocol = "UDP"
                    LocalAddress = $endpoint.LocalAddress
                    LocalPort = $endpoint.LocalPort
                    RemoteAddress = "*"  # UDP doesn't have remote endpoints in the same way as TCP
                    RemotePort = 0
                    State = "Bound"  # UDP doesn't have connection states
                    ProcessId = $endpoint.OwningProcess
                    ProcessName = $null  # Will be filled in later
                    CommandLine = $null  # Will be filled in later
                    CreationTime = $endpoint.CreationTime
                    RemoteHostName = $null  # Not applicable for UDP
                    SuspiciousScore = 0
                    SuspiciousReason = ""
                }
            }
        } else {
            # Fallback to using netstat if Get-NetUDPEndpoint not available
            $netstatOutput = netstat -ano | Out-String
            $netstatLines = $netstatOutput -split "`r`n"
            
            # Skip header lines
            $dataLines = $netstatLines | Select-Object -Skip 4
            
            foreach ($line in $dataLines) {
                if ($line -match '^\s*UDP\s+(\S+):(\d+)\s+(\S+)\s+(\d+)') {
                    $localParts = $matches[1]
                    $localPort = $matches[2]
                    $pid = $matches[4]
                    
                    # Parse local address
                    $localAddress = $localParts
                    if ($localAddress -eq "0.0.0.0" -or $localAddress -eq "::") {
                        $localAddress = "*"
                    }
                    
                    $udpEndpoints += [PSCustomObject]@{
                        Protocol = "UDP"
                        LocalAddress = $localAddress
                        LocalPort = [int]$localPort
                        RemoteAddress = "*"
                        RemotePort = 0
                        State = "Bound"
                        ProcessId = [int]$pid
                        ProcessName = $null  # Will be filled in later
                        CommandLine = $null  # Will be filled in later
                        CreationTime = $null  # Not available from netstat
                        RemoteHostName = $null  # Not applicable for UDP
                        SuspiciousScore = 0
                        SuspiciousReason = ""
                    }
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error collecting UDP endpoints: $_" -Severity "Warning"
    }
    
    return $udpEndpoints
}

function Get-DnsResolutionCache {
    $dnsCache = @{}
    
    try {
        # Get DNS client cache
        $dnsClientCache = Get-DnsClientCache -ErrorAction SilentlyContinue
        
        if ($dnsClientCache) {
            foreach ($entry in $dnsClientCache) {
                if ($entry.Data -and $entry.Data -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
                    $dnsCache[$entry.Data] = $entry.Name
                }
            }
        }
        
        # Add localhost entries
        $dnsCache["127.0.0.1"] = "localhost"
        $dnsCache["::1"] = "localhost"
        
        # Add local computer name
        $computerIPs = [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) | ForEach-Object { $_.IPAddressToString }
        foreach ($ip in $computerIPs) {
            $dnsCache[$ip] = $env:COMPUTERNAME
        }
    }
    catch {
        Write-ForensicLog "Error getting DNS cache: $_" -Severity "Warning"
    }
    
    return $dnsCache
}

function Enrich-ConnectionData {
    param (
        [array]$Connections,
        [hashtable]$DnsCache
    )
    
    # Create a hashtable of processes for faster lookup
    $processes = @{}
    
    # Get all running processes
    $runningProcesses = Get-Process -ErrorAction SilentlyContinue
    foreach ($process in $runningProcesses) {
        # Store process details
        $processes[$process.Id] = @{
            Name = $process.Name
            Path = $process.Path
            StartTime = $process.StartTime
            CommandLine = $null
        }
    }
    
    # Get command lines using WMI for better detail
    try {
        $wmiProcesses = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue
        foreach ($wmiProcess in $wmiProcesses) {
            if ($processes.ContainsKey($wmiProcess.ProcessId)) {
                $processes[$wmiProcess.ProcessId].CommandLine = $wmiProcess.CommandLine
            }
        }
    }
    catch {
        Write-ForensicLog "Error getting process command lines: $_" -Severity "Warning"
    }
    
    # Enrich each connection with process and DNS info
    $enrichedConnections = foreach ($conn in $Connections) {
        # Add process information
        if ($processes.ContainsKey($conn.ProcessId)) {
            $process = $processes[$conn.ProcessId]
            $conn.ProcessName = $process.Name
            $conn.CommandLine = $process.CommandLine
        } else {
            # If process not found, it might have terminated
            $conn.ProcessName = "Unknown (PID: $($conn.ProcessId))"
        }
        
        # Add DNS resolution for remote address
        if ($conn.RemoteAddress -and $conn.RemoteAddress -ne "*" -and $DnsCache.ContainsKey($conn.RemoteAddress)) {
            $conn.RemoteHostName = $DnsCache[$conn.RemoteAddress]
        } elseif ($conn.RemoteAddress -and $conn.RemoteAddress -ne "*") {
            # Try to resolve hostname directly
            try {
                $hostEntry = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress)
                if ($hostEntry -and $hostEntry.HostName) {
                    $conn.RemoteHostName = $hostEntry.HostName
                    # Add to cache for future lookups
                    $DnsCache[$conn.RemoteAddress] = $hostEntry.HostName
                }
            }
            catch {
                # Unable to resolve hostname, leave as null
            }
        }
        
        # Return the enriched connection
        $conn
    }
    
    return $enrichedConnections
}

function Score-SuspiciousConnections {
    param (
        [array]$Connections
    )
    
    # Initialize known good/bad data
    $knownGoodPorts = @(80, 443, 53, 22, 21, 25, 143, 993, 995, 110, 3389, 5985, 5986, 1433, 3306, 5432, 27017)
    $suspiciousPorts = @(4444, 1337, 31337, 8080, 8888, 9001, 9050, 6667, 6666)
    
    # Standard system network processes
    $systemNetworkProcesses = @(
        "svchost", "lsass", "System", "dnscache", "services", "spoolsv", "winlogon",
        "msdtc", "dllhost", "taskhost", "taskhostw", "smss"
    )
    
    # Standard user network applications
    $commonNetworkApps = @(
        "chrome", "firefox", "msedge", "iexplore", "opera", "brave", "safari", 
        "outlook", "thunderbird", "skype", "teams", "zoom", "slack", "discord",
        "onedrive", "dropbox", "googledrive", "adobeupdate", "steam", "battle.net",
        "epicgameslauncher", "spotify"
    )
    
    # Score each connection for suspicious indicators
    $scoredConnections = foreach ($conn in $Connections) {
        $suspiciousScore = 0
        $suspiciousReasons = @()
        
        # 1. Check for uncommon remote ports on established connections
        if ($conn.State -eq "Established" -and $conn.RemotePort -notin $knownGoodPorts -and $conn.RemotePort -gt 1023) {
            $suspiciousScore += 1
            $suspiciousReasons += "Unusual remote port: $($conn.RemotePort)"
        }
        
        # 2. Check for known suspicious ports
        if ($conn.RemotePort -in $suspiciousPorts -or $conn.LocalPort -in $suspiciousPorts) {
            $suspiciousScore += 3
            $suspiciousReasons += "Known suspicious port detected: $($conn.RemotePort)"
        }
        
        # 3. Check for direct IP connections (no DNS) to external IPs
        if ($conn.State -eq "Established" -and $conn.RemoteAddress -and 
            $conn.RemoteAddress -ne "*" -and -not $conn.RemoteHostName -and
            -not ($conn.RemoteAddress -match "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|fe80:|::1$)")) {
            $suspiciousScore += 2
            $suspiciousReasons += "Connection to external IP without DNS resolution"
        }
        
        # 4. Check for unexpected processes with network connections
        $isCommonNetworkProcess = $false
        foreach ($goodProcess in $systemNetworkProcesses) {
            if ($conn.ProcessName -like "$goodProcess*") {
                $isCommonNetworkProcess = $true
                break
            }
        }
        
        if (-not $isCommonNetworkProcess) {
            foreach ($goodApp in $commonNetworkApps) {
                if ($conn.ProcessName -like "$goodApp*") {
                    $isCommonNetworkProcess = $true
                    break
                }
            }
        }
        
        if (-not $isCommonNetworkProcess -and $conn.State -eq "Established") {
            $suspiciousScore += 1
            $suspiciousReasons += "Unusual process with network connection: $($conn.ProcessName)"
        }
        
        # 5. Check for non-browser processes connecting to HTTP/HTTPS ports
        if ($conn.State -eq "Established" -and ($conn.RemotePort -eq 80 -or $conn.RemotePort -eq 443) -and 
            $conn.ProcessName -notmatch "chrome|firefox|edge|iexplore|opera|brave|safari|outlook|teams|skype|zoom|slack|discord|onedrive|dropbox") {
            $suspiciousScore += 1
            $suspiciousReasons += "Non-browser process connecting to web port: $($conn.ProcessName)"
        }
        
        # 6. Check for suspicious process names
        if ($conn.ProcessName -match "cmd|powershell|pwsh|wscript|cscript|calc|notepad|rundll32|regsvr32|mshta") {
            $suspiciousScore += 2
            $suspiciousReasons += "Suspicious process with network connection: $($conn.ProcessName)"
        }
        
        # 7. Check for command-line applications with suspicious arguments
        if ($conn.CommandLine -match "-e |-enc |-w hidden|bypass|downloadstring|invoke-webrequest|iwr |curl |wget |iex |invoke-expression") {
            $suspiciousScore += 3
            $suspiciousReasons += "Suspicious command-line arguments detected"
        }
        
        # 8. Check for high local ports on LISTENING connections (unusual services)
        if ($conn.State -eq "Listen" -and $conn.LocalPort -gt 1024 -and $conn.LocalPort -notin $knownGoodPorts) {
            # Only suspicious if not a common network process
            if (-not $isCommonNetworkProcess) {
                $suspiciousScore += 1
                $suspiciousReasons += "Unusual process listening on high port: $($conn.LocalPort)"
            }
        }
        
        # 9. Check for processes listening on any interface (0.0.0.0 or ::)
        if ($conn.State -eq "Listen" -and ($conn.LocalAddress -eq "*" -or $conn.LocalAddress -eq "0.0.0.0" -or $conn.LocalAddress -eq "::")) {
            # Only suspicious if not a common network process and on an unusual port
            if (-not $isCommonNetworkProcess -and $conn.LocalPort -notin $knownGoodPorts) {
                $suspiciousScore += 1
                $suspiciousReasons += "Process listening on all interfaces: $($conn.ProcessName) ($($conn.LocalPort))"
            }
        }
        
        # Add scores to the connection object
        $conn.SuspiciousScore = $suspiciousScore
        $conn.SuspiciousReason = ($suspiciousReasons | Select-Object -Unique) -join "; "
        
        # Return the scored connection
        $conn
    }
    
    return $scoredConnections
}

# Export function
Export-ModuleMember -Function Get-NetworkConnections
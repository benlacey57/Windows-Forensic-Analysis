<#
.SYNOPSIS
    Identifies unusual network ports and connections on a Windows system.
    
.DESCRIPTION
    Get-UnusualPorts analyzes active network ports and connections to identify
    potentially suspicious network activity. It examines listening ports,
    established connections, and compares them against known-good and known-bad ports.
    The module assigns risk scores to unusual findings and provides detailed
    information about each suspicious connection.
    
.EXAMPLE
    $unusualPortsFile = Get-UnusualPorts
    
.OUTPUTS
    String. The path to the CSV file containing unusual port findings
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges recommended for complete results
#>

function Get-UnusualPorts {
    param()

    $outputFile = "$script:outputDir\UnusualPorts_$script:timestamp.csv"
    Write-ForensicLog "Analyzing network ports and connections..."

    try {
        # Initialize port data structures
        $portsData = @{
            TcpConnections = @()
            UdpListeners = @()
            UnusualFindings = @()
        }

        # Collect connection data
        $portsData = Get-NetworkConnections -PortsData $portsData
        
        # Analyze connections
        $portsData = Analyze-UnusualPorts -PortsData $portsData
        
        # Process the results
        Export-PortResults -UnusualFindings $portsData.UnusualFindings -OutputFile $outputFile
        
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error analyzing network ports: $_" -Severity "Error"
        return $null
    }
}

function Get-NetworkConnections {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$PortsData
    )
    
    # Get all TCP connections
    $PortsData.TcpConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{
            Name = 'ProcessName'; 
            Expression = { 
                try { 
                    (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name 
                } catch { "Unknown" }
            }
        }, CreationTime
    
    # Get all UDP listeners
    $PortsData.UdpListeners = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | 
        Select-Object LocalAddress, LocalPort, OwningProcess, @{
            Name = 'ProcessName'; 
            Expression = { 
                try { 
                    (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name 
                } catch { "Unknown" }
            }
        }, CreationTime
    
    return $PortsData
}

function Analyze-UnusualPorts {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$PortsData
    )
    
    # Define common ports and their expected services (simplified list)
    $commonTcpPorts = @{
        20 = "FTP Data"
        21 = "FTP Control"
        22 = "SSH"
        23 = "Telnet"
        25 = "SMTP"
        53 = "DNS"
        80 = "HTTP"
        88 = "Kerberos"
        110 = "POP3"
        143 = "IMAP"
        389 = "LDAP"
        443 = "HTTPS"
        445 = "SMB"
        465 = "SMTPS"
        587 = "SMTP Submission"
        636 = "LDAPS"
        993 = "IMAPS"
        995 = "POP3S"
        1433 = "MS SQL"
        1434 = "MS SQL Browser"
        3306 = "MySQL"
        3389 = "RDP"
        5060 = "SIP"
        5061 = "SIP TLS"
        5432 = "PostgreSQL"
        5985 = "WinRM HTTP"
        5986 = "WinRM HTTPS"
        8000 = "HTTP Alt"
        8080 = "HTTP Proxy"
        8443 = "HTTPS Alt"
    }
    
    $commonUdpPorts = @{
        53 = "DNS"
        67 = "DHCP Server"
        68 = "DHCP Client"
        69 = "TFTP"
        123 = "NTP"
        137 = "NetBIOS Name"
        138 = "NetBIOS Datagram"
        161 = "SNMP"
        162 = "SNMP Trap"
        500 = "IKE"
        514 = "Syslog"
        520 = "RIP"
        1434 = "MS SQL Browser"
        5060 = "SIP"
    }
    
    # Known malicious or high-risk ports
    $knownBadPorts = @(4444, 31337, 1337, 6666, 8090, 9001, 9002, 9050, 9051, 6667, 6668, 6669)
    
    # Analyze TCP connections
    foreach ($conn in $PortsData.TcpConnections) {
        $suspiciousScore = 0
        $reasons = @()
        
        # Skip loopback addresses for most checks
        if ($conn.RemoteAddress -match "^127\." -or $conn.RemoteAddress -eq "::1") {
            continue
        }
        
        # Check for unusual remote ports
        if ($conn.State -eq "Established") {
            # Check if connection is to a non-standard port
            if ($conn.RemotePort -notin $commonTcpPorts.Keys -and $conn.RemotePort -gt 1023) {
                $suspiciousScore += 1
                $reasons += "Unusual remote port"
            }
            
            # Check if connecting to a known bad port
            if ($conn.RemotePort -in $knownBadPorts) {
                $suspiciousScore += 3
                $reasons += "Connection to a known malicious port"
            }
            
            # Check for direct IP connections (no DNS resolution)
            if ($conn.RemoteAddress -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" -and 
                $conn.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)") {
                $suspiciousScore += 1
                $reasons += "Direct connection to non-RFC1918 IP address"
            }
        }
        
        # Check for unusual listening ports
        if ($conn.State -eq "Listen") {
            # Check if listening on a non-standard port
            if ($conn.LocalPort -notin $commonTcpPorts.Keys -and $conn.LocalPort -lt 1024) {
                $suspiciousScore += 2
                $reasons += "Listening on unusual privileged port"
            }
            elseif ($conn.LocalPort -notin $commonTcpPorts.Keys -and $conn.LocalPort -gt 1023) {
                $suspiciousScore += 1
                $reasons += "Listening on unusual port"
            }
            
            # Check if listening on multiple interfaces
            if ($conn.LocalAddress -eq "0.0.0.0" -or $conn.LocalAddress -eq "::") {
                $suspiciousScore += 1
                $reasons += "Listening on all interfaces"
            }
        }
        
        # Check for unusual processes using network connections
        $commonNetworkProcesses = @(
            "svchost", "lsass", "System", "iexplore", "chrome", "firefox", "msedge", 
            "outlook", "thunderbird", "Teams", "OneDrive", "dropbox", "zoom", "skype", 
            "sqlservr", "apache", "nginx", "httpd", "w3wp", "java", "node", "winlogon"
        )
        
        if ($conn.ProcessName -and $conn.ProcessName -notin $commonNetworkProcesses) {
            $suspiciousScore += 1
            $reasons += "Unusual process using network connection"
            
            # Check for suspicious process names
            if ($conn.ProcessName -match "cmd|powershell|wscript|cscript|rundll32|regsvr32") {
                $suspiciousScore += 2
                $reasons += "Interpreter/utility process with network connection"
            }
        }
        
        # Add to unusual findings if suspicious
        if ($suspiciousScore -gt 0) {
            $riskLevel = switch ($suspiciousScore) {
                { $_ -ge 4 } { "High" }
                { $_ -ge 2 } { "Medium" }
                default { "Low" }
            }
            
            $finding = [PSCustomObject]@{
                Protocol = "TCP"
                LocalAddress = $conn.LocalAddress
                LocalPort = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                State = $conn.State
                ProcessId = $conn.OwningProcess
                ProcessName = $conn.ProcessName
                CreationTime = $conn.CreationTime
                ExpectedService = if ($commonTcpPorts.ContainsKey($conn.RemotePort)) { $commonTcpPorts[$conn.RemotePort] } else { "Unknown" }
                SuspiciousScore = $suspiciousScore
                RiskLevel = $riskLevel
                SuspiciousReasons = ($reasons -join "; ")
            }
            
            $PortsData.UnusualFindings += $finding
        }
    }
    
    # Analyze UDP listeners
    foreach ($listener in $PortsData.UdpListeners) {
        $suspiciousScore = 0
        $reasons = @()
        
        # Skip loopback addresses
        if ($listener.LocalAddress -match "^127\." -or $listener.LocalAddress -eq "::1") {
            continue
        }
        
        # Check if listening on a non-standard port
        if ($listener.LocalPort -notin $commonUdpPorts.Keys -and $listener.LocalPort -lt 1024) {
            $suspiciousScore += 2
            $reasons += "Listening on unusual privileged UDP port"
        }
        elseif ($listener.LocalPort -notin $commonUdpPorts.Keys -and $listener.LocalPort -gt 1023) {
            $suspiciousScore += 1
            $reasons += "Listening on unusual UDP port"
        }
        
        # Check if listening on multiple interfaces
        if ($listener.LocalAddress -eq "0.0.0.0" -or $listener.LocalAddress -eq "::") {
            $suspiciousScore += 1
            $reasons += "Listening on all interfaces"
        }
        
        # Check for unusual processes
        $commonNetworkProcesses = @(
            "svchost", "lsass", "System", "dnscache", "chrome", "firefox", "msedge", 
            "outlook", "thunderbird", "Teams", "OneDrive", "dropbox", "zoom", "skype"
        )
        
        if ($listener.ProcessName -and $listener.ProcessName -notin $commonNetworkProcesses) {
            $suspiciousScore += 1
            $reasons += "Unusual process listening on UDP"
            
            # Check for suspicious process names
            if ($listener.ProcessName -match "cmd|powershell|wscript|cscript|rundll32|regsvr32") {
                $suspiciousScore += 2
                $reasons += "Interpreter/utility process listening on UDP"
            }
        }
        
        # Add to unusual findings if suspicious
        if ($suspiciousScore -gt 0) {
            $riskLevel = switch ($suspiciousScore) {
                { $_ -ge 4 } { "High" }
                { $_ -ge 2 } { "Medium" }
                default { "Low" }
            }
            
            $finding = [PSCustomObject]@{
                Protocol = "UDP"
                LocalAddress = $listener.LocalAddress
                LocalPort = $listener.LocalPort
                RemoteAddress = "N/A"
                RemotePort = "N/A"
                State = "Listening"
                ProcessId = $listener.OwningProcess
                ProcessName = $listener.ProcessName
                CreationTime = $listener.CreationTime
                ExpectedService = if ($commonUdpPorts.ContainsKey($listener.LocalPort)) { $commonUdpPorts[$listener.LocalPort] } else { "Unknown" }
                SuspiciousScore = $suspiciousScore
                RiskLevel = $riskLevel
                SuspiciousReasons = ($reasons -join "; ")
            }
            
            $PortsData.UnusualFindings += $finding
        }
    }
    
    return $PortsData
}

function Export-PortResults {
    param (
        [Parameter(Mandatory = $true)]
        [Array]$UnusualFindings,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )
    
    if ($UnusualFindings.Count -gt 0) {
        # Sort by risk level and suspicious score
        $sortedFindings = $UnusualFindings | Sort-Object -Property @{Expression = "RiskLevel"; Descending = $true}, @{Expression = "SuspiciousScore"; Descending = $true}
        
        # Export to CSV
        $sortedFindings | Export-Csv -Path $OutputFile -NoTypeInformation
        
        # Generate summary statistics
        $highRiskCount = ($sortedFindings | Where-Object RiskLevel -eq "High").Count
        $mediumRiskCount = ($sortedFindings | Where-Object RiskLevel -eq "Medium").Count
        $lowRiskCount = ($sortedFindings | Where-Object RiskLevel -eq "Low").Count
        
        Write-ForensicLog "Found $($UnusualFindings.Count) unusual network ports/connections"
        
        if ($highRiskCount -gt 0) {
            Write-ForensicLog "Found $highRiskCount high-risk network connections:" -Severity "Warning"
            foreach ($finding in ($sortedFindings | Where-Object RiskLevel -eq "High" | Select-Object -First 3)) {
                if ($finding.Protocol -eq "TCP" -and $finding.State -eq "Established") {
                    Write-ForensicLog "  - $($finding.ProcessName) (PID: $($finding.ProcessId)) connected to $($finding.RemoteAddress):$($finding.RemotePort) - $($finding.SuspiciousReasons)" -Severity "Warning"
                } else {
                    Write-ForensicLog "  - $($finding.ProcessName) (PID: $($finding.ProcessId)) listening on $($finding.Protocol):$($finding.LocalPort) - $($finding.SuspiciousReasons)" -Severity "Warning"
                }
            }
        }
    } else {
        Write-ForensicLog "No unusual network ports or connections detected"
        [PSCustomObject]@{
            Result = "No unusual network ports or connections detected"
            AnalysisTime = Get-Date
            SystemName = $env:COMPUTERNAME
        } | Export-Csv -Path $OutputFile -NoTypeInformation
    }
    
    Write-ForensicLog "Saved network port analysis to $OutputFile"
}

# Export function
Export-ModuleMember -Function Get-UnusualPorts
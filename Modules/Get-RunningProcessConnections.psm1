<#
.SYNOPSIS
    Maps network connections to their associated processes
    
.DESCRIPTION
    Creates a comprehensive mapping between running processes and their
    network connections, highlighting potential suspicious network activity
    and identifying processes communicating over unusual ports.
    
.EXAMPLE
    $processConnectionsFile = Get-RunningProcessConnections
    
.OUTPUTS
    String. The path to the CSV file containing process connection mappings
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required to get complete network connection information
#>

function Get-RunningProcessConnections {
    param()
    
    $outputFile = "$script:outputDir\ProcessConnections_$script:timestamp.csv"
    Write-ForensicLog "Mapping processes to network connections..."
    
    try {
        # Get all running processes
        $processes = Get-Process | Select-Object Id, ProcessName, Path, 
            @{Name="FileDescription";Expression={
                if ($_.Path) {
                    try {
                        return (Get-Item $_.Path -ErrorAction SilentlyContinue).VersionInfo.FileDescription
                    } catch {
                        return "Unknown"
                    }
                } else {
                    return "Unknown"
                }
            }},
            @{Name="Company";Expression={
                if ($_.Path) {
                    try {
                        return (Get-Item $_.Path -ErrorAction SilentlyContinue).VersionInfo.CompanyName
                    } catch {
                        return "Unknown"
                    }
                } else {
                    return "Unknown"
                }
            }}
        
        # Get all TCP connections
        $tcpConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue
        
        # Get all UDP endpoints
        $udpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
        
        # Create mappings for TCP connections
        $results = @()
        
        foreach ($conn in $tcpConnections) {
            $process = $processes | Where-Object { $_.Id -eq $conn.OwningProcess } | Select-Object -First 1
            
            $connectionInfo = [PSCustomObject]@{
                Protocol = "TCP"
                ProcessId = $conn.OwningProcess
                ProcessName = if ($process) { $process.ProcessName } else { "Unknown" }
                ProcessPath = if ($process) { $process.Path } else { "Unknown" }
                ProcessCompany = if ($process) { $process.Company } else { "Unknown" }
                ProcessDescription = if ($process) { $process.FileDescription } else { "Unknown" }
                LocalAddress = $conn.LocalAddress
                LocalPort = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                State = $conn.State
                CreationTime = $conn.CreationTime
                OffloadState = $conn.OffloadState
                SuspiciousScore = 0
                SuspiciousReasons = ""
            }
            
            # Check if this is a potentially suspicious connection
            $suspiciousScore = 0
            $suspiciousReasons = @()
            
            # Check for uncommon remote ports
            $commonPorts = @(80, 443, 20, 21, 22, 23, 25, 53, 110, 143, 389, 636, 993, 995, 3389, 139, 445, 5985, 5986)
            if ($conn.State -eq 'Established' -and $conn.RemotePort -notin $commonPorts -and $conn.RemotePort -gt 1023) {
                $suspiciousScore += 1
                $suspiciousReasons += "Uncommon remote port: $($conn.RemotePort)"
            }
            
            # Check for connections to non-private IPs with unusual ports
            if ($conn.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|0\.0\.0\.0|::1|fe80:)" -and
                $conn.State -eq 'Established' -and $conn.RemotePort -notin @(80, 443)) {
                $suspiciousScore += 1
                $suspiciousReasons += "External connection on non-standard port"
            }
            
            # Check for listening ports above 1024 that aren't common server ports
            $commonServerPorts = @(3389, 5985, 5986, 8080, 8443)
            if ($conn.State -eq 'Listen' -and $conn.LocalPort -gt 1024 -and $conn.LocalPort -notin $commonServerPorts) {
                $suspiciousScore += 1
                $suspiciousReasons += "Unusual listening port: $($conn.LocalPort)"
            }
            
            # Check for suspicious process names connecting to the internet
            $suspiciousProcessNames = @("powershell", "cmd", "wscript", "cscript", "rundll32", "regsvr32", "mshta", "certutil", "bitsadmin")
            if ($process -and $suspiciousProcessNames -contains $process.ProcessName -and 
                $conn.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|0\.0\.0\.0|::1|fe80:)") {
                $suspiciousScore += 2
                $suspiciousReasons += "Suspicious process with external connection"
            }
            
            # Check for high port number connections in both directions (potential C2)
            if ($conn.State -eq 'Established' -and $conn.LocalPort -gt 49000 -and $conn.RemotePort -gt 49000) {
                $suspiciousScore += 2
                $suspiciousReasons += "High port numbers on both ends"
            }
            
            # Update the suspicious score and reasons
            $connectionInfo.SuspiciousScore = $suspiciousScore
            $connectionInfo.SuspiciousReasons = $suspiciousReasons -join "; "
            
            $results += $connectionInfo
        }
        
        # Add UDP endpoints
        foreach ($endpoint in $udpEndpoints) {
            $process = $processes | Where-Object { $_.Id -eq $endpoint.OwningProcess } | Select-Object -First 1
            
            $endpointInfo = [PSCustomObject]@{
                Protocol = "UDP"
                ProcessId = $endpoint.OwningProcess
                ProcessName = if ($process) { $process.ProcessName } else { "Unknown" }
                ProcessPath = if ($process) { $process.Path } else { "Unknown" }
                ProcessCompany = if ($process) { $process.Company } else { "Unknown" }
                ProcessDescription = if ($process) { $process.FileDescription } else { "Unknown" }
                LocalAddress = $endpoint.LocalAddress
                LocalPort = $endpoint.LocalPort
                RemoteAddress = "N/A" # UDP endpoints don't have remote address
                RemotePort = "N/A" # UDP endpoints don't have remote port
                State = "N/A" # UDP doesn't maintain state
                CreationTime = $endpoint.CreationTime
                OffloadState = "N/A"
                SuspiciousScore = 0
                SuspiciousReasons = ""
            }
            
            # Check if this is a potentially suspicious UDP endpoint
            $suspiciousScore = 0
            $suspiciousReasons = @()
            
            # Check for uncommon local UDP ports
            $commonUdpPorts = @(53, 67, 68, 69, 123, 137, 138, 161, 162, 389, 636, 1900, 5353)
            if ($endpoint.LocalPort -notin $commonUdpPorts -and $endpoint.LocalPort -gt 1023) {
                $suspiciousScore += 1
                $suspiciousReasons += "Uncommon UDP port: $($endpoint.LocalPort)"
            }
            
            # Check for suspicious process using UDP
            $suspiciousUdpProcesses = @("powershell", "cmd", "wscript", "cscript", "rundll32", "regsvr32", "mshta")
            if ($process -and $suspiciousUdpProcesses -contains $process.ProcessName) {
                $suspiciousScore += 2
                $suspiciousReasons += "Suspicious process using UDP"
            }
            
            # Update the suspicious score and reasons
            $endpointInfo.SuspiciousScore = $suspiciousScore
            $endpointInfo.SuspiciousReasons = $suspiciousReasons -join "; "
            
            $results += $endpointInfo
        }
        
        # Export to CSV
        $results | Export-Csv -Path $outputFile -NoTypeInformation
        
        # Report suspicious connections
        $suspiciousConnections = $results | Where-Object { $_.SuspiciousScore -gt 0 } | Sort-Object -Property SuspiciousScore -Descending
        if ($suspiciousConnections.Count -gt 0) {
            Write-ForensicLog "Found $($suspiciousConnections.Count) suspicious network connections:" -Severity "Warning"
            foreach ($conn in $suspiciousConnections | Select-Object -First 5) {
                if ($conn.Protocol -eq "TCP") {
                    Write-ForensicLog "  - $($conn.ProcessName) ($($conn.ProcessId)) connected to $($conn.RemoteAddress):$($conn.RemotePort) - $($conn.SuspiciousReasons)" -Severity "Warning"
                } else {
                    Write-ForensicLog "  - $($conn.ProcessName) ($($conn.ProcessId)) using UDP port $($conn.LocalPort) - $($conn.SuspiciousReasons)" -Severity "Warning"
                }
            }
            
            # Create a separate file for suspicious connections
            $suspiciousConnections | Export-Csv -Path "$script:outputDir\SuspiciousConnections_$script:timestamp.csv" -NoTypeInformation
        }
        
        Write-ForensicLog "Saved process connection mapping to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error mapping processes to connections: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-RunningProcessConnections
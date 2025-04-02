<#
.SYNOPSIS
    Retrieves and analyses network usage.
    
.DESCRIPTION
    This module retrieves network usage statistics, including network adapter information,
    traffic data, and active connections. The results are saved to a CSV file.
    
.EXAMPLE
    $networkUsageFile = Get-NetworkUsage
    
.OUTPUTS
    String. The path to the CSV file containing the network usage analysis.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for complete network usage information.
#>

function Get-NetworkUsage {
    param()

    $outputFile = "$script:outputDir\NetworkUsage_$script:timestamp.csv"
    Write-ForensicLog "Retrieving network usage information..."

    try {
        $networkData = @()

        # Network Adapters
        $networkAdapters = Get-NetAdapter | Select-Object Name, InterfaceDescription, InterfaceAlias, MacAddress, Status, InterfaceOperationalStatus, ifIndex
        foreach ($adapter in $networkAdapters) {
            $networkData += [PSCustomObject]@{
                DataType          = "Adapter"
                Name              = $adapter.Name
                InterfaceDescription = $adapter.InterfaceDescription
                InterfaceAlias    = $adapter.InterfaceAlias
                MacAddress        = $adapter.MacAddress
                Status            = $adapter.Status
                OperationalStatus = $adapter.InterfaceOperationalStatus
                ifIndex           = $adapter.ifIndex
                LocalAddress      = (Get-NetIPAddress -InterfaceIndex $adapter.ifIndex | Where-Object {$_.AddressFamily -eq 'IPv4' -or $_.AddressFamily -eq 'IPv6'}).IPAddress -join ';'
                RemoteAddress     = $null
                Protocol          = $null
                BytesSent         = $null
                BytesReceived     = $null
            }
        }

        # Network Traffic Statistics
        $netStatistics = Get-NetAdapterStatistics | Select-Object InterfaceDescription, BytesSent, BytesReceived, ifIndex
        foreach ($statistic in $netStatistics) {
            $matchingAdapter = $networkData | Where-Object {$_.ifIndex -eq $statistic.ifIndex}
            if ($matchingAdapter) {
                $matchingAdapter.BytesSent = $statistic.BytesSent
                $matchingAdapter.BytesReceived = $statistic.BytesReceived
            }
        }

        # Active TCP Connections
        $tcpConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, ifIndex, Protocol
        foreach ($connection in $tcpConnections) {
            $networkData += [PSCustomObject]@{
                DataType          = "TCP Connection"
                Name              = (Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue).ProcessName
                InterfaceDescription = ($networkData | Where-Object {$_.ifIndex -eq $connection.ifIndex}).InterfaceDescription
                InterfaceAlias    = ($networkData | Where-Object {$_.ifIndex -eq $connection.ifIndex}).InterfaceAlias
                MacAddress        = ($networkData | Where-Object {$_.ifIndex -eq $connection.ifIndex}).MacAddress
                Status            = $connection.State
                OperationalStatus = ($networkData | Where-Object {$_.ifIndex -eq $connection.ifIndex}).OperationalStatus
                ifIndex           = $connection.ifIndex
                LocalAddress      = "$($connection.LocalAddress):$($connection.LocalPort)"
                RemoteAddress     = "$($connection.RemoteAddress):$($connection.RemotePort)"
                Protocol          = $connection.Protocol
                BytesSent         = $null
                BytesReceived     = $null
            }
        }

        # Active UDP Connections
        $udpConnections = Get-NetUDPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, ifIndex, Protocol
        foreach ($connection in $udpConnections) {
            $networkData += [PSCustomObject]@{
                DataType          = "UDP Connection"
                Name              = (Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue).ProcessName
                InterfaceDescription = ($networkData | Where-Object {$_.ifIndex -eq $connection.ifIndex}).InterfaceDescription
                InterfaceAlias    = ($networkData | Where-Object {$_.ifIndex -eq $connection.ifIndex}).InterfaceAlias
                MacAddress        = ($networkData | Where-Object {$_.ifIndex -eq $connection.ifIndex}).MacAddress
                Status            = "Established"
                OperationalStatus = ($networkData | Where-Object {$_.ifIndex -eq $connection.ifIndex}).OperationalStatus
                ifIndex           = $connection.ifIndex
                LocalAddress      = "$($connection.LocalAddress):$($connection.LocalPort)"
                RemoteAddress     = "$($connection.RemoteAddress):$($connection.RemotePort)"
                Protocol          = $connection.Protocol
                BytesSent         = $null
                BytesReceived     = $null
            }
        }

        # Save to CSV
        $networkData | Export-Csv -Path $outputFile -NoTypeInformation

        Write-ForensicLog "Saved network usage information to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error retrieving network usage information: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-NetworkUsage

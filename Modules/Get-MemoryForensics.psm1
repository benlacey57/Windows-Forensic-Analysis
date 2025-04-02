<#
.SYNOPSIS
    Retrieves and analyses memory forensics data.
    
.DESCRIPTION
    This module captures and analyses memory forensics data, including process information,
    loaded modules, network connections, and other relevant memory artifacts. The results are saved to a CSV file.
    
.EXAMPLE
    $memoryForensicsFile = Get-MemoryForensics
    
.OUTPUTS
    String. The path to the CSV file containing the memory forensics analysis.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for memory access.
#>

function Get-MemoryForensics {
    param()

    $outputFile = "$script:outputDir\MemoryForensics_$script:timestamp.csv"
    Write-ForensicLog "Retrieving memory forensics data..."

    try {
        $memoryData = @()

        # Process Information
        $processes = Get-Process | Select-Object Id, ProcessName, StartTime, Path, Company, CommandLine, UserName
        foreach ($process in $processes) {
            $memoryData += [PSCustomObject]@{
                DataType    = "Process"
                Id          = $process.Id
                Name        = $process.ProcessName
                StartTime   = $process.StartTime
                Path        = $process.Path
                Company     = $process.Company
                CommandLine = $process.CommandLine
                UserName    = $process.UserName
                Modules     = $null
                Connections = $null
            }

            # Loaded Modules
            try {
                $modules = Get-ProcessModule -ProcessId $process.Id | Select-Object FileName, ModuleName, FileVersion, CompanyName
                $memoryData | Where-Object { $_.Id -eq $process.Id -and $_.DataType -eq "Process" } | ForEach-Object { $_.Modules = ($modules | ConvertTo-Json) }
            }
            catch {
                Write-Verbose "Could not get modules for process $($process.Id): $_"
            }

            # Network Connections
            try {
                $connections = Get-NetTCPConnection -OwningProcess $process.Id | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, Protocol
                $memoryData | Where-Object { $_.Id -eq $process.Id -and $_.DataType -eq "Process" } | ForEach-Object { $_.Connections = ($connections | ConvertTo-Json) }
            }
            catch {
                Write-Verbose "Could not get connections for process $($process.Id): $_"
            }
        }

        # System Information
        $systemInfo = Get-ComputerInfo | Select-Object OsName, OsVersion, CsName, OsArchitecture, WindowsDirectory, TotalPhysicalMemory
        $memoryData += [PSCustomObject]@{
            DataType    = "System"
            OsName      = $systemInfo.OsName
            OsVersion   = $systemInfo.OsVersion
            ComputerName = $systemInfo.CsName
            Architecture = $systemInfo.OsArchitecture
            WindowsDirectory = $systemInfo.WindowsDirectory
            TotalMemory = $systemInfo.TotalPhysicalMemory
            Id = $null
            Name = $null
            StartTime = $null
            Path = $null
            Company = $null
            CommandLine = $null
            UserName = $null
            Modules = $null
            Connections = $null
        }

        # Save to CSV
        $memoryData | Export-Csv -Path $outputFile -NoTypeInformation

        Write-ForensicLog "Saved memory forensics data to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error retrieving memory forensics data: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-MemoryForensics

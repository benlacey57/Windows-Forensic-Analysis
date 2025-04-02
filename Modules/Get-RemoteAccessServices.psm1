<#
.SYNOPSIS
    Retrieves and analyses remote access services.
    
.DESCRIPTION
    This module retrieves information about remote access services, including Windows Remote Desktop,
    LogMeIn, AnyDesk, TeamViewer, and other potential remote access tools. The results are saved to a CSV file.
    
.EXAMPLE
    $remoteAccessServicesFile = Get-RemoteAccessServices
    
.OUTPUTS
    String. The path to the CSV file containing the remote access service analysis.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.1
    Required Permissions: Administrator privileges required for complete service information.
#>

function Get-RemoteAccessServices {
    param()

    $outputFile = "$script:outputDir\RemoteAccessServices_$script:timestamp.csv"
    Write-ForensicLog "Analysing remote access services..."

    try {
        $remoteAccessData = @()

        # Remote Access Services Configuration
        $remoteAccessServices = @(
            @{ Name = "TermService"; Type = "Windows Remote Desktop" },
            @{ Name = "LogMeIn*"; Type = "LogMeIn" },
            @{ Name = "AnyDesk*"; Type = "AnyDesk" },
            @{ Name = "TeamViewer*"; Type = "TeamViewer" }
        )

        # Loop through services
        foreach ($serviceConfig in $remoteAccessServices) {
            $services = Get-Service -Name $serviceConfig.Name -ErrorAction SilentlyContinue
            foreach ($service in $services) {
                $remoteAccessData += [PSCustomObject]@{
                    ServiceName   = $service.Name
                    DisplayName   = $service.DisplayName
                    Status        = $service.Status
                    StartType     = $service.StartType
                    BinaryPathName = $service.BinaryPathName
                    Type          = $serviceConfig.Type
                    PotentialRisk = if ($service.Status -eq "Running") { "$($serviceConfig.Type) Service Running" } else { $null }
                }
            }
        }

        # Remote Access Processes
        $remoteAccessProcesses = @(
            @{ Name = "mstsc.exe"; Type = "Windows Remote Desktop Application" },
            @{ Name = "logmein.exe"; Type = "LogMeIn Application" },
            @{ Name = "anydesk.exe"; Type = "AnyDesk Application" },
            @{ Name = "teamviewer.exe"; Type = "TeamViewer Application" },
            @{ Name = "vnc.exe"; Type = "VNC Application"}
        )

        # Loop through processes
        foreach ($processConfig in $remoteAccessProcesses) {
            $process = Get-Process -Name $processConfig.Name -ErrorAction SilentlyContinue
            if ($process) {
                $remoteAccessData += [PSCustomObject]@{
                    ServiceName   = $process.ProcessName
                    DisplayName   = $process.ProcessName
                    Status        = "Running"
                    StartType     = "Process"
                    BinaryPathName = $process.Path
                    Type          = $processConfig.Type
                    PotentialRisk = "$($processConfig.Type) Running"
                }
            }
        }

        # Save to CSV
        $remoteAccessData | Export-Csv -Path $outputFile -NoTypeInformation

        Write-ForensicLog "Saved remote access service analysis to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error analysing remote access services: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-RemoteAccessServices

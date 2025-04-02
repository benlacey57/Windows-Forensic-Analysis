<#
.SYNOPSIS
    Main function to run a complete forensic analysis of the system
    
.DESCRIPTION
    Orchestrates the collection and analysis of forensic data by calling
    individual specialized functions. Provides various options for controlling
    the scope of analysis and output formats.
    
.PARAMETER OutputDirectory
    Directory where to store all collected data and reports
    
.PARAMETER KeepData
    If specified, temporary data is not cleaned up after analysis
    
.PARAMETER EventHours
    Number of hours to look back for event logs (default 24)
    
.PARAMETER RecentExeDays
    Number of days to look back for recently modified executables (default 7)
    
.PARAMETER NetworkMonitorMinutes
    Number of minutes to monitor network activity (default 5)
    
.PARAMETER IncludeMemoryDump
    If specified, attempts to create a memory dump for offline analysis
    
.PARAMETER QuickScan
    If specified, performs a limited scan focusing on critical indicators
    
.PARAMETER GenerateHtmlReport
    If specified, generates an interactive HTML report
    
.PARAMETER SecureResults
    If specified, encrypts the results
    
.PARAMETER CertificateThumbprint
    Certificate thumbprint to use for securing results
    
.EXAMPLE
    Start-ForensicAnalysis -OutputDirectory "D:\ForensicData" -GenerateHtmlReport
    
.EXAMPLE
    Start-ForensicAnalysis -QuickScan -IncludeMemoryDump
    
.OUTPUTS
    Hashtable. Contains paths to all generated data files and reports
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Requires administrative privileges to collect comprehensive system data
#>

function Start-ForensicAnalysis {
    [CmdletBinding()]
    param(
        [string]$OutputDirectory = "C:\ForensicData",
        [switch]$KeepData,
        [int]$EventHours = 24,
        [int]$RecentExeDays = 7,
        [int]$NetworkMonitorMinutes = 5,
        [switch]$IncludeMemoryDump,
        [switch]$QuickScan,
        [switch]$GenerateHtmlReport,
        [switch]$SecureResults,
        [string]$CertificateThumbprint
    )
    
    # Initialize the environment
    Initialize-Environment -OutputDirectory $OutputDirectory
    
    # Store results
    $results = @{}
    
    # Core data collection - always run
    $results["Processes"] = Get-RunningProcesses
    $results["NetworkConnections"] = Get-NetworkConnections
    $results["Services"] = Get-ServiceInformation
    $results["UserAccounts"] = Get-UserAccountActivity
    $results["FirewallStatus"] = Get-FirewallStatus
    $results["WindowsDefender"] = Get-WindowsDefenderStatus
    
    # Additional checks based on quick scan flag
    if (-not $QuickScan) {
        $results["ScheduledTasks"] = Get-ScheduledTaskInfo
        $results["StartupItems"] = Get-StartupItems
        $results["SecurityEvents"] = Get-SecurityEvents -Hours $EventHours
        $results["RegistryPersistence"] = Get-RegistryPersistence
        $results["DNSSettings"] = Get-DNSSettings
        $results["Drivers"] = Get-SuspiciousDrivers
        $results["NetworkUsage"] = Get-NetworkUsage -Minutes $NetworkMonitorMinutes
        $results["SuspiciousTasks"] = Find-SuspiciousScheduledTasks
        $results["WMIPersistence"] = Get-WMIPersistence
        $results["AutorunLocations"] = Get-AutorunLocations
        $results["SMBShares"] = Get-SMBShareAnalysis
        $results["RemoteAccess"] = Get-RemoteAccessServices
        $results["RestorePoints"] = Get-SystemRestorePoints
        $results["GroupPolicy"] = Get-GroupPolicySettings
        $results["USBHistory"] = Get-USBHistory
        $results["PrefetchAnalysis"] = Get-PrefetchAnalysis
        $results["PowerShellHistory"] = Get-PowerShellHistory
        $results["AMSIBypass"] = Find-AMSIBypassAttempts
        $results["TimeStompedFiles"] = Find-TimeStompedFiles
        $results["UserPermissions"] = Get-DetailedUserPermissions
        $results["HostsFile"] = Get-HostsFileEntries
        $results["DriveHealth"] = Get-DriveHealthInfo
        $results["ConnectedDevices"] = Get-ConnectedDevices
        $results["SystemSpecs"] = Get-SystemSpecifications
        
        # Additional forensic checks
        $results["ProcessConnections"] = Get-RunningProcessConnections
        $results["InstalledPatches"] = Get-InstalledPatches
        $results["UnusualCronJobs"] = Get-UnusualCronJobs
        $results["LibraryHijacking"] = Get-SharedLibraryHijacking
        $results["EnvVarPersistence"] = Get-EnvironmentVariablePersistence
        $results["WebShells"] = Find-PotentialWebShells
        $results["UnusualCertificates"] = Find-UnusualCertificates
        $results["ShadowCopies"] = Get-ShadowCopies
        $results["DeletedFiles"] = Get-RecentlyDeletedFiles
        $results["BrowserExtensions"] = Get-BrowserExtensions
        $results["RootkitIndicators"] = Get-RootKitIndicators
        $results["PowerShellLogs"] = Get-PowerShellLogs
    }
    
    # Analysis checks
    $results["UnusualPorts"] = Find-UnusualPorts -NetworkConnectionsFile $results["NetworkConnections"]
    $results["RecentExecutables"] = Find-RecentlyModifiedExecutables -Days $RecentExeDays
    
    # Memory dump (optional)
    if ($IncludeMemoryDump) {
        $results["MemoryDump"] = Get-MemoryDump
    }
    
    # Generate analysis report
    $results["Report"] = New-AnalysisReport -Results $results
    
    # Generate HTML report if requested
    if ($GenerateHtmlReport) {
        $htmlReport = New-ForensicHtmlReport -Results $results -ComputerName $env:COMPUTERNAME
        $results["HtmlReport"] = $htmlReport
        
        Write-ForensicLog "HTML report generated: $htmlReport"
    }
    
    # Secure results if requested
    if ($SecureResults) {
        $securedPath = $null
        
        if ($CertificateThumbprint) {
            $securedPath = Protect-ForensicReport -ReportPath $OutputDirectory -CertificateThumbprint $CertificateThumbprint -IncludeManifest
        } else {
            # Generate a secure random password
            $securePassword = New-Object System.Security.SecureString
            $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_-+=[]{}".ToCharArray()
            $random = New-Object System.Random
            
            for ($i = 0; $i -lt 20; $i++) {
                $securePassword.AppendChar($chars[$random.Next(0, $chars.Length)])
            }
            
            $securedPath = Protect-ForensicReport -ReportPath $OutputDirectory -Password $securePassword -IncludeManifest
            
            # Display the password once (for admin to record)
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
            $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            Write-ForensicLog "IMPORTANT: Record this password for accessing the encrypted results: $plainPassword"
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        
        if ($securedPath) {
            $results["SecuredArchive"] = $securedPath
            Write-ForensicLog "Results secured and archived to: $securedPath"
        }
    }
    
    # Clean up
    Invoke-Cleanup -KeepData:$KeepData
    
    # Output report location
    Write-Output "`nForensic analysis complete. Report saved to: $($results['Report'])"
    Write-Output "All data files are located in: $OutputDirectory"
    
    return $results
}

# Export function
Export-ModuleMember -Function Start-ForensicAnalysis
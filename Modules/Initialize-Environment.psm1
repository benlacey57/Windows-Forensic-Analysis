<#
.SYNOPSIS
    Initializes the environment for forensic analysis
    
.DESCRIPTION
    Creates the output directory structure, initializes logging, and sets up
    the necessary environment for the forensic analysis to run successfully.
    
.PARAMETER OutputDirectory
    The directory where forensic analysis results will be stored.
    Defaults to "C:\ForensicData" if not specified.
    
.EXAMPLE
    Initialize-Environment -OutputDirectory "D:\ForensicResults"
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Requires administrative privileges to create directories and access system information
#>

function Initialize-Environment {
    param(
        [string]$OutputDirectory = "C:\ForensicsData"
    )
    
    # Set global variables
    $script:outputDir = $OutputDirectory
    $script:timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:logFile = "$outputDir\ForensicAnalysis_$timestamp.log"
    
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir | Out-Null
        Write-Output "Created output directory: $outputDir"
    }
    
    Start-Transcript -Path $logFile
    Write-Output "Starting forensic analysis at $(Get-Date)"
    Write-Output "System: $env:COMPUTERNAME"
    Write-Output "User: $env:USERNAME"
}

# Export function
Export-ModuleMember -Function Initialize-Environment
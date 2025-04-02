<#
.SYNOPSIS
    Main module file for the Windows Forensic Analyzer
    
.DESCRIPTION
    Imports all function modules and exports the public functions.
    This file serves as the entry point for the entire forensic toolkit.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Last Updated: 2025-04-01
    
    This module requires administrative privileges to run most functions.
#>

# Get module definition files
$ModulePath = Join-Path -Path $PSScriptRoot -ChildPath "Modules"
$ModuleFiles = Get-ChildItem -Path $ModulePath -Filter "*.psm1" -ErrorAction SilentlyContinue

# Import all modules
foreach ($module in $ModuleFiles) {
    try {
        Import-Module $module.FullName -Force -DisableNameChecking
    }
    catch {
        Write-Error -Message "Failed to import module $($module.FullName): $_"
    }
}

# Export public functions
Export-ModuleMember -Function @(
    # Core functions
    'Start-ForensicAnalysis',
    
    # Reporting functions
    'New-ForensicHtmlReport',
    'New-MultiComputerForensicReport',
    
    # Scheduling and distribution
    'Register-ForensicAnalysisSchedule',
    'Protect-ForensicReport',
    'Send-SecureForensicReport'
)
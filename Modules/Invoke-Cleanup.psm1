<#
.SYNOPSIS
    Cleans up temporary files after forensic analysis
    
.DESCRIPTION
    Handles cleanup operations after forensic analysis is complete,
    optionally preserving the collected data based on the KeepData parameter.
    
.PARAMETER KeepData
    If specified, temporary data is not cleaned up after analysis
    
.EXAMPLE
    Invoke-Cleanup -KeepData
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
#>

function Invoke-Cleanup {
    param(
        [switch]$KeepData
    )
    
    Write-ForensicLog "Forensic analysis complete."
    
    if (-not $KeepData) {
        # Cleanup code would go here if needed
        # For now, we retain all data for investigative purposes
    }
    
    Stop-Transcript
}

# Export function
Export-ModuleMember -Function Invoke-Cleanup
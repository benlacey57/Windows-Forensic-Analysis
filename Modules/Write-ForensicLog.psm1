<#
.SYNOPSIS
    Writes formatted log entries for forensic analysis
    
.DESCRIPTION
    Provides standardized logging with severity indicators and timestamps
    for the forensic analysis process. Writes to both console and log file.
    
.PARAMETER Message
    The message to be logged
    
.PARAMETER Severity
    The severity level of the message (Info, Warning, Error)
    Default is "Info"
    
.EXAMPLE
    Write-ForensicLog "Found suspicious process" -Severity "Warning"
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Relies on $script:logFile being set by Initialize-Environment
#>

function Write-ForensicLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Info", "Warning", "Error")]
        [string]$Severity = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $formattedMessage = "[$timestamp] [$Severity] $Message"
    
    switch ($Severity) {
        "Warning" { Write-Host $formattedMessage -ForegroundColor Yellow }
        "Error" { Write-Host $formattedMessage -ForegroundColor Red }
        default { Write-Host $formattedMessage }
    }
    
    # Also write to the log file
    $formattedMessage | Out-File -FilePath $script:logFile -Append
}

# Export function
Export-ModuleMember -Function Write-ForensicLog
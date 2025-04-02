<#
.SYNOPSIS
    Retrieves and analyses files with time stamp anomalies.
    
.DESCRIPTION
    This module scans the file system for files where the last modified time is earlier than the creation time,
    indicating potential time stomping. The results are saved to a CSV file.
    
.EXAMPLE
    $timeStompedFilesFile = Get-TimeStompedFiles -Path "C:\Users\Public\Documents"
    
.OUTPUTS
    String. The path to the CSV file containing the time stomped file analysis.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for complete file system access.
#>

function Get-TimeStompedFiles {
    param (
        [Parameter(Mandatory = $false)]
        [string]$Path = "C:\" # Default to C:\ if no path is specified
    )

    $outputFile = "$script:outputDir\TimeStompedFiles_$script:timestamp.csv"
    Write-ForensicLog "Analysing files for time stamp anomalies in path: $Path"

    try {
        $timeStompedFiles = @()

        $files = Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -eq $false }

        foreach ($file in $files) {
            if ($file.LastWriteTime -lt $file.CreationTime) {
                $timeStompedFiles += [PSCustomObject]@{
                    FilePath        = $file.FullName
                    FileName        = $file.Name
                    CreationTime    = $file.CreationTime
                    LastWriteTime   = $file.LastWriteTime
                    Description     = "Last modified time is earlier than creation time."
                    Severity        = "High"
                }
            }
        }

        # Save to CSV
        $timeStompedFiles | Export-Csv -Path $outputFile -NoTypeInformation

        Write-ForensicLog "Saved time stomped file analysis to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error analysing time stomped files: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-TimeStompedFiles

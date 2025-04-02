<#
.SYNOPSIS
    Retrieves and analyses recently modified executable files.
    
.DESCRIPTION
    This module scans common application directories for executable files (.exe)
    and retrieves information about their last modification times. It identifies
    recently modified executables, which could indicate suspicious activity. The results are saved to a CSV file.
    
.EXAMPLE
    $recentlyModifiedExecutablesFile = Get-RecentlyModifiedExecutables -Days 7
    
.OUTPUTS
    String. The path to the CSV file containing the recently modified executable analysis.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for complete file system access.
#>

function Get-RecentlyModifiedExecutables {
    param (
        [Parameter(Mandatory = $false)]
        [int]$Days = 7 # Default to 7 days if not specified
    )

    $outputFile = "$script:outputDir\RecentlyModifiedExecutables_$script:timestamp.csv"
    Write-ForensicLog "Analysing recently modified executables (last $Days days)..."

    try {
        $modifiedDate = (Get-Date).AddDays(-$Days)
        $modifiedExecutables = @()

        # Common Application Directories
        $applicationDirectories = @(
            "$env:ProgramFiles",
            "$env:ProgramFiles(x86)",
            "$env:LocalAppData",
            "$env:AppData",
            "$env:SystemRoot\System32"
        )

        foreach ($directory in $applicationDirectories) {
            if (Test-Path -Path $directory) {
                $executables = Get-ChildItem -Path $directory -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -ge $modifiedDate }

                foreach ($executable in $executables) {
                    $modifiedExecutables += [PSCustomObject]@{
                        FileName      = $executable.Name
                        FullPath      = $executable.FullName
                        LastModified  = $executable.LastWriteTime
                        FileSize      = $executable.Length
                        Directory     = $executable.DirectoryName
                    }
                }
            }
        }

        # Save to CSV
        $modifiedExecutables | Export-Csv -Path $outputFile -NoTypeInformation

        Write-ForensicLog "Saved recently modified executable analysis to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error analysing recently modified executables: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-RecentlyModifiedExecutables

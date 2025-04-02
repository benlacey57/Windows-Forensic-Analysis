<#
.SYNOPSIS
    Retrieves system restore points and saves them to a CSV file.
    
.DESCRIPTION
    This module retrieves the system restore points from the local machine,
    including their creation time, description, and sequence number, and
    exports the data to a CSV file.
    
.EXAMPLE
    $restorePointsFile = Get-SystemRestorePoints
    
.OUTPUTS
    String. The path to the CSV file containing the system restore points.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required.
#>

function Get-SystemRestorePoints {
    param()

    $outputFile = "$script:outputDir\SystemRestorePoints_$script:timestamp.csv"
    Write-ForensicLog "Retrieving System Restore Points..."

    try {
        # Get System Restore Points using WMI
        $restorePoints = Get-WmiObject -Class SystemRestore -Namespace root\default |
            Select-Object CreationTime, Description, SequenceNumber, RestorePointType

        # Format CreationTime
        $formattedRestorePoints = $restorePoints | ForEach-Object {
            $creationTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($_.CreationTime)
            [PSCustomObject]@{
                CreationTime     = $creationTime
                Description      = $_.Description
                SequenceNumber   = $_.SequenceNumber
                RestorePointType = $_.RestorePointType
            }
        }

        # Export the restore points to a CSV file
        $formattedRestorePoints | Export-Csv -Path $outputFile -NoTypeInformation

        Write-ForensicLog "Saved System Restore Points to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error retrieving System Restore Points: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-SystemRestorePoints

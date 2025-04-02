<#
.SYNOPSIS
    Retrieves shadow copies (Volume Shadow Copy Service - VSS) using vssadmin and saves them to a CSV file.
    
.DESCRIPTION
    This module retrieves information about existing shadow copies on the local machine using vssadmin,
    including their shadow copy ID, original volume, creation time, and service volume. The results are saved to a CSV file.
    
.EXAMPLE
    $shadowCopiesFile = Get-ShadowCopies
    
.OUTPUTS
    String. The path to the CSV file containing the shadow copy information.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.1
    Required Permissions: Administrator privileges required.
#>

function Get-ShadowCopies {
    param()

    $outputFile = "$script:outputDir\ShadowCopies_$script:timestamp.csv"
    Write-ForensicLog "Retrieving Shadow Copies using vssadmin..."

    try {
        # Get shadow copies using vssadmin
        $vssadminOutput = vssadmin list shadows /for=C: # You can remove /for=C: to get all shadow copies.
        $shadowCopyObjects = @()
        $currentShadowCopy = @{}

        foreach ($line in $vssadminOutput) {
            if ($line -match "Shadow Copy ID: (.+)") {
                if ($currentShadowCopy.Count -gt 0) {
                    $shadowCopyObjects += [PSCustomObject]$currentShadowCopy
                    $currentShadowCopy = @{}
                }
                $currentShadowCopy.ID = $Matches[1].Trim()
            } elseif ($line -match "Original Volume: (.+)") {
                $currentShadowCopy.OriginalVolume = $Matches[1].Trim()
            } elseif ($line -match "Creation Time: (.+)") {
                $currentShadowCopy.CreationTime = [datetime]$Matches[1].Trim()
            } elseif ($line -match "Shadow Copy Volume: (.+)") {
                $currentShadowCopy.ShadowCopyVolume = $Matches[1].Trim()
            }
        }
        if ($currentShadowCopy.Count -gt 0) {
            $shadowCopyObjects += [PSCustomObject]$currentShadowCopy
        }

        # Export the shadow copy information to a CSV file
        $shadowCopyObjects | Export-Csv -Path $outputFile -NoTypeInformation

        Write-ForensicLog "Saved Shadow Copy information to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error retrieving Shadow Copies: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-ShadowCopies

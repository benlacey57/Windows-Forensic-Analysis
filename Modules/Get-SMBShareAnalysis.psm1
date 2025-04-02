<#
.SYNOPSIS
    Retrieves and analyses SMB shares.
    
.DESCRIPTION
    This module retrieves information about SMB shares on the local machine and analyses
    them for potential security risks, such as open shares with write access or
    shares with weak permissions. The results are saved to a CSV file.
    
.EXAMPLE
    $smbShareAnalysisFile = Get-SmbShareAnalysis
    
.OUTPUTS
    String. The path to the CSV file containing the SMB share analysis.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for complete share information.
#>

function Get-SmbShareAnalysis {
    param()

    $outputFile = "$script:outputDir\SmbShareAnalysis_$script:timestamp.csv"
    Write-ForensicLog "Analysing SMB shares..."

    try {
        $shares = Get-SmbShare | Select-Object Name, Path, Description, FolderEnumerationMode, CurrentUsers, SpecialType

        $shareAnalysis = foreach ($share in $shares) {
            $shareObject = [PSCustomObject]@{
                Name                  = $share.Name
                Path                  = $share.Path
                Description           = $share.Description
                FolderEnumerationMode = $share.FolderEnumerationMode
                CurrentUsers          = $share.CurrentUsers
                SpecialType           = $share.SpecialType
                Permissions           = ""
                PotentialRisks        = @()
            }

            try {
                $acl = Get-Acl -Path $share.Path
                $shareObject.Permissions = ($acl.Access | ForEach-Object { "$($_.FileSystemRights) - $($_.IdentityReference)" }) -join ";"

                # Analyse permissions for potential risks
                foreach ($access in $acl.Access) {
                    if ($access.FileSystemRights -match "FullControl|Change|Write" -and $access.IdentityReference -match "Everyone|Users|Authenticated Users") {
                        $shareObject.PotentialRisks += "Open share with write access: $($access.IdentityReference)"
                    }
                }

                if ($share.CurrentUsers -gt 0 -and $share.FolderEnumerationMode -eq "AccessBased") {
                    $shareObject.PotentialRisks += "Active users and Access-Based Enumeration"
                }

                if($share.SpecialType -eq 'IPC'){
                    $shareObject.PotentialRisks += "IPC$ share"
                }

                if($share.SpecialType -eq 'ADMIN'){
                    $shareObject.PotentialRisks += "ADMIN$ share"
                }

            }
            catch {
                Write-Verbose "Could not get ACL for share: $($share.Name) - $_"
            }

            $shareObject
        }

        # Save to CSV
        $shareAnalysis | Export-Csv -Path $outputFile -NoTypeInformation

        Write-ForensicLog "Saved SMB share analysis to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error analysing SMB shares: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-SmbShareAnalysis

<#
.SYNOPSIS
    Retrieves and analyses unusual SSL certificates from browser stores.
    
.DESCRIPTION
    This module scans the certificate stores of Google Chrome, Microsoft Edge, Firefox, and Internet Explorer
    for unusual SSL certificates. The results are saved to a CSV file.
    
.EXAMPLE
    $unusualCertsFile = Get-UnusualCertificates
    
.OUTPUTS
    String. The path to the CSV file containing the unusual certificate analysis.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for access to browser certificate stores.
#>

function Get-UnusualCertificates {
    param()

    $outputFile = "$script:outputDir\UnusualCertificates_$script:timestamp.csv"
    Write-ForensicLog "Analysing browser certificate stores for unusual certificates..."

    try {
        $certData = @()

        # Google Chrome/Edge Certificate Store
        $chromeEdgeCerts = Get-ChildItem -Path "Cert:\CurrentUser\Root" | Where-Object {$_.Issuer -match "CN=.*Google Trust Services.*|CN=.*Microsoft Root Certificate Authority.*" -eq $false}
        foreach ($cert in $chromeEdgeCerts) {
            $certData += [PSCustomObject]@{
                Browser     = "Chrome/Edge"
                Subject     = $cert.Subject
                Issuer      = $cert.Issuer
                Thumbprint  = $cert.Thumbprint
                NotBefore   = $cert.NotBefore
                NotAfter    = $cert.NotAfter
                Description = "Unusual certificate found in Chrome/Edge store."
                Severity    = "Medium"
            }
        }

        # Firefox Certificate Store (Requires parsing cert8.db/cert9.db)
        # This example uses a placeholder. In a real scenario, you'd need to use a tool like certutil.exe (nss) or implement custom parsing.
        $firefoxCerts = Parse-FirefoxCertificates
        if ($firefoxCerts) {
            foreach ($cert in $firefoxCerts) {
                $certData += [PSCustomObject]@{
                    Browser     = "Firefox"
                    Subject     = $cert.Subject
                    Issuer      = $cert.Issuer
                    Thumbprint  = $cert.Thumbprint
                    NotBefore   = $cert.NotBefore
                    NotAfter    = $cert.NotAfter
                    Description = "Unusual certificate found in Firefox store."
                    Severity    = "Medium"
                }
            }
        }

        # Internet Explorer Certificate Store
        $ieCerts = Get-ChildItem -Path "Cert:\CurrentUser\Root" | Where-Object {$_.Issuer -match "CN=.*Microsoft Root Certificate Authority.*" -eq $false}
        foreach ($cert in $ieCerts) {
            $certData += [PSCustomObject]@{
                Browser     = "Internet Explorer"
                Subject     = $cert.Subject
                Issuer      = $cert.Issuer
                Thumbprint  = $cert.Thumbprint
                NotBefore   = $cert.NotBefore
                NotAfter    = $cert.NotAfter
                Description = "Unusual certificate found in Internet Explorer store."
                Severity    = "Medium"
            }
        }

        # Save to CSV
        $certData | Export-Csv -Path $outputFile -NoTypeInformation

        Write-ForensicLog "Saved unusual certificate analysis to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error analysing browser certificate stores: $_" -Severity "Error"
        return $null
    }
}

# Placeholder for Firefox certificate parsing (replace with actual parsing logic)
function Parse-FirefoxCertificates {
    # Replace this placeholder with your actual Firefox certificate parsing logic
    # You can use a tool like certutil.exe (nss) or implement custom parsing.
    # Example placeholder output (replace with real data)
    return @() # return empty array if there is no data.
}

# Export function
Export-ModuleMember -Function Get-UnusualCertificates

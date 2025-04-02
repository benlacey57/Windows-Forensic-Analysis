<#
.SYNOPSIS
    Encrypts and protects forensic reports.
    
.DESCRIPTION
    This module encrypts forensic reports using AES encryption and optionally
    signs them to ensure integrity. It provides functions to encrypt, decrypt,
    and verify the integrity of reports.
    
.EXAMPLE
    $protectedReport = Protect-ForensicReport -ReportPath "C:\ForensicsDqta\Report.html" -Key "YourSecretKey"
    Unprotect-ForensicReport -ProtectedReportPath $protectedReport -Key "YourSecretKey" -OutputPath "C:\ForensicsData\DecryptedReport.html"
    
.OUTPUTS
    String. The path to the protected (encrypted) report.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: None.
#>

function Protect-ForensicReport {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ReportPath,

        [Parameter(Mandatory = $true)]
        [string]$Key,

        [switch]$SignReport # Optional: Sign the report for integrity
    )

    $protectedReportPath = "$ReportPath.protected"
    Write-ForensicLog "Protecting forensic report: $ReportPath"

    try {
        # Read the report content
        $reportContent = Get-Content -Path $ReportPath -Raw

        # Generate a random salt
        $salt = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
        $saltBytes = New-Object byte[] 32
        $salt.GetBytes($saltBytes)

        # Derive the encryption key
        $keyBytes = (New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $Key, $saltBytes, 1000).GetBytes(32)

        # Create an AES encryptor
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $keyBytes
        $aes.GenerateIV()

        # Encrypt the report content
        $encryptor = $aes.CreateEncryptor()
        $encryptedBytes = $encryptor.TransformFinalBlock([System.Text.Encoding]::UTF8.GetBytes($reportContent), 0, [System.Text.Encoding]::UTF8.GetBytes($reportContent).Length)

        # Combine salt, IV, and encrypted data
        $combinedData = $saltBytes + $aes.IV + $encryptedBytes

        # Optionally sign the report
        if ($SignReport) {
            # Generate a signature
            $signature = [System.Security.Cryptography.HMACSHA256]::Create()
            $signature.Key = $keyBytes
            $reportSignature = $signature.ComputeHash($combinedData)

            # Combine signature with encrypted data
            $combinedData += $reportSignature
        }

        # Save the protected report
        [System.IO.File]::WriteAllBytes($protectedReportPath, $combinedData)

        Write-ForensicLog "Forensic report protected successfully: $protectedReportPath"
        return $protectedReportPath
    }
    catch {
        Write-ForensicLog "Error protecting forensic report: $_" -Severity "Error"
        return $null
    }
}

function Unprotect-ForensicReport {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ProtectedReportPath,

        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [switch]$VerifySignature # Optional: Verify the report signature
    )

    Write-ForensicLog "Unprotecting forensic report: $ProtectedReportPath"

    try {
        # Read the protected report content
        $combinedData = [System.IO.File]::ReadAllBytes($ProtectedReportPath)

        # Extract salt and IV
        $saltBytes = $combinedData[0..31]
        $ivBytes = $combinedData[32..47]
        $encryptedBytes = $combinedData[48..($combinedData.Length - 1)]

        # Derive the encryption key
        $keyBytes = (New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $Key, $saltBytes, 1000).GetBytes(32)

        # Create an AES decryptor
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $keyBytes
        $aes.IV = $ivBytes

        # Decrypt the report content
        $decryptor = $aes.CreateDecryptor()
        $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
        $decryptedContent = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)

        # Verify signature if requested
        if ($VerifySignature) {
            # Extract signature
            $reportSignature = $combinedData[($combinedData.Length - 32)..($combinedData.Length - 1)]
            $originalData = $combinedData[0..($combinedData.Length - 33)]

            # Verify signature
            $signature = [System.Security.Cryptography.HMACSHA256]::Create()
            $signature.Key = $keyBytes
            $calculatedSignature = $signature.ComputeHash($originalData)

            if (-not ([System.Collections.StructuralComparisons]::StructuralEquals($reportSignature, $calculatedSignature))) {
                Write-ForensicLog "Signature verification failed: $ProtectedReportPath" -Severity "Error"
                return
            }
        }

        # Save the unprotected report
        [System.IO.File]::WriteAllText($OutputPath, $decryptedContent)

        Write-ForensicLog "Forensic report unprotected successfully: $OutputPath"
    }
    catch {
        Write-ForensicLog "Error unprotecting forensic report: $_" -Severity "Error"
    }
}

# Export functions
Export-ModuleMember -Function Protect-ForensicReport, Unprotect-ForensicReport

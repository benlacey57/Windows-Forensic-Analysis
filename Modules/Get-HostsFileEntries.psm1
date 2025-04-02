<#
.SYNOPSIS
    Analyzes hosts file for suspicious entries and potential DNS hijacking.
    
.DESCRIPTION
    Get-HostsFileEntries examines the Windows hosts file for suspicious entries
    that could indicate DNS hijacking or malicious redirection. It identifies
    entries redirecting to unusual IP addresses, high-value domains being redirected,
    and other potential security issues related to host file manipulation.
    
.EXAMPLE
    $hostsFileEntries = Get-HostsFileEntries
    
.OUTPUTS
    Array of PSCustomObject containing hosts file entry analysis results
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Standard user privileges sufficient
#>

function Get-HostsFileEntries {
    param()

    $outputFile = "$script:outputDir\HostsFileEntries_$script:timestamp.csv"
    Write-ForensicLog "Analyzing hosts file entries..."

    try {
        # Initialize findings collection
        $findings = @()
        
        $hostsFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"
        
        if (Test-Path $hostsFilePath) {
            $hostsContent = Get-Content -Path $hostsFilePath -ErrorAction SilentlyContinue
            
            # Skip comment lines and empty lines
            $hostsEntries = $hostsContent | Where-Object { $_ -match '^\s*\d+\.\d+\.\d+\.\d+' }
            
            # Common legitimate localhost entries
            $legitimateEntries = @(
                "^127\.0\.0\.1\s+localhost$",
                "^::1\s+localhost$",
                "^127\.0\.0\.1\s+$env:COMPUTERNAME$",
                "^127\.0\.0\.1\s+$env:COMPUTERNAME\.$env:USERDNSDOMAIN$"
            )
            
            # Common ad-blocking hosts entries
            $adBlockingDomains = @(
                "googlesyndication", "doubleclick", "googleadservices", "google-analytics",
                "advertising", "banners", "adserving", "adsystem", "tracking", "metrics",
                "analytics", "telemetry", "statistics", "advert"
            )
            
            foreach ($entry in $hostsEntries) {
                # Parse the hosts file entry
                $entryParts = $entry -split '\s+', 2
                $ipAddress = $entryParts[0]
                $hostname = $entryParts[1]
                
                # Skip if line doesn't have both parts
                if (-not $ipAddress -or -not $hostname) {
                    continue
                }
                
                # Remove comments from hostname
                $hostname = ($hostname -split '#')[0].Trim()
                
                # Skip empty hostnames
                if ([string]::IsNullOrWhiteSpace($hostname)) {
                    continue
                }
                
                $suspiciousScore = 0
                $description = "Hosts file entry: $ipAddress $hostname"
                
                # Check if this is a legitimate entry
                $isLegitimate = $false
                foreach ($pattern in $legitimateEntries) {
                    if ($entry -match $pattern) {
                        $isLegitimate = $true
                        break
                    }
                }
                
                # Skip common legitimate entries
                if ($isLegitimate) {
                    continue
                }
                
                # Check if this is likely an ad-blocking entry
                $isAdBlocking = $false
                if ($ipAddress -eq "0.0.0.0" -or $ipAddress -eq "127.0.0.1") {
                    foreach ($adDomain in $adBlockingDomains) {
                        if ($hostname -like "*$adDomain*") {
                            $isAdBlocking = $true
                            break
                        }
                    }
                }
                
                if ($isAdBlocking) {
                    $description += " (Likely ad-blocking entry)"
                }
                else {
                    # Potentially suspicious entry
                    $suspiciousScore += 2
                    
                    # Redirecting common domains is highly suspicious
                    $highValueDomains = @(
                        "google.com", "bing.com", "yahoo.com", "microsoft.com", "apple.com",
                        "amazon.com", "facebook.com", "twitter.com", "linkedin.com", "github.com",
                        "live.com", "outlook.com", "office.com", "windows.com", "windowsupdate.com",
                        "mozilla.org", "firefox.com", "adobe.com", "paypal.com", "ebay.com",
                        "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com"
                    )
                    
                    foreach ($domain in $highValueDomains) {
                        if ($hostname -eq $domain -or $hostname -like "*.$domain") {
                            $suspiciousScore += 3
                            $description += " (Redirecting high-value domain)"
                            break
                        }
                    }
                    
                    # Security-related domains being redirected is even more suspicious
                    $securityDomains = @(
                        "antivirus", "security", "secure", "norton", "mcafee", "kaspersky",
                        "avg", "avast", "trend", "symantec", "sophos", "defender", "malware",
                        "virus", "firewall", "cert", "update", "patch"
                    )
                    
                    foreach ($secDomain in $securityDomains) {
                        if ($hostname -like "*$secDomain*") {
                            $suspiciousScore += 4
                            $description += " (Redirecting security-related domain)"
                            break
                        }
                    }
                    
                    # Check if redirecting to unusual IP
                    if ($ipAddress -ne "127.0.0.1" -and $ipAddress -ne "0.0.0.0" -and 
                        -not ($ipAddress -match "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)")) {
                        $suspiciousScore += 2
                        $description += " (Redirecting to non-standard IP)"
                    }
                }
                
                # Add to findings
                $findings += [PSCustomObject]@{
                    EntryType = "Hosts File Entry"
                    Hostname = $hostname
                    IPAddress = $ipAddress
                    Location = $hostsFilePath
                    IsAdBlocking = $isAdBlocking
                    SuspiciousScore = $suspiciousScore
                    Description = $description
                }
            }
        }
        else {
            # Missing hosts file is unusual
            $findings += [PSCustomObject]@{
                EntryType = "Hosts File Status"
                Hostname = "N/A"
                IPAddress = "N/A"
                Location = "$env:SystemRoot\System32\drivers\etc\hosts"
                IsAdBlocking = $false
                SuspiciousScore = 3
                Description = "System hosts file is missing - potential tampering or misconfiguration"
            }
        }
        
        # Export results
        if ($findings.Count -gt 0) {
            # Sort findings by suspicious score
            $sortedFindings = $findings | Sort-Object -Property SuspiciousScore -Descending
            $sortedFindings | Export-Csv -Path $outputFile -NoTypeInformation
            
            # Log high-risk findings
            $highRiskFindings = $sortedFindings | Where-Object { $_.SuspiciousScore -ge 3 }
            if ($highRiskFindings.Count -gt 0) {
                Write-ForensicLog "Found $($highRiskFindings.Count) suspicious hosts file entries:" -Severity "Warning"
                foreach ($finding in $highRiskFindings | Select-Object -First 5) {
                    Write-ForensicLog "  - $($finding.Hostname) -> $($finding.IPAddress) - $($finding.Description)" -Severity "Warning"
                }
            }
        } else {
            Write-ForensicLog "No suspicious hosts file entries detected"
            # Create an empty file to indicate analysis was performed
            [PSCustomObject]@{
                Result = "No suspicious hosts file entries detected"
                AnalysisTime = Get-Date
                SystemName = $env:COMPUTERNAME
            } | Export-Csv -Path $outputFile -NoTypeInformation
        }
        
        Write-ForensicLog "Saved hosts file analysis to $outputFile"
        return [PSCustomObject]@{
            Findings = $findings
            OutputFile = $outputFile
        }
    }
    catch {
        Write-ForensicLog "Error analyzing hosts file: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-HostsFileEntries
<#
.SYNOPSIS
    Analyzes DNS settings and identifies potential DNS-related security issues.
    
.DESCRIPTION
    Get-DnsSettings examines DNS client and server configurations on Windows systems,
    checking for potential DNS hijacking, unusual DNS servers, DNS cache entries,
    and other DNS-related security issues that could indicate network tampering.
    
.EXAMPLE
    $dnsSettingsFile = Get-DnsSettings
    
.OUTPUTS
    String. The path to the CSV file containing DNS settings analysis results
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges recommended for complete results
#>

# Import the hosts file analysis module
Import-Module "$PSScriptRoot\Get-HostsFileEntries.psm1" -ErrorAction SilentlyContinue

function Get-DnsSettings {
    param()

    $outputFile = "$script:outputDir\DnsSettings_$script:timestamp.csv"
    Write-ForensicLog "Analyzing DNS settings..."

    try {
        # Initialize findings collection
        $dnsFindings = @()
        
        # Collect DNS client settings
        $dnsClientSettings = Get-DnsClientConfiguration
        $dnsFindings += $dnsClientSettings
        
        # Collect hosts file entries using the separate module
        # First check if module was imported successfully
        if (Get-Command -Name Get-HostsFileEntries -ErrorAction SilentlyContinue) {
            Write-ForensicLog "Collecting hosts file entries from separate module..."
            
            # Call the hosts file module
            $hostsFileResults = Get-HostsFileEntries
            
            # Add any findings to our DNS results
            if ($hostsFileResults -and $hostsFileResults.Findings) {
                # Convert hosts file findings to DNS findings format
                foreach ($hostEntry in $hostsFileResults.Findings) {
                    $dnsFindings += [PSCustomObject]@{
                        SettingType = "Hosts File"
                        SettingName = "hosts: $($hostEntry.Hostname)"
                        SettingValue = $hostEntry.IPAddress
                        IsPublicDNS = $false
                        PublicDNSName = ""
                        InterfaceName = "Hosts File"
                        InterfaceDescription = "System Hosts File"
                        SuspiciousScore = $hostEntry.SuspiciousScore
                        Description = $hostEntry.Description
                    }
                }
            }
        }
        else {
            Write-ForensicLog "Hosts file module not available, skipping hosts file analysis" -Severity "Warning"
        }
        
        # Check for DNS cache poisoning evidence
        $dnsCacheEntries = Get-DnsCacheEntries
        $dnsFindings += $dnsCacheEntries
        
        # Check for DNS security issues
        $dnsSecurityIssues = Get-DnsSecurityConfiguration
        $dnsFindings += $dnsSecurityIssues
        
        # Export results
        if ($dnsFindings.Count -gt 0) {
            # Sort findings by suspicious score
            $sortedFindings = $dnsFindings | Sort-Object -Property SuspiciousScore -Descending
            $sortedFindings | Export-Csv -Path $outputFile -NoTypeInformation
            
            # Log summary of findings
            $highRiskCount = ($sortedFindings | Where-Object { $_.SuspiciousScore -ge 4 }).Count
            $mediumRiskCount = ($sortedFindings | Where-Object { $_.SuspiciousScore -ge 2 -and $_.SuspiciousScore -lt 4 }).Count
            $lowRiskCount = ($sortedFindings | Where-Object { $_.SuspiciousScore -gt 0 -and $_.SuspiciousScore -lt 2 }).Count
            
            Write-ForensicLog "DNS analysis complete: $highRiskCount high risk, $mediumRiskCount medium risk, $lowRiskCount low risk findings"
            
            # Report high-risk findings
            if ($highRiskCount -gt 0) {
                Write-ForensicLog "High-risk DNS findings detected:" -Severity "Warning"
                foreach ($finding in ($sortedFindings | Where-Object { $_.SuspiciousScore -ge 4 } | Select-Object -First 5)) {
                    Write-ForensicLog "  - $($finding.SettingName): $($finding.SettingValue) - $($finding.Description)" -Severity "Warning"
                }
            }
        } else {
            Write-ForensicLog "No suspicious DNS settings detected"
            # Create an empty file to indicate analysis was performed
            [PSCustomObject]@{
                Result = "No suspicious DNS settings detected"
                AnalysisTime = Get-Date
                SystemName = $env:COMPUTERNAME
            } | Export-Csv -Path $outputFile -NoTypeInformation
        }
        
        Write-ForensicLog "Saved DNS settings analysis to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error analyzing DNS settings: $_" -Severity "Error"
        return $null
    }
}

function Get-DnsClientConfiguration {
    $findings = @()
    
    try {
        # Get all network adapters
        $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        
        # Known public DNS servers
        $knownPublicDnsServers = @{
            "8.8.8.8" = "Google Public DNS"
            "8.8.4.4" = "Google Public DNS"
            "1.1.1.1" = "Cloudflare DNS"
            "1.0.0.1" = "Cloudflare DNS"
            "9.9.9.9" = "Quad9 DNS"
            "149.112.112.112" = "Quad9 DNS"
            "208.67.222.222" = "OpenDNS"
            "208.67.220.220" = "OpenDNS"
            "64.6.64.6" = "Verisign DNS"
            "64.6.65.6" = "Verisign DNS"
            "84.200.69.80" = "DNS.WATCH"
            "84.200.70.40" = "DNS.WATCH"
            "8.26.56.26" = "Comodo Secure DNS"
            "8.20.247.20" = "Comodo Secure DNS"
            "195.46.39.39" = "SafeDNS"
            "195.46.39.40" = "SafeDNS"
            "77.88.8.8" = "Yandex DNS"
            "77.88.8.1" = "Yandex DNS"
            "76.76.19.19" = "Alternate DNS"
            "76.76.2.0" = "Alternate DNS"
            "94.140.14.14" = "AdGuard DNS"
            "94.140.15.15" = "AdGuard DNS"
        }
        
        foreach ($adapter in $networkAdapters) {
            # Get DNS settings for the adapter
            $dnsConfig = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex | 
                        Where-Object { $_.AddressFamily -eq 2 }  # IPv4 addresses
            
            if ($dnsConfig -and $dnsConfig.ServerAddresses) {
                foreach ($dnsServer in $dnsConfig.ServerAddresses) {
                    $suspiciousScore = 0
                    $description = ""
                    
                    # Determine if this is a known public DNS server
                    $isKnownPublic = $knownPublicDnsServers.ContainsKey($dnsServer)
                    $publicDnsName = if ($isKnownPublic) { $knownPublicDnsServers[$dnsServer] } else { "Unknown" }
                    
                    # Check if the DNS server is within typical private ranges
                    $isPrivateRange = $dnsServer -match "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.)"
                    
                    # Evaluate suspiciousness based on various factors
                    if ($isKnownPublic) {
                        # Using public DNS is common but worth noting
                        $suspiciousScore += 0
                        $description = "Known public DNS server: $publicDnsName"
                    }
                    elseif ($isPrivateRange) {
                        # Private range DNS is normal, but we'll check if it's the expected pattern
                        $domainInfo = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Domain
                        
                        if ($domainInfo -and $domainInfo -ne "WORKGROUP") {
                            # System is domain-joined, so should be using domain DNS
                            # This is just informational
                            $description = "Private range DNS server in domain environment: $dnsServer"
                        }
                        else {
                            # System is in workgroup, likely using router or ISP DNS
                            $description = "Private range DNS server in workgroup environment: $dnsServer"
                        }
                    }
                    else {
                        # Unknown public IP as DNS - somewhat suspicious
                        $suspiciousScore += 2
                        $description = "Non-standard public DNS server: $dnsServer"
                        
                        # Try to do a reverse lookup to identify the DNS server
                        try {
                            $hostEntry = [System.Net.Dns]::GetHostEntry($dnsServer)
                            if ($hostEntry.HostName) {
                                $description += " (Hostname: $($hostEntry.HostName))"
                            }
                        }
                        catch {
                            # Failed to resolve - more suspicious
                            $suspiciousScore += 1
                            $description += " (Hostname resolution failed)"
                        }
                    }
                    
                    # Check if DNS server is actually reachable
                    $pingResult = Test-Connection -ComputerName $dnsServer -Count 1 -Quiet -ErrorAction SilentlyContinue
                    if (-not $pingResult) {
                        $suspiciousScore += 2
                        $description += " (DNS server not responding to ping)"
                    }
                    
                    # Add to findings
                    $findings += [PSCustomObject]@{
                        SettingType = "DNS Server"
                        SettingName = "DNS Server ($($adapter.Name))"
                        SettingValue = $dnsServer
                        IsPublicDNS = $isKnownPublic
                        PublicDNSName = $publicDnsName
                        InterfaceName = $adapter.Name
                        InterfaceDescription = $adapter.InterfaceDescription
                        SuspiciousScore = $suspiciousScore
                        Description = $description
                    }
                }
            }
            else {
                # No DNS servers configured is unusual
                $findings += [PSCustomObject]@{
                    SettingType = "DNS Server"
                    SettingName = "No DNS Servers ($($adapter.Name))"
                    SettingValue = "None configured"
                    IsPublicDNS = $false
                    PublicDNSName = ""
                    InterfaceName = $adapter.Name
                    InterfaceDescription = $adapter.InterfaceDescription
                    SuspiciousScore = 3
                    Description = "No DNS servers configured for this adapter - potential connectivity issues or DNS bypass"
                }
            }
        }
        
        # Check global DNS suffix search order
        $dnsSuffixes = Get-DnsClientGlobalSetting
        if ($dnsSuffixes.SuffixSearchList -and $dnsSuffixes.SuffixSearchList.Count -gt 0) {
            foreach ($suffix in $dnsSuffixes.SuffixSearchList) {
                $suspiciousScore = 0
                $description = "DNS Suffix: $suffix"
                
                # Unusual TLDs can be suspicious
                $unusualTlds = @(".local", ".internal", ".lan", ".corp", ".home")
                $tld = "." + ($suffix -split "\.")[-1]
                
                if ($tld -in $unusualTlds) {
                    $suspiciousScore += 1
                    $description += " (Non-standard TLD)"
                }
                
                $findings += [PSCustomObject]@{
                    SettingType = "DNS Suffix"
                    SettingName = "DNS Suffix Search List"
                    SettingValue = $suffix
                    IsPublicDNS = $false
                    PublicDNSName = ""
                    InterfaceName = "Global"
                    InterfaceDescription = "DNS Client Global Configuration"
                    SuspiciousScore = $suspiciousScore
                    Description = $description
                }
            }
        }
        
        # Check DNS client settings
        $dnsClient = Get-DnsClient
        foreach ($client in $dnsClient) {
            # Check if LLMNR is enabled (potential security risk)
            if ($client.LLMNR -eq "Enabled") {
                $findings += [PSCustomObject]@{
                    SettingType = "DNS Client"
                    SettingName = "LLMNR Enabled ($($client.InterfaceAlias))"
                    SettingValue = "Enabled"
                    IsPublicDNS = $false
                    PublicDNSName = ""
                    InterfaceName = $client.InterfaceAlias
                    InterfaceDescription = "DNS Client Configuration"
                    SuspiciousScore = 2
                    Description = "Link-Local Multicast Name Resolution (LLMNR) is enabled - potential vector for MITM attacks"
                }
            }
            
            # Check if NetBIOS is enabled (potential security risk)
            $netbiosOption = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | 
                            Where-Object { $_.InterfaceIndex -eq $client.InterfaceIndex } | 
                            Select-Object -ExpandProperty TcpipNetbiosOptions -ErrorAction SilentlyContinue
            
            if ($netbiosOption -eq 0 -or $netbiosOption -eq 1) {
                $findings += [PSCustomObject]@{
                    SettingType = "DNS Client"
                    SettingName = "NetBIOS Enabled ($($client.InterfaceAlias))"
                    SettingValue = "Enabled"
                    IsPublicDNS = $false
                    PublicDNSName = ""
                    InterfaceName = $client.InterfaceAlias
                    InterfaceDescription = "NetBIOS Configuration"
                    SuspiciousScore = 2
                    Description = "NetBIOS name resolution is enabled - potential vector for MITM attacks"
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error gathering DNS client configuration: $_" -Severity "Warning"
    }
    
    return $findings
}

function Get-DnsCacheEntries {
    $findings = @()
    
    try {
        # Get DNS cache entries
        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
        
        if ($dnsCache) {
            # Known suspicious TLDs and domain patterns
            $suspiciousTlds = @(".top", ".xyz", ".tk", ".pw", ".ml", ".ga", ".cf", ".gq", ".cc", ".ru", ".cn", ".su")
            $suspiciousDomainPatterns = @(
                "^[a-z0-9]{10,}\.",        # Long random-looking subdomains
                "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP addresses in domain names
                "^[a-f0-9]{8,}\.onion\."   # Onion domains leaking to DNS
            )
            
            # High-value domains that might be targeted for spoofing
            $highValueDomains = @(
                "google.com", "bing.com", "yahoo.com", "microsoft.com", "apple.com",
                "amazon.com", "facebook.com", "twitter.com", "linkedin.com", "github.com",
                "live.com", "outlook.com", "office.com", "windows.com", "windowsupdate.com",
                "mozilla.org", "firefox.com", "adobe.com", "paypal.com", "ebay.com",
                "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com"
            )
            
            foreach ($entry in $dnsCache) {
                $suspiciousScore = 0
                $description = "DNS Cache entry: $($entry.Name) -> $($entry.Data)"
                
                # Skip common Windows and Microsoft domains
                if ($entry.Name -like "*.microsoft.com" -or 
                    $entry.Name -like "*.windows.com" -or 
                    $entry.Name -like "*.windowsupdate.com") {
                    continue
                }
                
                # Check for suspicious TLDs
                foreach ($tld in $suspiciousTlds) {
                    if ($entry.Name -like "*$tld") {
                        $suspiciousScore += 1
                        $description += " (Suspicious TLD)"
                        break
                    }
                }
                
                # Check for suspicious domain patterns
                foreach ($pattern in $suspiciousDomainPatterns) {
                    if ($entry.Name -match $pattern) {
                        $suspiciousScore += 2
                        $description += " (Suspicious domain pattern)"
                        break
                    }
                }
                
                # Check for high-value domains with unusual IPs
                foreach ($domain in $highValueDomains) {
                    if ($entry.Name -eq $domain -or $entry.Name -like "*.$domain") {
                        # Verify the IP address against expected patterns
                        $entryData = $entry.Data

                        # Attempt to do an independent DNS lookup for comparison
                        try {
                            $actualIp = [System.Net.Dns]::GetHostAddresses($domain) | 
                                        Select-Object -ExpandProperty IPAddressToString -First 1
                            
                            if ($entryData -ne $actualIp) {
                                $suspiciousScore += 4
                                $description += " (IP mismatch: expected $actualIp)"
                            }
                        }
                        catch {
                            # Can't resolve for comparison
                        }
                        
                        break
                    }
                }
                
                # Add suspicious entries to findings
                if ($suspiciousScore -gt 0) {
                    $findings += [PSCustomObject]@{
                        SettingType = "DNS Cache"
                        SettingName = "Cache: $($entry.Name)"
                        SettingValue = $entry.Data
                        IsPublicDNS = $false
                        PublicDNSName = ""
                        InterfaceName = "DNS Cache"
                        InterfaceDescription = "DNS Client Cache"
                        SuspiciousScore = $suspiciousScore
                        Description = $description
                    }
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error analyzing DNS cache: $_" -Severity "Warning"
    }
    
    return $findings
}

function Get-DnsSecurityConfiguration {
    $findings = @()
    
    try {
        # Check if the system is using secure DNS (DoH, DoT)
        $secureDnsEnabled = $false
        
        # Check for DoH in Windows settings (Windows 10 version 2004 and later)
        try {
            $dohSetting = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -ErrorAction SilentlyContinue
            
            if ($dohSetting -and $dohSetting.EnableAutoDoh -eq 2) {
                $secureDnsEnabled = $true
                $findings += [PSCustomObject]@{
                    SettingType = "DNS Security"
                    SettingName = "DNS over HTTPS (DoH)"
                    SettingValue = "Enabled"
                    IsPublicDNS = $false
                    PublicDNSName = ""
                    InterfaceName = "System"
                    InterfaceDescription = "DNS Security Configuration"
                    SuspiciousScore = 0
                    Description = "DNS over HTTPS is enabled - provides encrypted DNS lookups"
                }
            }
            elseif ($dohSetting -and $dohSetting.EnableAutoDoh -eq 0) {
                $findings += [PSCustomObject]@{
                    SettingType = "DNS Security"
                    SettingName = "DNS over HTTPS (DoH)"
                    SettingValue = "Disabled"
                    IsPublicDNS = $false
                    PublicDNSName = ""
                    InterfaceName = "System"
                    InterfaceDescription = "DNS Security Configuration"
                    SuspiciousScore = 1
                    Description = "DNS over HTTPS is explicitly disabled - DNS traffic is unencrypted"
                }
            }
        }
        catch {
            # DoH setting not available
        }
        
        # Check if DNSSEC validation is enabled
        try {
            $dnssecSetting = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableIdnMapping" -ErrorAction SilentlyContinue
            
            if ($dnssecSetting -and $dnssecSetting.EnableIdnMapping -eq 1) {
                $findings += [PSCustomObject]@{
                    SettingType = "DNS Security"
                    SettingName = "IDN Mapping"
                    SettingValue = "Enabled"
                    IsPublicDNS = $false
                    PublicDNSName = ""
                    InterfaceName = "System"
                    InterfaceDescription = "DNS Security Configuration"
                    SuspiciousScore = 0
                    Description = "Internationalized Domain Name (IDN) mapping is enabled - helps protect against homograph attacks"
                }
            }
            else {
                $findings += [PSCustomObject]@{
                    SettingType = "DNS Security"
                    SettingName = "IDN Mapping"
                    SettingValue = "Disabled"
                    IsPublicDNS = $false
                    PublicDNSName = ""
                    InterfaceName = "System"
                    InterfaceDescription = "DNS Security Configuration"
                    SuspiciousScore = 2
                    Description = "Internationalized Domain Name (IDN) mapping is disabled - potential vulnerability to homograph attacks"
                }
            }
        }
        catch {
            # IDN setting not available
        }

        # Check if DNS Client service is running
        $dnsClientService = Get-Service -Name "Dnscache" -ErrorAction SilentlyContinue
        
        if ($dnsClientService -and $dnsClientService.Status -ne "Running") {
            $findings += [PSCustomObject]@{
                SettingType = "DNS Service"
                SettingName = "DNS Client Service"
                SettingValue = $dnsClientService.Status
                IsPublicDNS = $false
                PublicDNSName = ""
                InterfaceName = "System"
                InterfaceDescription = "DNS Client Service"
                SuspiciousScore = 4
                Description = "DNS Client service is not running - potential indicator of DNS bypassing or tampering"
            }
        }
        
        # Check for DNS server service (unusual on client systems)
        $dnsServerService = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
        
        if ($dnsServerService -and $dnsServerService.Status -eq "Running") {
            # Check if this is a domain controller (where DNS server is expected)
            $isDomainController = $false
            try {
                $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
                if ($computerSystem -and $computerSystem.DomainRole -ge 4) {
                    $isDomainController = $true
                }
            }
            catch {
                # Can't determine if domain controller
            }
            
            if (-not $isDomainController) {
                $findings += [PSCustomObject]@{
                    SettingType = "DNS Service"
                    SettingName = "DNS Server Service"
                    SettingValue = $dnsServerService.Status
                    IsPublicDNS = $false
                    PublicDNSName = ""
                    InterfaceName = "System"
                    InterfaceDescription = "DNS Server Service"
                    SuspiciousScore = 3
                    Description = "DNS Server service is running on a non-domain controller - unusual configuration that could indicate DNS spoofing"
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error analyzing DNS security settings: $_" -Severity "Warning"
    }
    
    return $findings
}

# Export function
Export-ModuleMember -Function Get-DnsSettings
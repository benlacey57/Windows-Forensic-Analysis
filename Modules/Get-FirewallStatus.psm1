<#
.SYNOPSIS
    Checks Windows Firewall status and rules
    
.DESCRIPTION
    Analyzes the Windows Firewall configuration, including profiles status
    and rule settings. Identifies potentially suspicious or dangerous rules
    that could indicate compromise or create security vulnerabilities.
    
.EXAMPLE
    $firewallStatusFile = Get-FirewallStatus
    
.OUTPUTS
    String. The path to the CSV file containing firewall data
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for complete firewall information
#>

function Get-FirewallStatus {
    param()
    
    $outputFile = "$script:outputDir\Firewall_$script:timestamp.csv"
    Write-ForensicLog "Checking Windows Firewall status and rules..."
    
    try {
        # Get firewall status for each profile
        $firewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, 
            LogFileName, LogAllowed, LogBlocked, LogIgnored, LogMaxSizeKilobytes
        
        # Save firewall profiles status
        $firewallProfiles | Export-Csv -Path "$script:outputDir\FirewallProfiles_$script:timestamp.csv" -NoTypeInformation
        
        # Get all firewall rules
        $allRules = Get-NetFirewallRule | Select-Object Name, DisplayName, Description, DisplayGroup, Group, 
            Enabled, Profile, Direction, Action, EdgeTraversalPolicy, Owner, 
            @{Name="Protocol";Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).Protocol}},
            @{Name="LocalPort";Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).LocalPort}},
            @{Name="RemotePort";Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).RemotePort}},
            @{Name="RemoteAddress";Expression={(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_).RemoteAddress}},
            @{Name="Program";Expression={(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $_).Program}},
            @{Name="Service";Expression={(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $_).Service}}
        
        # Enhance rules with additional analysis
        foreach ($rule in $allRules) {
            # Add suspicious score and reasons
            $suspiciousScore = 0
            $suspiciousReasons = @()
            
            # Check for inbound allow rules that are enabled
            if ($rule.Direction -eq "Inbound" -and $rule.Action -eq "Allow" -and $rule.Enabled -eq "True") {
                # Check if the rule allows connections from any remote address
                if ($rule.RemoteAddress -contains "Any" -or $rule.RemoteAddress -eq "*") {
                    $suspiciousScore += 1
                    $suspiciousReasons += "Allows connections from any IP address"
                }
                
                # Check for rules allowing sensitive ports
                $sensitivePorts = @("3389", "22", "21", "23", "445", "135", "139", "5985", "5986", "4444")
                foreach ($port in $sensitivePorts) {
                    if ($rule.LocalPort -contains $port -or $rule.LocalPort -eq "*") {
                        $suspiciousScore += 2
                        $suspiciousReasons += "Allows access to sensitive port: $port"
                        break
                    }
                }
                
                # Check for rules that allow access to sensitive applications
                if ($rule.Program -match "powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32") {
                    $suspiciousScore += 3
                    $suspiciousReasons += "Allows network access to scripting or system tool"
                }
                
                # Check for recently created rules (check based on rule name convention for some vendors)
                if ($rule.Name -match "\d{8}" -or $rule.Name -match "\d{4}-\d{2}-\d{2}") {
                    $suspiciousScore += 1
                    $suspiciousReasons += "Possibly recently created rule (date in name)"
                }
                
                # Non-standard rule with high port
                if ($rule.LocalPort -match "\d{4,5}" -and $rule.LocalPort -ne "*" -and 
                    -not [string]::IsNullOrEmpty($rule.LocalPort) -and $rule.LocalPort -notin @("3389", "8080", "8443")) {
                    $suspiciousScore += 1
                    $suspiciousReasons += "Allows access to uncommon high port: $($rule.LocalPort)"
                }
            }
            
            # Check for outbound block rules that are disabled
            if ($rule.Direction -eq "Outbound" -and $rule.Action -eq "Block" -and $rule.Enabled -eq "False" -and
                $rule.DisplayName -match "security|protection|defender|firewall") {
                $suspiciousScore += 2
                $suspiciousReasons += "Disabled outbound security rule"
            }
            
            # Add suspicious score and reasons to rule object
            $rule | Add-Member -MemberType NoteProperty -Name "SuspiciousScore" -Value $suspiciousScore
            $rule | Add-Member -MemberType NoteProperty -Name "SuspiciousReasons" -Value ($suspiciousReasons -join "; ")
        }
        
        # Save all rules to a file
        $allRules | Export-Csv -Path $outputFile -NoTypeInformation
        
        # Check for disabled firewall
        $disabledProfiles = $firewallProfiles | Where-Object { $_.Enabled -eq $false }
        if ($disabledProfiles) {
            Write-ForensicLog "WARNING: The following firewall profiles are disabled: $($disabledProfiles.Name -join ', ')" -Severity "Warning"
        }
        
        # Check for suspicious rules
        $suspiciousRules = $allRules | Where-Object { $_.SuspiciousScore -gt 0 } | Sort-Object -Property SuspiciousScore -Descending
        if ($suspiciousRules.Count -gt 0) {
            Write-ForensicLog "Found $($suspiciousRules.Count) potentially risky firewall rules:" -Severity "Warning"
            foreach ($rule in $suspiciousRules | Select-Object -First 5) {
                Write-ForensicLog "  - $($rule.DisplayName): $($rule.Program) on port $($rule.LocalPort) - $($rule.SuspiciousReasons)" -Severity "Warning"
            }
            
            # Create a separate file for suspicious rules
            $suspiciousRules | Export-Csv -Path "$script:outputDir\SuspiciousFirewallRules_$script:timestamp.csv" -NoTypeInformation
        }
        
        Write-ForensicLog "Saved firewall data to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error checking firewall: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-FirewallStatus
<#
.SYNOPSIS
    Collects and analyzes Group Policy settings for security and configuration analysis.
    
.DESCRIPTION
    Get-GroupPolicySettings retrieves local and domain Group Policy settings,
    identifies security-relevant configurations, and highlights potentially risky
    or non-compliant settings that could affect system security.
    
.EXAMPLE
    $gpoSettingsFile = Get-GroupPolicySettings
    
.OUTPUTS
    String. The path to the CSV file containing Group Policy settings analysis
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges recommended for complete results
#>

function Get-GroupPolicySettings {
    param()

    $outputFile = "$script:outputDir\GroupPolicySettings_$script:timestamp.csv"
    Write-ForensicLog "Collecting Group Policy settings..."

    try {
        # Initialize configuration
        $config = Initialize-GPOConfiguration
        
        # Collect Group Policy settings
        $gpoSettings = @()
        $gpoSettings += Get-SecurityPolicySettings -Config $config
        $gpoSettings += Get-RegistryPolicySettings -Config $config
        $gpoSettings += Get-AuditPolicySettings -Config $config
        
        # Export findings
        if ($gpoSettings.Count -gt 0) {
            # Sort by category and then by setting name
            $sortedSettings = $gpoSettings | Sort-Object -Property Category, PolicyName
            $sortedSettings | Export-Csv -Path $outputFile -NoTypeInformation
            
            # Log summary
            $categories = $sortedSettings | Group-Object -Property Category
            
            Write-ForensicLog "Collected $($sortedSettings.Count) Group Policy settings across $($categories.Count) categories"
            
            # Log security issues
            $securityIssues = $sortedSettings | Where-Object { $_.ComplianceStatus -eq "Non-Compliant" }
            if ($securityIssues.Count -gt 0) {
                Write-ForensicLog "Found $($securityIssues.Count) Group Policy settings that may present security issues:" -Severity "Warning"
                foreach ($issue in ($securityIssues | Select-Object -First 5)) {
                    Write-ForensicLog "  - $($issue.Category) | $($issue.PolicyName): $($issue.ConfiguredValue) - $($issue.ComplianceIssue)" -Severity "Warning"
                }
            }
        } else {
            Write-ForensicLog "No Group Policy settings found"
            [PSCustomObject]@{
                Result = "No Group Policy settings found"
                AnalysisTime = Get-Date
                SystemName = $env:COMPUTERNAME
            } | Export-Csv -Path $outputFile -NoTypeInformation
        }
        
        Write-ForensicLog "Saved Group Policy settings to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error collecting Group Policy settings: $_" -Severity "Error"
        return $null
    }
}

function Initialize-GPOConfiguration {
    # Create a configuration object with security baselines and policy paths
    return @{
        # Registry paths for common Group Policy settings
        RegistryPaths = @{
            SecurityPolicy = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            NetworkPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections"
            WindowsUpdatePolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            PasswordPolicy = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            AuditPolicy = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            UserRightsPolicy = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            FirewallPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall"
            DefenderPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
            RemoteDesktopPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        }
        
        # Security baseline for common settings (simplified)
        SecurityBaseline = @{
            "NoLockScreenCamera" = @{
                RecommendedValue = 1
                Description = "Disable camera on lock screen"
                SecurityRationale = "Prevents potential privacy issues with lock screen camera"
                IsCritical = $false
            }
            "DisableCAD" = @{
                RecommendedValue = 0
                Description = "Require CTRL+ALT+DEL for login"
                SecurityRationale = "Helps prevent keyloggers from capturing credentials"
                IsCritical = $true
            }
            "EnableLUA" = @{
                RecommendedValue = 1
                Description = "User Account Control (UAC) enabled"
                SecurityRationale = "UAC helps prevent unauthorized elevation"
                IsCritical = $true
            }
            "ConsentPromptBehaviorAdmin" = @{
                RecommendedValue = @(1, 2)  # Array means any of these values is considered compliant
                Description = "UAC consent prompt behavior for administrators"
                SecurityRationale = "Proper UAC settings prevent silent elevation"
                IsCritical = $true
            }
            "FilterAdministratorToken" = @{
                RecommendedValue = 1
                Description = "Admin Approval Mode for built-in admin"
                SecurityRationale = "Ensures Administrator account has UAC protection"
                IsCritical = $true
            }
            "EnableSecureUIAPaths" = @{
                RecommendedValue = 1
                Description = "UAC virtualization enabled"
                SecurityRationale = "Provides additional isolation for UAC processes"
                IsCritical = $false
            }
            "MaxPasswordAge" = @{
                RecommendedValue = @(30..90)  # Range indicates acceptable values
                Description = "Maximum password age (days)"
                SecurityRationale = "Ensures passwords are changed regularly"
                IsCritical = $true
            }
            "MinimumPasswordLength" = @{
                RecommendedValue = @(8..14)
                Description = "Minimum password length"
                SecurityRationale = "Longer passwords provide better security"
                IsCritical = $true
            }
            "PasswordComplexity" = @{
                RecommendedValue = 1
                Description = "Password complexity requirements"
                SecurityRationale = "Complex passwords are harder to crack"
                IsCritical = $true
            }
            "LockoutThreshold" = @{
                RecommendedValue = @(3..10)
                Description = "Account lockout threshold"
                SecurityRationale = "Prevents brute force password attacks"
                IsCritical = $true
            }
            "AUOptions" = @{
                RecommendedValue = @(3, 4)
                Description = "Windows Update configuration"
                SecurityRationale = "Automatic updates ensure security patches are applied"
                IsCritical = $true
            }
        }
    }
}

function Get-SecurityPolicySettings {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    $settings = @()
    
    try {
        # Export security policy to a temporary file
        $secpolFile = "$env:TEMP\secpol_$script:timestamp.txt"
        
        # Use secedit to export the security policy
        $null = Start-Process -FilePath "secedit.exe" -ArgumentList "/export /cfg `"$secpolFile`" /quiet" -NoNewWindow -Wait
        
        if (Test-Path $secpolFile) {
            $securityPolicy = Get-Content -Path $secpolFile -Raw
            
            # Parse security policy sections
            $settings += Parse-PasswordPolicy -PolicyContent $securityPolicy -Config $Config
            $settings += Parse-AccountLockoutPolicy -PolicyContent $securityPolicy -Config $Config
            $settings += Parse-UserRightsPolicy -PolicyContent $securityPolicy -Config $Config
            
            # Clean up temporary file
            Remove-Item -Path $secpolFile -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-ForensicLog "Error retrieving security policy settings: $_" -Severity "Warning"
    }
    
    return $settings
}

function Parse-PasswordPolicy {
    param (
        [string]$PolicyContent,
        [hashtable]$Config
    )
    
    $settings = @()
    $baseline = $Config.SecurityBaseline
    
    # Extract password policy section
    if ($PolicyContent -match "\[System Access\](.*?)(\[\w+\]|\Z)") {
        $passwordSection = $matches[1]
        
        # Extract password settings
        $passwordSettings = @{
            "MinimumPasswordAge" = Extract-PolicyValue -Section $passwordSection -Setting "MinimumPasswordAge"
            "MaximumPasswordAge" = Extract-PolicyValue -Section $passwordSection -Setting "MaximumPasswordAge"
            "MinimumPasswordLength" = Extract-PolicyValue -Section $passwordSection -Setting "MinimumPasswordLength"
            "PasswordComplexity" = Extract-PolicyValue -Section $passwordSection -Setting "PasswordComplexity"
            "PasswordHistorySize" = Extract-PolicyValue -Section $passwordSection -Setting "PasswordHistorySize"
            "ClearTextPassword" = Extract-PolicyValue -Section $passwordSection -Setting "ClearTextPassword"
        }
        
        # Process each setting
        foreach ($setting in $passwordSettings.Keys) {
            $value = $passwordSettings[$setting]
            
            if ($value -ne $null) {
                $complianceData = Get-ComplianceStatus -SettingName $setting -Value $value -Baseline $baseline
                
                $settings += [PSCustomObject]@{
                    Category = "Password Policy"
                    PolicyName = Get-SettingDisplayName -SettingName $setting
                    ConfiguredValue = $value
                    RecommendedValue = $complianceData.RecommendedValue
                    IsConfigured = $true
                    Source = "Security Policy"
                    ComplianceStatus = $complianceData.Status
                    ComplianceIssue = $complianceData.Issue
                }
            }
        }
    }
    
    return $settings
}

function Parse-AccountLockoutPolicy {
    param (
        [string]$PolicyContent,
        [hashtable]$Config
    )
    
    $settings = @()
    $baseline = $Config.SecurityBaseline
    
    # Extract account lockout policy section
    if ($PolicyContent -match "\[System Access\](.*?)(\[\w+\]|\Z)") {
        $lockoutSection = $matches[1]
        
        # Extract lockout settings
        $lockoutSettings = @{
            "LockoutBadCount" = Extract-PolicyValue -Section $lockoutSection -Setting "LockoutBadCount"
            "ResetLockoutCount" = Extract-PolicyValue -Section $lockoutSection -Setting "ResetLockoutCount"
            "LockoutDuration" = Extract-PolicyValue -Section $lockoutSection -Setting "LockoutDuration"
        }
        
        # Process each setting
        foreach ($setting in $lockoutSettings.Keys) {
            $value = $lockoutSettings[$setting]
            
            if ($value -ne $null) {
                $complianceData = Get-ComplianceStatus -SettingName $setting -Value $value -Baseline $baseline
                
                $settings += [PSCustomObject]@{
                    Category = "Account Lockout Policy"
                    PolicyName = Get-SettingDisplayName -SettingName $setting
                    ConfiguredValue = $value
                    RecommendedValue = $complianceData.RecommendedValue
                    IsConfigured = $true
                    Source = "Security Policy"
                    ComplianceStatus = $complianceData.Status
                    ComplianceIssue = $complianceData.Issue
                }
            }
        }
    }
    
    return $settings
}

function Parse-UserRightsPolicy {
    param (
        [string]$PolicyContent,
        [hashtable]$Config
    )
    
    $settings = @()
    
    # Extract user rights policy section
    if ($PolicyContent -match "\[Privilege Rights\](.*?)(\[\w+\]|\Z)") {
        $rightsSection = $matches[1]
        
        # Define critical user rights to check
        $criticalRights = @{
            "SeBackupPrivilege" = "Backup files and directories"
            "SeDebugPrivilege" = "Debug programs"
            "SeRestorePrivilege" = "Restore files and directories"
            "SeTakeOwnershipPrivilege" = "Take ownership of files or other objects"
            "SeLoadDriverPrivilege" = "Load and unload device drivers"
            "SeRemoteShutdownPrivilege" = "Force shutdown from a remote system"
            "SeSystemtimePrivilege" = "Change the system time"
            "SeShutdownPrivilege" = "Shut down the system"
            "SeInteractiveLogonRight" = "Log on locally"
            "SeRemoteInteractiveLogonRight" = "Allow log on through Remote Desktop Services"
            "SeNetworkLogonRight" = "Access this computer from the network"
        }
        
        # Look for each right in the policy
        foreach ($right in $criticalRights.Keys) {
            $value = Extract-PolicyValue -Section $rightsSection -Setting $right
            
            if ($value -ne $null) {
                # Determine if the setting presents a security risk
                $riskyGroups = @("*S-1-1-0*", "*S-1-5-32-545*", "*Everyone*", "*Users*", "*Authenticated Users*")
                $isRisky = $false
                $riskReason = ""
                
                # High-risk user rights that should be restricted
                $highRiskRights = @("SeDebugPrivilege", "SeLoadDriverPrivilege", "SeTakeOwnershipPrivilege")
                
                if ($right -in $highRiskRights) {
                    foreach ($group in $riskyGroups) {
                        if ($value -like $group) {
                            $isRisky = $true
                            $riskReason = "Critical privilege granted to non-administrative users"
                            break
                        }
                    }
                }
                
                $settings += [PSCustomObject]@{
                    Category = "User Rights Policy"
                    PolicyName = $criticalRights[$right]
                    ConfiguredValue = $value
                    RecommendedValue = if ($isRisky) { "Administrators only" } else { "N/A" }
                    IsConfigured = $true
                    Source = "Security Policy"
                    ComplianceStatus = if ($isRisky) { "Non-Compliant" } else { "Compliant" }
                    ComplianceIssue = $riskReason
                }
            }
        }
    }
    
    return $settings
}

function Get-RegistryPolicySettings {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    $settings = @()
    $registryPaths = $Config.RegistryPaths
    $baseline = $Config.SecurityBaseline
    
    # Process each policy area
    foreach ($areaName in $registryPaths.Keys) {
        $path = $registryPaths[$areaName]
        
        # Skip paths that don't exist
        if (-not (Test-Path $path)) {
            continue
        }
        
        try {
            # Get registry values
            $regValues = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            
            if ($regValues) {
                # Process each registry value
                foreach ($valueName in ($regValues.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" })) {
                    $settingName = $valueName.Name
                    $value = $valueName.Value
                    
                    $complianceData = Get-ComplianceStatus -SettingName $settingName -Value $value -Baseline $baseline
                    
                    $settings += [PSCustomObject]@{
                        Category = $areaName
                        PolicyName = Get-SettingDisplayName -SettingName $settingName
                        ConfiguredValue = $value
                        RecommendedValue = $complianceData.RecommendedValue
                        IsConfigured = $true
                        Source = "Registry Policy"
                        ComplianceStatus = $complianceData.Status
                        ComplianceIssue = $complianceData.Issue
                    }
                }
            }
        }
        catch {
            Write-ForensicLog "Error retrieving registry settings for $areaName : $_" -Severity "Warning"
        }
    }
    
    return $settings
}

function Get-AuditPolicySettings {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    $settings = @()
    
    try {
        # Use auditpol.exe to get current audit settings
        $auditPolicyOutput = auditpol /get /category:* /r | ConvertFrom-Csv
        
        if ($auditPolicyOutput) {
            foreach ($policy in $auditPolicyOutput) {
                $categoryName = $policy.'Subcategory'
                $auditSettings = $policy.'Inclusion Setting'
                
                # Determine if the audit settings are appropriate
                $isNonCompliant = $false
                $complianceIssue = ""
                
                # Critical audit categories that should be enabled
                $criticalAuditCategories = @(
                    "Security System Extension",
                    "System Integrity",
                    "Logon",
                    "Logoff",
                    "Account Lockout",
                    "Special Logon",
                    "Other Logon/Logoff Events",
                    "User Account Management",
                    "Computer Account Management",
                    "Security Group Management",
                    "Authentication Policy Change",
                    "Authorization Policy Change",
                    "Sensitive Privilege Use",
                    "Process Creation",
                    "Account Lockout"
                )
                
                if ($categoryName -in $criticalAuditCategories -and $auditSettings -eq "No Auditing") {
                    $isNonCompliant = $true
                    $complianceIssue = "Critical security events should be audited"
                }
                
                $settings += [PSCustomObject]@{
                    Category = "Audit Policy"
                    PolicyName = $categoryName
                    ConfiguredValue = $auditSettings
                    RecommendedValue = if ($isNonCompliant) { "Success and Failure" } else { "N/A" }
                    IsConfigured = $true
                    Source = "Audit Policy"
                    ComplianceStatus = if ($isNonCompliant) { "Non-Compliant" } else { "Compliant" }
                    ComplianceIssue = $complianceIssue
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error retrieving audit policy settings: $_" -Severity "Warning"
    }
    
    return $settings
}

function Extract-PolicyValue {
    param (
        [string]$Section,
        [string]$Setting
    )
    
    if ($Section -match "$Setting\s*=\s*(.+?)(\r|\n|$)") {
        return $matches[1].Trim()
    }
    
    return $null
}

function Get-SettingDisplayName {
    param (
        [string]$SettingName
    )
    
    # Dictionary of common setting names to display names
    $displayNames = @{
        "MinimumPasswordAge" = "Minimum Password Age (days)"
        "MaximumPasswordAge" = "Maximum Password Age (days)"
        "MinimumPasswordLength" = "Minimum Password Length"
        "PasswordComplexity" = "Password Complexity Requirements"
        "PasswordHistorySize" = "Password History Size"
        "ClearTextPassword" = "Store Passwords in Clear Text"
        "LockoutBadCount" = "Account Lockout Threshold"
        "ResetLockoutCount" = "Reset Account Lockout Counter After (mins)"
        "LockoutDuration" = "Account Lockout Duration (mins)"
        "EnableLUA" = "User Account Control Enabled"
        "ConsentPromptBehaviorAdmin" = "UAC Prompt Behavior for Administrators"
        "FilterAdministratorToken" = "UAC Admin Approval Mode"
        "DisableCAD" = "Disable CTRL+ALT+DEL Requirement"
        "NoLockScreenCamera" = "Disable Lock Screen Camera"
        "EnableSecureUIAPaths" = "UAC Virtualization Enabled"
        "AUOptions" = "Windows Update Setting"
    }
    
    if ($displayNames.ContainsKey($SettingName)) {
        return $displayNames[$SettingName]
    }
    
    # If no display name defined, use the original name
    return $SettingName
}

function Get-ComplianceStatus {
    param (
        [string]$SettingName,
        $Value,
        [hashtable]$Baseline
    )
    
    # Default values
    $status = "Informational"
    $issue = ""
    $recommendedValue = "N/A"
    
    # Check if the setting is in our baseline
    if ($Baseline.ContainsKey($SettingName)) {
        $baselineSetting = $Baseline[$SettingName]
        $baselineValue = $baselineSetting.RecommendedValue
        $recommendedValue = $baselineValue
        
        # Determine compliance based on recommended value type
        if ($baselineValue -is [Array]) {
            # For array values, check if the current value is within the array
            if ($baselineValue[0] -is [int] -and $baselineValue.Count -eq 2) {
                # This is likely a range (e.g., 30..90)
                $min = $baselineValue[0]
                $max = $baselineValue[1]
                
                if ([int]$Value -lt $min -or [int]$Value -gt $max) {
                    $status = "Non-Compliant"
                    $issue = $baselineSetting.SecurityRationale
                    $recommendedValue = "$min to $max"
                } else {
                    $status = "Compliant"
                }
            } else {
                # This is a list of acceptable values
                if ($Value -notin $baselineValue) {
                    $status = "Non-Compliant"
                    $issue = $baselineSetting.SecurityRationale
                    $recommendedValue = $baselineValue -join ", "
                } else {
                    $status = "Compliant"
                }
            }
        } else {
            # For single values, direct comparison
            if ($Value -ne $baselineValue) {
                $status = "Non-Compliant"
                $issue = $baselineSetting.SecurityRationale
            } else {
                $status = "Compliant"
            }
        }
    }
    
    return @{
        Status = $status
        Issue = $issue
        RecommendedValue = $recommendedValue
    }
}

# Export function
Export-ModuleMember -Function Get-GroupPolicySettings
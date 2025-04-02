<#
.SYNOPSIS
    Collects information about user accounts and their activity
    
.DESCRIPTION
    Gathers detailed information about all local user accounts, including
    their group memberships, last logon times, and password settings.
    Identifies potentially suspicious user accounts that could indicate compromise.
    
.EXAMPLE
    $userAccountFile = Get-UserAccountActivity
    
.OUTPUTS
    String. The path to the CSV file containing user account data
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for complete user account details
#>

function Get-UserAccountActivity {
    param()
    
    $outputFile = "$script:outputDir\UserAccounts_$script:timestamp.csv"
    Write-ForensicLog "Collecting user account information..."
    
    try {
        # Get all local users
        $users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, 
            PasswordLastSet, AccountExpires, SID, Description,
            @{Name="Groups";Expression={
                try {
                    (Get-LocalGroupMember -Member $_.Name -ErrorAction SilentlyContinue | 
                    Select-Object -ExpandProperty Name) -join ';'
                } catch {
                    "Error retrieving groups"
                }
            }}
        
        # Enhance with additional properties
        foreach ($user in $users) {
            # Check if user is in administrators group
            $user | Add-Member -MemberType NoteProperty -Name "IsAdmin" -Value ($user.Groups -match "Administrators")
            
            # Calculate days since last password change
            if ($user.PasswordLastSet) {
                $daysSincePasswordChange = [math]::Round(((Get-Date) - $user.PasswordLastSet).TotalDays)
                $user | Add-Member -MemberType NoteProperty -Name "DaysSincePasswordChange" -Value $daysSincePasswordChange
            } else {
                $user | Add-Member -MemberType NoteProperty -Name "DaysSincePasswordChange" -Value "Never"
            }
            
            # Calculate days since last logon
            if ($user.LastLogon) {
                $daysSinceLastLogon = [math]::Round(((Get-Date) - $user.LastLogon).TotalDays)
                $user | Add-Member -MemberType NoteProperty -Name "DaysSinceLastLogon" -Value $daysSinceLastLogon
            } else {
                $user | Add-Member -MemberType NoteProperty -Name "DaysSinceLastLogon" -Value "Never"
            }
            
            # Get additional user details from WMI when possible
            try {
                $userProfile = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$($user.SID)'" -ErrorAction SilentlyContinue
                if ($userProfile) {
                    $user | Add-Member -MemberType NoteProperty -Name "ProfilePath" -Value $userProfile.LocalPath
                    $user | Add-Member -MemberType NoteProperty -Name "ProfileLoaded" -Value $userProfile.Loaded
                    $user | Add-Member -MemberType NoteProperty -Name "ProfileLastUseTime" -Value $userProfile.LastUseTime
                } else {
                    $user | Add-Member -MemberType NoteProperty -Name "ProfilePath" -Value "Unknown"
                    $user | Add-Member -MemberType NoteProperty -Name "ProfileLoaded" -Value "Unknown"
                    $user | Add-Member -MemberType NoteProperty -Name "ProfileLastUseTime" -Value "Unknown"
                }
            } catch {
                $user | Add-Member -MemberType NoteProperty -Name "ProfilePath" -Value "Error"
                $user | Add-Member -MemberType NoteProperty -Name "ProfileLoaded" -Value "Error"
                $user | Add-Member -MemberType NoteProperty -Name "ProfileLastUseTime" -Value "Error"
            }
            
            # Check recent logon events for this user from security log
            try {
                $logonEvents = Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    Id = 4624  # Successful logon
                    StartTime = (Get-Date).AddDays(-30)
                } -ErrorAction SilentlyContinue | Where-Object {
                    $_.Properties[5].Value -eq $user.Name -or
                    $_.Properties[5].Value -like "*\$($user.Name)"
                } | Select-Object -First 10
                
                $user | Add-Member -MemberType NoteProperty -Name "RecentLogons" -Value $logonEvents.Count
                
                if ($logonEvents.Count -gt 0) {
                    $latestLogon = $logonEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1
                    $user | Add-Member -MemberType NoteProperty -Name "LastLogonEvent" -Value $latestLogon.TimeCreated
                    
                    # Extract logon type
                    $logonTypes = @{
                        2 = "Interactive"
                        3 = "Network"
                        4 = "Batch"
                        5 = "Service"
                        7 = "Unlock"
                        8 = "NetworkCleartext"
                        9 = "NewCredentials"
                        10 = "RemoteInteractive"
                        11 = "CachedInteractive"
                    }
                    
                    $logonType = $latestLogon.Properties[8].Value
                    $user | Add-Member -MemberType NoteProperty -Name "LastLogonType" -Value ($logonTypes[[int]$logonType] ?? "Unknown ($logonType)")
                } else {
                    $user | Add-Member -MemberType NoteProperty -Name "LastLogonEvent" -Value "No recent events"
                    $user | Add-Member -MemberType NoteProperty -Name "LastLogonType" -Value "Unknown"
                }
            } catch {
                $user | Add-Member -MemberType NoteProperty -Name "RecentLogons" -Value "Error"
                $user | Add-Member -MemberType NoteProperty -Name "LastLogonEvent" -Value "Error"
                $user | Add-Member -MemberType NoteProperty -Name "LastLogonType" -Value "Error"
            }
            
            # Add suspicious score and reasons
            $suspiciousScore = 0
            $suspiciousReasons = @()
            
            # Check for enabled administrator accounts
            if ($user.Enabled -and $user.IsAdmin -and $user.Name -ne $env:USERNAME) {
                $suspiciousScore += 1
                $suspiciousReasons += "Enabled administrator account"
            }
            
            # Check for accounts with no password required
            if (-not $user.PasswordRequired -and $user.Enabled) {
                $suspiciousScore += 3
                $suspiciousReasons += "No password required"
            }
            
            # Check for accounts with old passwords
            if ($user.DaysSincePasswordChange -ne "Never" -and [int]$user.DaysSincePasswordChange -gt 90) {
                $suspiciousScore += 1
                $suspiciousReasons += "Password older than 90 days"
            }
            
            # Check for accounts with suspicious names
            if ($user.Name -match "^[a-z0-9]{8,}$" -or $user.Name -match "^admin[0-9]+$") {
                $suspiciousScore += 2
                $suspiciousReasons += "Suspicious account name"
            }
            
            # Check for accounts with suspicious descriptions
            if ($user.Description -match "temp|test|admin|backup" -and $user.Enabled) {
                $suspiciousScore += 1
                $suspiciousReasons += "Suspicious account description"
            }
            
            # Check for recently created admin accounts
            if ($user.IsAdmin -and $user.PasswordLastSet -and ((Get-Date) - $user.PasswordLastSet).TotalDays -lt 30) {
                $suspiciousScore += 2
                $suspiciousReasons += "Recently created admin account"
            }
            
            # Add suspicious score and reasons to user object
            $user | Add-Member -MemberType NoteProperty -Name "SuspiciousScore" -Value $suspiciousScore
            $user | Add-Member -MemberType NoteProperty -Name "SuspiciousReasons" -Value ($suspiciousReasons -join "; ")
        }
        
        # Export to CSV
        $users | Export-Csv -Path $outputFile -NoTypeInformation
        
        # Report suspicious user accounts
        $suspiciousUsers = $users | Where-Object { $_.SuspiciousScore -gt 0 } | Sort-Object -Property SuspiciousScore -Descending
        if ($suspiciousUsers.Count -gt 0) {
            Write-ForensicLog "Found $($suspiciousUsers.Count) potentially suspicious user accounts:" -Severity "Warning"
            foreach ($user in $suspiciousUsers) {
                Write-ForensicLog "  - $($user.Name) (Enabled: $($user.Enabled), Admin: $($user.IsAdmin)) - $($user.SuspiciousReasons)" -Severity "Warning"
            }
            
            # Create a separate file for suspicious users
            $suspiciousUsers | Export-Csv -Path "$script:outputDir\SuspiciousUsers_$script:timestamp.csv" -NoTypeInformation
        }
        
        Write-ForensicLog "Saved user account data to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error collecting user account data: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-UserAccountActivity
<#
.SYNOPSIS
    Retrieves detailed user permissions for local and domain users.
    
.DESCRIPTION
    This module retrieves detailed user permissions, including group memberships,
    local permissions, and file system permissions for both local and domain users.
    The results are saved to a CSV file.
    
.EXAMPLE
    $userPermissionsFile = Get-UserPermissions -Username "JohnDoe" -Domain "CONTOSO"
    $userPermissionsFileLocal = Get-UserPermissions -Username "JohnDoe"
    
.OUTPUTS
    String. The path to the CSV file containing the user permissions.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.1
    Required Permissions: Administrator privileges required for complete permission information.
#>

function Get-UserPermissions {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username,
        [string]$Domain
    )

    $outputFile = "$script:outputDir\UserPermissions_$Username"
    if ($Domain) {
        $outputFile += "_$Domain"
    }
    $outputFile += "_$script:timestamp.csv"

    Write-ForensicLog "Retrieving permissions for user: $Username"
    if ($Domain) {
        Write-ForensicLog " in domain: $Domain..."
    } else {
        Write-ForensicLog " (local)..."
    }

    try {
        if ($Domain) {
            # Domain User
            $user = Get-ADUser -Identity "$Username" -Server $Domain -ErrorAction Stop
            if (-not $user) {
                Write-ForensicLog "Domain user '$Username' in domain '$Domain' not found." -Severity "Warning"
                return $null
            }
            $userPrincipalName = $user.UserPrincipalName
        } else {
            # Local User
            $user = Get-LocalUser -Name $Username -ErrorAction Stop
            if (-not $user) {
                Write-ForensicLog "Local user '$Username' not found." -Severity "Warning"
                return $null
            }
            $userPrincipalName = $user.Name
        }

        $permissions = @()

        if ($Domain) {
            # Domain Group Memberships
            $groups = Get-ADPrincipalGroupMembership -Identity $user -Server $Domain | Select-Object Name
            foreach ($group in $groups) {
                $permissions += [PSCustomObject]@{
                    PermissionType = "Domain Group Membership"
                    ObjectName     = $group.Name
                    Access         = "Member"
                }
            }
        } else {
            # Local Group Memberships
            $groups = $user | Get-LocalGroupMember | Get-LocalGroup | Select-Object Name
            foreach ($group in $groups) {
                $permissions += [PSCustomObject]@{
                    PermissionType = "Local Group Membership"
                    ObjectName     = $group.Name
                    Access         = "Member"
                }
            }
        }

        # Local Privileges (e.g., SeBackupPrivilege)
        $userPrivileges = Get-WmiObject -Class Win32_UserAccount -Filter "Name='$userPrincipalName'" | Select-Object Privileges
        if ($userPrivileges.Privileges) {
            foreach ($privilege in $userPrivileges.Privileges) {
                $permissions += [PSCustomObject]@{
                    PermissionType = "Local Privilege"
                    ObjectName     = $privilege
                    Access         = "Granted"
                }
            }
        }

        # File System Permissions (example: C:\Users\$Username or C:\Users\$username@domain.com)
        $userProfilePath = "C:\Users\$Username"
        if($domain){
            $userProfilePath = "C:\Users\$userPrincipalName"
        }
        if (Test-Path -Path $userProfilePath) {
            $acl = Get-Acl -Path $userProfilePath
            foreach ($access in $acl.Access) {
                $permissions += [PSCustomObject]@{
                    PermissionType = "File System"
                    ObjectName     = $userProfilePath
                    Access         = "$($access.FileSystemRights) - $($access.IdentityReference)"
                }
            }
        }

        #Registry permissions Example: HKEY_LOCAL_MACHINE\SOFTWARE
        $registryPath = "HKEY_LOCAL_MACHINE\SOFTWARE"
        if(Test-Path -Path $registryPath){
            $regAcl = Get-Acl -Path $registryPath
            foreach($regAccess in $regAcl.Access){
                if($regAccess.IdentityReference -match $Username -or $regAccess.IdentityReference -match $userPrincipalName){
                    $permissions += [PSCustomObject]@{
                        PermissionType = "Registry"
                        ObjectName = $registryPath
                        Access = "$($regAccess.RegistryRights) - $($regAccess.IdentityReference)"
                    }
                }
            }
        }

        # Save to CSV
        $permissions | Export-Csv -Path $outputFile -NoTypeInformation

        Write-ForensicLog "Saved permissions for user '$Username'"
        if ($Domain) {
            Write-ForensicLog " in domain '$Domain' to $outputFile"
        } else {
            Write-ForensicLog " (local) to $outputFile"
        }
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error retrieving permissions for user '$Username': $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-UserPermissions

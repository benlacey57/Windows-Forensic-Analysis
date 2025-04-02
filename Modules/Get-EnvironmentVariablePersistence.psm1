<#
.SYNOPSIS
    Detects persistence techniques using Windows environment variables.
    
.DESCRIPTION
    Get-EnvironmentVariablePersistence identifies suspicious environment variable
    configurations that could be used for persistence or privilege escalation.
    It analyzes both system and user environment variables for paths containing
    unusual locations, writable directories, or references to suspicious executables.
    
.EXAMPLE
    $envVarFile = Get-EnvironmentVariablePersistence
    
.OUTPUTS
    String. The path to the CSV file containing environment variable analysis results
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges recommended for complete results
#>

function Get-EnvironmentVariablePersistence {
    param()

    $outputFile = "$script:outputDir\EnvironmentVariablePersistence_$script:timestamp.csv"
    Write-ForensicLog "Analyzing environment variables for persistence techniques..."

    try {
        # Define shared detection criteria
        $detectionCriteria = Initialize-DetectionCriteria
        
        # Initialize findings collection
        $envFindings = @()
        
        # Get system environment variables
        $systemEnvVars = Get-SystemEnvironmentVariables
        $envFindings += Analyze-EnvironmentVariables -Variables $systemEnvVars -VariableType "System" -DetectionCriteria $detectionCriteria
        
        # Get user environment variables for all users
        $userEnvVars = Get-UserEnvironmentVariables
        $envFindings += Analyze-EnvironmentVariables -Variables $userEnvVars -VariableType "User" -DetectionCriteria $detectionCriteria
        
        # Check PATH variable specifically (both system and user)
        $pathFindings = Analyze-PathVariable -DetectionCriteria $detectionCriteria
        $envFindings += $pathFindings
        
        # Export results
        Export-EnvVariableFindings -Findings $envFindings -OutputFile $outputFile
        
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error analyzing environment variables: $_" -Severity "Error"
        return $null
    }
}

function Initialize-DetectionCriteria {
    return @{
        SuspiciousLocations = @(
            "\\Temp\\", "\\AppData\\Local\\Temp\\", "%Temp%",
            "\\Downloads\\", "%USERPROFILE%\\Downloads\\",
            "\\Public\\", "\\ProgramData\\", 
            "\\AppData\\Roaming\\", "\\AppData\\Local\\",
            "\\Desktop\\", "%USERPROFILE%\\Desktop\\"
        )
        
        SuspiciousExecutables = @(
            "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
            "rundll32.exe", "regsvr32.exe", "mshta.exe", "bitsadmin.exe",
            "certutil.exe", "reg.exe", "regedit.exe", "msiexec.exe"
        )
        
        CriticalVariables = @(
            "COMSPEC", "PATHEXT", "WINDIR", "SYSTEMROOT", "PROCESSOR_ARCHITECTURE",
            "OS", "COMPUTERNAME", "TEMP", "TMP"
        )
        
        DefaultValues = @{
            "COMSPEC" = "%SystemRoot%\system32\cmd.exe"
            "PATHEXT" = ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"
            "WINDIR" = $env:SystemRoot
            "SYSTEMROOT" = $env:SystemRoot
            "OS" = "Windows_NT"
            "TEMP" = "%SystemRoot%\TEMP"
            "TMP" = "%SystemRoot%\TEMP"
        }
    }
}

function Get-SystemEnvironmentVariables {
    $systemVars = @()
    
    try {
        # Get system environment variables from registry
        $systemEnvPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        
        if (Test-Path $systemEnvPath) {
            $regValues = Get-ItemProperty -Path $systemEnvPath -ErrorAction SilentlyContinue
            
            # Convert registry values to PSCustomObjects
            foreach ($property in $regValues.PSObject.Properties) {
                # Skip system properties that start with PS
                if ($property.Name -match "^PS" -or $property.Name -eq "ErrorVariable") {
                    continue
                }
                
                $systemVars += [PSCustomObject]@{
                    Name = $property.Name
                    Value = $property.Value
                    Owner = "SYSTEM"
                    Source = "Registry"
                }
            }
        }
        
        # Also get environment variables from the process
        $envVars = [System.Environment]::GetEnvironmentVariables('Machine')
        
        foreach ($varName in $envVars.Keys) {
            # Skip duplicates already found in registry
            if ($systemVars | Where-Object { $_.Name -eq $varName }) {
                continue
            }
            
            $systemVars += [PSCustomObject]@{
                Name = $varName
                Value = $envVars[$varName]
                Owner = "SYSTEM"
                Source = "Environment"
            }
        }
    }
    catch {
        Write-ForensicLog "Error retrieving system environment variables: $_" -Severity "Warning"
    }
    
    return $systemVars
}

function Get-UserEnvironmentVariables {
    $userVars = @()
    
    try {
        # Get environment variables for the current user
        $currentUserEnvPath = "HKCU:\Environment"
        $currentUserVars = Get-UserEnvVarsFromRegistry -RegistryPath $currentUserEnvPath -Username $env:USERNAME
        $userVars += $currentUserVars
        
        # Get environment variables for all user profiles on the system
        $userProfiles = Get-ChildItem -Path "C:\Users" -Directory | 
                      Where-Object { $_.Name -ne "Public" -and $_.Name -ne "Default" -and $_.Name -ne "Default User" }
        
        foreach ($userProfile in $userProfiles) {
            $username = $userProfile.Name
            
            # Skip current user (already processed)
            if ($username -eq $env:USERNAME) {
                continue
            }
            
            $ntUserDatPath = Join-Path -Path $userProfile.FullName -ChildPath "NTUSER.DAT"
            
            # Only process if NTUSER.DAT exists
            if (Test-Path $ntUserDatPath) {
                $userRegistryVars = Get-UserEnvVarsFromNTUserDat -NTUserDatPath $ntUserDatPath -Username $username
                $userVars += $userRegistryVars
            }
        }
        
        # Also get environment variables from the process for the current user
        $envVars = [System.Environment]::GetEnvironmentVariables('User')
        
        foreach ($varName in $envVars.Keys) {
            # Skip duplicates already found in registry
            if ($userVars | Where-Object { $_.Name -eq $varName -and $_.Owner -eq $env:USERNAME }) {
                continue
            }
            
            $userVars += [PSCustomObject]@{
                Name = $varName
                Value = $envVars[$varName]
                Owner = $env:USERNAME
                Source = "Environment"
            }
        }
    }
    catch {
        Write-ForensicLog "Error retrieving user environment variables: $_" -Severity "Warning"
    }
    
    return $userVars
}

function Get-UserEnvVarsFromRegistry {
    param (
        [string]$RegistryPath,
        [string]$Username
    )
    
    $userVars = @()
    
    if (Test-Path $RegistryPath) {
        $regValues = Get-ItemProperty -Path $RegistryPath -ErrorAction SilentlyContinue
        
        # Convert registry values to PSCustomObjects
        foreach ($property in $regValues.PSObject.Properties) {
            # Skip system properties that start with PS
            if ($property.Name -match "^PS" -or $property.Name -eq "ErrorVariable") {
                continue
            }
            
            $userVars += [PSCustomObject]@{
                Name = $property.Name
                Value = $property.Value
                Owner = $Username
                Source = "Registry"
            }
        }
    }
    
    return $userVars
}

function Get-UserEnvVarsFromNTUserDat {
    param (
        [string]$NTUserDatPath,
        [string]$Username
    )
    
    $userVars = @()
    $hiveName = "HKU_$($Username)_Temp"
    
    try {
        # Mount the registry hive
        $null = reg load "HKU\$hiveName" $NTUserDatPath 2>$null
        
        if ($?) {
            # Get user environment variables
            $userEnvPath = "Registry::HKEY_USERS\$hiveName\Environment"
            $userVars = Get-UserEnvVarsFromRegistry -RegistryPath $userEnvPath -Username $Username
        }
    }
    catch {
        Write-ForensicLog "Error accessing registry hive for user $Username`: $_" -Severity "Warning"
    }
    finally {
        # Always unload the hive
        [gc]::Collect()  # Force garbage collection to release file handles
        $null = reg unload "HKU\$hiveName" 2>$null
    }
    
    return $userVars
}

function Analyze-EnvironmentVariables {
    param (
        [Parameter(Mandatory = $true)]
        [array]$Variables,
        
        [Parameter(Mandatory = $true)]
        [string]$VariableType,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$DetectionCriteria
    )
    
    $findings = @()
    
    # Extract detection criteria
    $suspiciousLocations = $DetectionCriteria.SuspiciousLocations
    $suspiciousExecutables = $DetectionCriteria.SuspiciousExecutables
    $criticalVariables = $DetectionCriteria.CriticalVariables
    $defaultValues = $DetectionCriteria.DefaultValues
    
    # Process each environment variable
    foreach ($variable in $Variables) {
        $suspiciousScore = 0
        $reasons = @()
        
        # Skip empty variables
        if ([string]::IsNullOrEmpty($variable.Value)) {
            continue
        }
        
        # Check for suspicious indicators
        $checkResults = Test-EnvVarSuspiciousIndicators -Variable $variable -DetectionCriteria $DetectionCriteria
        $suspiciousScore = $checkResults.Score
        $reasons = $checkResults.Reasons
        
        # Add finding
        $findings += [PSCustomObject]@{
            Name = $variable.Name
            Value = $variable.Value
            VariableType = $VariableType
            Owner = $variable.Owner
            SuspiciousScore = $suspiciousScore
            Reason = if ($reasons.Count -gt 0) { ($reasons -join "; ") } else { "No suspicious indicators" }
        }
    }
    
    return $findings
}

function Test-EnvVarSuspiciousIndicators {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Variable,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$DetectionCriteria
    )
    
    $suspiciousScore = 0
    $reasons = @()
    
    # Extract detection criteria
    $suspiciousLocations = $DetectionCriteria.SuspiciousLocations
    $suspiciousExecutables = $DetectionCriteria.SuspiciousExecutables
    $criticalVariables = $DetectionCriteria.CriticalVariables
    $defaultValues = $DetectionCriteria.DefaultValues
    
    # Check if this is a critical variable that's been modified
    if ($criticalVariables -contains $Variable.Name.ToUpper()) {
        $defaultValue = $defaultValues[$Variable.Name.ToUpper()]
        
        if ($defaultValue -and $Variable.Value -ne $defaultValue) {
            $suspiciousScore += 4
            $reasons += "Critical environment variable modified from default value"
        }
    }
    
    # Check for suspicious locations
    foreach ($location in $suspiciousLocations) {
        if ($Variable.Value -like "*$location*") {
            $suspiciousScore += 2
            $reasons += "References suspicious location: $location"
            break
        }
    }
    
    # Check for suspicious executables
    foreach ($exe in $suspiciousExecutables) {
        if ($Variable.Value -like "*$exe*") {
            $suspiciousScore += 3
            $reasons += "References suspicious executable: $exe"
            break
        }
    }
    
    # Check if the variable references network locations
    if ($Variable.Value -match '\\\\') {
        $suspiciousScore += 2
        $reasons += "References network location"
    }
    
    # Check if the variable references unusual URLs
    if ($Variable.Value -match 'http:|https:|ftp:') {
        $suspiciousScore += 3
        $reasons += "Contains URL reference"
    }
    
    # Check if the directories in the variable value are writable by non-admins
    $expandedValue = [System.Environment]::ExpandEnvironmentVariables($Variable.Value)
    
    if (Test-Path $expandedValue -PathType Container) {
        $writableResult = Test-DirectoryWritableByNonAdmin -Path $expandedValue
        if ($writableResult) {
            $suspiciousScore += 2
            $reasons += "Directory is writable by non-administrators"
        }
    }
    
    # Check if the variable creates a command injection opportunity
    if ($Variable.Name -match "PROMPT|PS\d") {
        if ($Variable.Value -match '`|&|\||\$\(|;') {
            $suspiciousScore += 4
            $reasons += "Contains command injection characters"
        }
    }
    
    return @{
        Score = $suspiciousScore
        Reasons = $reasons
    }
}

function Analyze-PathVariable {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$DetectionCriteria
    )
    
    $findings = @()
    
    try {
        # Get system PATH variable
        $systemPath = [System.Environment]::GetEnvironmentVariable('PATH', 'Machine')
        
        if ($systemPath) {
            $systemPathEntries = $systemPath -split ';'
            $finding = Analyze-PathEntries -PathEntries $systemPathEntries -VariableType "System" -Owner "SYSTEM" -DetectionCriteria $DetectionCriteria
            $findings += $finding
        }
        
        # Get user PATH variables
        $userProfiles = Get-ChildItem -Path "C:\Users" -Directory | 
                      Where-Object { $_.Name -ne "Public" -and $_.Name -ne "Default" -and $_.Name -ne "Default User" }
        
        foreach ($userProfile in $userProfiles) {
            $username = $userProfile.Name
            $userPathEntries = Get-UserPathEntries -Username $username -UserProfile $userProfile
            
            if ($userPathEntries) {
                $finding = Analyze-PathEntries -PathEntries $userPathEntries -VariableType "User" -Owner $username -DetectionCriteria $DetectionCriteria
                $findings += $finding
            }
        }
    }
    catch {
        Write-ForensicLog "Error analyzing PATH variable: $_" -Severity "Warning"
    }
    
    return $findings
}

function Get-UserPathEntries {
    param (
        [string]$Username,
        [System.IO.DirectoryInfo]$UserProfile
    )
    
    # Get PATH for current user from environment
    if ($Username -eq $env:USERNAME) {
        $userPath = [System.Environment]::GetEnvironmentVariable('PATH', 'User')
        if ($userPath) {
            return $userPath -split ';'
        }
    }
    # Get PATH for other users from registry
    else {
        $ntUserDatPath = Join-Path -Path $UserProfile.FullName -ChildPath "NTUSER.DAT"
        
        if (Test-Path $ntUserDatPath) {
            $hiveName = "HKU_$($Username)_Temp_Path"
            
            try {
                # Mount the registry hive
                $null = reg load "HKU\$hiveName" $ntUserDatPath 2>$null
                
                if ($?) {
                    $userPathKey = "Registry::HKEY_USERS\$hiveName\Environment"
                    if (Test-Path $userPathKey) {
                        $userPath = (Get-ItemProperty -Path $userPathKey -Name "PATH" -ErrorAction SilentlyContinue).PATH
                        
                        if ($userPath) {
                            return $userPath -split ';'
                        }
                    }
                }
            }
            catch {
                Write-ForensicLog "Error accessing PATH variable for user $Username`: $_" -Severity "Warning"
            }
            finally {
                # Always unload the hive
                [gc]::Collect()
                $null = reg unload "HKU\$hiveName" 2>$null
            }
        }
    }
    
    return $null
}

function Analyze-PathEntries {
    param (
        [Parameter(Mandatory = $true)]
        [array]$PathEntries,
        
        [Parameter(Mandatory = $true)]
        [string]$VariableType,
        
        [Parameter(Mandatory = $true)]
        [string]$Owner,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$DetectionCriteria
    )
    
    $findings = @()
    $entryNumber = 0
    
    # Extract detection criteria
    $suspiciousLocations = $DetectionCriteria.SuspiciousLocations
    
    # Process each PATH entry
    foreach ($entry in $PathEntries) {
        $entryNumber++
        
        # Skip empty entries
        if ([string]::IsNullOrWhiteSpace($entry)) {
            continue
        }
        
        $checkResults = Test-PathEntrySuspiciousIndicators -Entry $entry -EntryNumber $entryNumber -VariableType $VariableType -DetectionCriteria $DetectionCriteria
        
        # Add finding
        $findings += [PSCustomObject]@{
            Name = "PATH Entry $entryNumber"
            Value = $entry
            VariableType = $VariableType
            Owner = $Owner
            SuspiciousScore = $checkResults.Score
            Reason = if ($checkResults.Reasons.Count -gt 0) { ($checkResults.Reasons -join "; ") } else { "No suspicious indicators" }
        }
    }
    
    return $findings
}

function Test-PathEntrySuspiciousIndicators {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Entry,
        
        [Parameter(Mandatory = $true)]
        [int]$EntryNumber,
        
        [Parameter(Mandatory = $true)]
        [string]$VariableType,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$DetectionCriteria
    )
    
    $suspiciousScore = 0
    $reasons = @()
    
    # Extract detection criteria
    $suspiciousLocations = $DetectionCriteria.SuspiciousLocations
    
    # Check if the entry exists
    $expandedEntry = [System.Environment]::ExpandEnvironmentVariables($Entry)
    $entryExists = Test-Path $expandedEntry -PathType Container
    
    if (-not $entryExists) {
        $suspiciousScore += 1
        $reasons += "Directory does not exist"
    }
    
    # Check for suspicious locations
    foreach ($location in $suspiciousLocations) {
        if ($Entry -like "*$location*") {
            $suspiciousScore += 3
            $reasons += "PATH references suspicious location: $location"
            break
        }
    }
    
    # Check for unusual PATH locations
    if ($Entry -match '\\AppData\\' -or $Entry -match '\\Roaming\\' -or $Entry -match '\\Local\\') {
        $suspiciousScore += 2
        $reasons += "PATH includes user AppData directory"
    }
    
    # Check if PATH entry is writable by non-admins
    if ($entryExists) {
        $writableResult = Test-DirectoryWritableByNonAdmin -Path $expandedEntry
        if ($writableResult) {
            $suspiciousScore += 3
            $reasons += "PATH directory is writable by non-administrators"
        }
    }
    
    # Check for relative paths
    if ($Entry -notmatch '^[A-Za-z]:\\' -and $Entry -notmatch '^\\\\') {
        $suspiciousScore += 2
        $reasons += "PATH contains relative path"
    }
    
    # Check for network paths
    if ($Entry -match '^\\\\') {
        $suspiciousScore += 2
        $reasons += "PATH contains network location"
    }
    
    # Check PATH entry order - early entries can override system commands
    if ($EntryNumber -le 3 -and $VariableType -eq "System" -and $suspiciousScore -gt 0) {
        $suspiciousScore += 1
        $reasons += "Suspicious entry appears early in PATH order"
    }
    
    return @{
        Score = $suspiciousScore
        Reasons = $reasons
    }
}

function Test-DirectoryWritableByNonAdmin {
    param (
        [string]$Path
    )
    
    try {
        $acl = Get-Acl -Path $Path -ErrorAction SilentlyContinue
        
        if ($acl) {
            foreach ($access in $acl.Access) {
                if (($access.IdentityReference -match "Everyone|INTERACTIVE|Users|Authenticated Users") -and 
                    ($access.FileSystemRights -match "Write|Modify|FullControl|CreateFiles|CreateDirectories")) {
                    return $true
                }
            }
        }
    }
    catch {
        # Cannot check permissions
    }
    
    return $false
}

function Export-EnvVariableFindings {
    param (
        [array]$Findings,
        [string]$OutputFile
    )
    
    if ($Findings.Count -gt 0) {
        # Sort by suspicious score (most suspicious first)
        $sortedFindings = $Findings | Sort-Object -Property SuspiciousScore -Descending
        $sortedFindings | Export-Csv -Path $OutputFile -NoTypeInformation
        
        # Log summary
        $suspiciousCount = ($sortedFindings | Where-Object { $_.SuspiciousScore -gt 0 }).Count
        Write-ForensicLog "Found $($Findings.Count) environment variables, $suspiciousCount potentially suspicious"
        
        # Log most suspicious findings
        $highRiskFindings = $sortedFindings | Where-Object { $_.SuspiciousScore -ge 3 } | Select-Object -First 5
        if ($highRiskFindings.Count -gt 0) {
            Write-ForensicLog "High-risk environment variable findings:" -Severity "Warning"
            foreach ($finding in $highRiskFindings) {
                Write-ForensicLog "  - $($finding.Name): $($finding.Value) - $($finding.Reason)" -Severity "Warning"
            }
        }
    } else {
        Write-ForensicLog "No suspicious environment variables found"
        # Create an empty file to indicate analysis was performed
        [PSCustomObject]@{
            Result = "No suspicious environment variables found"
            AnalysisTime = Get-Date
            SystemName = $env:COMPUTERNAME
        } | Export-Csv -Path $OutputFile -NoTypeInformation
    }
    
    Write-ForensicLog "Saved environment variable analysis to $OutputFile"
}

# Export function
Export-ModuleMember -Function Get-EnvironmentVariablePersistence
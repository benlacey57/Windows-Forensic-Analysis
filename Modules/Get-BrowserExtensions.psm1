<#
.SYNOPSIS
    Collects information about browser extensions installed on the system.
    
.DESCRIPTION
    Get-BrowserExtensions gathers data about extensions and add-ons installed in
    major web browsers including Chrome, Firefox, Edge, and Internet Explorer.
    It identifies potentially suspicious extensions that could be used for data
    exfiltration, browser hijacking, or other malicious purposes.
    
.EXAMPLE
    $browserExtensionsFile = Get-BrowserExtensions
    
.OUTPUTS
    String. The path to the CSV file containing browser extension data
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Standard user privileges are sufficient
#>

function Get-BrowserExtensions {
    param()

    $outputFile = "$script:outputDir\BrowserExtensions_$script:timestamp.csv"
    Write-ForensicLog "Collecting browser extensions..."

    try {
        # Initialize findings collection
        $extensions = @()
        
        # Get extensions from each browser
        $chromeExtensions = Get-ChromeExtensions
        $extensions += $chromeExtensions
        
        $firefoxExtensions = Get-FirefoxExtensions
        $extensions += $firefoxExtensions
        
        $edgeExtensions = Get-EdgeExtensions
        $extensions += $edgeExtensions
        
        $ieAddons = Get-InternetExplorerAddons
        $extensions += $ieAddons
        
        # Export results
        if ($extensions.Count -gt 0) {
            # Sort by suspicious score (descending)
            $sortedExtensions = $extensions | Sort-Object -Property @{Expression = "SuspiciousScore"; Descending = $true}
            $sortedExtensions | Export-Csv -Path $outputFile -NoTypeInformation
            
            # Log summary of findings
            $suspiciousCount = ($sortedExtensions | Where-Object {$_.SuspiciousScore -gt 0}).Count
            
            Write-ForensicLog "Found $($extensions.Count) browser extensions, $suspiciousCount potentially suspicious"
            
            # Log the most suspicious extensions
            $highRiskExtensions = $sortedExtensions | Where-Object {$_.SuspiciousScore -ge 3} | Select-Object -First 5
            if ($highRiskExtensions.Count -gt 0) {
                Write-ForensicLog "Potentially suspicious browser extensions:" -Severity "Warning"
                foreach ($ext in $highRiskExtensions) {
                    Write-ForensicLog "  - $($ext.Name) ($($ext.Browser)) - $($ext.SuspiciousReason)" -Severity "Warning"
                }
            }
        } else {
            Write-ForensicLog "No browser extensions found"
            # Create an empty file to indicate analysis was performed
            [PSCustomObject]@{
                Result = "No browser extensions found"
                AnalysisTime = Get-Date
                SystemName = $env:COMPUTERNAME
            } | Export-Csv -Path $outputFile -NoTypeInformation
        }
        
        Write-ForensicLog "Saved browser extension data to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error collecting browser extensions: $_" -Severity "Error"
        return $null
    }
}

function Get-ChromeExtensions {
    $extensions = @()
    
    try {
        Write-ForensicLog "Checking for Chrome extensions..."
        
        # Get user profiles
        $userProfiles = Get-ChildItem -Path "C:\Users" -Directory |
                         Where-Object { $_.Name -ne "Public" -and $_.Name -ne "Default" -and $_.Name -ne "Default User" }
        
        foreach ($userProfile in $userProfiles) {
            $username = $userProfile.Name
            $extensionsPath = Join-Path -Path $userProfile.FullName -ChildPath "AppData\Local\Google\Chrome\User Data\Default\Extensions"
            
            if (Test-Path $extensionsPath) {
                $extensionFolders = Get-ChildItem -Path $extensionsPath -Directory
                
                foreach ($extFolder in $extensionFolders) {
                    # Each extension has its ID as folder name
                    $extensionId = $extFolder.Name
                    
                    # Extensions can have multiple versions, get the most recent one
                    $versionFolders = Get-ChildItem -Path $extFolder.FullName -Directory |
                                      Sort-Object -Property Name -Descending
                    
                    if ($versionFolders.Count -gt 0) {
                        $latestVersion = $versionFolders[0]
                        $manifestPath = Join-Path -Path $latestVersion.FullName -ChildPath "manifest.json"
                        
                        if (Test-Path $manifestPath) {
                            try {
                                $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                                
                                # Basic extension info
                                $name = if ($manifest.name) {
                                    # Some extension names are in ___MSG_extensionName___ format, use description instead
                                    if ($manifest.name -match "^__MSG_") {
                                        if ($manifest.description) { $manifest.description } else { $extensionId }
                                    } else {
                                        $manifest.name
                                    }
                                } else { $extensionId }
                                
                                $version = if ($manifest.version) { $manifest.version } else { $latestVersion.Name }
                                $description = if ($manifest.description) { $manifest.description } else { "No description" }
                                
                                # Get permissions
                                $permissions = @()
                                if ($manifest.permissions) {
                                    $permissions = $manifest.permissions | ForEach-Object { "$_" }
                                }
                                
                                # Check for content scripts that run on pages
                                $contentScripts = @()
                                if ($manifest.content_scripts) {
                                    foreach ($script in $manifest.content_scripts) {
                                        if ($script.matches) {
                                            $contentScripts += $script.matches | ForEach-Object { "$_" }
                                        }
                                    }
                                }
                                
                                # Check for background scripts
                                $backgroundScripts = @()
                                if ($manifest.background -and $manifest.background.scripts) {
                                    $backgroundScripts = $manifest.background.scripts | ForEach-Object { "$_" }
                                }
                                
                                # Calculate a suspiciousness score based on permissions and behavior
                                $suspiciousScore = 0
                                $suspiciousReasons = @()
                                
                                # Check for high-risk permissions
                                $highRiskPermissions = @(
                                    "tabs", "webRequest", "webRequestBlocking", "<all_urls>", "history",
                                    "management", "proxy", "cookies", "bookmarks", "clipboardRead", "debugger",
                                    "declarativeNetRequest", "webNavigation", "contentSettings", "privacy"
                                )
                                
                                foreach ($permission in $permissions) {
                                    if ($permission -in $highRiskPermissions) {
                                        $suspiciousScore += 1
                                        $suspiciousReasons += "Uses high-risk permission: $permission"
                                    }
                                }
                                
                                # Check for access to all websites
                                if ($contentScripts -contains "<all_urls>" -or $permissions -contains "<all_urls>") {
                                    $suspiciousScore += 1
                                    $suspiciousReasons += "Has access to all websites"
                                }
                                
                                # Check for extensions that can read sensitive website content
                                $sensitivePatterns = @("*://*.google.com/*", "*://*.facebook.com/*", "*://*.microsoft.com/*", 
                                                     "*://*.apple.com/*", "*://*.amazon.com/*", "*://mail.*/*", 
                                                     "*://banking.*/*", "*://*.bank.*/*", "*://.*bank.com/*")
                                
                                foreach ($pattern in $sensitivePatterns) {
                                    if ($contentScripts | Where-Object { $_ -like $pattern }) {
                                        $suspiciousScore += 1
                                        $suspiciousReasons += "Accesses sensitive websites: $pattern"
                                        break  # Only count this issue once
                                    }
                                }
                                
                                # Add extension information to results
                                $extensions += [PSCustomObject]@{
                                    Browser = "Chrome"
                                    Name = $name
                                    ID = $extensionId
                                    Version = $version
                                    Description = $description
                                    Permissions = ($permissions -join "; ")
                                    ContentScripts = ($contentScripts -join "; ")
                                    BackgroundScripts = ($backgroundScripts -join "; ")
                                    User = $username
                                    InstalledPath = $extFolder.FullName
                                    SuspiciousScore = $suspiciousScore
                                    SuspiciousReason = ($suspiciousReasons -join "; ")
                                }
                            }
                            catch {
                                Write-ForensicLog "Error parsing Chrome extension manifest for $extensionId : $_" -Severity "Warning"
                            }
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error collecting Chrome extensions: $_" -Severity "Warning"
    }
    
    return $extensions
}

function Get-FirefoxExtensions {
    $extensions = @()
    
    try {
        Write-ForensicLog "Checking for Firefox extensions..."
        
        # Get user profiles
        $userProfiles = Get-ChildItem -Path "C:\Users" -Directory |
                         Where-Object { $_.Name -ne "Public" -and $_.Name -ne "Default" -and $_.Name -ne "Default User" }
        
        foreach ($userProfile in $userProfiles) {
            $username = $userProfile.Name
            $firefoxProfilesPath = Join-Path -Path $userProfile.FullName -ChildPath "AppData\Roaming\Mozilla\Firefox\Profiles"
            
            if (Test-Path $firefoxProfilesPath) {
                $profileFolders = Get-ChildItem -Path $firefoxProfilesPath -Directory
                
                foreach ($profileFolder in $profileFolders) {
                    $extensionsPath = Join-Path -Path $profileFolder.FullName -ChildPath "extensions"
                    
                    if (Test-Path $extensionsPath) {
                        # Regular extensions as XPI files
                        $extensionFiles = Get-ChildItem -Path $extensionsPath -File -Filter "*.xpi"
                        
                        foreach ($extFile in $extensionFiles) {
                            try {
                                # XPI files are just ZIP files, extract the manifest
                                $tempFolder = Join-Path -Path $env:TEMP -ChildPath "FF_Ext_$($extFile.BaseName)"
                                
                                if (Test-Path $tempFolder) {
                                    Remove-Item -Path $tempFolder -Recurse -Force
                                }
                                
                                New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null
                                
                                # Use .NET to extract manifest.json from the XPI
                                Add-Type -AssemblyName System.IO.Compression.FileSystem
                                $zip = [System.IO.Compression.ZipFile]::OpenRead($extFile.FullName)
                                
                                $manifestEntry = $zip.Entries | Where-Object { $_.FullName -eq "manifest.json" }
                                if ($manifestEntry) {
                                    $manifestFile = Join-Path -Path $tempFolder -ChildPath "manifest.json"
                                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($manifestEntry, $manifestFile, $true)
                                    
                                    $manifest = Get-Content -Path $manifestFile -Raw | ConvertFrom-Json
                                    
                                    # Basic extension info
                                    $name = if ($manifest.name) { $manifest.name } else { $extFile.BaseName }
                                    $version = if ($manifest.version) { $manifest.version } else { "Unknown" }
                                    $description = if ($manifest.description) { $manifest.description } else { "No description" }
                                    
                                    # Get permissions
                                    $permissions = @()
                                    if ($manifest.permissions) {
                                        $permissions = $manifest.permissions | ForEach-Object { "$_" }
                                    }
                                    
                                    # Check for content scripts
                                    $contentScripts = @()
                                    if ($manifest.content_scripts) {
                                        foreach ($script in $manifest.content_scripts) {
                                            if ($script.matches) {
                                                $contentScripts += $script.matches | ForEach-Object { "$_" }
                                            }
                                        }
                                    }
                                    
                                    # Check for background scripts
                                    $backgroundScripts = @()
                                    if ($manifest.background -and $manifest.background.scripts) {
                                        $backgroundScripts = $manifest.background.scripts | ForEach-Object { "$_" }
                                    }
                                    
                                    # Calculate suspiciousness score
                                    $suspiciousScore = 0
                                    $suspiciousReasons = @()
                                    
                                    # Check for high-risk permissions
                                    $highRiskPermissions = @(
                                        "tabs", "webRequest", "webRequestBlocking", "<all_urls>", "history",
                                        "management", "proxy", "cookies", "bookmarks", "clipboardRead", "debugger",
                                        "declarativeNetRequest", "webNavigation", "contentSettings", "privacy"
                                    )
                                    
                                    foreach ($permission in $permissions) {
                                        if ($permission -in $highRiskPermissions) {
                                            $suspiciousScore += 1
                                            $suspiciousReasons += "Uses high-risk permission: $permission"
                                        }
                                    }
                                    
                                    # Check for access to all websites
                                    if ($contentScripts -contains "<all_urls>" -or $permissions -contains "<all_urls>") {
                                        $suspiciousScore += 1
                                        $suspiciousReasons += "Has access to all websites"
                                    }
                                    
                                    # Add extension information to results
                                    $extensions += [PSCustomObject]@{
                                        Browser = "Firefox"
                                        Name = $name
                                        ID = $extFile.BaseName
                                        Version = $version
                                        Description = $description
                                        Permissions = ($permissions -join "; ")
                                        ContentScripts = ($contentScripts -join "; ")
                                        BackgroundScripts = ($backgroundScripts -join "; ")
                                        User = $username
                                        InstalledPath = $extFile.FullName
                                        SuspiciousScore = $suspiciousScore
                                        SuspiciousReason = ($suspiciousReasons -join "; ")
                                    }
                                }
                                
                                $zip.Dispose()
                                
                                # Clean up temp folder
                                if (Test-Path $tempFolder) {
                                    Remove-Item -Path $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
                                }
                            }
                            catch {
                                Write-ForensicLog "Error analyzing Firefox extension $($extFile.Name): $_" -Severity "Warning"
                            }
                        }
                        
                        # Extensions installed as folders
                        $extensionFolders = Get-ChildItem -Path $extensionsPath -Directory
                        
                        foreach ($extFolder in $extensionFolders) {
                            $manifestPath = Join-Path -Path $extFolder.FullName -ChildPath "manifest.json"
                            
                            if (Test-Path $manifestPath) {
                                try {
                                    $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
                                    
                                    # Basic extension info
                                    $name = if ($manifest.name) { $manifest.name } else { $extFolder.Name }
                                    $version = if ($manifest.version) { $manifest.version } else { "Unknown" }
                                    $description = if ($manifest.description) { $manifest.description } else { "No description" }
                                    
                                    # Get permissions
                                    $permissions = @()
                                    if ($manifest.permissions) {
                                        $permissions = $manifest.permissions | ForEach-Object { "$_" }
                                    }
                                    
                                    # Check for content scripts
                                    $contentScripts = @()
                                    if ($manifest.content_scripts) {
                                        foreach ($script in $manifest.content_scripts) {
                                            if ($script.matches) {
                                                $contentScripts += $script.matches | ForEach-Object { "$_" }
                                            }
                                        }
                                    }
                                    
                                    # Check for background scripts
                                    $backgroundScripts = @()
                                    if ($manifest.background -and $manifest.background.scripts) {
                                        $backgroundScripts = $manifest.background.scripts | ForEach-Object { "$_" }
                                    }
                                    
                                    # Calculate suspiciousness score
                                    $suspiciousScore = 0
                                    $suspiciousReasons = @()
                                    
                                    # Check for high-risk permissions
                                    $highRiskPermissions = @(
                                        "tabs", "webRequest", "webRequestBlocking", "<all_urls>", "history",
                                        "management", "proxy", "cookies", "bookmarks", "clipboardRead", "debugger",
                                        "declarativeNetRequest", "webNavigation", "contentSettings", "privacy"
                                    )
                                    
                                    foreach ($permission in $permissions) {
                                        if ($permission -in $highRiskPermissions) {
                                            $suspiciousScore += 1
                                            $suspiciousReasons += "Uses high-risk permission: $permission"
                                        }
                                    }
                                    
                                    # Check for access to all websites
                                    if ($contentScripts -contains "<all_urls>" -or $permissions -contains "<all_urls>") {
                                        $suspiciousScore += 1
                                        $suspiciousReasons += "Has access to all websites"
                                    }
                                    
                                    # Add extension information to results
                                    $extensions += [PSCustomObject]@{
                                        Browser = "Firefox"
                                        Name = $name
                                        ID = $extFolder.Name
                                        Version = $version
                                        Description = $description
                                        Permissions = ($permissions -join "; ")
                                        ContentScripts = ($contentScripts -join "; ")
                                        BackgroundScripts = ($backgroundScripts -join "; ")
                                        User = $username
                                        InstalledPath = $extFolder.FullName
                                        SuspiciousScore = $suspiciousScore
                                        SuspiciousReason = ($suspiciousReasons -join "; ")
                                    }
                                }
                                catch {
                                    Write-ForensicLog "Error parsing Firefox extension manifest in $($extFolder.Name): $_" -Severity "Warning"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error collecting Firefox extensions: $_" -Severity "Warning"
    }
    
    return $extensions
}

function Get-EdgeExtensions {
    $extensions = @()
    
    try {
        Write-ForensicLog "Checking for Edge extensions..."
        
        # Get user profiles
        $userProfiles = Get-ChildItem -Path "C:\Users" -Directory |
                         Where-Object { $_.Name -ne "Public" -and $_.Name -ne "Default" -and $_.Name -ne "Default User" }
        
        foreach ($userProfile in $userProfiles) {
            $username = $userProfile.Name
            
            # Edge Chromium follows Chrome's extension structure
            $extensionsPath = Join-Path -Path $userProfile.FullName -ChildPath "AppData\Local\Microsoft\Edge\User Data\Default\Extensions"
            
            if (Test-Path $extensionsPath) {
                $extensionFolders = Get-ChildItem -Path $extensionsPath -Directory
                
                foreach ($extFolder in $extensionFolders) {
                    # Each extension has its ID as folder name
                    $extensionId = $extFolder.Name
                    
                    # Extensions can have multiple versions, get the most recent one
                    $versionFolders = Get-ChildItem -Path $extFolder.FullName -Directory |
                                      Sort-Object -Property Name -Descending
                    
                    if ($versionFolders.Count -gt 0) {
                        $latestVersion = $versionFolders[0]
                        $manifestPath = Join-Path -Path $latestVersion.FullName -ChildPath "manifest.json"
                        
                        if (Test-Path $manifestPath) {
                            try {
                                $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                                
                                # Basic extension info
                                $name = if ($manifest.name) {
                                    # Some extension names are in ___MSG_extensionName___ format, use description instead
                                    if ($manifest.name -match "^__MSG_") {
                                        if ($manifest.description) { $manifest.description } else { $extensionId }
                                    } else {
                                        $manifest.name
                                    }
                                } else { $extensionId }
                                
                                $version = if ($manifest.version) { $manifest.version } else { $latestVersion.Name }
                                $description = if ($manifest.description) { $manifest.description } else { "No description" }
                                
                                # Get permissions
                                $permissions = @()
                                if ($manifest.permissions) {
                                    $permissions = $manifest.permissions | ForEach-Object { "$_" }
                                }
                                
                                # Check for content scripts that run on pages
                                $contentScripts = @()
                                if ($manifest.content_scripts) {
                                    foreach ($script in $manifest.content_scripts) {
                                        if ($script.matches) {
                                            $contentScripts += $script.matches | ForEach-Object { "$_" }
                                        }
                                    }
                                }
                                
                                # Check for background scripts
                                $backgroundScripts = @()
                                if ($manifest.background -and $manifest.background.scripts) {
                                    $backgroundScripts = $manifest.background.scripts | ForEach-Object { "$_" }
                                }
                                
                                # Calculate a suspiciousness score based on permissions and behavior
                                $suspiciousScore = 0
                                $suspiciousReasons = @()
                                
                                # Check for high-risk permissions
                                $highRiskPermissions = @(
                                    "tabs", "webRequest", "webRequestBlocking", "<all_urls>", "history",
                                    "management", "proxy", "cookies", "bookmarks", "clipboardRead", "debugger",
                                    "declarativeNetRequest", "webNavigation", "contentSettings", "privacy"
                                )
                                
                                foreach ($permission in $permissions) {
                                    if ($permission -in $highRiskPermissions) {
                                        $suspiciousScore += 1
                                        $suspiciousReasons += "Uses high-risk permission: $permission"
                                    }
                                }
                                
                                # Check for access to all websites
                                if ($contentScripts -contains "<all_urls>" -or $permissions -contains "<all_urls>") {
                                    $suspiciousScore += 1
                                    $suspiciousReasons += "Has access to all websites"
                                }
                                
                                # Check for extensions that can read sensitive website content
                                $sensitivePatterns = @("*://*.google.com/*", "*://*.facebook.com/*", "*://*.microsoft.com/*", 
                                                     "*://*.apple.com/*", "*://*.amazon.com/*", "*://mail.*/*", 
                                                     "*://banking.*/*", "*://*.bank.*/*", "*://.*bank.com/*")
                                
                                foreach ($pattern in $sensitivePatterns) {
                                    if ($contentScripts | Where-Object { $_ -like $pattern }) {
                                        $suspiciousScore += 1
                                        $suspiciousReasons += "Accesses sensitive websites: $pattern"
                                        break  # Only count this issue once
                                    }
                                }
                                
                                # Add extension information to results
                                $extensions += [PSCustomObject]@{
                                    Browser = "Edge"
                                    Name = $name
                                    ID = $extensionId
                                    Version = $version
                                    Description = $description
                                    Permissions = ($permissions -join "; ")
                                    ContentScripts = ($contentScripts -join "; ")
                                    BackgroundScripts = ($backgroundScripts -join "; ")
                                    User = $username
                                    InstalledPath = $extFolder.FullName
                                    SuspiciousScore = $suspiciousScore
                                    SuspiciousReason = ($suspiciousReasons -join "; ")
                                }
                            }
                            catch {
                                Write-ForensicLog "Error parsing Edge extension manifest for $extensionId : $_" -Severity "Warning"
                            }
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error collecting Edge extensions: $_" -Severity "Warning"
    }
    
    return $extensions
}

function Get-InternetExplorerAddons {
    $addons = @()
    
    try {
        Write-ForensicLog "Checking for Internet Explorer add-ons..."
        
        # Check IE Add-ons in registry
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Extensions",
            "HKCU:\SOFTWARE\Microsoft\Internet Explorer\Extensions"
        )
        
        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                $addonKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
                
                foreach ($addonKey in $addonKeys) {
                    try {
                        $addonProps = Get-ItemProperty -Path $addonKey.PSPath -ErrorAction SilentlyContinue
                        
                        # Basic add-on info
                        $name = if ($addonProps.ButtonText) { $addonProps.ButtonText } else { $addonKey.PSChildName }
                        $exec = if ($addonProps.Exec) { $addonProps.Exec } else { "Unknown" }
                        $clsid = $addonKey.PSChildName
                        
                        # Calculate suspiciousness score
                        $suspiciousScore = 0
                        $suspiciousReasons = @()
                        
                        # Check for suspicious executables
                        if ($exec -match "\.exe$|\.dll$|\.ocx$") {
                            # Check if the executable is digitally signed
                            if (Test-Path $exec) {
                                try {
                                    $signature = Get-AuthenticodeSignature -FilePath $exec -ErrorAction SilentlyContinue
                                    
                                    if ($signature.Status -ne "Valid") {
                                        $suspiciousScore += 2
                                        $suspiciousReasons += "Unsigned executable: $exec"
                                    }
                                }
                                catch {
                                    $suspiciousScore += 1
                                    $suspiciousReasons += "Could not verify signature: $exec"
                                }
                            }
                            else {
                                $suspiciousScore += 1
                                $suspiciousReasons += "Executable not found: $exec"
                            }
                        }
                        
                        # Check for suspicious locations
                        if ($exec -match "\\Temp\\|\\AppData\\Local\\Temp|%Temp%|\\Downloads\\") {
                            $suspiciousScore += 3
                            $suspiciousReasons += "Executable in temporary directory"
                        }
                        
                        # Add add-on information to results
                        $addons += [PSCustomObject]@{
                            Browser = "Internet Explorer"
                            Name = $name
                            ID = $clsid
                            Version = "Unknown"
                            Description = if ($addonProps.MenuText) { $addonProps.MenuText } else { "No description" }
                            Permissions = "N/A"
                            ContentScripts = "N/A"
                            BackgroundScripts = "N/A"
                            User = if ($regPath -like "HKCU:*") { $env:USERNAME } else { "All Users" }
                            InstalledPath = $exec
                            SuspiciousScore = $suspiciousScore
                            SuspiciousReason = ($suspiciousReasons -join "; ")
                        }
                    }
                    catch {
                        Write-ForensicLog "Error analyzing IE add-on $($addonKey.PSChildName): $_" -Severity "Warning"
                    }
                }
            }
        }

        # Check for Browser Helper Objects (BHOs)
        $bhoKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
        )
        
        foreach ($bhoKey in $bhoKeys) {
            if (Test-Path $bhoKey) {
                $bhos = Get-ChildItem -Path $bhoKey -ErrorAction SilentlyContinue
                
                foreach ($bho in $bhos) {
                    try {
                        $clsid = $bho.PSChildName
                        
                        # Get BHO details from CLSID
                        $clsidPath = "HKLM:\SOFTWARE\Classes\CLSID\$clsid"
                        if (-not (Test-Path $clsidPath)) {
                            $clsidPath = "HKLM:\SOFTWARE\Classes\Wow6432Node\CLSID\$clsid"
                        }
                        
                        if (Test-Path $clsidPath) {
                            $clsidProps = Get-ItemProperty -Path $clsidPath -ErrorAction SilentlyContinue
                            $name = if ($clsidProps."(Default)") { $clsidProps."(Default)" } else { "Unknown BHO" }
                            
                            # Check for InprocServer32 to get the DLL path
                            $inprocPath = Join-Path -Path $clsidPath -ChildPath "InprocServer32"
                            $dllPath = "Unknown"
                            
                            if (Test-Path $inprocPath) {
                                $inprocProps = Get-ItemProperty -Path $inprocPath -ErrorAction SilentlyContinue
                                $dllPath = if ($inprocProps."(Default)") { $inprocProps."(Default)" } else { "Unknown" }
                            }
                            
                            # Calculate suspiciousness score
                            $suspiciousScore = 0
                            $suspiciousReasons = @()

                            # Check for known malicious BHOs
                            $maliciousBHOs = @(
                                "{761497BB-D6F0-462C-B6EB-D4DAF1D92D43}",
                                "{7E853D72-626A-48EC-A868-BA8D5E23E045}",
                                "{0006F045-2F92-4F2F-8D3C-4B65A9ABF1D4}",
                                "{A463F10F-6B1E-4B80-83F1-5C34B8131D1D}",
                                "{FDD3B846-8D59-4FFB-8758-209B6AD74ACC}",
                                "{4D25F926-B9FE-4682-BF72-8AB8210D6D75}",
                                "{49A615F4-7F61-4F6A-9B7B-B42BD7EF67FE}",
                                "{11111111-1111-1111-1111-110011221158}"  # Example of a browser hijacker
                            )
                            
                            if ($clsid -in $maliciousBHOs) {
                                $suspiciousScore += 5
                                $suspiciousReasons += "Known malicious Browser Helper Object"
                            }
                            
                            # Check if BHO is enabled or disabled
                            $noExplorerKey = Join-Path -Path $bho.PSPath -ChildPath "NoExplorer"
                            $isDisabled = $false
                            
                            if (Test-Path $noExplorerKey) {
                                $noExplorerValue = (Get-ItemProperty -Path $bho.PSPath -Name "NoExplorer" -ErrorAction SilentlyContinue).NoExplorer
                                $isDisabled = ($noExplorerValue -eq 1)
                            }
                            
                            if (-not $isDisabled) {
                                $suspiciousScore += 1
                                $suspiciousReasons += "Active Browser Helper Object"
                            }
                            
                            # Check for unsigned DLLs
                            if ($dllPath -ne "Unknown" -and (Test-Path $dllPath)) {
                                try {
                                    $signature = Get-AuthenticodeSignature -FilePath $dllPath -ErrorAction SilentlyContinue
                                    
                                    if ($signature.Status -ne "Valid") {
                                        $suspiciousScore += 2
                                        $suspiciousReasons += "Unsigned BHO DLL: $dllPath"
                                    }
                                }
                                catch {
                                    $suspiciousScore += 1
                                    $suspiciousReasons += "Could not verify BHO signature: $dllPath"
                                }
                            }
                            
                            # Add BHO information to results
                            $addons += [PSCustomObject]@{
                                Browser = "Internet Explorer"
                                Name = $name
                                ID = $clsid
                                Version = "Unknown"
                                Description = "Browser Helper Object" + $(if ($isDisabled) { " (Disabled)" } else { "" })
                                Permissions = "System Level"
                                ContentScripts = "N/A"
                                BackgroundScripts = "N/A"
                                User = if ($bhoKey -like "HKCU:*") { $env:USERNAME } else { "All Users" }
                                InstalledPath = $dllPath
                                SuspiciousScore = $suspiciousScore
                                SuspiciousReason = ($suspiciousReasons -join "; ")
                            }
                        }
                    }
                    catch {
                        Write-ForensicLog "Error analyzing IE BHO $($bho.PSChildName): $_" -Severity "Warning"
                    }
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error collecting Internet Explorer add-ons: $_" -Severity "Warning"
    }
    
    return $addons
}

# Export function
Export-ModuleMember -Function Get-BrowserExtensions
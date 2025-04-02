<#
.SYNOPSIS
    Collects information about installed Windows patches and hotfixes.
    
.DESCRIPTION
    Get-InstalledPatches gathers information about installed Windows updates and hotfixes
    from multiple system sources to provide a comprehensive view of the system's patch state.
    
.EXAMPLE
    $patchesFile = Get-InstalledPatches
    
.OUTPUTS
    String. The path to the CSV file containing installed patches data
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges recommended for complete results
#>

function Get-InstalledPatches {
    param()

    $outputFile = "$script:outputDir\InstalledPatches_$script:timestamp.csv"
    Write-ForensicLog "Collecting installed patches and hotfixes..."

    try {
        # Initialize patches collection
        $patches = @()
        
        # Get installed patches from multiple sources for better coverage
        $patches += Get-HotfixFromWMI
        $patches += Get-HotfixFromCBS
        $patches += Get-HotfixFromWindowsUpdate
        
        # Remove duplicates based on KB number
        $uniquePatches = Remove-DuplicatePatches -Patches $patches
        
        # Export to CSV
        if ($uniquePatches.Count -gt 0) {
            # Sort by installation date
            $sortedPatches = $uniquePatches | Sort-Object -Property InstalledOn -Descending
            $sortedPatches | Export-Csv -Path $outputFile -NoTypeInformation
            
            Write-ForensicLog "Found $($uniquePatches.Count) installed patches/hotfixes"
        } else {
            Write-ForensicLog "No patch information found" -Severity "Warning"
            # Create an empty file to indicate analysis was performed
            [PSCustomObject]@{
                Result = "No patch information found"
                AnalysisTime = Get-Date
                SystemName = $env:COMPUTERNAME
            } | Export-Csv -Path $outputFile -NoTypeInformation
        }
        
        Write-ForensicLog "Saved patch information to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error collecting patch information: $_" -Severity "Error"
        return $null
    }
}

function Get-HotfixFromWMI {
    $patches = @()
    
    try {
        # Use WMI to get installed hotfixes
        $hotfixes = Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction SilentlyContinue
        
        foreach ($hotfix in $hotfixes) {
            $patches += [PSCustomObject]@{
                HotfixID = $hotfix.HotFixID
                Description = $hotfix.Description
                InstalledOn = $hotfix.InstalledOn
                InstalledBy = $hotfix.InstalledBy
                Source = "WMI"
            }
        }
    }
    catch {
        Write-ForensicLog "Error collecting WMI hotfix information: $_" -Severity "Warning"
    }
    
    return $patches
}

function Get-HotfixFromCBS {
    $patches = @()
    
    try {
        # Check Component Based Servicing (CBS) registry for installed packages
        $cbsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
        
        if (Test-Path $cbsPath) {
            $kbPackages = Get-ChildItem -Path $cbsPath -ErrorAction SilentlyContinue | 
                         Where-Object { $_.Name -match "KB\d+" }
            
            foreach ($package in $kbPackages) {
                # Extract the KB number
                if ($package.Name -match "KB(\d+)") {
                    $kbNumber = "KB" + $matches[1]
                    
                    # Check if the package is actually installed
                    $packageState = Get-ItemProperty -Path "Registry::$($package.Name)" -ErrorAction SilentlyContinue
                    
                    if ($packageState -and $packageState.CurrentState -eq 112) {  # 112 = installed
                        $patches += [PSCustomObject]@{
                            HotfixID = $kbNumber
                            Description = $package.Name.Split('\')[-1]
                            InstalledOn = $null  # Not available from registry
                            InstalledBy = "System"
                            Source = "CBS"
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error collecting CBS hotfix information: $_" -Severity "Warning"
    }
    
    return $patches
}

function Get-HotfixFromWindowsUpdate {
    $patches = @()
    
    try {
        # Use Windows Update API to get installation history
        $session = New-Object -ComObject "Microsoft.Update.Session"
        $searcher = $session.CreateUpdateSearcher()
        $historyCount = $searcher.GetTotalHistoryCount()
        
        # Limit to most recent 1000 updates to avoid performance issues
        $count = [Math]::Min(1000, $historyCount)
        
        if ($count -gt 0) {
            $history = $searcher.QueryHistory(0, $count)
            
            for ($i = 0; $i -lt $history.Count; $i++) {
                $update = $history.Item($i)
                
                # Only include successful installations
                if ($update.Operation -eq 1 -and $update.ResultCode -eq 2) {
                    # Extract KB number if present
                    $kbNumber = ""
                    if ($update.Title -match "KB(\d+)") {
                        $kbNumber = "KB" + $matches[1]
                    }
                    
                    $patches += [PSCustomObject]@{
                        HotfixID = $kbNumber
                        Description = $update.Title
                        InstalledOn = $update.Date
                        InstalledBy = "Windows Update"
                        Source = "WindowsUpdate"
                    }
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error collecting Windows Update history: $_" -Severity "Warning"
    }
    
    return $patches
}

function Remove-DuplicatePatches {
    param (
        [array]$Patches
    )
    
    $uniquePatches = @{}
    
    foreach ($patch in $Patches) {
        # Skip entries without a KB number
        if (-not $patch.HotfixID -or $patch.HotfixID -eq "") {
            continue
        }
        
        $key = $patch.HotfixID
        
        # If this KB isn't in our hashtable yet, add it
        if (-not $uniquePatches.ContainsKey($key)) {
            $uniquePatches[$key] = $patch
        }
        # Otherwise, keep the one with the more precise date or better source
        elseif ($patch.InstalledOn -and (-not $uniquePatches[$key].InstalledOn -or 
                                        ($patch.Source -eq "WindowsUpdate" -and $uniquePatches[$key].Source -ne "WindowsUpdate"))) {
            $uniquePatches[$key] = $patch
        }
    }
    
    # Convert hashtable to array
    return $uniquePatches.Values
}

# Export function
Export-ModuleMember -Function Get-InstalledPatches
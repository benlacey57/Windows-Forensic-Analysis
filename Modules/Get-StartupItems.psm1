<#
.SYNOPSIS
    Retrieves and analyses startup items.
    
.DESCRIPTION
    This module retrieves information about programs and services configured to run at startup
    from various registry locations, startup folders, and scheduled tasks. The results are saved to a CSV file.
    
.EXAMPLE
    $startupItemsFile = Get-StartupItems
    
.OUTPUTS
    String. The path to the CSV file containing the startup item analysis.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for complete startup item information.
#>

function Get-StartupItems {
    param()

    $outputFile = "$script:outputDir\StartupItems_$script:timestamp.csv"
    Write-ForensicLog "Retrieving and analysing startup items..."

    try {
        $startupItems = @()

        # Registry Autorun Locations
        $registryLocations = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        )

        foreach ($location in $registryLocations) {
            try {
                $registryItems = Get-ItemProperty -Path $location | Select-Object * -ExcludeProperty PSChildName, PSProvider, PSPath, PSDrive
                foreach ($item in $registryItems.PSObject.Properties) {
                    $startupItems += [PSCustomObject]@{
                        Location = $location
                        Name     = $item.Name
                        Value    = $item.Value
                        Type     = "Registry"
                    }
                }
            }
            catch {
                Write-Verbose "Could not access registry location: $location - $_"
            }
        }

        # Startup Folders
        $startupFolders = @(
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        )

        foreach ($folder in $startupFolders) {
            if (Test-Path -Path $folder) {
                $files = Get-ChildItem -Path $folder
                foreach ($file in $files) {
                    $startupItems += [PSCustomObject]@{
                        Location = $folder
                        Name     = $file.Name
                        Value    = $file.FullName
                        Type     = "Startup Folder"
                    }
                }
            }
        }

        # Scheduled Tasks
        $scheduledTasks = Get-ScheduledTask | Where-Object {$_.Settings.Enabled -eq $true -and $_.Triggers.AtStartup} | Select-Object TaskName, TaskPath, Actions
        foreach ($task in $scheduledTasks) {
            foreach($action in $task.Actions){
                $startupItems += [PSCustomObject]@{
                    Location = $task.TaskPath
                    Name     = $task.TaskName
                    Value    = $action.Execute
                    Type     = "Scheduled Task"
                }
            }
        }

        # Services
        $services = Get-Service | Where-Object {$_.StartType -eq "Automatic"} | Select-Object Name, DisplayName, BinaryPathName, StartType
        foreach ($service in $services) {
            $startupItems += [PSCustomObject]@{
                Location = "Services"
                Name     = $service.Name
                Value    = $service.BinaryPathName
                Type     = "Service"
            }
        }

        # Save to CSV
        $startupItems | Export-Csv -Path $outputFile -NoTypeInformation

        Write-ForensicLog "Saved startup item analysis to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error retrieving startup items: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-StartupItems

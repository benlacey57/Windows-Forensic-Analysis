<#
.SYNOPSIS
    Retrieves and analyses autorun locations.
    
.DESCRIPTION
    This module retrieves information about programs configured to run at startup
    from various registry locations and startup folders. The results are saved to a CSV file.
    
.EXAMPLE
    $autorunLocationsFile = Get-AutorunLocations
    
.OUTPUTS
    String. The path to the CSV file containing the autorun location analysis.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for complete registry access.
#>

function Get-AutorunLocations {
    param()

    $outputFile = "$script:outputDir\AutorunLocations_$script:timestamp.csv"
    Write-ForensicLog "Retrieving and analysing autorun locations..."

    try {
        $autoruns = @()

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
                    $autoruns += [PSCustomObject]@{
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
                    $autoruns += [PSCustomObject]@{
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
                $autoruns += [PSCustomObject]@{
                    Location = $task.TaskPath
                    Name     = $task.TaskName
                    Value    = $action.Execute
                    Type     = "Scheduled Task"
                }
            }
        }

        # Save to CSV
        $autoruns | Export-Csv -Path $outputFile -NoTypeInformation

        Write-ForensicLog "Saved autorun location analysis to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error retrieving autorun locations: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-AutorunLocations

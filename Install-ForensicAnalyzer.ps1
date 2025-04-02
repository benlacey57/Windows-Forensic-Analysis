# Install-ForensicAnalyzer.ps1

<#
.SYNOPSIS
    Installs the Forensic Analyzer tool and its dependencies.
    
.DESCRIPTION
    This script automates the installation of the Forensic Analyzer tool, including creating necessary directories,
    copying files, and configuring scheduled tasks.
    
.EXAMPLE
    .\Install-ForensicAnalyzer.ps1 -InstallPath "C:\ForensicAnalyzer" -ScheduleTask -TaskName "ForensicAnalysis" -ScriptPath "C:\ForensicAnalyzer\ForensicAnalysis.ps1" -Trigger "Daily" -At "02:00"
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$InstallPath,

    [switch]$ScheduleTask,

    [string]$TaskName,

    [string]$ScriptPath,

    [ValidateSet("Daily", "Weekly", "Monthly", "Once", "AtStartup", "AtLogon")]
    [string]$Trigger,

    [string]$At,
    [int]$DaysOfWeek,
    [int]$DayOfMonth
)

# Create installation directory
if (-not (Test-Path -Path $InstallPath)) {
    try {
        New-Item -ItemType Directory -Path $InstallPath | Out-Null
        Write-Host "Created installation directory: $InstallPath"
    }
    catch {
        Write-Error "Failed to create installation directory: $_"
        return
    }
}

# Copy Forensic Analyzer files (replace with your actual file copy logic)
try {
    # Example file copy (replace with actual files)
    Copy-Item -Path ".\ForensicAnalyzer\*" -Destination $InstallPath -Recurse -Force
    Write-Host "Copied Forensic Analyzer files to $InstallPath"
}
catch {
    Write-Error "Failed to copy Forensic Analyzer files: $_"
    return
}

# Configure scheduled task (if requested)
if ($ScheduleTask) {
    try {
        # Create action to run the script
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$ScriptPath`""

        # Create trigger based on specified type
        switch ($Trigger) {
            "Daily" {
                $trigger = New-ScheduledTaskTrigger -Daily -At $At
            }
            "Weekly" {
                $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $DaysOfWeek -At $At
            }
            "Monthly" {
                $trigger = New-ScheduledTaskTrigger -Monthly -DaysOfMonth $DayOfMonth -At $At
            }
            "Once" {
                $trigger = New-ScheduledTaskTrigger -Once -At $At
            }
            "AtStartup" {
                $trigger = New-ScheduledTaskTrigger -AtStartup
            }
            "AtLogon" {
                $trigger = New-ScheduledTaskTrigger -AtLogon
            }
            default {
                Write-Error "Invalid trigger type: $Trigger"
                return
            }
        }

        # Create scheduled task settings
        $settings = New-ScheduledTaskSettingsSet -RunOnlyIfLoggedOn $false -StartWhenAvailable $true

        # Create principal
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM"

        # Register the scheduled task
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal

        Write-Host "Scheduled task '$TaskName' registered successfully."
    }
    catch {
        Write-Error "Failed to register scheduled task: $_"
    }
}

Write-Host "Forensic Analyzer installation complete."

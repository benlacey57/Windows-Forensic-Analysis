<#
.SYNOPSIS
    Registers a forensic analysis schedule as a scheduled task.
    
.DESCRIPTION
    This module creates a scheduled task to run a forensic analysis script at a specified
    interval. It allows configuration of the task name, script path, trigger, and other settings.
    
.EXAMPLE
    Register-ForensicAnalysisSchedule -TaskName "ForensicAudit" -ScriptPath "C:\Forensics\Audit.ps1" -Trigger "Daily" -At "10:00"
    
.OUTPUTS
    None.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required.
#>

function Register-ForensicAnalysisSchedule {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TaskName,

        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Daily", "Weekly", "Monthly", "Once", "AtStartup", "AtLogon")]
        [string]$Trigger,

        [string]$At, # Time for daily, weekly, monthly, once triggers (e.g., "10:00")
        [int]$DaysOfWeek, # Days of week for Weekly trigger (e.g., 1 for Sunday, 2 for Monday, etc.)
        [int]$DayOfMonth, # Day of month for Monthly trigger (e.g., 1-31)
        [string]$User, # User account to run the task under (e.g., "SYSTEM", "domain\user")
        [string]$Password # Password for the user account (if needed)
    )

    Write-ForensicLog "Registering forensic analysis schedule: $TaskName"

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
                Write-ForensicLog "Invalid trigger type: $Trigger" -Severity "Error"
                return
            }
        }

        # Create scheduled task settings
        $settings = New-ScheduledTaskSettingsSet -RunOnlyIfLoggedOn $false -StartWhenAvailable $true

        # Create principal
        if ($User) {
            if ($Password) {
                $principal = New-ScheduledTaskPrincipal -UserId $User -Password $Password -LogonType Password
            } else {
                $principal = New-ScheduledTaskPrincipal -UserId $User
            }
        } else {
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM"
        }

        # Register the scheduled task
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal

        Write-ForensicLog "Forensic analysis schedule '$TaskName' registered successfully."
    }
    catch {
        Write-ForensicLog "Error registering forensic analysis schedule: $_" -Severity "Error"
    }
}

# Export function
Export-ModuleMember -Function Register-ForensicAnalysisSchedule

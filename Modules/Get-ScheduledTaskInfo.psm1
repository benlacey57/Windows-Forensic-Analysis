<#
.SYNOPSIS
    Identifies suspicious scheduled tasks
    
.DESCRIPTION
    Analyzes scheduled tasks for suspicious characteristics that could indicate
    persistence mechanisms used by attackers, such as encoded PowerShell commands,
    unusual execution paths, or non-standard task registration patterns.
    
.EXAMPLE
    $suspiciousTasksFile = Find-SuspiciousScheduledTasks
    
.OUTPUTS
    String. The path to the CSV file containing suspicious scheduled tasks
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges recommended for complete task information
#>

function Find-SuspiciousScheduledTasks {
    param()
    
    $outputFile = "$script:outputDir\SuspiciousTasks_$script:timestamp.csv"
    Write-ForensicLog "Analyzing scheduled tasks for suspicious patterns..."
    
    try {
        # Get all scheduled tasks with detailed information
        $allTasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, State, 
            @{Name="Actions";Expression={$_.Actions.Execute}},
            @{Name="Arguments";Expression={$_.Actions.Arguments}},
            @{Name="Author";Expression={
                try {
                    $taskXml = [xml]$_.XML
                    $taskXml.Task.RegistrationInfo.Author
                } catch {
                    "Unknown"
                }
            }},
            @{Name="Date";Expression={
                try {
                    $taskXml = [xml]$_.XML
                    $taskXml.Task.RegistrationInfo.Date
                } catch {
                    "Unknown"
                }
            }},
            @{Name="Description";Expression={
                try {
                    $taskXml = [xml]$_.XML
                    $taskXml.Task.RegistrationInfo.Description
                } catch {
                    "Unknown"
                }
            }},
            @{Name="UserId";Expression={
                try {
                    $taskXml = [xml]$_.XML
                    $taskXml.Task.Principals.Principal.UserId
                } catch {
                    "Unknown"
                }
            }},
            @{Name="RunLevel";Expression={
                try {
                    $taskXml = [xml]$_.XML
                    $taskXml.Task.Principals.Principal.RunLevel
                } catch {
                    "Unknown"
                }
            }},
            @{Name="Triggers";Expression={
                try {
                    $taskXml = [xml]$_.XML
                    ($taskXml.Task.Triggers | Get-Member -MemberType Property | ForEach-Object { $_.Name }) -join "; "
                } catch {
                    "Unknown"
                }
            }},
            @{Name="LastRunTime";Expression={
                try {
                    $taskInfo = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
                    $taskInfo.LastRunTime
                } catch {
                    "Unknown"
                }
            }},
            @{Name="NextRunTime";Expression={
                try {
                    $taskInfo = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
                    $taskInfo.NextRunTime
                } catch {
                    "Unknown"
                }
            }},
            @{Name="LastTaskResult";Expression={
                try {
                    $taskInfo = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
                    $taskInfo.LastTaskResult
                } catch {
                    "Unknown"
                }
            }}
        
        # Analyze tasks for suspicious characteristics
        foreach ($task in $allTasks) {
            # Add suspicious score and reasons
            $suspiciousScore = 0
            $suspiciousReasons = @()
            
            # Check for enabled tasks
            if ($task.State -eq "Ready") {
                # Check for tasks with suspicious executables
                $suspiciousExecutables = @("powershell", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin")
                foreach ($exe in $suspiciousExecutables) {
                    if ($task.Actions -match $exe) {
                        $suspiciousScore += 1
                        $suspiciousReasons += "Uses potentially suspicious executable: $exe"
                        break
                    }
                }
                
                # Check for tasks with suspicious arguments
                $suspiciousArguments = @(
                    "-enc", "-encodedcommand", "-e ", "-w hidden", "-windowstyle h", "-exec bypass", "-noprofile", "-noexit",
                    "downloadstring", "downloadfile", "webclient", "invoke-webrequest", "invoke-expression", "iex ", 
                    "net user", "net group", "net localgroup", "reg add", "reg delete", "sc create", "sc start"
                )
                
                foreach ($arg in $suspiciousArguments) {
                    if ($task.Arguments -match [regex]::Escape($arg)) {
                        $suspiciousScore += 2
                        $suspiciousReasons += "Contains suspicious argument: $arg"
                        break
                    }
                }
                
                # Check for Base64 encoded commands
                if ($task.Arguments -match "[A-Za-z0-9+/]{50,}={0,2}") {
                    $suspiciousScore += 3
                    $suspiciousReasons += "Contains potential Base64 encoded command"
                }
                
                # Check for tasks in non-standard paths
                if ($task.TaskPath -notmatch "\\Microsoft\\|\\WPD\\") {
                    $suspiciousScore += 1
                    $suspiciousReasons += "Located in non-standard task path"
                }
                
                # Check for tasks with random-looking names
                if ($task.TaskName -match "^[A-Za-z0-9]{8,}$") {
                    $suspiciousScore += 2
                    $suspiciousReasons += "Random-looking task name"
                }
                
                # Check for tasks running with highest privileges
                if ($task.RunLevel -eq "HighestAvailable") {
                    $suspiciousScore += 1
                    $suspiciousReasons += "Runs with highest available privileges"
                }
                
                # Check for recently created tasks
                if ($task.Date -ne "Unknown") {
                    try {
                        $taskDate = [DateTime]::Parse($task.Date)
                        if (((Get-Date) - $taskDate).TotalDays -lt 30) {
                            $suspiciousScore += 1
                            $suspiciousReasons += "Recently created task (last 30 days)"
                        }
                    } catch {}
                }
                
                # Check for tasks with network connections
                if ($task.Actions -match "http:|https:|ftp:|\\\\|net use") {
                    $suspiciousScore += 2
                    $suspiciousReasons += "Contains network connection indicators"
                }
                
                # Check for tasks with non-standard author
                if ($task.Author -notmatch "Microsoft|Windows|Administrator" -and $task.Author -ne "Unknown") {
                    $suspiciousScore += 1
                    $suspiciousReasons += "Non-standard author: $($task.Author)"
                }
                
                # Check for system tasks with unusual executables
                if ($task.TaskPath -match "\\Microsoft\\" -and 
                    $task.Actions -match "powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin") {
                    $suspiciousScore += 3
                    $suspiciousReasons += "System task path with suspicious executable"
                }
            }
            
            # Add suspicious score and reasons to task object
            $task | Add-Member -MemberType NoteProperty -Name "SuspiciousScore" -Value $suspiciousScore
            $task | Add-Member -MemberType NoteProperty -Name "SuspiciousReasons" -Value ($suspiciousReasons -join "; ")
        }
        
        # Filter and save suspicious tasks
        $suspiciousTasks = $allTasks | Where-Object { $_.SuspiciousScore -gt 0 } | Sort-Object -Property SuspiciousScore -Descending
        
        if ($suspiciousTasks.Count -gt 0) {
            $suspiciousTasks | Export-Csv -Path $outputFile -NoTypeInformation
            
            Write-ForensicLog "Found $($suspiciousTasks.Count) suspicious scheduled tasks:" -Severity "Warning"
            foreach ($task in $suspiciousTasks | Select-Object -First 5) {
                Write-ForensicLog "  - $($task.TaskPath)$($task.TaskName): $($task.Actions) $($task.Arguments) - $($task.SuspiciousReasons)" -Severity "Warning"
            }
        } else {
            Write-ForensicLog "No suspicious scheduled tasks detected."
            "No suspicious scheduled tasks detected." | Out-File -Path $outputFile
        }
        
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error analyzing scheduled tasks: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Find-SuspiciousScheduledTasks
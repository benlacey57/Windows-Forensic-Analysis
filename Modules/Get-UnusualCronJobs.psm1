<#
.SYNOPSIS
    Identifies unusual scheduled tasks and jobs on Windows systems.
    
.DESCRIPTION
    Get-UnusualCronJobs examines scheduled tasks and Windows jobs to identify
    potentially suspicious scheduled activities. It analyzes task triggers,
    actions, permissions, and execution history to flag unusual configurations
    that could indicate persistence mechanisms or unauthorized activity.
    
.EXAMPLE
    $cronJobsFile = Get-UnusualCronJobs
    
.OUTPUTS
    String. The path to the CSV file containing unusual scheduled job findings
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges recommended for complete results
#>

function Get-UnusualCronJobs {
    param()

    $outputFile = "$script:outputDir\UnusualScheduledJobs_$script:timestamp.csv"
    Write-ForensicLog "Analyzing scheduled tasks and jobs..."

    try {
        # Initialize findings collection
        $unusualJobs = @()
        
        # Analyze scheduled tasks
        $taskFindings = Find-UnusualScheduledTasks
        $unusualJobs += $taskFindings
        
        # Analyze WMI event subscriptions (another form of persistence)
        $wmiFindings = Find-UnusualWmiSubscriptions
        $unusualJobs += $wmiFindings
        
        # Examine the Task Scheduler directories for hidden tasks
        $hiddenTaskFindings = Find-HiddenScheduledTasks
        $unusualJobs += $hiddenTaskFindings
        
        # Export results
        if ($unusualJobs.Count -gt 0) {
            # Sort findings by risk level and score
            $sortedFindings = $unusualJobs | Sort-Object -Property @{Expression = "RiskLevel"; Descending = $true}, @{Expression = "SuspiciousScore"; Descending = $true}
            $sortedFindings | Export-Csv -Path $outputFile -NoTypeInformation
            
            # Report high-risk findings
            $highRiskFindings = $sortedFindings | Where-Object { $_.RiskLevel -eq "High" }
            if ($highRiskFindings.Count -gt 0) {
                Write-ForensicLog "Found $($highRiskFindings.Count) high-risk scheduled job findings:" -Severity "Warning"
                foreach ($finding in $highRiskFindings | Select-Object -First 5) {
                    Write-ForensicLog "  - $($finding.TaskName) - $($finding.SuspiciousReasons)" -Severity "Warning"
                }
            }
            
            Write-ForensicLog "Found a total of $($unusualJobs.Count) suspicious scheduled jobs"
        } else {
            Write-ForensicLog "No suspicious scheduled jobs detected"
            # Create an empty file to indicate analysis was performed
            [PSCustomObject]@{
                Result = "No suspicious scheduled jobs detected"
                AnalysisTime = Get-Date
                SystemName = $env:COMPUTERNAME
            } | Export-Csv -Path $outputFile -NoTypeInformation
        }
        
        Write-ForensicLog "Saved scheduled job analysis data to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error analyzing scheduled jobs: $_" -Severity "Error"
        return $null
    }
}

function Find-UnusualScheduledTasks {
    $findings = @()
    
    # Get all scheduled tasks
    $scheduledTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    
    foreach ($task in $scheduledTasks) {
        $suspiciousScore = 0
        $suspiciousReasons = @()
        
        # Get task details
        $taskInfo = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        $taskSettings = $task.Settings
        $taskTriggers = $task.Triggers
        $taskActions = $task.Actions
        
        # Check task path (location)
        if (-not $task.TaskPath.StartsWith("\Microsoft\") -and 
            -not $task.TaskPath.StartsWith("\Windows\")) {
            
            # Non-standard task location
            $suspiciousScore += 1
            $suspiciousReasons += "Non-standard task location: $($task.TaskPath)"
        }
        
        # Deep inspection of task actions
        foreach ($action in $taskActions) {
            # Check for suspicious executables/scripts
            if ($action.Execute) {
                # PowerShell with encoded commands
                if ($action.Execute -match "powershell|pwsh" -and 
                    $action.Arguments -match "-e |-enc |-EncodedCommand") {
                    $suspiciousScore += 4
                    $suspiciousReasons += "PowerShell encoded command execution"
                }
                # Command-line utilities often used maliciously
                elseif ($action.Execute -match "cmd\.exe|wscript\.exe|cscript\.exe|regsvr32\.exe|rundll32\.exe|mshta\.exe") {
                    $suspiciousScore += 2
                    $suspiciousReasons += "Task uses script interpreter or suspicious utility: $($action.Execute)"
                    
                    # Additional inspection of arguments
                    if ($action.Arguments -match "/c|/k|-w hidden|-windowstyle h|downloadstring|invoke-expression|iex |bypass") {
                        $suspiciousScore += 2
                        $suspiciousReasons += "Suspicious command-line arguments: $($action.Arguments)"
                    }
                }
                
                # Check for tasks running from suspicious locations
                if ($action.Execute -match "\\Temp\\|\\AppData\\|\\Downloads\\|\\Public\\") {
                    $suspiciousScore += 3
                    $suspiciousReasons += "Task executes from suspicious location: $($action.Execute)"
                }
                
                # Check tasks using remote resources
                if ($action.Execute.StartsWith("\\\\") -or ($action.Arguments -and $action.Arguments.Contains("\\\\"))) {
                    $suspiciousScore += 3
                    $suspiciousReasons += "Task uses remote network resource"
                }
                
                # Check for unusual file extensions
                if ($action.Execute -match "\.(bat|vbs|ps1|hta|js)$") {
                    $suspiciousScore += 2
                    $suspiciousReasons += "Task executes script directly: $($action.Execute)"
                }
            }
        }
        
        # Check task timing and triggers
        $hasSuspiciousTrigger = $false
        foreach ($trigger in $taskTriggers) {
            # Check for tasks that run at unusual times
            if ($trigger.StartBoundary -and $trigger.StartBoundary -match "T0[0-3]:|T22:|T23:") {
                $suspiciousScore += 1
                $suspiciousReasons += "Task scheduled during low-activity hours (night time)"
                $hasSuspiciousTrigger = $true
            }
            
            # Check logon triggers with no specific user
            if ($trigger.CimClass -and $trigger.CimClass.CimClassName -match "MSFT_TaskLogonTrigger" -and 
                (-not $trigger.UserId -or $trigger.UserId -eq "")) {
                $suspiciousScore += 2
                $suspiciousReasons += "Task triggers on any user logon"
                $hasSuspiciousTrigger = $true
            }
            
            # Check for tasks with registration trigger (runs immediately when created)
            if ($trigger.CimClass -and $trigger.CimClass.CimClassName -match "MSFT_TaskRegistrationTrigger") {
                $suspiciousScore += 1
                $suspiciousReasons += "Task runs immediately upon registration"
                $hasSuspiciousTrigger = $true
            }
        }
        
        # Check if the task has no triggers (often a sign of a manually launched persistence task)
        if ($taskTriggers.Count -eq 0) {
            $suspiciousScore += 2
            $suspiciousReasons += "Task has no triggers (potentially manually activated)"
        }
        
        # Check task settings
        if ($taskSettings) {
            # Check for hidden tasks
            if ($taskSettings.Hidden) {
                $suspiciousScore += 3
                $suspiciousReasons += "Task is hidden from Task Scheduler UI"
            }
            
            # Check for tasks that don't stop when they run too long
            if ($taskSettings.ExecutionTimeLimit -eq "PT0S") {
                $suspiciousScore += 1
                $suspiciousReasons += "Task has no execution time limit"
            }
            
            # Check for tasks with highest privileges
            if ($task.Principal.RunLevel -eq "Highest") {
                $suspiciousScore += 1
                $suspiciousReasons += "Task runs with highest privileges"
            }
        }
        
        # Check last run results
        if ($taskInfo -and $taskInfo.LastRunTime -ne $null) {
            # Check for recently created tasks
            $taskAge = (Get-Date) - $taskInfo.LastRunTime
            if ($taskAge.TotalDays -lt 7) {
                $suspiciousScore += 1
                $suspiciousReasons += "Recently executed task (within 7 days)"
            }
            
            # Check for tasks that run frequently
            $runFrequency = $taskInfo.NumberOfMissedRuns
            if ($runFrequency -gt 10) {
                $suspiciousScore += 1
                $suspiciousReasons += "Frequently running task ($runFrequency runs/missed runs)"
            }
        }
        
        # Only add task to findings if it's suspicious
        if ($suspiciousScore -gt 0) {
            $taskActionText = $taskActions | ForEach-Object {
                if ($_.Execute) {
                    "$($_.Execute) $($_.Arguments)"
                } elseif ($_.Uri) {
                    "COM: $($_.Uri)"
                } else {
                    "Unknown action type"
                }
            } | Out-String
            
            $taskTriggerText = $taskTriggers | ForEach-Object {
                "$($_.CimClass.CimClassName)"
            } | Out-String
            
            $riskLevel = switch ($suspiciousScore) {
                { $_ -ge 5 } { "High" }
                { $_ -ge 3 } { "Medium" }
                default { "Low" }
            }
            
            $findings += [PSCustomObject]@{
                JobType = "Scheduled Task"
                TaskName = $task.TaskName
                TaskPath = $task.TaskPath
                FullName = "$($task.TaskPath)$($task.TaskName)"
                State = $task.State
                Author = $task.Author
                Description = $task.Description
                Actions = $taskActionText.Trim()
                Triggers = $taskTriggerText.Trim()
                LastRunTime = if ($taskInfo) { $taskInfo.LastRunTime } else { "Unknown" }
                NextRunTime = if ($taskInfo) { $taskInfo.NextRunTime } else { "Unknown" }
                RunLevel = $task.Principal.RunLevel
                UserId = $task.Principal.UserId
                SuspiciousScore = $suspiciousScore
                RiskLevel = $riskLevel
                SuspiciousReasons = ($suspiciousReasons -join "; ")
            }
        }
    }
    
    return $findings
}


function Find-UnusualWmiSubscriptions {
    $findings = @()
    
    try {
        # Get WMI Event Consumers (actions to be taken when an event fires)
        $consumers = @()
        $consumers += Get-CimInstance -Namespace "ROOT\Subscription" -ClassName "CommandLineEventConsumer" -ErrorAction SilentlyContinue
        $consumers += Get-CimInstance -Namespace "ROOT\Subscription" -ClassName "ActiveScriptEventConsumer" -ErrorAction SilentlyContinue
        
        # Get WMI Event Filters (conditions that trigger an event)
        $filters = Get-CimInstance -Namespace "ROOT\Subscription" -ClassName "__EventFilter" -ErrorAction SilentlyContinue
        
        # Get WMI Event Filter to Consumer Bindings (links between filters and consumers)
        $bindings = Get-CimInstance -Namespace "ROOT\Subscription" -ClassName "__FilterToConsumerBinding" -ErrorAction SilentlyContinue
        
        foreach ($consumer in $consumers) {
            $suspiciousScore = 0
            $suspiciousReasons = @()
            
            # Find associated filters and bindings
            $consumerBindings = $bindings | Where-Object { $_.Consumer -like "*$($consumer.Name)" }
            $associatedFilters = @()
            
            foreach ($binding in $consumerBindings) {
                $filter = $filters | Where-Object { $_.Name -eq ($binding.Filter -replace '.*:', '') }
                if ($filter) {
                    $associatedFilters += $filter
                }
            }
            
            $filterQueries = ($associatedFilters | ForEach-Object { $_.Query }) -join "; "
            
            # Analyze CommandLineEventConsumer
            if ($consumer.CimClass.CimClassName -eq "CommandLineEventConsumer") {
                # Check for suspicious commands
                if ($consumer.CommandLineTemplate -match "powershell|cmd\.exe|wscript|cscript|rundll32|regsvr32|mshta") {
                    $suspiciousScore += 3
                    $suspiciousReasons += "WMI consumer uses script interpreter or suspicious binary"
                }
                
                # Check for encoded commands or suspicious flags
                if ($consumer.CommandLineTemplate -match "-e |-enc |-EncodedCommand|-w hidden|-windowstyle h|downloadstring|iex |invoke-expr|bypass") {
                    $suspiciousScore += 3
                    $suspiciousReasons += "WMI consumer uses suspicious command-line arguments"
                }
                
                # Check for execution from suspicious locations
                if ($consumer.CommandLineTemplate -match "\\Temp\\|\\AppData\\|\\Downloads\\|\\Public\\") {
                    $suspiciousScore += 3
                    $suspiciousReasons += "WMI consumer executes from suspicious location"
                }
                
                # Check for network access
                if ($consumer.CommandLineTemplate -match "http:|https:|ftp:|\\\\") {
                    $suspiciousScore += 3
                    $suspiciousReasons += "WMI consumer accesses network resources"
                }
            }
            # Analyze ActiveScriptEventConsumer
            elseif ($consumer.CimClass.CimClassName -eq "ActiveScriptEventConsumer") {
                $suspiciousScore += 2
                $suspiciousReasons += "WMI uses script-based consumer (potential for code execution)"
                
                # Check script content for suspicious patterns
                if ($consumer.ScriptText -match "WScript\.Shell|ActiveXObject|XMLHttpRequest|MSXML2|download|exec|eval|CreateObject") {
                    $suspiciousScore += 3
                    $suspiciousReasons += "WMI script contains suspicious code patterns"
                }
            }
            
            # Check event filter queries for suspicious patterns
            foreach ($filter in $associatedFilters) {
                # Process creation monitoring is often used for persistence
                if ($filter.Query -match "SELECT.*FROM.*ProcessStart|Win32_ProcessStartTrace|__InstanceCreationEvent.*Win32_Process") {
                    $suspiciousScore += 2
                    $suspiciousReasons += "WMI subscription monitors process creation"
                }
                
                # User logon monitoring is often used for persistence
                if ($filter.Query -match "SELECT.*FROM.*__InstanceCreationEvent.*Win32_LogonSession") {
                    $suspiciousScore += 2
                    $suspiciousReasons += "WMI subscription monitors user logon events"
                }
                
                # System startup monitoring is often used for persistence
                if ($filter.Query -match "SystemBoot|ShutdownInitiated|EventID = 12") {
                    $suspiciousScore += 2
                    $suspiciousReasons += "WMI subscription monitors system startup/shutdown"
                }
            }
            
            # Only add to findings if suspicious
            if ($suspiciousScore -gt 0) {
                $riskLevel = switch ($suspiciousScore) {
                    { $_ -ge 5 } { "High" }
                    { $_ -ge 3 } { "Medium" }
                    default { "Low" }
                }
                
                $findings += [PSCustomObject]@{
                    JobType = "WMI Subscription"
                    TaskName = $consumer.Name
                    TaskPath = "ROOT\Subscription"
                    FullName = "WMI: $($consumer.Name)"
                    State = "Active"
                    Author = "Unknown"
                    Description = "WMI Event Subscription"
                    Actions = if ($consumer.CimClass.CimClassName -eq "CommandLineEventConsumer") { 
                        $consumer.CommandLineTemplate 
                    } elseif ($consumer.CimClass.CimClassName -eq "ActiveScriptEventConsumer") {
                        "ScriptType: $($consumer.ScriptingEngine), ScriptText: $($consumer.ScriptText)"
                    } else {
                        "Unknown consumer type"
                    }
                    Triggers = $filterQueries
                    LastRunTime = "Unknown"
                    NextRunTime = "Unknown"
                    RunLevel = "System"
                    UserId = "SYSTEM"
                    SuspiciousScore = $suspiciousScore
                    RiskLevel = $riskLevel
                    SuspiciousReasons = ($suspiciousReasons -join "; ")
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error analyzing WMI subscriptions: $_" -Severity "Warning"
    }
    
    return $findings
}


function Find-HiddenScheduledTasks {
    $findings = @()
    
    try {
        # Look for task files directly in the task scheduler directories
        $taskFolders = @(
            "$env:SystemRoot\System32\Tasks",
            "$env:SystemRoot\SysWOW64\Tasks"
        )
        
        foreach ($taskFolder in $taskFolders) {
            if (Test-Path $taskFolder) {
                $taskFiles = Get-ChildItem -Path $taskFolder -Recurse -File -ErrorAction SilentlyContinue
                
                foreach ($taskFile in $taskFiles) {
                    # Skip files that are obviously not task files
                    if ($taskFile.Extension -ne "") {
                        continue
                    }
                    
                    $taskPath = $taskFile.FullName.Replace($taskFolder, "").Replace("\", "/")
                    $taskXml = $null
                    
                    # Try to read the task XML
                    try {
                        $taskXml = [xml](Get-Content -Path $taskFile.FullName -ErrorAction SilentlyContinue)
                    }
                    catch {
                        # Skip if can't read the file
                        continue
                    }
                    
                    # Skip if XML couldn't be parsed
                    if (-not $taskXml) {
                        continue
                    }
                    
                    # Check if this task is visible in Get-ScheduledTask
                    $taskName = $taskFile.Name
                    $visibleTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                    
                    # If not visible in Get-ScheduledTask, it might be hidden
                    if (-not $visibleTask) {
                        $suspiciousScore = 3
                        $suspiciousReasons = @("Task exists on disk but is not visible in Task Scheduler")
                        
                        # Extract information from the XML
                        $actions = ""
                        $triggers = ""
                        $author = "Unknown"
                        $description = "Unknown"
                        $userId = "Unknown"
                        $runLevel = "Unknown"
                        
                        # Extract action information
                        try {
                            $actionNodes = $taskXml.SelectNodes("//Actions/*")
                            $actions = $actionNodes | ForEach-Object {
                                if ($_.Name -eq "Exec") {
                                    "$($_.Command) $($_.Arguments)"
                                } elseif ($_.Name -eq "ComHandler") {
                                    "COM: $($_.ClassId)"
                                } else {
                                    "$($_.Name) action"
                                }
                            } | Out-String
                            
                            # Check for suspicious executable/command line
                            if ($actions -match "powershell|cmd\.exe|wscript|cscript|rundll32|regsvr32|mshta") {
                                $suspiciousScore += 2
                                $suspiciousReasons += "Hidden task uses script interpreter or suspicious binary"
                            }
                            
                            if ($actions -match "-e |-enc |-EncodedCommand|-w hidden|-windowstyle h|downloadstring|iex |invoke-expr|bypass") {
                                $suspiciousScore += 3
                                $suspiciousReasons += "Hidden task uses suspicious command-line arguments"
                            }
                            
                            if ($actions -match "\\Temp\\|\\AppData\\|\\Downloads\\|\\Public\\") {
                                $suspiciousScore += 3
                                $suspiciousReasons += "Hidden task executes from suspicious location"
                            }
                        }
                        catch {
                            $actions = "Error parsing actions"
                        }
                        
                        # Extract trigger information
                        try {
                            $triggerNodes = $taskXml.SelectNodes("//Triggers/*")
                            $triggers = $triggerNodes | ForEach-Object { $_.Name } | Out-String
                        }
                        catch {
                            $triggers = "Error parsing triggers"
                        }
                        
                        # Extract registration info
                        try {
                            $regInfoNode = $taskXml.SelectSingleNode("//RegistrationInfo")
                            if ($regInfoNode) {
                                $author = $regInfoNode.Author
                                $description = $regInfoNode.Description
                            }
                        }
                        catch {}
                        
                        # Extract principal info
                        try {
                            $principalNode = $taskXml.SelectSingleNode("//Principals/Principal")
                            if ($principalNode) {
                                $userId = $principalNode.UserId
                                $runLevel = $principalNode.RunLevel
                            }
                        }
                        catch {}
                        
                        $riskLevel = switch ($suspiciousScore) {
                            { $_ -ge 5 } { "High" }
                            { $_ -ge 3 } { "Medium" }
                            default { "Low" }
                        }
                        
                        $findings += [PSCustomObject]@{
                            JobType = "Hidden Scheduled Task"
                            TaskName = $taskName
                            TaskPath = $taskPath
                            FullName = "HIDDEN: $taskPath/$taskName"
                            State = "Unknown"
                            Author = $author
                            Description = $description
                            Actions = $actions.Trim()
                            Triggers = $triggers.Trim()
                            LastRunTime = "Unknown"
                            NextRunTime = "Unknown"
                            RunLevel = $runLevel
                            UserId = $userId
                            SuspiciousScore = $suspiciousScore
                            RiskLevel = $riskLevel
                            SuspiciousReasons = ($suspiciousReasons -join "; ")
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error looking for hidden scheduled tasks: $_" -Severity "Warning"
    }
    
    return $findings
}

# Export function
Export-ModuleMember -Function Get-UnusualCronJobs
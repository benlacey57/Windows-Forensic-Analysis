<#
.SYNOPSIS
    Identifies and recovers information about recently deleted files on Windows systems.
    
.DESCRIPTION
    Get-RecentlyDeletedFiles analyzes the file system for evidence of recently deleted files
    by examining the Recycle Bin, shadow copies, USN journal, and other forensic artifacts.
    It helps identify potentially suspicious file deletion activity that might indicate
    anti-forensics or data destruction attempts.
    
.EXAMPLE
    $deletedFilesData = Get-RecentlyDeletedFiles
    
.OUTPUTS
    String. The path to the CSV file containing information about recently deleted files
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for complete results
#>

function Get-RecentlyDeletedFiles {
    param()

    $outputFile = "$script:outputDir\DeletedFiles_$script:timestamp.csv"
    Write-ForensicLog "Analyzing recently deleted files..."

    try {
        # Initialize findings collection
        $deletedFiles = @()
        
        # Collect findings from each source
        $deletedFiles += Get-RecycleBinContents
        $deletedFiles += Get-UsnJournalDeletedFiles
        $deletedFiles += Get-ShadowCopyDeletedFiles
        $deletedFiles += Get-FileShredderEvidence
        
        # Export results
        Export-DeletedFileResults -Findings $deletedFiles -OutputFile $outputFile
        
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error analyzing deleted files: $_" -Severity "Error"
        return $null
    }
}

function Get-RecycleBinContents {
    $findings = @()
    
    try {
        Write-ForensicLog "Examining Recycle Bin contents..."
        
        # Get all recycled file metadata
        $metadataFiles = @()
        
        # Check each drive for $Recycle.Bin
        Get-PSDrive -PSProvider FileSystem | 
            Where-Object { $_.Root -match "^\w:\\" } | 
            ForEach-Object {
                $recyclePath = "$($_.Root)`$Recycle.Bin"
                if (Test-Path $recyclePath) {
                    # Find all $I metadata files recursively
                    $metadataFiles += Get-ChildItem -Path $recyclePath -Filter '$I*' -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        
        # Process each metadata file
        foreach ($metadataFile in $metadataFiles) {
            try {
                # Extract file details from metadata file
                $fileInfo = Read-RecycleBinMetadata -MetadataFile $metadataFile
                if ($fileInfo) {
                    # Score the suspiciousness of the deletion
                    $suspiciousData = Get-FileDeletionSuspiciousness -FileName $fileInfo.FileName -FilePath $fileInfo.OriginalPath -DeletionTime $fileInfo.DeletionTime
                    
                    # Create finding
                    $findings += [PSCustomObject]@{
                        Source = "Recycle Bin"
                        FileName = $fileInfo.FileName
                        FileType = $fileInfo.FileType
                        OriginalPath = $fileInfo.OriginalPath
                        FileSize = $fileInfo.FileSize
                        DeletionTime = $fileInfo.DeletionTime
                        UserSID = $fileInfo.UserSID
                        FileRecoverable = $fileInfo.FileRecoverable
                        RecoveryPath = $fileInfo.RecoveryPath
                        SuspiciousScore = $suspiciousData.Score
                        SuspiciousReasons = $suspiciousData.Reasons
                    }
                }
            }
            catch {
                Write-ForensicLog "Error reading Recycle Bin metadata file $($metadataFile.FullName): $_" -Severity "Warning"
            }
        }
    }
    catch {
        Write-ForensicLog "Error accessing Recycle Bin: $_" -Severity "Warning"
    }
    
    return $findings
}

function Read-RecycleBinMetadata {
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$MetadataFile
    )
    
    try {
        # The $I files contain metadata about the deleted file
        $fileStream = [System.IO.File]::OpenRead($MetadataFile.FullName)
        $reader = New-Object System.IO.BinaryReader($fileStream)
        
        # Skip header (8 bytes)
        $reader.BaseStream.Position = 8
        
        # Read file size (8 bytes)
        $fileSize = $reader.ReadInt64()
        
        # Read deletion time (8 bytes, Windows FILETIME)
        $fileTimeBytes = $reader.ReadBytes(8)
        $fileTime = [BitConverter]::ToInt64($fileTimeBytes, 0)
        $deletionTime = [DateTime]::FromFileTime($fileTime)
        
        # Skip 8 bytes
        $reader.BaseStream.Position += 8
        
        # Read path length (4 bytes)
        $pathLength = $reader.ReadInt32()
        
        # Read original path (variable length, Unicode)
        $pathBytes = $reader.ReadBytes($pathLength * 2)
        $originalPath = [System.Text.Encoding]::Unicode.GetString($pathBytes)
        
        # Clean up
        $reader.Close()
        $fileStream.Close()
        
        # Corresponding $R file (actual file content)
        $rFileName = $MetadataFile.Name.Replace('$I', '$R')
        $rFilePath = Join-Path -Path $MetadataFile.DirectoryName -ChildPath $rFileName
        $fileExists = Test-Path -Path $rFilePath
        
        # Extract file details
        $fileName = [System.IO.Path]::GetFileName($originalPath)
        $fileExtension = [System.IO.Path]::GetExtension($originalPath)
        $fileType = if ($fileExtension) { $fileExtension.TrimStart('.') } else { "Unknown" }
        
        # Get the user SID from the parent folder name
        $userSID = Split-Path -Path (Split-Path -Path $MetadataFile.DirectoryName -Parent) -Leaf
        
        return @{
            FileName = $fileName
            FileType = $fileType
            OriginalPath = $originalPath
            FileSize = $fileSize
            DeletionTime = $deletionTime
            UserSID = $userSID
            FileRecoverable = $fileExists
            RecoveryPath = if ($fileExists) { $rFilePath } else { "Not available" }
        }
    }
    catch {
        return $null
    }
}

function Get-UsnJournalDeletedFiles {
    $findings = @()
    
    try {
        Write-ForensicLog "Examining USN Journal for deletion records..."
        
        # Get the system drive letter
        $systemDrive = $env:SystemDrive.TrimEnd(":")
        
        # Run fsutil to dump USN journal (requires admin privileges)
        $tempUsnFile = "$env:TEMP\usnjrnl_dump_$script:timestamp.txt"
        $null = Start-Process -FilePath "fsutil" -ArgumentList "usn readjournal $systemDrive: csv" -NoNewWindow -Wait -RedirectStandardOutput $tempUsnFile -PassThru
        
        if (Test-Path $tempUsnFile) {
            # Import and process the USN journal data
            $thirtyDaysAgo = (Get-Date).AddDays(-30)
            
            # Process in batches to reduce memory pressure
            $reader = [System.IO.File]::OpenText($tempUsnFile)
            try {
                # Skip header
                $reader.ReadLine()
                
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    if (-not $line) { continue }
                    
                    # Parse the CSV line
                    $fields = $line -split ','
                    
                    # Check if this is a deletion operation
                    $reason = $fields[5]
                    if (-not ($reason -match "(DELETE|CLOSE)")) { continue }
                    
                    # Parse timestamp
                    $timestamp = $fields[2].Trim('"')
                    try {
                        $deletionTime = [DateTime]::Parse($timestamp)
                        # Skip if older than 30 days
                        if ($deletionTime -lt $thirtyDaysAgo) { continue }
                    }
                    catch {
                        continue
                    }
                    
                    # Get file information
                    $fileName = $fields[6].Trim('"')
                    $fileExtension = [System.IO.Path]::GetExtension($fileName)
                    $fileType = if ($fileExtension) { $fileExtension.TrimStart('.') } else { "Unknown" }
                    
                    # Score the suspiciousness of the deletion
                    $suspiciousData = Get-FileDeletionSuspiciousness -FileName $fileName -FilePath $fileName -DeletionTime $deletionTime
                    
                    # Add to findings
                    $findings += [PSCustomObject]@{
                        Source = "USN Journal"
                        FileName = $fileName
                        FileType = $fileType
                        OriginalPath = "Unknown path"
                        FileSize = "Unknown"
                        DeletionTime = $deletionTime
                        UserSID = "Unknown"
                        FileRecoverable = $false
                        RecoveryPath = "Not available"
                        SuspiciousScore = $suspiciousData.Score
                        SuspiciousReasons = $suspiciousData.Reasons
                    }
                }
            }
            finally {
                $reader.Close()
                # Clean up temp file
                Remove-Item -Path $tempUsnFile -Force -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        Write-ForensicLog "Error analyzing USN Journal: $_" -Severity "Warning"
    }
    
    return $findings
}

function Get-ShadowCopyDeletedFiles {
    $findings = @()
    
    try {
        # Get list of shadow copies
        $shadowCopies = Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction SilentlyContinue
        if (-not $shadowCopies -or $shadowCopies.Count -eq 0) {
            Write-ForensicLog "No shadow copies found for analysis" -Severity "Warning"
            return $findings
        }
        
        Write-ForensicLog "Found $($shadowCopies.Count) shadow copies to analyze"
        
        # Important paths to check (simplified list)
        $pathsToCheck = @(
            "Windows\System32\winevt\Logs",
            "Users\*\AppData\Local\Microsoft\Windows\PowerShell\PSReadLine",
            "Windows\Prefetch"
        )
        
        # Mount point for shadow copies
        $mountPoint = "$env:TEMP\ShadowCopyMount_$script:timestamp"
        New-Item -ItemType Directory -Path $mountPoint -Force -ErrorAction SilentlyContinue | Out-Null
        
        # Process each shadow copy (newest first)
        foreach ($shadowCopy in ($shadowCopies | Sort-Object -Property InstallDate -Descending)) {
            try {
                # Create a symbolic link to the shadow copy
                $shadowDevice = $shadowCopy.DeviceObject
                $linkCommand = "cmd.exe /c mklink /d `"$mountPoint`" `"$shadowDevice\`""
                $null = Invoke-Expression -Command $linkCommand -ErrorAction SilentlyContinue
                
                if (-not (Test-Path -Path $mountPoint)) { continue }
                
                # Check each important path
                foreach ($pathToCheck in $pathsToCheck) {
                    $shadowPath = Join-Path -Path $mountPoint -ChildPath $pathToCheck
                    
                    # Skip if path doesn't exist in shadow copy
                    if (-not (Test-Path -Path $shadowPath -ErrorAction SilentlyContinue)) { continue }
                    
                    # Find files in shadow copy
                    $shadowFiles = Get-ChildItem -Path $shadowPath -File -Recurse -ErrorAction SilentlyContinue
                    
                    foreach ($shadowFile in $shadowFiles) {
                        # Get the equivalent current system path
                        $currentPath = $shadowFile.FullName.Replace($mountPoint, $env:SystemDrive)
                        
                        # If file doesn't exist in current system, it was likely deleted
                        if (-not (Test-Path -Path $currentPath)) {
                            $fileName = $shadowFile.Name
                            $fileType = if ($shadowFile.Extension) { $shadowFile.Extension.TrimStart('.') } else { "Unknown" }
                            
                            # Score the suspiciousness of the deletion
                            $suspiciousData = Get-FileDeletionSuspiciousness -FileName $fileName -FilePath $currentPath -DeletionTime $shadowCopy.InstallDate
                            
                            $findings += [PSCustomObject]@{
                                Source = "Shadow Copy"
                                FileName = $fileName
                                FileType = $fileType
                                OriginalPath = $currentPath
                                FileSize = $shadowFile.Length
                                DeletionTime = "After $($shadowCopy.InstallDate)"
                                UserSID = "Unknown"
                                FileRecoverable = $true
                                RecoveryPath = $shadowFile.FullName
                                SuspiciousScore = $suspiciousData.Score
                                SuspiciousReasons = $suspiciousData.Reasons
                            }
                        }
                    }
                }
                
                # Clean up the mount point
                Remove-Item -Path $mountPoint -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-ForensicLog "Error processing shadow copy: $_" -Severity "Warning"
                # Clean up if error occurs
                if (Test-Path -Path $mountPoint) {
                    Remove-Item -Path $mountPoint -Force -ErrorAction SilentlyContinue
                }
            }
        }
        
        # Final cleanup
        if (Test-Path -Path $mountPoint) {
            Remove-Item -Path $mountPoint -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-ForensicLog "Error analyzing shadow copies: $_" -Severity "Warning"
    }
    
    return $findings
}

function Get-FileShredderEvidence {
    $findings = @()
    
    try {
        Write-ForensicLog "Checking for evidence of file shredding tools..."
        
        # Common file shredder tools
        $shredderTools = @(
            "Eraser.exe",
            "sdelete.exe",
            "CCleaner.exe",
            "BleachBit.exe",
            "WipeFile.exe",
            "FileShreder.exe",
            "KillDisk.exe"
        )
        
        # Find evidence of tools in common locations
        $findings += Find-ToolEvidence -ToolNames $shredderTools
        
        # Find evidence in prefetch
        $findings += Find-PrefetchEvidence -ToolNames $shredderTools
        
        # Find evidence in event logs
        $findings += Find-EventLogEvidence -ToolNames $shredderTools
    }
    catch {
        Write-ForensicLog "Error checking for file shredder evidence: $_" -Severity "Warning"
    }
    
    return $findings
}

function Find-ToolEvidence {
    param (
        [string[]]$ToolNames
    )
    
    $results = @()
    
    # Places to look for tools
    $searchPaths = @(
        "$env:ProgramFiles",
        "${env:ProgramFiles(x86)}",
        "$env:LOCALAPPDATA\Programs",
        "$env:LOCALAPPDATA\Temp"
    )
    
    foreach ($path in $searchPaths) {
        if (-not (Test-Path $path)) { continue }
        
        # Search for each tool
        foreach ($tool in $ToolNames) {
            $foundTools = Get-ChildItem -Path $path -Filter $tool -Recurse -ErrorAction SilentlyContinue -Force
            
            foreach ($foundTool in $foundTools) {
                $results += [PSCustomObject]@{
                    Source = "Shredder Tool Detection"
                    FileName = $foundTool.Name
                    FileType = $foundTool.Extension.TrimStart('.')
                    OriginalPath = $foundTool.FullName
                    FileSize = $foundTool.Length
                    DeletionTime = "N/A (Tool found)"
                    UserSID = "Unknown"
                    FileRecoverable = "N/A"
                    RecoveryPath = "N/A"
                    SuspiciousScore = 3
                    SuspiciousReasons = "File shredding tool detected: $($foundTool.Name)"
                }
            }
        }
    }
    
    return $results
}

function Find-PrefetchEvidence {
    param (
        [string[]]$ToolNames
    )
    
    $results = @()
    $prefetchPath = "$env:SystemRoot\Prefetch"
    
    if (-not (Test-Path $prefetchPath)) { return $results }
    
    foreach ($tool in $ToolNames) {
        $toolNameNoExt = $tool.Replace(".exe", "")
        $prefetchFiles = Get-ChildItem -Path $prefetchPath -Filter "*$toolNameNoExt*" -ErrorAction SilentlyContinue
        
        foreach ($prefetchFile in $prefetchFiles) {
            $results += [PSCustomObject]@{
                Source = "Shredder Execution Evidence"
                FileName = $prefetchFile.Name
                FileType = "Prefetch"
                OriginalPath = $prefetchFile.FullName
                FileSize = $prefetchFile.Length
                DeletionTime = $prefetchFile.LastWriteTime
                UserSID = "Unknown"
                FileRecoverable = "N/A"
                RecoveryPath = "N/A"
                SuspiciousScore = 4
                SuspiciousReasons = "Evidence of file shredder tool execution found in prefetch"
            }
        }
    }
    
    return $results
}

function Find-EventLogEvidence {
    param (
        [string[]]$ToolNames
    )
    
    $results = @()
    
    try {
        # Build search pattern for tools
        $searchPattern = '(' + ($ToolNames -join '|').Replace('.exe', '') + ')'
        
        # Check application log for evidence (limited to 100 results for performance)
        $evtLogs = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            StartTime = (Get-Date).AddDays(-30)
        } -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {
            $_.Message -match $searchPattern
        }
        
        foreach ($event in $evtLogs) {
            $results += [PSCustomObject]@{
                Source = "Shredder Event Log"
                FileName = "Event $($event.Id)"
                FileType = "EventLog"
                OriginalPath = "Windows Event Log"
                FileSize = "N/A"
                DeletionTime = $event.TimeCreated
                UserSID = "Unknown"
                FileRecoverable = "N/A"
                RecoveryPath = "N/A"
                SuspiciousScore = 3
                SuspiciousReasons = "Evidence of file shredder tool in event logs: $($event.Message.Substring(0, [Math]::Min(100, $event.Message.Length)))..."
            }
        }
    }
    catch {
        # Continue if event log access fails
    }
    
    return $results
}

function Get-FileDeletionSuspiciousness {
    param (
        [string]$FileName,
        [string]$FilePath,
        [DateTime]$DeletionTime
    )
    
    $suspiciousScore = 0
    $suspiciousReasons = @()
    
    # Get file extension
    $fileExtension = [System.IO.Path]::GetExtension($FileName).TrimStart('.')
    
    # Check for suspicious file types
    $suspiciousFileTypes = @(
        "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "wsf", "hta",
        "log", "evt", "evtx", "etl", "db", "sqlite", "mdb", "accdb"
    )
    
    if ($fileExtension -in $suspiciousFileTypes) {
        $suspiciousScore += 2
        $suspiciousReasons += "Suspicious file type deleted: $fileExtension"
    }
    
    # Check for log files deletion
    if ($FilePath -match "\\Windows\\System32\\winevt\\Logs\\|\\Windows\\Logs\\|\.log$|\.evt$|\.evtx$|\.etl$") {
        $suspiciousScore += 3
        $suspiciousReasons += "Log file deletion (potential anti-forensic activity)"
    }
    
    # Check for command history deletion
    if ($FilePath -match "\\PSReadLine\\|ConsoleHost_history\.txt") {
        $suspiciousScore += 3
        $suspiciousReasons += "PowerShell history deletion (potential anti-forensic activity)"
    }
    
    # Check for prefetch file deletion
    if ($FilePath -match "\\Prefetch\\") {
        $suspiciousScore += 2
        $suspiciousReasons += "Prefetch file deletion (potential anti-forensic activity)"
    }
    
    # Check for recent deletions (within 24 hours)
    if ((Get-Date) - $DeletionTime -lt [TimeSpan]::FromHours(24)) {
        $suspiciousScore += 1
        $suspiciousReasons += "Recently deleted (within 24 hours)"
    }
    
    return @{
        Score = $suspiciousScore
        Reasons = ($suspiciousReasons -join "; ")
    }
}

function Export-DeletedFileResults {
    param (
        [Array]$Findings,
        [string]$OutputFile
    )
    
    if ($Findings.Count -gt 0) {
        # Sort findings by deletion time (most recent first)
        $sortedFindings = $Findings | Sort-Object -Property DeletionTime -Descending
        $sortedFindings | Export-Csv -Path $OutputFile -NoTypeInformation
        
        # Log findings summary
        Write-ForensicLog "Found information about $($Findings.Count) recently deleted files"
        
        # Report suspicious deletions (high risk items)
        $suspiciousDeletedFiles = $sortedFindings | Where-Object { $_.SuspiciousScore -ge 3 }
        if ($suspiciousDeletedFiles.Count -gt 0) {
            Write-ForensicLog "Found $($suspiciousDeletedFiles.Count) suspicious file deletions:" -Severity "Warning"
            foreach ($file in $suspiciousDeletedFiles | Select-Object -First 5) {
                Write-ForensicLog "  - $($file.FileName) ($($file.FileType)) - $($file.SuspiciousReasons)" -Severity "Warning"
            }
        }
    } else {
        Write-ForensicLog "No recently deleted files detected"
        # Create an empty file to indicate analysis was performed
        [PSCustomObject]@{
            Result = "No recently deleted files detected"
            AnalysisTime = Get-Date
            SystemName = $env:COMPUTERNAME
        } | Export-Csv -Path $OutputFile -NoTypeInformation
    }
    
    Write-ForensicLog "Saved deleted file analysis data to $OutputFile"
}

# Export function
Export-ModuleMember -Function Get-RecentlyDeletedFiles
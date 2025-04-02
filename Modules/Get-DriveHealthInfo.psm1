<#
.SYNOPSIS
    Collects and analyzes disk drive health information.
    
.DESCRIPTION
    Get-DriveHealthInfo gathers detailed health metrics for all storage devices
    including S.M.A.R.T. attributes, disk errors, bad sectors, and overall
    reliability indicators. This module helps identify failing or degraded storage
    devices that may lead to data loss or system instability.
    
.EXAMPLE
    $driveHealthFile = Get-DriveHealthInfo
    
.OUTPUTS
    String. The path to the CSV file containing drive health data
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for complete S.M.A.R.T. data access
#>

function Get-DriveHealthInfo {
    param()

    $outputFile = "$script:outputDir\DriveHealth_$script:timestamp.csv"
    Write-ForensicLog "Collecting drive health information..."

    try {
        # Initialize findings collection
        $driveHealthData = @()
        
        # Collect physical disk information
        $physicalDisks = Get-PhysicalDiskInfo
        $driveHealthData += $physicalDisks
        
        # Collect S.M.A.R.T. attributes when available
        $smartData = Get-SmartAttributeInfo
        $driveHealthData += $smartData
        
        # Collect storage reliability counters
        $reliabilityData = Get-ReliabilityCounterInfo
        $driveHealthData += $reliabilityData
        
        # Collect storage event log errors
        $storageErrors = Get-StorageEventErrors
        $driveHealthData += $storageErrors
        
        # Export results
        if ($driveHealthData.Count -gt 0) {
            # Group results by disk
            $groupedData = $driveHealthData | Group-Object -Property DiskNumber
            $combinedResults = Format-DriveHealthResults -GroupedData $groupedData
            
            # Export to CSV
            $combinedResults | Export-Csv -Path $outputFile -NoTypeInformation
            
            # Log summary
            $diskCount = ($groupedData | Measure-Object).Count
            $degradedDisks = $combinedResults | Where-Object { $_.HealthStatus -ne "Healthy" }
            
            Write-ForensicLog "Analyzed health status for $diskCount disk drives"
            
            if ($degradedDisks.Count -gt 0) {
                Write-ForensicLog "Found $($degradedDisks.Count) drives with potential health issues:" -Severity "Warning"
                foreach ($disk in $degradedDisks) {
                    Write-ForensicLog "  - Disk $($disk.DiskNumber) ($($disk.Model)): $($disk.HealthStatus) - $($disk.HealthDetails)" -Severity "Warning"
                }
            } else {
                Write-ForensicLog "All drives appear to be healthy"
            }
        } else {
            Write-ForensicLog "No drive health information collected" -Severity "Warning"
            # Create an empty file to indicate analysis was performed
            [PSCustomObject]@{
                Result = "No drive health information collected"
                AnalysisTime = Get-Date
                SystemName = $env:COMPUTERNAME
            } | Export-Csv -Path $outputFile -NoTypeInformation
        }
        
        Write-ForensicLog "Saved drive health data to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error collecting drive health information: $_" -Severity "Error"
        return $null
    }
}

function Get-PhysicalDiskInfo {
    $diskData = @()
    
    try {
        # Try using Storage module cmdlets first (Windows 8/Server 2012 and newer)
        if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
            $physicalDisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
            
            foreach ($disk in $physicalDisks) {
                $diskNumber = $disk.DeviceId
                
                # Get detailed disk properties
                $diskDetails = $disk | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
                
                # Get media type description
                $mediaType = switch ($disk.MediaType) {
                    0 { "Unspecified" }
                    3 { "HDD" }
                    4 { "SSD" }
                    5 { "SCM" } # Storage Class Memory
                    default { "Unknown ($($disk.MediaType))" }
                }
                
                # Get health status description
                $healthStatus = switch ($disk.HealthStatus) {
                    0 { "Healthy" }
                    1 { "Warning" }
                    2 { "Unhealthy" }
                    default { "Unknown ($($disk.HealthStatus))" }
                }
                
                # Get operational status description
                $operationalStatus = switch ($disk.OperationalStatus) {
                    0 { "Unknown" }
                    1 { "Other" }
                    2 { "OK" }
                    3 { "Degraded" }
                    4 { "Stressed" }
                    5 { "Predictive Failure" }
                    6 { "Error" }
                    7 { "Non-Recoverable Error" }
                    8 { "Starting" }
                    9 { "Stopping" }
                    10 { "Stopped" }
                    11 { "In Service" }
                    12 { "No Contact" }
                    13 { "Lost Communication" }
                    14 { "Aborted" }
                    15 { "Dormant" }
                    16 { "Supporting Entity in Error" }
                    17 { "Completed" }
                    default { "Unknown ($($disk.OperationalStatus))" }
                }
                
                # Create disk health entry
                $diskData += [PSCustomObject]@{
                    DataType = "PhysicalDisk"
                    DiskNumber = $diskNumber
                    Model = $disk.Model
                    SerialNumber = $disk.SerialNumber
                    MediaType = $mediaType
                    BusType = $disk.BusType
                    Size = [math]::Round($disk.Size / 1GB, 2)
                    HealthStatus = $healthStatus
                    OperationalStatus = $operationalStatus
                    Temperature = if ($diskDetails.Temperature) { $diskDetails.Temperature } else { $null }
                    ReadErrors = if ($diskDetails.ReadErrorsTotal) { $diskDetails.ReadErrorsTotal } else { $null }
                    WriteErrors = if ($diskDetails.WriteErrorsTotal) { $diskDetails.WriteErrorsTotal } else { $null }
                    PowerOnHours = if ($diskDetails.PowerOnHours) { $diskDetails.PowerOnHours } else { $null }
                    DiskMetric = "Overview"
                    MetricValue = ""
                    MetricStatus = if ($disk.HealthStatus -eq 0) { "OK" } else { "Warning" }
                    Details = "Physical Disk Information"
                }
            }
        }
        
        # If no results from Get-PhysicalDisk, fall back to WMI
        if ($diskData.Count -eq 0) {
            $wmiDisks = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue
            
            foreach ($disk in $wmiDisks) {
                $diskNumber = $disk.Index
                
                # Get media type based on model string
                $mediaType = "HDD"
                if ($disk.Model -match "SSD|Solid.State|NVME|NVMe|flash") {
                    $mediaType = "SSD"
                }
                
                # Create disk health entry
                $diskData += [PSCustomObject]@{
                    DataType = "PhysicalDisk"
                    DiskNumber = $diskNumber
                    Model = $disk.Model
                    SerialNumber = $disk.SerialNumber
                    MediaType = $mediaType
                    BusType = $disk.InterfaceType
                    Size = [math]::Round($disk.Size / 1GB, 2)
                    HealthStatus = "Unknown" # WMI doesn't provide health status
                    OperationalStatus = if ($disk.Status -eq "OK") { "OK" } else { $disk.Status }
                    Temperature = $null
                    ReadErrors = $null
                    WriteErrors = $null
                    PowerOnHours = $null
                    DiskMetric = "Overview"
                    MetricValue = ""
                    MetricStatus = "Unknown"
                    Details = "Physical Disk Information (WMI)"
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error collecting physical disk information: $_" -Severity "Warning"
    }
    
    return $diskData
}

function Get-SmartAttributeInfo {
    $smartData = @()
    
    try {
        # Try to get S.M.A.R.T. data using WMI
        $smartEnabled = Get-CimInstance -Namespace "root\wmi" -ClassName "MSStorageDriver_FailurePredictStatus" -ErrorAction SilentlyContinue
        
        if ($smartEnabled) {
            foreach ($disk in $smartEnabled) {
                # Extract disk number from the instance name
                $diskNumber = $null
                if ($disk.InstanceName -match "PHYSDRV(\d+)") {
                    $diskNumber = [int]$matches[1]
                }
                
                # S.M.A.R.T. status
                $smartData += [PSCustomObject]@{
                    DataType = "SMART"
                    DiskNumber = $diskNumber
                    Model = ""
                    SerialNumber = ""
                    MediaType = ""
                    BusType = ""
                    Size = $null
                    HealthStatus = if ($disk.PredictFailure -eq $true) { "Warning" } else { "Healthy" }
                    OperationalStatus = if ($disk.PredictFailure -eq $true) { "Predictive Failure" } else { "OK" }
                    Temperature = $null
                    ReadErrors = $null
                    WriteErrors = $null
                    PowerOnHours = $null
                    DiskMetric = "SMART Status"
                    MetricValue = if ($disk.PredictFailure -eq $true) { "Failure Predicted" } else { "OK" }
                    MetricStatus = if ($disk.PredictFailure -eq $true) { "Warning" } else { "OK" }
                    Details = "S.M.A.R.T. failure prediction status"
                }
            }
            
            # Try to get detailed S.M.A.R.T. attributes
            $smartAttribs = Get-CimInstance -Namespace "root\wmi" -ClassName "MSStorageDriver_FailurePredictData" -ErrorAction SilentleContinue
            
            if ($smartAttribs) {
                foreach ($disk in $smartAttribs) {
                    # Extract disk number from the instance name
                    $diskNumber = $null
                    if ($disk.InstanceName -match "PHYSDRV(\d+)") {
                        $diskNumber = [int]$matches[1]
                    }
                    
                    # The VendorSpecific property contains the S.M.A.R.T. attributes
                    if ($disk.VendorSpecific) {
                        # Process S.M.A.R.T. attributes - this is a simplified version
                        # Complete parsing would require more detailed analysis of the binary data
                        
                        # S.M.A.R.T. data is typically in groups of 12 bytes
                        $attribCount = $disk.VendorSpecific.Count / 12
                        
                        for ($i = 0; $i -lt $attribCount; $i++) {
                            $offset = $i * 12
                            
                            # Extract attribute ID and current value
                            $attribId = $disk.VendorSpecific[$offset]
                            $attribValue = $disk.VendorSpecific[$offset + 5]
                            $attribThreshold = $disk.VendorSpecific[$offset + 6]
                            $attribRaw = 0
                            
                            # For some attributes, the raw value is more important (like reallocated sectors)
                            for ($j = 0; $j -lt 6; $j++) {
                                $attribRaw += $disk.VendorSpecific[$offset + 6 + $j] * [math]::Pow(256, $j)
                            }
                            
                            # Only include useful attributes
                            if ($attribId -in @(1, 5, 9, 10, 12, 184, 187, 188, 190, 194, 196, 197, 198, 199, 200, 201, 202)) {
                                # Get attribute name
                                $attribName = Get-SmartAttributeName -Id $attribId
                                
                                # Determine if attribute is critical
                                $isCritical = $attribId -in @(5, 187, 188, 197, 198, 10)
                                
                                # Determine status based on threshold
                                $attribStatus = "OK"
                                if ($isCritical -and $attribValue -le $attribThreshold) {
                                    $attribStatus = "Critical"
                                } elseif ($isCritical -and $attribValue -le $attribThreshold + 10) {
                                    $attribStatus = "Warning"
                                }
                                
                                $smartData += [PSCustomObject]@{
                                    DataType = "SMART"
                                    DiskNumber = $diskNumber
                                    Model = ""
                                    SerialNumber = ""
                                    MediaType = ""
                                    BusType = ""
                                    Size = $null
                                    HealthStatus = $attribStatus
                                    OperationalStatus = $attribStatus
                                    Temperature = $null
                                    ReadErrors = $null
                                    WriteErrors = $null
                                    PowerOnHours = $null
                                    DiskMetric = "SMART Attribute $attribId"
                                    MetricValue = "$attribName: Value=$attribValue, Threshold=$attribThreshold, Raw=$attribRaw"
                                    MetricStatus = $attribStatus
                                    Details = "S.M.A.R.T. attribute $attribName (ID: $attribId)"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error collecting S.M.A.R.T. data: $_" -Severity "Warning"
    }
    
    return $smartData
}

function Get-ReliabilityCounterInfo {
    $reliabilityData = @()
    
    try {
        # Check if the Storage module cmdlets are available
        if (Get-Command Get-StorageReliabilityCounter -ErrorAction SilentlyContinue) {
            $disks = Get-PhysicalDisk -ErrorAction SilentlyContinue
            
            foreach ($disk in $disks) {
                $diskNumber = $disk.DeviceId
                
                # Get detailed reliability counters
                $reliability = $disk | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
                
                if ($reliability) {
                    # Temperature
                    if ($reliability.Temperature) {
                        $reliabilityData += [PSCustomObject]@{
                            DataType = "Reliability"
                            DiskNumber = $diskNumber
                            Model = $disk.Model
                            SerialNumber = $disk.SerialNumber
                            MediaType = $disk.MediaType
                            BusType = $disk.BusType
                            Size = [math]::Round($disk.Size / 1GB, 2)
                            HealthStatus = if ($reliability.Temperature -gt 55) { "Warning" } else { "Healthy" }
                            OperationalStatus = if ($reliability.Temperature -gt 55) { "Warning" } else { "OK" }
                            Temperature = $reliability.Temperature
                            ReadErrors = $null
                            WriteErrors = $null
                            PowerOnHours = $null
                            DiskMetric = "Temperature"
                            MetricValue = "$($reliability.Temperature)°C"
                            MetricStatus = if ($reliability.Temperature -gt 55) { "Warning" } else { "OK" }
                            Details = "Drive temperature"
                        }
                    }
                    
                    # Power on hours
                    if ($reliability.PowerOnHours) {
                        $reliabilityData += [PSCustomObject]@{
                            DataType = "Reliability"
                            DiskNumber = $diskNumber
                            Model = $disk.Model
                            SerialNumber = $disk.SerialNumber
                            MediaType = $disk.MediaType
                            BusType = $disk.BusType
                            Size = [math]::Round($disk.Size / 1GB, 2)
                            HealthStatus = "Healthy"
                            OperationalStatus = "OK"
                            Temperature = $null
                            ReadErrors = $null
                            WriteErrors = $null
                            PowerOnHours = $reliability.PowerOnHours
                            DiskMetric = "Power On Hours"
                            MetricValue = "$($reliability.PowerOnHours) hours"
                            MetricStatus = "OK"
                            Details = "Total power on time"
                        }
                    }
                    
                    # Read errors
                    if ($reliability.ReadErrorsTotal -gt 0) {
                        $reliabilityData += [PSCustomObject]@{
                            DataType = "Reliability"
                            DiskNumber = $diskNumber
                            Model = $disk.Model
                            SerialNumber = $disk.SerialNumber
                            MediaType = $disk.MediaType
                            BusType = $disk.BusType
                            Size = [math]::Round($disk.Size / 1GB, 2)
                            HealthStatus = if ($reliability.ReadErrorsTotal -gt 100) { "Warning" } else { "Healthy" }
                            OperationalStatus = if ($reliability.ReadErrorsTotal -gt 100) { "Warning" } else { "OK" }
                            Temperature = $null
                            ReadErrors = $reliability.ReadErrorsTotal
                            WriteErrors = $null
                            PowerOnHours = $null
                            DiskMetric = "Read Errors"
                            MetricValue = $reliability.ReadErrorsTotal
                            MetricStatus = if ($reliability.ReadErrorsTotal -gt 100) { "Warning" } else { "OK" }
                            Details = "Total read errors detected"
                        }
                    }
                    
                    # Write errors
                    if ($reliability.WriteErrorsTotal -gt 0) {
                        $reliabilityData += [PSCustomObject]@{
                            DataType = "Reliability"
                            DiskNumber = $diskNumber
                            Model = $disk.Model
                            SerialNumber = $disk.SerialNumber
                            MediaType = $disk.MediaType
                            BusType = $disk.BusType
                            Size = [math]::Round($disk.Size / 1GB, 2)
                            HealthStatus = if ($reliability.WriteErrorsTotal -gt 100) { "Warning" } else { "Healthy" }
                            OperationalStatus = if ($reliability.WriteErrorsTotal -gt 100) { "Warning" } else { "OK" }
                            Temperature = $null
                            ReadErrors = $null
                            WriteErrors = $reliability.WriteErrorsTotal
                            PowerOnHours = $null
                            DiskMetric = "Write Errors"
                            MetricValue = $reliability.WriteErrorsTotal
                            MetricStatus = if ($reliability.WriteErrorsTotal -gt 100) { "Warning" } else { "OK" }
                            Details = "Total write errors detected"
                        }
                    }
                    
                    # Start-Stop Cycles
                    if ($reliability.StartStopCycleCount) {
                        $reliabilityData += [PSCustomObject]@{
                            DataType = "Reliability"
                            DiskNumber = $diskNumber
                            Model = $disk.Model
                            SerialNumber = $disk.SerialNumber
                            MediaType = $disk.MediaType
                            BusType = $disk.BusType
                            Size = [math]::Round($disk.Size / 1GB, 2)
                            HealthStatus = "Healthy"
                            OperationalStatus = "OK"
                            Temperature = $null
                            ReadErrors = $null
                            WriteErrors = $null
                            PowerOnHours = $null
                            DiskMetric = "Start-Stop Cycles"
                            MetricValue = $reliability.StartStopCycleCount
                            MetricStatus = "OK"
                            Details = "Number of times the drive has been powered on and off"
                        }
                    }
                    
                    # Load-Unload Cycles (primarily for HDDs)
                    if ($reliability.LoadUnloadCycleCount -and $disk.MediaType -ne 4) {
                        $reliabilityData += [PSCustomObject]@{
                            DataType = "Reliability"
                            DiskNumber = $diskNumber
                            Model = $disk.Model
                            SerialNumber = $disk.SerialNumber
                            MediaType = $disk.MediaType
                            BusType = $disk.BusType
                            Size = [math]::Round($disk.Size / 1GB, 2)
                            HealthStatus = "Healthy"
                            OperationalStatus = "OK"
                            Temperature = $null
                            ReadErrors = $null
                            WriteErrors = $null
                            PowerOnHours = $null
                            DiskMetric = "Load-Unload Cycles"
                            MetricValue = $reliability.LoadUnloadCycleCount
                            MetricStatus = "OK"
                            Details = "Number of head load/unload cycles"
                        }
                    }
                    
                    # Wear leveling count (primarily for SSDs)
                    if ($reliability.WearLevelingCount -and $disk.MediaType -eq 4) {
                        # Calculate a percentage of SSD life remaining
                        $wearLevel = $reliability.WearLevelingCount
                        $ssdLifePercentage = if ($wearLevel -gt 0 -and $wearLevel -le 100) { $wearLevel } else { 100 }
                        
                        $reliabilityData += [PSCustomObject]@{
                            DataType = "Reliability"
                            DiskNumber = $diskNumber
                            Model = $disk.Model
                            SerialNumber = $disk.SerialNumber
                            MediaType = $disk.MediaType
                            BusType = $disk.BusType
                            Size = [math]::Round($disk.Size / 1GB, 2)
                            HealthStatus = if ($ssdLifePercentage -lt 20) { "Warning" } else { "Healthy" }
                            OperationalStatus = if ($ssdLifePercentage -lt 20) { "Warning" } else { "OK" }
                            Temperature = $null
                            ReadErrors = $null
                            WriteErrors = $null
                            PowerOnHours = $null
                            DiskMetric = "SSD Life Remaining"
                            MetricValue = "$ssdLifePercentage%"
                            MetricStatus = if ($ssdLifePercentage -lt 20) { "Warning" } else { "OK" }
                            Details = "Estimated SSD life remaining based on wear leveling"
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error collecting reliability counter information: $_" -Severity "Warning"
    }
    
    return $reliabilityData
}

function Get-StorageEventErrors {
    $storageEventData = @()
    
    try {
        # Get storage-related events from the System event log
        $diskErrors = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ProviderName = @('disk', 'spaceport', 'NTFS', 'volsnap', 'iaStorA', 'iaStorV', 'StorPort', 'stornvme')
            Level = @(1, 2, 3)  # Error, Warning, Information
        } -MaxEvents 100 -ErrorAction SilentlyContinue
        
        # Process events and correlate with physical disks
        if ($diskErrors) {
            # Get physical disks
            $physicalDisks = Get-PhysicalDiskMapping
            
            foreach ($event in $diskErrors) {
                # Only process error and warning events
                if ($event.Level -gt 3) {
                    continue
                }
                
                # Try to identify which disk this event is related to
                $diskNumber = $null
                $message = $event.Message
                
                # Look for disk number patterns in the message
                if ($message -match "disk (\d+)") {
                    $diskNumber = [int]$matches[1]
                } elseif ($message -match "PhysicalDisk(\d+)") {
                    $diskNumber = [int]$matches[1]
                } elseif ($message -match "\\Device\\Harddisk(\d+)") {
                    $diskNumber = [int]$matches[1]
                }
                
                # Get basic disk info if available
                $diskInfo = $physicalDisks | Where-Object { $_.DiskNumber -eq $diskNumber } | Select-Object -First 1
                
                # Determine severity
                $severity = switch ($event.Level) {
                    1 { "Critical" }
                    2 { "Warning" }
                    3 { "Information" }
                    default { "Unknown" }
                }
                
                # Add to results
                $storageEventData += [PSCustomObject]@{
                    DataType = "Event"
                    DiskNumber = $diskNumber
                    Model = if ($diskInfo) { $diskInfo.Model } else { "" }
                    SerialNumber = if ($diskInfo) { $diskInfo.SerialNumber } else { "" }
                    MediaType = if ($diskInfo) { $diskInfo.MediaType } else { "" }
                    BusType = if ($diskInfo) { $diskInfo.BusType } else { "" }
                    Size = if ($diskInfo) { $diskInfo.Size } else { $null }
                    HealthStatus = if ($event.Level -eq 1) { "Unhealthy" } elseif ($event.Level -eq 2) { "Warning" } else { "Healthy" }
                    OperationalStatus = $severity
                    Temperature = $null
                    ReadErrors = $null
                    WriteErrors = $null
                    PowerOnHours = $null
                    DiskMetric = "Event $($event.Id)"
                    MetricValue = $event.TimeCreated
                    MetricStatus = $severity
                    Details = "Provider: $($event.ProviderName), Message: $($message.Substring(0, [Math]::Min(100, $message.Length)))..."
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error collecting storage event information: $_" -Severity "Warning"
    }
    
    return $storageEventData
}

function Get-PhysicalDiskMapping {
    $diskMapping = @()
    
    try {
        # Try using Storage module cmdlets first
        if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
            $disks = Get-PhysicalDisk -ErrorAction SilentlyContinue
            
            foreach ($disk in $disks) {
                $diskMapping += [PSCustomObject]@{
                    DiskNumber = $disk.DeviceId
                    Model = $disk.Model
                    SerialNumber = $disk.SerialNumber
                    MediaType = $disk.MediaType
                    BusType = $disk.BusType
                    Size = [math]::Round($disk.Size / 1GB, 2)
                }
            }
        }
        
        # If no results, fall back to WMI
        if ($diskMapping.Count -eq 0) {
            $wmiDisks = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue
            
            foreach ($disk in $wmiDisks) {
                # Get media type based on model string
                $mediaType = "HDD"
                if ($disk.Model -match "SSD|Solid.State|NVME|NVMe|flash") {
                    $mediaType = "SSD"
                }
                
                $diskMapping += [PSCustomObject]@{
                    DiskNumber = $disk.Index
                    Model = $disk.Model
                    SerialNumber = $disk.SerialNumber
                    MediaType = $mediaType
                    BusType = $disk.InterfaceType
                    Size = [math]::Round($disk.Size / 1GB, 2)
                }
            }
        }
    }
    catch {
        # Cannot get disk mapping
    }
    
    return $diskMapping
}

function Get-SmartAttributeName {
    param (
        [int]$Id
    )
    
    # Common S.M.A.R.T. attribute IDs and names
    switch ($Id) {
        1 { "Read Error Rate" }
        2 { "Throughput Performance" }
        3 { "Spin-Up Time" }
        4 { "Start/Stop Count" }
        5 { "Reallocated Sectors Count" }
        7 { "Seek Error Rate" }
        8 { "Seek Time Performance" }
        9 { "Power-On Hours" }
        10 { "Spin Retry Count" }
        11 { "Recalibration Retries" }
        12 { "Power Cycle Count" }
        184 { "End-to-End Error" }
        187 { "Reported Uncorrectable Errors" }
        188 { "Command Timeout" }
        189 { "High Fly Writes" }
        190 { "Temperature" }
        191 { "G-Sense Error Rate" }
        192 { "Power-off Retract Count" }
        193 { "Load Cycle Count" }
        194 { "Temperature" }
        195 { "Hardware ECC Recovered" }
        196 { "Reallocation Event Count" }
        197 { "Current Pending Sectors" }
        198 { "Offline Uncorrectable Sectors" }
        199 { "UltraDMA CRC Error Count" }
        200 { "Multi-Zone Error Rate" }
        201 { "Soft Read Error Rate" }
        202 { "Data Address Mark Errors" }
        203 { "Run Out Cancel" }
        204 { "Soft ECC Correction" }
        205 { "Thermal Asperity Rate" }
        206 { "Flying Height" }
        207 { "Spin High Current" }
        208 { "Spin Buzz" }
        209 { "Offline Seek Performance" }
        220 { "Disk Shift" }
        221 { "G-Sense Error Rate" }
        222 { "Loaded Hours" }
        223 { "Load/Unload Retry Count" }
        224 { "Load Friction" }
        225 { "Load/Unload Cycle Count" }
        226 { "Load-in Time" }
        227 { "Torque Amplification Count" }
        228 { "Power-Off Retract Cycle" }
        230 { "GMR Head Amplitude" }
        231 { "Temperature" }
        240 { "Head Flying Hours" }
        241 { "Total LBAs Written" }
        242 { "Total LBAs Read" }
        default { "Unknown Attribute ($Id)" }
    }
}


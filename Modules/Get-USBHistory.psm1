<#
.SYNOPSIS
    Collects information about USB devices connected to the system over time.
    
.DESCRIPTION
    Get-UsbDeviceHistory retrieves information about USB devices that have been connected
    to the system, including current and historical connections. It identifies device types,
    serial numbers, vendors, and connection timestamps to help with forensic analysis of 
    data exfiltration or unauthorized device usage.
    
.EXAMPLE
    $usbHistoryFile = Get-UsbDeviceHistory
    
.OUTPUTS
    String. The path to the CSV file containing USB device history data
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges recommended for complete results
#>

function Get-UsbDeviceHistory {
    param()

    $outputFile = "$script:outputDir\UsbDeviceHistory_$script:timestamp.csv"
    Write-ForensicLog "Collecting USB device connection history..."

    try {
        # Initialize findings collection
        $usbDevices = @()
        
        # Get device information from multiple sources for better coverage
        $registryDevices = Get-UsbDevicesFromRegistry
        $usbDevices += $registryDevices
        
        $setupApiDevices = Get-UsbDevicesFromSetupAPI
        $usbDevices += $setupApiDevices
        
        $mountedDevices = Get-MountedUsbDevices
        $usbDevices += $mountedDevices
        
        $eventLogDevices = Get-UsbDevicesFromEventLog
        $usbDevices += $eventLogDevices
        
        # Deduplicate devices based on serial number and drive letter
        $uniqueDevices = Get-UniqueUsbDevices -Devices $usbDevices
        
        # Export results
        if ($uniqueDevices.Count -gt 0) {
            # Sort by last connection time (most recent first)
            $sortedDevices = $uniqueDevices | Sort-Object -Property LastConnected -Descending
            $sortedDevices | Export-Csv -Path $outputFile -NoTypeInformation
            
            # Log summary of findings
            Write-ForensicLog "Found $($uniqueDevices.Count) unique USB devices"
            
            # Log recent connections
            $recentDevices = $sortedDevices | Where-Object { 
                $_.LastConnected -and $_.LastConnected -gt (Get-Date).AddDays(-30)
            } | Select-Object -First 5
            
            if ($recentDevices.Count -gt 0) {
                Write-ForensicLog "Recent USB device connections:"
                foreach ($device in $recentDevices) {
                    $deviceInfo = "$($device.FriendlyName)"
                    if ($device.SerialNumber) { $deviceInfo += " (S/N: $($device.SerialNumber))" }
                    $deviceInfo += " - Last connected: $($device.LastConnected)"
                    
                    Write-ForensicLog "  - $deviceInfo"
                }
            }
        } else {
            Write-ForensicLog "No USB device history found"
            # Create an empty file to indicate analysis was performed
            [PSCustomObject]@{
                Result = "No USB device history found"
                AnalysisTime = Get-Date
                SystemName = $env:COMPUTERNAME
            } | Export-Csv -Path $outputFile -NoTypeInformation
        }
        
        Write-ForensicLog "Saved USB device history to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error collecting USB device history: $_" -Severity "Error"
        return $null
    }
}

function Get-UsbDevicesFromRegistry {
    $devices = @()
    
    try {
        Write-ForensicLog "Checking registry for USB device history..."
        
        # Check USB storage devices in registry
        $usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
        
        if (Test-Path $usbStorPath) {
            $usbStorDevices = Get-ChildItem -Path $usbStorPath -ErrorAction SilentlyContinue
            
            foreach ($deviceCategory in $usbStorDevices) {
                $deviceInstances = Get-ChildItem -Path $deviceCategory.PSPath -ErrorAction SilentlyContinue
                
                foreach ($instance in $deviceInstances) {
                    try {
                        # Parse device information
                        $deviceId = Split-Path -Path $instance.PSPath -Leaf
                        $deviceProps = Get-ItemProperty -Path $instance.PSPath -ErrorAction SilentlyContinue
                        
                        # Extract device details from the device ID
                        $deviceParts = $deviceCategory.PSChildName -split '\\'
                        $deviceType = $deviceParts[0]
                        
                        $vendorProduct = ""
                        $serialNumber = $deviceId
                        
                        # Parse USBSTOR device ID format (e.g., "Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00")
                        if ($deviceCategory.PSChildName -match "^.*Ven_([^&]+)&Prod_([^&]+)&Rev_(.*)$") {
                            $vendor = $matches[1]
                            $product = $matches[2]
                            $revision = $matches[3]
                            
                            $vendorProduct = "$vendor $product"
                        }
                        
                        # Get friendly name
                        $friendlyName = $deviceProps.FriendlyName
                        if (-not $friendlyName) {
                            $friendlyName = $vendorProduct
                        }
                        
                        # Get last connected time
                        $lastConnected = $null
                        $firstConnected = $null
                        
                        # Try to get last connection time from registry properties
                        if ($deviceProps.LastArrivalDate) {
                            $lastConnected = [DateTime]::FromFileTime($deviceProps.LastArrivalDate)
                        } elseif ($deviceProps.LastInsertTime) {
                            $lastConnected = [DateTime]::FromFileTime($deviceProps.LastInsertTime)
                        } elseif ($deviceProps.'ContainerID') {
                            # Try to get connection time from device container properties
                            $containerIdGuid = $deviceProps.'ContainerID'
                            $deviceContainerPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM"
                            
                            if (Test-Path $deviceContainerPath) {
                                $containerDevices = Get-ChildItem -Path $deviceContainerPath -ErrorAction SilentlyContinue
                                
                                foreach ($containerDevice in $containerDevices) {
                                    $containerProps = Get-ItemProperty -Path $containerDevice.PSPath -ErrorAction SilentlyContinue
                                    
                                    if ($containerProps.'ContainerID' -eq $containerIdGuid) {
                                        if ($containerProps.InstallDate) {
                                            $lastConnected = [DateTime]::FromFileTime($containerProps.InstallDate)
                                        }
                                        break
                                    }
                                }
                            }
                        } else {
                            # Use registry key timestamp as fallback
                            $lastConnected = $instance.LastWriteTime
                        }
                        
                        # Check parent registry keys for first connection time
                        try {
                            $parentInfo = Get-Item -Path $deviceCategory.PSPath -ErrorAction SilentlyContinue
                            $firstConnected = $parentInfo.CreationTime
                        } catch {
                            # Default to last connected if first connected can't be determined
                            $firstConnected = $lastConnected
                        }
                        
                        # Get device class
                        $deviceClass = "Storage Device"
                        $compatibleIds = $deviceProps.CompatibleIDs
                        
                        if ($compatibleIds -contains "USB\Class_08") {
                            $deviceClass = "Mass Storage"
                        } elseif ($compatibleIds -contains "USB\Class_03") {
                            $deviceClass = "HID Device"
                        } elseif ($compatibleIds -contains "USB\Class_07") {
                            $deviceClass = "Printer"
                        } elseif ($compatibleIds -contains "USB\Class_02") {
                            $deviceClass = "Communication Device"
                        } elseif ($compatibleIds -contains "USB\Class_01") {
                            $deviceClass = "Audio Device"
                        } elseif ($compatibleIds -contains "USB\Class_0E") {
                            $deviceClass = "Video Device"
                        }
                        
                        # Check drive letters
                        $driveLetters = Get-UsbDriveLetters -SerialNumber $serialNumber
                        
                        # Add device to results
                        $devices += [PSCustomObject]@{
                            DeviceType = $deviceType
                            VendorName = $vendor
                            ProductName = $product
                            FriendlyName = $friendlyName
                            SerialNumber = $serialNumber
                            DeviceID = $deviceId
                            FirstConnected = $firstConnected
                            LastConnected = $lastConnected
                            DeviceClass = $deviceClass
                            DriveLetters = $driveLetters
                            SourceKey = $instance.PSPath
                            Source = "Registry-USBSTOR"
                        }
                    }
                    catch {
                        Write-ForensicLog "Error processing USB device $($instance.PSPath): $_" -Severity "Warning"
                    }
                }
            }
        }
        
        # Also check USB device class in registry
        $usbDevicePath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"
        
        if (Test-Path $usbDevicePath) {
            $usbDevices = Get-ChildItem -Path $usbDevicePath -ErrorAction SilentlyContinue
            
            foreach ($device in $usbDevices) {
                $deviceInstances = Get-ChildItem -Path $device.PSPath -ErrorAction SilentlyContinue
                
                foreach ($instance in $deviceInstances) {
                    try {
                        $deviceProps = Get-ItemProperty -Path $instance.PSPath -ErrorAction SilentlyContinue
                        
                        # Skip devices that aren't storage devices
                        $deviceClass = ""
                        $compatibleIds = $deviceProps.CompatibleIDs
                        
                        if ($compatibleIds) {
                            if ($compatibleIds -contains "USB\Class_08") {
                                $deviceClass = "Mass Storage"
                            } elseif ($compatibleIds -contains "USB\Class_03") {
                                $deviceClass = "HID Device"
                            } elseif ($compatibleIds -contains "USB\Class_07") {
                                $deviceClass = "Printer"
                            } elseif ($compatibleIds -contains "USB\Class_02") {
                                $deviceClass = "Communication Device"
                            } elseif ($compatibleIds -contains "USB\Class_01") {
                                $deviceClass = "Audio Device"
                            } elseif ($compatibleIds -contains "USB\Class_0E") {
                                $deviceClass = "Video Device"
                            } else {
                                $deviceClass = "Other USB Device"
                            }
                        }
                        
                        # Only process storage devices and devices with hardware IDs
                        if (-not $deviceProps.HardwareID) {
                            continue
                        }
                        
                        # Parse device info
                        $deviceId = Split-Path -Path $instance.PSPath -Leaf
                        $vendorProduct = $device.PSChildName
                        
                        # Extract vendor and product IDs if available
                        $vendor = ""
                        $product = ""
                        
                        if ($vendorProduct -match "VID_([A-F0-9]{4})&PID_([A-F0-9]{4})") {
                            $vendor = $matches[1]
                            $product = $matches[2]
                        }
                        
                        # Get connection times
                        $lastConnected = $instance.LastWriteTime
                        $firstConnected = $device.CreationTime
                        
                        # Get friendly name
                        $friendlyName = $deviceProps.FriendlyName
                        if (-not $friendlyName) {
                            $friendlyName = "USB Device $vendorProduct"
                        }
                        
                        # Add device to results if not already added
                        if (-not ($devices | Where-Object { $_.DeviceID -eq $deviceId })) {
                            $devices += [PSCustomObject]@{
                                DeviceType = if ($deviceClass -eq "Mass Storage") { "Disk" } else { "Device" }
                                VendorName = $vendor
                                ProductName = $product
                                FriendlyName = $friendlyName
                                SerialNumber = $deviceId
                                DeviceID = $deviceId
                                FirstConnected = $firstConnected
                                LastConnected = $lastConnected
                                DeviceClass = $deviceClass
                                DriveLetters = ""
                                SourceKey = $instance.PSPath
                                Source = "Registry-USB"
                            }
                        }
                    }
                    catch {
                        Write-ForensicLog "Error processing USB device $($instance.PSPath): $_" -Severity "Warning"
                    }
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error retrieving USB devices from registry: $_" -Severity "Warning"
    }
    
    return $devices
}

function Get-UsbDevicesFromSetupAPI {
    $devices = @()
    
    try {
        Write-ForensicLog "Checking SetupAPI logs for USB device history..."
        
        # SetupAPI logs are in the Windows directory
        $setupApiLogPaths = @(
            "$env:SystemRoot\INF\setupapi.dev.log",
            "$env:SystemRoot\INF\setupapi.setup.log"
        )
        
        foreach ($logPath in $setupApiLogPaths) {
            if (Test-Path $logPath) {
                $logContent = Get-Content -Path $logPath -ErrorAction SilentlyContinue
                
                if ($logContent) {
                    # Extract USB device installations from the logs
                    $device = $null
                    $installDate = $null
                    
                    foreach ($line in $logContent) {
                        # New device installation section
                        if ($line -match '>>>  \[Device Install.*#(Disk&Ven_|USB\\VID_)') {
                            # Save previous device if exists
                            if ($device) {
                                $devices += $device
                            }
                            
                            # Start a new device
                            $device = [PSCustomObject]@{
                                DeviceType = if ($line -match 'Disk&Ven_') { "Disk" } else { "Device" }
                                VendorName = ""
                                ProductName = ""
                                FriendlyName = ""
                                SerialNumber = ""
                                DeviceID = ""
                                FirstConnected = $null
                                LastConnected = $null
                                DeviceClass = ""
                                DriveLetters = ""
                                SourceKey = $logPath
                                Source = "SetupAPI"
                            }
                            
                            # Extract timestamp
                            if ($line -match '\[([0-9/: ]+)\]') {
                                try {
                                    $installDate = [DateTime]::Parse($matches[1])
                                    $device.FirstConnected = $installDate
                                    $device.LastConnected = $installDate
                                }
                                catch {
                                    # Use file timestamp as fallback
                                    $installDate = (Get-Item $logPath).LastWriteTime
                                    $device.FirstConnected = $installDate
                                    $device.LastConnected = $installDate
                                }
                            }
                            
                            # Extract device ID
                            if ($line -match '#(Disk&Ven_[^#]+)#') {
                                $deviceId = $matches[1]
                                $device.DeviceID = $deviceId
                                
                                # Parse USBSTOR device ID format
                                if ($deviceId -match "Disk&Ven_([^&]+)&Prod_([^&]+)&Rev_(.*)") {
                                    $device.VendorName = $matches[1]
                                    $device.ProductName = $matches[2]
                                    $device.FriendlyName = "$($matches[1]) $($matches[2])"
                                }
                            }
                            elseif ($line -match '#(USB\\VID_[^#]+)#') {
                                $deviceId = $matches[1]
                                $device.DeviceID = $deviceId
                                
                                # Parse USB device ID format
                                if ($deviceId -match "USB\\VID_([A-F0-9]{4})&PID_([A-F0-9]{4})") {
                                    $device.VendorName = $matches[1]
                                    $device.ProductName = $matches[2]
                                    $device.FriendlyName = "USB Device $($matches[1]):$($matches[2])"
                                }
                            }
                        }
                        # Extract serial number if available
                        elseif ($device -and $line -match '\s+Serial Number:\s+(.+)$') {
                            $device.SerialNumber = $matches[1].Trim()
                        }
                        # Extract device class if available
                        elseif ($device -and $line -match '\s+Class:\s+(.+)$') {
                            $device.DeviceClass = $matches[1].Trim()
                        }
                        # Extract device description/friendly name if available
                        elseif ($device -and $line -match '\s+Device Description:\s+(.+)$') {
                            $device.FriendlyName = $matches[1].Trim()
                        }
                    }
                    
                    # Add the last device if exists
                    if ($device) {
                        $devices += $device
                    }
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error retrieving USB devices from SetupAPI logs: $_" -Severity "Warning"
    }
    
    return $devices
}

function Get-MountedUsbDevices {
    $devices = @()
    
    try {
        Write-ForensicLog "Checking for currently mounted USB storage devices..."
        
        # Get current USB drives
        $usbDrives = Get-WmiObject -Class Win32_DiskDrive -Filter "InterfaceType='USB'" -ErrorAction SilentlyContinue
        
        foreach ($drive in $usbDrives) {
            try {
                # Get basic drive information
                $model = $drive.Model
                $serialNumber = $drive.SerialNumber
                
                # Get partition information
                $partitions = Get-WmiObject -Class Win32_DiskDriveToDiskPartition -Filter "Antecedent='$($drive.Path.Replace('\', '\\'))'" -ErrorAction SilentlyContinue
                $driveLetters = @()
                
                foreach ($partition in $partitions) {
                    $logicalDisks = Get-WmiObject -Class Win32_LogicalDiskToPartition -Filter "Antecedent='$($partition.Dependent.Replace('\', '\\'))'" -ErrorAction SilentlyContinue
                    
                    foreach ($logicalDisk in $logicalDisks) {
                        $diskProps = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$($logicalDisk.Dependent.Replace('\', '\\').Split('=')[1].Trim('"'))'" -ErrorAction SilentlyContinue
                        if ($diskProps) {
                            $driveLetters += $diskProps.DeviceID
                        }
                    }
                }
                
                # Parse model info for vendor/product
                $vendor = ""
                $product = ""
                
                if ($model -match "^([^ ]+) (.+)") {
                    $vendor = $matches[1]
                    $product = $matches[2]
                } else {
                    $vendor = "Unknown"
                    $product = $model
                }
                
                # Add device to results
                $devices += [PSCustomObject]@{
                    DeviceType = "Disk"
                    VendorName = $vendor
                    ProductName = $product
                    FriendlyName = $model
                    SerialNumber = $serialNumber
                    DeviceID = $drive.PNPDeviceID
                    FirstConnected = $null  # Not available from WMI
                    LastConnected = Get-Date  # Currently connected
                    DeviceClass = "Mass Storage"
                    DriveLetters = ($driveLetters -join ", ")
                    SourceKey = $drive.DeviceID
                    Source = "WMI-Current"
                }
            }
            catch {
                Write-ForensicLog "Error processing USB drive $($drive.DeviceID): $_" -Severity "Warning"
            }
        }
    }
    catch {
        Write-ForensicLog "Error retrieving mounted USB devices: $_" -Severity "Warning"
    }
    
    return $devices
}

function Get-UsbDevicesFromEventLog {
    $devices = @()
    
    try {
        Write-ForensicLog "Checking event logs for USB device connections..."
        
        # Check System event log for USB device events
        $events = @()
        
        # Limit to the past 90 days to avoid performance issues
        $startTime = (Get-Date).AddDays(-90)
        
        # PnP events for device connections
        $events += Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ProviderName = 'Microsoft-Windows-Kernel-PnP'
            Id = 2003, 2010, 2100, 2102  # Device install/arrival events
            StartTime = $startTime
        } -ErrorAction SilentlyContinue
        
        # DriverFrameworks-UserMode events for USB connections
        $events += Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ProviderName = 'Microsoft-Windows-DriverFrameworks-UserMode'
            Id = 2003, 2100, 2102
            StartTime = $startTime
        } -ErrorAction SilentlyContinue
        
        # Process events to extract USB device information
        foreach ($event in $events) {
            try {
                $eventXml = [xml]$event.ToXml()
                $eventData = $eventXml.Event.EventData.Data
                
                # Extract device information based on event type
                $deviceId = $null
                $deviceDescription = $null
                
                # Different events have different data structures
                foreach ($data in $eventData) {
                    if ($data.Name -eq "DeviceInstanceId") {
                        $deviceId = $data.'#text'
                    }
                    elseif ($data.Name -eq "DeviceDescription") {
                        $deviceDescription = $data.'#text'
                    }
                }
                
                # If no structured data, try to parse from the message
                if (-not $deviceId -and $event.Message) {
                    if ($event.Message -match "Device .*?'(.+?)' \(") {
                        $deviceDescription = $matches[1]
                    }
                    
                    if ($event.Message -match "instance ID \((.+?)\)") {
                        $deviceId = $matches[1]
                    }
                }
                
                # Only process USB devices
                if ($deviceId -and ($deviceId -match "USBSTOR" -or $deviceId -match "USB\\VID_")) {
                    # Determine device type and details
                    $deviceType = if ($deviceId -match "USBSTOR") { "Disk" } else { "Device" }
                    $vendor = ""
                    $product = ""
                    $serialNumber = ""
                    
                    # Parse different device ID formats
                    if ($deviceId -match "USBSTOR\\Disk&Ven_([^&]+)&Prod_([^&]+)&Rev_[^\\]+\\(.+)") {
                        $vendor = $matches[1]
                        $product = $matches[2]
                        $serialNumber = $matches[3]
                    }
                    elseif ($deviceId -match "USB\\VID_([A-F0-9]{4})&PID_([A-F0-9]{4})") {
                        $vendor = $matches[1]
                        $product = $matches[2]
                        $serialNumber = $deviceId.Split('\\')[-1]
                    }
                    
                    # Friendly name fallback
                    $friendlyName = $deviceDescription
                    if (-not $friendlyName) {
                        $friendlyName = if ($vendor -and $product) { "$vendor $product" } else { $deviceId }
                    }
                    
                    # Get the connection time from the event
                    $connectionTime = $event.TimeCreated
                    
                    # Add device to results
                    $devices += [PSCustomObject]@{
                        DeviceType = $deviceType
                        VendorName = $vendor
                        ProductName = $product
                        FriendlyName = $friendlyName
                        SerialNumber = $serialNumber
                        DeviceID = $deviceId
                        FirstConnected = $connectionTime
                        LastConnected = $connectionTime
                        DeviceClass = if ($deviceType -eq "Disk") { "Mass Storage" } else { "USB Device" }
                        DriveLetters = ""  # Not available from event logs
                        SourceKey = "EventID: $($event.Id), RecordID: $($event.RecordId)"
                        Source = "EventLog"
                    }
                }
            }
            catch {
                # Skip events that can't be processed
                continue
            }
        }
    }
    catch {
        Write-ForensicLog "Error retrieving USB devices from event logs: $_" -Severity "Warning"
    }
    
    return $devices
}

function Get-UsbDriveLetters {
    param (
        [string]$SerialNumber
    )
    
    $driveLetters = ""
    
    try {
        # Check MountedDevices registry key for drive letter mappings
        $mountedDevicesPath = "HKLM:\SYSTEM\MountedDevices"
        
        if (Test-Path $mountedDevicesPath) {
            $mountedDevices = Get-ItemProperty -Path $mountedDevicesPath -ErrorAction SilentlyContinue
            
            # Look for drive letters
            foreach ($property in $mountedDevices.PSObject.Properties) {
                # Drive letters start with \DosDevices\
                if ($property.Name -match "^\\DosDevices\\([A-Z]:)") {
                    $driveLetter = $matches[1]
                    $value = $property.Value
                    
                    # Convert binary data to string and check for serial number
                    if ($value) {
                        $valueString = [System.Text.Encoding]::Unicode.GetString($value)
                        
                        if ($valueString -match $SerialNumber) {
                            if ($driveLetters) {
                                $driveLetters += ", "
                            }
                            $driveLetters += $driveLetter
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error retrieving drive letters for USB device $SerialNumber : $_" -Severity "Warning"
    }
    
    return $driveLetters
}

function Get-UniqueUsbDevices {
    param (
        [array]$Devices
    )
    
    $uniqueDevices = @{}
    
    foreach ($device in $Devices) {
        # Create a unique key based on serial number or device ID
        $key = if ($device.SerialNumber) { $device.SerialNumber } else { $device.DeviceID }
        
        # If device doesn't exist in our hashtable yet, add it
        if (-not $uniqueDevices.ContainsKey($key)) {
            $uniqueDevices[$key] = $device
        }
        # Else update the device with more complete information
        else {
            $existingDevice = $uniqueDevices[$key]
            
            # Update first connected time if earlier
            if ($device.FirstConnected -and 
                (!$existingDevice.FirstConnected -or $device.FirstConnected -lt $existingDevice.FirstConnected)) {
                $existingDevice.FirstConnected = $device.FirstConnected
            }
            
            # Update last connected time if later
            if ($device.LastConnected -and 
                (!$existingDevice.LastConnected -or $device.LastConnected -gt $existingDevice.LastConnected)) {
                $existingDevice.LastConnected = $device.LastConnected
            }
            
            # Use drive letters if available
            if ($device.DriveLetters -and -not $existingDevice.DriveLetters) {
                $existingDevice.DriveLetters = $device.DriveLetters
            }
            
            # Use friendly name if available
            if ($device.FriendlyName -and 
                ($existingDevice.FriendlyName -eq "" -or $existingDevice.FriendlyName -match "^USB Device")) {
                $existingDevice.FriendlyName = $device.FriendlyName
            }
            
            # Use vendor and product if available
            if ($device.VendorName -and -not $existingDevice.VendorName) {
                $existingDevice.VendorName = $device.VendorName
            }
            
            if ($device.ProductName -and -not $existingDevice.ProductName) {
                $existingDevice.ProductName = $device.ProductName
            }
            
            # Append source if different
            if ($device.Source -ne $existingDevice.Source) {
                $existingDevice.Source = "$($existingDevice.Source), $($device.Source)"
            }
        }
    }
    
    return $uniqueDevices.Values
}

# Export function
Export-ModuleMember -Function Get-UsbDeviceHistory
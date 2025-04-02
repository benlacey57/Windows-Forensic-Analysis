<#
.SYNOPSIS
    Collects detailed system specifications and hardware information.
    
.DESCRIPTION
    Get-SystemSpecifications gathers comprehensive information about system hardware
    including processor, memory, storage, motherboard, BIOS, network adapters, and
    graphics cards. It provides detailed specifications useful for system inventory,
    troubleshooting, and forensic analysis.
    
.EXAMPLE
    $systemSpecsFile = Get-SystemSpecifications
    
.OUTPUTS
    String. The path to the CSV file containing system specifications data
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges recommended for complete results
#>

function Get-SystemSpecifications {
    param()

    $outputFile = "$script:outputDir\SystemSpecifications_$script:timestamp.csv"
    Write-ForensicLog "Collecting system hardware specifications..."

    try {
        # Initialize specifications collections
        $systemSpecs = @()
        
        # Get system information
        $computerSystem = Get-ComputerSystemInfo
        $systemSpecs += $computerSystem
        
        # Get processor information
        $processorInfo = Get-ProcessorInfo
        $systemSpecs += $processorInfo
        
        # Get memory information
        $memoryInfo = Get-MemoryInfo
        $systemSpecs += $memoryInfo
        
        # Get storage information
        $storageInfo = Get-StorageInfo
        $systemSpecs += $storageInfo
        
        # Get motherboard and BIOS information
        $motherboardInfo = Get-MotherboardInfo
        $systemSpecs += $motherboardInfo
        
        # Get network adapter information
        $networkInfo = Get-NetworkAdapterInfo
        $systemSpecs += $networkInfo
        
        # Get graphics card information
        $graphicsInfo = Get-GraphicsInfo
        $systemSpecs += $graphicsInfo
        
        # Get installed security software
        $securityInfo = Get-SecuritySoftwareInfo
        $systemSpecs += $securityInfo
        
        # Export results
        if ($systemSpecs.Count -gt 0) {
            # Sort by component type
            $sortedSpecs = $systemSpecs | Sort-Object -Property Category, Name
            $sortedSpecs | Export-Csv -Path $outputFile -NoTypeInformation
            
            # Log summary
            Write-ForensicLog "Collected $($systemSpecs.Count) system specification details"
            
            # Log basic system info
            $computerInfo = $systemSpecs | Where-Object { $_.Category -eq "System" } | Select-Object -First 1
            if ($computerInfo) {
                Write-ForensicLog "System: $($computerInfo.Name), $($computerInfo.Value)"
            }
            
            $cpuInfo = $systemSpecs | Where-Object { $_.Category -eq "Processor" -and $_.Name -eq "Name" } | Select-Object -First 1
            if ($cpuInfo) {
                Write-ForensicLog "Processor: $($cpuInfo.Value)"
            }
            
            $ramInfo = $systemSpecs | Where-Object { $_.Category -eq "Memory" -and $_.Name -eq "Total Physical Memory" } | Select-Object -First 1
            if ($ramInfo) {
                Write-ForensicLog "Memory: $($ramInfo.Value)"
            }
        } else {
            Write-ForensicLog "No system specifications collected" -Severity "Warning"
            # Create an empty file to indicate analysis was performed
            [PSCustomObject]@{
                Result = "No system specifications collected"
                AnalysisTime = Get-Date
                SystemName = $env:COMPUTERNAME
            } | Export-Csv -Path $outputFile -NoTypeInformation
        }
        
        Write-ForensicLog "Saved system specifications to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error collecting system specifications: $_" -Severity "Error"
        return $null
    }
}

function Get-ComputerSystemInfo {
    $specs = @()
    
    try {
        # Get basic computer system information
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        
        if ($computerSystem) {
            $specs += [PSCustomObject]@{
                Category = "System"
                Name = "System Manufacturer"
                Value = $computerSystem.Manufacturer
                Details = ""
            }
            
            $specs += [PSCustomObject]@{
                Category = "System"
                Name = "System Model"
                Value = $computerSystem.Model
                Details = ""
            }
            
            $specs += [PSCustomObject]@{
                Category = "System"
                Name = "System Type"
                Value = $computerSystem.SystemType
                Details = ""
            }
            
            $specs += [PSCustomObject]@{
                Category = "System"
                Name = "Name"
                Value = $computerSystem.Name
                Details = ""
            }
            
            $specs += [PSCustomObject]@{
                Category = "System"
                Name = "Domain"
                Value = $computerSystem.Domain
                Details = if ($computerSystem.PartOfDomain) { "Domain Joined" } else { "Workgroup" }
            }
            
            $specs += [PSCustomObject]@{
                Category = "System"
                Name = "Total Physical Memory"
                Value = "$([Math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)) GB"
                Details = "$($computerSystem.TotalPhysicalMemory) bytes"
            }
        }
        
        # Get operating system information
        $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        
        if ($operatingSystem) {
            $specs += [PSCustomObject]@{
                Category = "Operating System"
                Name = "Name"
                Value = $operatingSystem.Caption
                Details = ""
            }
            
            $specs += [PSCustomObject]@{
                Category = "Operating System"
                Name = "Version"
                Value = $operatingSystem.Version
                Details = "Build $($operatingSystem.BuildNumber)"
            }
            
            $specs += [PSCustomObject]@{
                Category = "Operating System"
                Name = "Architecture"
                Value = $operatingSystem.OSArchitecture
                Details = ""
            }
            
            $specs += [PSCustomObject]@{
                Category = "Operating System"
                Name = "Install Date"
                Value = $operatingSystem.InstallDate
                Details = ""
            }
            
            $specs += [PSCustomObject]@{
                Category = "Operating System"
                Name = "Last Boot Time"
                Value = $operatingSystem.LastBootUpTime
                Details = "Uptime: $([Math]::Round(((Get-Date) - $operatingSystem.LastBootUpTime).TotalHours, 2)) hours"
            }
            
            $specs += [PSCustomObject]@{
                Category = "Operating System"
                Name = "System Directory"
                Value = $operatingSystem.SystemDirectory
                Details = ""
            }
        }
        
        # Get Windows product key if possible
        $productKey = Get-WindowsProductKey
        if ($productKey) {
            $specs += [PSCustomObject]@{
                Category = "Operating System"
                Name = "Product Key"
                Value = $productKey
                Details = "Retrieved from registry"
            }
        }
        
        # Get time zone information
        $timeZone = Get-CimInstance -ClassName Win32_TimeZone -ErrorAction SilentlyContinue
        
        if ($timeZone) {
            $specs += [PSCustomObject]@{
                Category = "System"
                Name = "Time Zone"
                Value = $timeZone.Caption
                Details = "Bias: $($timeZone.Bias) minutes"
            }
        }
    }
    catch {
        Write-ForensicLog "Error collecting computer system information: $_" -Severity "Warning"
    }
    
    return $specs
}

function Get-ProcessorInfo {
    $specs = @()
    
    try {
        # Get processor information
        $processors = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue
        
        foreach ($processor in $processors) {
            $specs += [PSCustomObject]@{
                Category = "Processor"
                Name = "Name"
                Value = $processor.Name
                Details = ""
            }
            
            $specs += [PSCustomObject]@{
                Category = "Processor"
                Name = "Manufacturer"
                Value = $processor.Manufacturer
                Details = ""
            }
            
            $specs += [PSCustomObject]@{
                Category = "Processor"
                Name = "Cores"
                Value = $processor.NumberOfCores
                Details = "Logical Processors: $($processor.NumberOfLogicalProcessors)"
            }
            
            $specs += [PSCustomObject]@{
                Category = "Processor"
                Name = "Max Clock Speed"
                Value = "$($processor.MaxClockSpeed) MHz"
                Details = ""
            }
            
            $specs += [PSCustomObject]@{
                Category = "Processor"
                Name = "Socket Designation"
                Value = $processor.SocketDesignation
                Details = ""
            }
            
            $specs += [PSCustomObject]@{
                Category = "Processor"
                Name = "L2 Cache Size"
                Value = if ($processor.L2CacheSize) { "$($processor.L2CacheSize) KB" } else { "Unknown" }
                Details = ""
            }
            
            $specs += [PSCustomObject]@{
                Category = "Processor"
                Name = "L3 Cache Size"
                Value = if ($processor.L3CacheSize) { "$($processor.L3CacheSize) KB" } else { "Unknown" }
                Details = ""
            }
            
            $specs += [PSCustomObject]@{
                Category = "Processor"
                Name = "Architecture"
                Value = switch ($processor.Architecture) {
                    0 { "x86" }
                    1 { "MIPS" }
                    2 { "Alpha" }
                    3 { "PowerPC" }
                    5 { "ARM" }
                    6 { "ia64" }
                    9 { "x64" }
                    default { "Unknown" }
                }
                Details = ""
            }
            
            $specs += [PSCustomObject]@{
                Category = "Processor"
                Name = "Virtualization"
                Value = if ($processor.VirtualizationFirmwareEnabled -eq $true) { "Enabled" } else { "Disabled" }
                Details = ""
            }
        }
    }
    catch {
        Write-ForensicLog "Error collecting processor information: $_" -Severity "Warning"
    }
    
    return $specs
}

function Get-MemoryInfo {
    $specs = @()
    
    try {
        # Get physical memory information
        $physicalMemory = Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue
        
        if ($physicalMemory) {
            $totalMemory = 0
            $memoryCount = 0
            
            foreach ($memory in $physicalMemory) {
                $memoryCount++
                $totalMemory += $memory.Capacity
                
                $specs += [PSCustomObject]@{
                    Category = "Memory"
                    Name = "Memory Module $memoryCount"
                    Value = "$([Math]::Round($memory.Capacity / 1GB, 2)) GB"
                    Details = "Bank: $($memory.BankLabel), Slot: $($memory.DeviceLocator)"
                }
                
                $specs += [PSCustomObject]@{
                    Category = "Memory"
                    Name = "Memory Module $memoryCount Type"
                    Value = switch ($memory.MemoryType) {
                        0 { "Unknown" }
                        1 { "Other" }
                        2 { "DRAM" }
                        3 { "Synchronous DRAM" }
                        4 { "Cache DRAM" }
                        5 { "EDO" }
                        6 { "EDRAM" }
                        7 { "VRAM" }
                        8 { "SRAM" }
                        9 { "RAM" }
                        10 { "ROM" }
                        11 { "Flash" }
                        12 { "EEPROM" }
                        13 { "FEPROM" }
                        14 { "EPROM" }
                        15 { "CDRAM" }
                        16 { "3DRAM" }
                        17 { "SDRAM" }
                        18 { "SGRAM" }
                        19 { "RDRAM" }
                        20 { "DDR" }
                        21 { "DDR2" }
                        22 { "DDR2 FB-DIMM" }
                        24 { "DDR3" }
                        25 { "FBD2" }
                        26 { "DDR4" }
                        default { "Unknown" }
                    }
                    Details = "Speed: $($memory.Speed) MHz"
                }
                
                $specs += [PSCustomObject]@{
                    Category = "Memory"
                    Name = "Memory Module $memoryCount Manufacturer"
                    Value = $memory.Manufacturer
                    Details = if ($memory.PartNumber) { "Part Number: $($memory.PartNumber.Trim())" } else { "" }
                }
            }
            
            # Add total memory
            $specs += [PSCustomObject]@{
                Category = "Memory"
                Name = "Total Physical Memory"
                Value = "$([Math]::Round($totalMemory / 1GB, 2)) GB"
                Details = "$($memoryCount) Memory Modules Installed"
            }
        }
        
        # Get virtual memory information
        $pageFile = Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction SilentlyContinue
        
        if ($pageFile) {
            foreach ($pf in $pageFile) {
                $specs += [PSCustomObject]@{
                    Category = "Memory"
                    Name = "Page File"
                    Value = $pf.Name
                    Details = "Size: $($pf.AllocatedBaseSize) MB"
                }
                
                $specs += [PSCustomObject]@{
                    Category = "Memory"
                    Name = "Page File Current Usage"
                    Value = "$($pf.CurrentUsage) MB"
                    Details = "Peak Usage: $($pf.PeakUsage) MB"
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error collecting memory information: $_" -Severity "Warning"
    }
    
    return $specs
}

function Get-StorageInfo {
    $specs = @()
    
    try {
        # Get disk drive information
        $diskDrives = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue
        
        if ($diskDrives) {
            $diskNumber = 0
            
            foreach ($disk in $diskDrives) {
                $diskNumber++
                
                # Get partition information
                $partitions = Get-CimInstance -ClassName Win32_DiskDriveToDiskPartition -Filter "Antecedent='$($disk.Path.Replace('\', '\\'))'" -ErrorAction SilentlyContinue
                
                # Calculate partition count
                $partitionCount = ($partitions | Measure-Object).Count
                
                $specs += [PSCustomObject]@{
                    Category = "Storage"
                    Name = "Disk $diskNumber"
                    Value = "$($disk.Model)"
                    Details = "Size: $([Math]::Round($disk.Size / 1GB, 2)) GB, Partitions: $partitionCount"
                }
                
                $specs += [PSCustomObject]@{
                    Category = "Storage"
                    Name = "Disk $diskNumber Interface"
                    Value = $disk.InterfaceType
                    Details = "Media Type: $($disk.MediaType)"
                }
                
                # Add S.M.A.R.T. status if possible
                try {
                    $smartStatus = Get-WmiObject -Namespace "root\wmi" -Class MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue | 
                                  Where-Object { $_.InstanceName -match $disk.PNPDeviceID.Replace('\', '\\') }
                    
                    if ($smartStatus) {
                        $specs += [PSCustomObject]@{
                            Category = "Storage"
                            Name = "Disk $diskNumber S.M.A.R.T. Status"
                            Value = if ($smartStatus.PredictFailure -eq $true) { "Failure Predicted" } else { "OK" }
                            Details = "Based on S.M.A.R.T. data"
                        }
                    }
                }
                catch {
                    # S.M.A.R.T. information not available
                }
            }
        }
        
        # Get logical drive information
        $logicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
        
        if ($logicalDisks) {
            foreach ($logicalDisk in $logicalDisks) {
                $specs += [PSCustomObject]@{
                    Category = "Storage"
                    Name = "Volume $($logicalDisk.DeviceID)"
                    Value = if ($logicalDisk.VolumeName) { $logicalDisk.VolumeName } else { "No Label" }
                    Details = "File System: $($logicalDisk.FileSystem)"
                }
                
                $usedSpace = $logicalDisk.Size - $logicalDisk.FreeSpace
                $usedPercent = if ($logicalDisk.Size -gt 0) { [Math]::Round(($usedSpace / $logicalDisk.Size) * 100, 2) } else { 0 }
                
                $specs += [PSCustomObject]@{
                    Category = "Storage"
                    Name = "Volume $($logicalDisk.DeviceID) Capacity"
                    Value = "$([Math]::Round($logicalDisk.Size / 1GB, 2)) GB"
                    Details = "Free: $([Math]::Round($logicalDisk.FreeSpace / 1GB, 2)) GB ($usedPercent% Used)"
                }
            }
        }
        
        # Get optical drive information
        $opticalDrives = Get-CimInstance -ClassName Win32_CDROMDrive -ErrorAction SilentlyContinue
        
        if ($opticalDrives) {
            foreach ($drive in $opticalDrives) {
                $specs += [PSCustomObject]@{
                    Category = "Storage"
                    Name = "Optical Drive"
                    Value = $drive.Name
                    Details = "Drive Letter: $($drive.Drive)"
                }
            }
        }
        
        # Check for BitLocker encryption status
        try {
            $bitLockerVolumes = Get-WmiObject -Namespace "ROOT\CIMV2\Security\MicrosoftVolumeEncryption" -Class "Win32_EncryptableVolume" -ErrorAction SilentlyContinue
            
            if ($bitLockerVolumes) {
                foreach ($volume in $bitLockerVolumes) {
                    $protectionStatus = $volume.GetProtectionStatus().ProtectionStatus
                    $encryptionStatus = switch ($protectionStatus) {
                        0 { "Unprotected" }
                        1 { "Protected" }
                        2 { "Unknown" }
                        default { "Unknown" }
                    }
                    
                $specs += [PSCustomObject]@{
                    Category = "Security"
                    Name = "Windows Defender"
                    Value = if ($defenderStatus.AntivirusEnabled) { "Enabled" } else { "Disabled" }
                    Details = "Real-time Protection: " + $(if ($defenderStatus.RealTimeProtectionEnabled) { "Enabled" } else { "Disabled" })
                }
                
                $specs += [PSCustomObject]@{
                    Category = "Security"
                    Name = "Windows Defender Definitions"
                    Value = $defenderStatus.AntispywareSignatureVersion
                    Details = "Last Updated: $($defenderStatus.AntispywareSignatureLastUpdated)"
                }
            }
        }
        catch {
            # Windows Defender information not available
        }
        
        # Check Windows Firewall status
        try {
            $firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
            
            if ($firewallProfiles) {
                foreach ($profile in $firewallProfiles) {
                    $specs += [PSCustomObject]@{
                        Category = "Security"
                        Name = "Windows Firewall $($profile.Name)"
                        Value = if ($profile.Enabled) { "Enabled" } else { "Disabled" }
                        Details = "Default Inbound Action: $($profile.DefaultInboundAction), Default Outbound Action: $($profile.DefaultOutboundAction)"
                    }
                }
            }
        }
        catch {
            # Windows Firewall information not available
        }
        
        # Check installed antivirus products (Windows Security Center)
        try {
            $antivirusProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction SilentlyContinue
            
            if ($antivirusProducts) {
                $avCount = 0
                foreach ($av in $antivirusProducts) {
                    $avCount++
                    
                    # Decode product state
                    $productState = [Convert]::ToString($av.ProductState, 16).PadLeft(6, '0')
                    $enabled = $productState.Substring(2, 1) -eq "1"
                    $upToDate = $productState.Substring(3, 1) -eq "0"
                    
                    $specs += [PSCustomObject]@{
                        Category = "Security"
                        Name = "Antivirus $avCount"
                        Value = $av.DisplayName
                        Details = "Status: " + $(if ($enabled) { "Enabled" } else { "Disabled" }) + ", Definitions: " + $(if ($upToDate) { "Up to date" } else { "Out of date" })
                    }
                }
            }
        }
        catch {
            # Antivirus information not available
        }
        
        # Check installed security products from installed applications
        $securityProducts = Get-InstalledApplication -Category "Security"
        
        if ($securityProducts) {
            foreach ($product in $securityProducts) {
                # Skip products already found in Security Center
                if ($antivirusProducts -and $antivirusProducts.DisplayName -contains $product.Name) {
                    continue
                }
                
                $specs += [PSCustomObject]@{
                    Category = "Security"
                    Name = "Security Software"
                    Value = $product.Name
                    Details = "Version: $($product.Version), Vendor: $($product.Publisher)"
                }
            }
        }
    }
    catch {
        Write-ForensicLog "Error collecting security software information: $_" -Severity "Warning"
    }
    
    return $specs
}

function Get-InstalledApplication {
    param (
        [string]$Category = "All"
    )
    
    $applications = @()
    
    try {
        # Check registry for installed applications
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        foreach ($path in $regPaths) {
            if (Test-Path $path) {
                $applications += Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | 
                                Where-Object { $_.DisplayName } | 
                                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString
            }
        }
        
        # Convert to standardized format
        $formattedApps = $applications | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.DisplayName
                Version = $_.DisplayVersion
                Publisher = $_.Publisher
                InstallDate = $_.InstallDate
                InstallLocation = $_.InstallLocation
                UninstallString = $_.UninstallString
            }
        }
        
        # Filter by category if specified
        if ($Category -ne "All") {
            $securityKeywords = @(
                "antivirus", "anti-virus", "firewall", "security", "protection", "defender",
                "endpoint", "malware", "anti-malware", "threat", "kaspersky", "mcafee",
                "norton", "symantec", "avast", "avg", "bitdefender", "eset", "f-secure",
                "trend micro", "sophos", "webroot", "zonealarm", "bullguard", "comodo"
            )
            
            return $formattedApps | Where-Object {
                $app = $_
                $securityKeywords | Where-Object { $app.Name -match $_ -or $app.Publisher -match $_ }
            }
        }
        
        return $formattedApps
    }
    catch {
        Write-ForensicLog "Error retrieving installed applications: $_" -Severity "Warning"
        return @()
    }
}

function Get-WindowsProductKey {
    try {
        # Try to get product key from registry
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform"
        
        if (Test-Path $regPath) {
            $licenseInfo = Get-ItemProperty -Path $regPath -Name BackupProductKeyDefault -ErrorAction SilentlyContinue
            
            if ($licenseInfo -and $licenseInfo.BackupProductKeyDefault) {
                return $licenseInfo.BackupProductKeyDefault
            }
        }
        
        # Fallback method to decode the product key from the DigitalProductId
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        
        if (Test-Path $regPath) {
            $licenseInfo = Get-ItemProperty -Path $regPath -Name DigitalProductId -ErrorAction SilentlyContinue
            
            if ($licenseInfo -and $licenseInfo.DigitalProductId) {
                # Decode the binary product key
                $chars = "BCDFGHJKMPQRTVWXY2346789"
                $keyOffset = 52
                
                $key = ""
                $digitalProductId = $licenseInfo.DigitalProductId[($keyOffset)..($keyOffset + 14)]
                
                # Decode the base24 encoded binary data
                $keyChars = New-Object Char[] 29
                $isWindows8 = ($licenseInfo.DigitalProductId[66] -band 0xF) -ge 3
                
                $last = 0
                for ($i = 24; $i -ge 0; $i--) {
                    $current = 0
                    for ($j = 14; $j -ge 0; $j--) {
                        $current = $current * 256
                        $current = $digitalProductId[$j] + $current
                        $digitalProductId[$j] = [math]::Floor($current / 24)
                        $current = $current % 24
                    }
                    $keyChars[$i] = $chars[$current]
                    $last = $current
                }
                
                # Add dashes to product key
                if ($isWindows8) {
                    $groups = @(1,1,5,5,5,5,3,5)
                    $keyStart = 0
                    
                    for ($i = 0; $i -lt $groups.Count; $i++) {
                        $key += $keyChars[$keyStart..($keyStart + $groups[$i] - 1)] -join ""
                        if ($i -lt $groups.Count - 1) {
                            $key += "-"
                        }
                        $keyStart += $groups[$i]
                    }
                }
                else {
                    for ($i = 0; $i -lt 25; $i++) {
                        $key += $keyChars[$i]
                        if (($i + 1) % 5 -eq 0 -and $i -lt 24) {
                            $key += "-"
                        }
                    }
                }
                
                return $key
            }
        }
    }
    catch {
        # Product key retrieval failed
        return $null
    }
    
    return $null
}

# Export function
Export-ModuleMember -Function Get-SystemSpecifications
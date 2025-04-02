<#
.SYNOPSIS
    Retrieves information about connected devices.
    
.DESCRIPTION
    This module retrieves information about connected devices, including USB devices,
    network adapters, and other connected hardware. The results are saved to a CSV file.
    
.EXAMPLE
    $connectedDevicesFile = Get-ConnectedDevices
    
.OUTPUTS
    String. The path to the CSV file containing the connected device information.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for complete device information.
#>

function Get-ConnectedDevices {
    param()

    $outputFile = "$script:outputDir\ConnectedDevices_$script:timestamp.csv"
    Write-ForensicLog "Retrieving connected device information..."

    try {
        $connectedDevices = @()

        # USB Devices
        $usbDevices = Get-WmiObject -Class Win32_USBHub | Select-Object DeviceID, Description, Manufacturer, PNPDeviceID
        foreach ($device in $usbDevices) {
            $connectedDevices += [PSCustomObject]@{
                DeviceType    = "USB"
                DeviceID      = $device.DeviceID
                Description   = $device.Description
                Manufacturer  = $device.Manufacturer
                PNPDeviceID   = $device.PNPDeviceID
            }
        }

        # Network Adapters
        $networkAdapters = Get-NetAdapter | Select-Object Name, InterfaceDescription, InterfaceAlias, MacAddress, Status, InterfaceOperationalStatus
        foreach ($adapter in $networkAdapters) {
            $connectedDevices += [PSCustomObject]@{
                DeviceType    = "Network Adapter"
                Name          = $adapter.Name
                Description   = $adapter.InterfaceDescription
                InterfaceAlias = $adapter.InterfaceAlias
                MacAddress    = $adapter.MacAddress
                Status        = $adapter.Status
                OperationalStatus = $adapter.InterfaceOperationalStatus
            }
        }

        # Disk Drives
        $diskDrives = Get-WmiObject -Class Win32_DiskDrive | Select-Object Model, InterfaceType, Size, PNPDeviceID
        foreach ($drive in $diskDrives) {
            $connectedDevices += [PSCustomObject]@{
                DeviceType    = "Disk Drive"
                Model         = $drive.Model
                InterfaceType = $drive.InterfaceType
                Size          = $drive.Size
                PNPDeviceID   = $drive.PNPDeviceID
            }
        }

        # Other PNP Devices (Generic)
        $pnpDevices = Get-PnpDevice | Where-Object {$_.Present -eq $true} | Select-Object FriendlyName, InstanceId, Class, Manufacturer
        foreach($pnpDevice in $pnpDevices){
            $connectedDevices += [PSCustomObject]@{
                DeviceType = "PNP Device"
                FriendlyName = $pnpDevice.FriendlyName
                InstanceId = $pnpDevice.InstanceId
                Class = $pnpDevice.Class
                Manufacturer = $pnpDevice.Manufacturer
            }
        }

        # Save to CSV
        $connectedDevices | Export-Csv -Path $outputFile -NoTypeInformation

        Write-ForensicLog "Saved connected device information to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error retrieving connected device information: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-ConnectedDevices

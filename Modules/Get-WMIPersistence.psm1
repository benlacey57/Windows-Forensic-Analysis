<#
.SYNOPSIS
    Retrieves and analyses WMI persistence mechanisms.
    
.DESCRIPTION
    This module scans WMI namespaces for potential persistence mechanisms, including event consumers,
    filters, and bindings. The results are saved to a CSV file.
    
.EXAMPLE
    $wmiPersistenceFile = Get-WMIPersistence
    
.OUTPUTS
    String. The path to the CSV file containing the WMI persistence analysis.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for WMI access.
#>

function Get-WMIPersistence {
    param()

    $outputFile = "$script:outputDir\WMIPersistence_$script:timestamp.csv"
    Write-ForensicLog "Analysing WMI persistence mechanisms..."

    try {
        $wmiData = @()

        # WMI Event Consumers
        $consumers = Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer -ErrorAction SilentlyContinue
        foreach ($consumer in $consumers) {
            $wmiData += [PSCustomObject]@{
                Namespace     = $consumer.PSPath.Namespace
                ClassName     = $consumer.PSObject.Class.Name
                Name          = $consumer.Name
                Description   = "WMI Event Consumer"
                Details       = $consumer | ConvertTo-Json
                Severity      = "Medium"
            }
        }

        # WMI Event Filters
        $filters = Get-WmiObject -Namespace "root\subscription" -Class __EventFilter -ErrorAction SilentlyContinue
        foreach ($filter in $filters) {
            $wmiData += [PSCustomObject]@{
                Namespace     = $filter.PSPath.Namespace
                ClassName     = $filter.PSObject.Class.Name
                Name          = $filter.Name
                Description   = "WMI Event Filter"
                Details       = $filter | ConvertTo-Json
                Severity      = "Medium"
            }
        }

        # WMI Filter-Consumer Bindings
        $bindings = Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
        foreach ($binding in $bindings) {
            $wmiData += [PSCustomObject]@{
                Namespace     = $binding.PSPath.Namespace
                ClassName     = $binding.PSObject.Class.Name
                Name          = $binding.PSPath.RelativePath
                Description   = "WMI Filter-Consumer Binding"
                Details       = $binding | ConvertTo-Json
                Severity      = "High"
            }
        }

        # Save to CSV
        $wmiData | Export-Csv -Path $outputFile -NoTypeInformation

        Write-ForensicLog "Saved WMI persistence analysis to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error analysing WMI persistence: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-WMIPersistence

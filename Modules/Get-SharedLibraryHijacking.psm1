<#
.SYNOPSIS
    Detects potential shared library hijacking vulnerabilities.
    
.DESCRIPTION
    This module scans common application directories and registry locations
    for potential shared library hijacking vulnerabilities. It identifies
    applications that load DLLs from insecure locations. The results are saved to a CSV file.
    
.EXAMPLE
    $hijackingVulnerabilitiesFile = Get-SharedLibraryHijacking
    
.OUTPUTS
    String. The path to the CSV file containing the shared library hijacking analysis.
    
.NOTES
    Author: Forensic Analyzer Team
    Version: 1.0
    Required Permissions: Administrator privileges required for complete analysis.
#>

function Get-SharedLibraryHijacking {
    param()

    $outputFile = "$script:outputDir\SharedLibraryHijacking_$script:timestamp.csv"
    Write-ForensicLog "Analysing for shared library hijacking vulnerabilities..."

    try {
        $vulnerabilities = @()

        # Common Application Directories
        $applicationDirectories = @(
            "$env:ProgramFiles",
            "$env:ProgramFiles(x86)",
            "$env:LocalAppData",
            "$env:AppData"
        )

        foreach ($directory in $applicationDirectories) {
            if (Test-Path -Path $directory) {
                $applications = Get-ChildItem -Path $directory -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue
                foreach ($application in $applications) {
                    try {
                        $dlls = Get-ProcessModule -FilePath $application.FullName -ErrorAction SilentlyContinue | Select-Object FileName

                        if ($dlls) {
                            foreach ($dll in $dlls) {
                                $dllPath = $dll.FileName
                                if ($dllPath -and $dllPath -notmatch "System32|Windows|Program Files|Program Files \(x86\)") {
                                    $vulnerabilities += [PSCustomObject]@{
                                        Application = $application.FullName
                                        DLL         = $dllPath
                                        Vulnerability = "Potential DLL Hijacking"
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Could not analyse application: $($application.FullName) - $_"
                    }
                }
            }
        }

        # Registry AppInit_DLLs
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
        try {
            $appInitDlls = Get-ItemProperty -Path $registryPath -Name AppInit_DLLs -ErrorAction SilentlyContinue
            if ($appInitDlls.AppInit_DLLs) {
                $dlls = $appInitDlls.AppInit_DLLs -split ","
                foreach ($dll in $dlls) {
                    $dllPath = $dll.Trim()
                    if ($dllPath -and $dllPath -notmatch "System32|Windows|Program Files|Program Files \(x86\)") {
                        $vulnerabilities += [PSCustomObject]@{
                            Application = "Registry AppInit_DLLs"
                            DLL         = $dllPath
                            Vulnerability = "Potential DLL Hijacking (Registry)"
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not access registry location: $registryPath - $_"
        }

        # KnownDLLs Registry Key
        $knownDllsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
        try{
            $knownDlls = Get-ItemProperty -Path $knownDllsPath -ErrorAction SilentlyContinue
            if($knownDlls){
                foreach($property in $knownDlls.psobject.properties){
                    $dllPath = $property.value
                    if($dllPath -and $dllPath -notmatch "System32|Windows"){
                        $vulnerabilities += [PSCustomObject]@{
                            Application = "Registry KnownDLLs"
                            DLL = $dllPath
                            Vulnerability = "Potential DLL Hijacking (KnownDLLs)"
                        }
                    }
                }
            }
        }
        catch{
            Write-Verbose "Could not access registry location: $knownDllsPath - $_"
        }

        # Save to CSV
        $vulnerabilities | Export-Csv -Path $outputFile -NoTypeInformation

        Write-ForensicLog "Saved shared library hijacking analysis to $outputFile"
        return $outputFile
    }
    catch {
        Write-ForensicLog "Error analysing for shared library hijacking vulnerabilities: $_" -Severity "Error"
        return $null
    }
}

# Export function
Export-ModuleMember -Function Get-SharedLibraryHijacking

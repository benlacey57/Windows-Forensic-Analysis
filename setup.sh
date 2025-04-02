#!/bin/bash
# create_forensic_analyzer_structure.sh
# Script to create the Windows Forensic Analyzer project directory structure

# Base directory
BASE_DIR="."

# Create base directory
mkdir -p "$BASE_DIR"
cd "$BASE_DIR"

# Create module manifest and main module file
touch "ForensicAnalyzer.psd1"
touch "ForensicAnalyzer.psm1"

# Create installer script
touch "Install-ForensicAnalyzer.ps1"

# Create directories
mkdir -p Modules Templates/css Templates/js

# Create template files
touch "Templates/single-device-template.html"
touch "Templates/multi-device-template.html"
touch "Templates/css/forensic-report.css"
touch "Templates/js/forensic-report.js"

# Create module files
MODULE_FILES=(
    # Core Module
        "Initialize-Environment.psm1"
            "Write-ForensicLog.psm1"
                "Invoke-Cleanup.psm1"
                    "New-AnalysisReport.psm1"
                        "Start-ForensicAnalysis.psm1"
                            
                                # System Information Module
                                    "Get-SystemSpecifications.psm1"
                                        "Get-DriveHealthInfo.psm1"
                                            "Get-DetailedUserPermissions.psm1"
                                                "Get-ConnectedDevices.psm1"
                                                    "Get-UserAccountActivity.psm1"
                                                        "Get-HostsFileEntries.psm1"
                                                            "Get-InstalledPatches.psm1"
                                                                "Get-SystemRestorePoints.psm1"
                                                                    "Get-GroupPolicySettings.psm1"
                                                                        "Get-USBHistory.psm1"
                                                                            
                                                                                # Process Analysis Module
                                                                                    "Get-RunningProcesses.psm1"
                                                                                        "Get-RunningProcessConnections.psm1"
                                                                                            "Get-ServiceInformation.psm1"
                                                                                                "Get-PrefetchAnalysis.psm1"
                                                                                                    "Get-PowerShellHistory.psm1"
                                                                                                        "Get-PowerShellLogs.psm1"
                                                                                                            "Find-RecentlyModifiedExecutables.psm1"
                                                                                                                "Find-TimeStompedFiles.psm1"
                                                                                                                    "Get-MemoryDump.psm1"
                                                                                                                        
                                                                                                                            # Network Analysis Module
                                                                                                                                "Get-NetworkConnections.psm1"
                                                                                                                                    "Find-UnusualPorts.psm1"
                                                                                                                                        "Get-NetworkUsage.psm1"
                                                                                                                                            "Get-DNSSettings.psm1"
                                                                                                                                                "Get-SMBShareAnalysis.psm1"
                                                                                                                                                    "Get-RemoteAccessServices.psm1"
                                                                                                                                                        
                                                                                                                                                            # Security Configuration Module
                                                                                                                                                                "Get-FirewallStatus.psm1"
                                                                                                                                                                    "Get-WindowsDefenderStatus.psm1"
                                                                                                                                                                        "Find-AMSIBypassAttempts.psm1"
                                                                                                                                                                            "Get-SuspiciousDrivers.psm1"
                                                                                                                                                                                "Get-ShadowCopies.psm1"
                                                                                                                                                                                    "Find-UnusualCertificates.psm1"
                                                                                                                                                                                        
                                                                                                                                                                                            # Persistence Detection Module
                                                                                                                                                                                                "Get-ScheduledTaskInfo.psm1"
                                                                                                                                                                                                    "Find-SuspiciousScheduledTasks.psm1"
                                                                                                                                                                                                        "Get-StartupItems.psm1"
                                                                                                                                                                                                            "Get-RegistryPersistence.psm1"
                                                                                                                                                                                                                "Get-WMIPersistence.psm1"
                                                                                                                                                                                                                    "Get-AutorunLocations.psm1"
                                                                                                                                                                                                                        "Get-UnusualCronJobs.psm1"
                                                                                                                                                                                                                            "Get-SharedLibraryHijacking.psm1"
                                                                                                                                                                                                                                "Get-EnvironmentVariablePersistence.psm1"
                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                        # Malware Detection Module
                                                                                                                                                                                                                                            "Find-PotentialWebShells.psm1"
                                                                                                                                                                                                                                                "Get-RootKitIndicators.psm1"
                                                                                                                                                                                                                                                    "Get-DriverStatus.psm1"
                                                                                                                                                                                                                                                        "Get-BrowserExtensions.psm1"
                                                                                                                                                                                                                                                            "Get-RecentlyDeletedFiles.psm1"
                                                                                                                                                                                                                                                                
                                                                                                                                                                                                                                                                    # Reporting Module
                                                                                                                                                                                                                                                                        "New-ForensicHtmlReport.psm1"
                                                                                                                                                                                                                                                                            "New-MultiComputerForensicReport.psm1"
                                                                                                                                                                                                                                                                                
                                                                                                                                                                                                                                                                                    # Scheduling and Distribution Module
                                                                                                                                                                                                                                                                                        "Register-ForensicAnalysisSchedule.psm1"
                                                                                                                                                                                                                                                                                            "Protect-ForensicReport.psm1"
                                                                                                                                                                                                                                                                                                "Send-SecureForensicReport.psm1"
                                                                                                                                                                                                                                                                                                )

                                                                                                                                                                                                                                                                                                # Create each module file (empty)
                                                                                                                                                                                                                                                                                                for MODULE in "${MODULE_FILES[@]}"; do
                                                                                                                                                                                                                                                                                                    touch "Modules/$MODULE"
                                                                                                                                                                                                                                                                                                        echo "Created module: Modules/$MODULE"
                                                                                                                                                                                                                                                                                                        done

                                                                                                                                                                                                                                                                                                        echo ""
                                                                                                                                                                                                                                                                                                        echo "ForensicAnalyzer project structure created successfully!"
                                                                                                                                                                                                                                                                                                        echo "Project is located at: $(pwd)"
                                                                                                                                                                                                                                                                                                        echo ""
                                                                                                                                                                                                                                                                                                        echo "Key files:"
                                                                                                                                                                                                                                                                                                        echo "- ForensicAnalyzer.psd1 (Module manifest)"
                                                                                                                                                                                                                                                                                                        echo "- ForensicAnalyzer.psm1 (Main module loader)"
                                                                                                                                                                                                                                                                                                        echo "- Install-ForensicAnalyzer.ps1 (Installation script)"
                                                                                                                                                                                                                                                                                                        echo ""
                                                                                                                                                                                                                                                                                                        echo "Next steps:"
                                                                                                                                                                                                                                                                                                        echo "1. Implement the module functions in the Modules/ directory"
                                                                                                                                                                                                                                                                                                        echo "2. Customize the HTML templates in the Templates/ directory"
                                                                                                                                                                                                                                                                                                        echo "3. Run the module with 'Import-Module ./ForensicAnalyzer.psd1'"
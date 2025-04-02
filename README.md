# Windows Forensic Analyser

A comprehensive PowerShell toolkit for system forensic analysis, threat hunting, and security incident response on Windows systems. Automates the collection and analysis of forensic artifacts to identify potential security compromises.

![Forensic Analyser Banner](https://example.com/path/to/banner.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/ForensicAnalyzer.svg)](https://www.powershellgallery.com/packages/ForensicAnalyzer)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/ForensicAnalyzer.svg)](https://www.powershellgallery.com/packages/ForensicAnalyzer)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Usage](#basic-usage)
    - [Advanced Usage](#advanced-usage)
      - [Scheduled Analysis](#scheduled-analysis)
        - [Multi-System Analysis](#multi-system-analysis)
          - [Report Generation](#report-generation)
            - [Secure Distribution](#secure-distribution)
            - [Modules](#modules)
            - [Output](#output)
            - [Customization](#customization)
            - [Contributing](#contributing)
            - [Security Considerations](#security-considerations)

            ## Overview

            Windows Forensic Analyser is a powerful toolkit designed for security professionals, system administrators, and incident responders who need to quickly assess Windows systems for signs of compromise. The toolkit automates the collection and analysis of forensic artifacts, helping to identify suspicious activity and potential security incidents.

            The framework follows a modular approach, with separate functions for different analysis areas, allowing for flexibility in deployment and execution. Results are presented in interactive HTML reports that highlight critical findings and provide detailed information for further investigation.

            ## Features

            ### System Information
            - System specifications (OS, hardware, memory)
            - Drive health, encryption status, and space usage
            - Connected devices and hardware inventory
            - User accounts and detailed permissions
            - Hosts file mappings

            ### Security Analysis
            - Windows Firewall status and rule analysis
            - Windows Defender configuration assessment
            - Installed security patches
            - Certificate store analysis
            - AMSI bypass attempts detection

            ### Persistence Mechanisms
            - Scheduled tasks and potential backdoors
            - Startup items and autorun locations
            - Registry persistence techniques
            - WMI event subscription persistence
            - Environment variable manipulations
            - DLL hijacking opportunities

            ### Network Analysis
            - Active network connections and mapped processes
            - Unusual network ports and connections
            - DNS settings and potential tampering
            - SMB share analysis
            - Remote access services detection

            ### Process Analysis
            - Running processes and loaded modules
            - Recently modified executables
            - Suspicious process-to-network mappings
            - Driver and kernel module verification
            - Potential rootkit indicators

            ### Activity Analysis
            - PowerShell command history and script block logs
            - Browser extensions and plugins
            - Recently deleted files
            - USB device history
            - Shadow copy analysis

            ### Web Server Analysis
            - Potential web shells detection
            - Suspicious web server configurations
            - Unauthorized file access points

            ### Reporting
            - Interactive HTML reports with Bootstrap
            - Summary dashboards with critical findings
            - Mobile-responsive design
            - Multi-system consolidated reports

            ## Requirements

            - Windows 7/Server 2012 R2 or later
            - PowerShell 5.1 or later
            - Administrator privileges on the target system
            - Approximately 50MB of free disk space for the toolkit
            - Additional space for storing analysis results (varies based on system)

            ## Installation

            ### Install from PowerShell Gallery (Recommended)

            ```powershell
            Install-Module -Name ForensicAnalyzer -Scope CurrentUser
            ```

            ### Manual Installation

            1. Clone the repository or download the ZIP file
            2. Extract the contents to a directory of your choice
            3. Import the module:

            ```powershell
            Import-Module "C:\Path\To\ForensicAnalyzer\ForensicAnalyzer.psd1"
            ```

            ### System-wide Installation

            Run the installation script as Administrator:

            ```powershell
            # Navigate to the directory containing the module
            cd C:\Path\To\ForensicAnalyzer

            # Run the installer
            .\Install-ForensicAnalyzer.ps1
            ```

            ## Usage

            ### Basic Usage

            Run a basic analysis of the local system:

            ```powershell
            # Import the module if not already imported
            Import-Module ForensicAnalyzer

            # Run a full analysis
            Start-ForensicAnalysis

            # Run a quick scan
            Start-ForensicAnalysis -QuickScan
            ```

            ### Advanced Usage

            Customize the analysis with additional parameters:

            ```powershell
            # Specify custom output directory and include memory dump
            Start-ForensicAnalysis -OutputDirectory "D:\ForensicData" -IncludeMemoryDump

            # Collect more event logs and check for recent executables
            Start-ForensicAnalysis -EventHours 72 -RecentExeDays 14

            # Generate an HTML report
            Start-ForensicAnalysis -GenerateHtmlReport

            # Secure results with encryption
            Start-ForensicAnalysis -SecureResults -CertificateThumbprint "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t"
            ```

            ### Scheduled Analysis

            Schedule regular forensic scans:

            ```powershell
            # Schedule daily analysis at 11:00 PM
            Register-ForensicAnalysisSchedule -ScheduleType Daily -Time "23:00" -QuickScan

            # Schedule weekly analysis with email reporting
            Register-ForensicAnalysisSchedule -ScheduleType Weekly -DayOfWeek Saturday -Time "22:00" `
                                            -CentralRepository "\\Server\Share\ForensicResults" `
                                                                            -SecureReporting `
                                                                                                            -ReportRecipients "security@company.com" `
                                                                                                                                            -SMTPServer "smtp.company.com" `
                                                                                                                                                                            -SMTPCredential (Get-Credential)
                                                                                                                                                                            ```

                                                                                                                                                                            ### Multi-System Analysis

                                                                                                                                                                            Analyze multiple systems on your network:

                                                                                                                                                                            ```powershell
                                                                                                                                                                            # Define the computers to analyze
                                                                                                                                                                            $computers = @("Workstation01", "Server01", "LaptopXYZ")

                                                                                                                                                                            # Create a hashtable for results
                                                                                                                                                                            $computerData = @{}

                                                                                                                                                                            # Process each computer
                                                                                                                                                                            foreach ($computer in $computers) {
                                                                                                                                                                                    Write-Host "Analyzing $computer..."
                                                                                                                                                                                        
                                                                                                                                                                                            # Remote analysis
                                                                                                                                                                                                Invoke-Command -ComputerName $computer -ScriptBlock {
                                                                                                                                                                                                            Import-Module ForensicAnalyzer
                                                                                                                                                                                                                    Start-ForensicAnalysis -OutputDirectory "C:\ForensicData"
                                                                                                                                                                                                }
                                                                                                                                                                                                    
                                                                                                                                                                                                        # Map the remote output directory
                                                                                                                                                                                                            $computerData[$computer] = "\\$computer\C$\ForensicData"
                                                                                                                                                                            }

                                                                                                                                                                            # Generate a consolidated report
                                                                                                                                                                            New-MultiComputerForensicReport -ComputerData $computerData -OutputPath "D:\Reports\MultiSystemReport.html"
                                                                                                                                                                            ```

                                                                                                                                                                            ### Report Generation

                                                                                                                                                                            Generate rich HTML reports:

                                                                                                                                                                            ```powershell
                                                                                                                                                                            # Generate a report from previously collected data
                                                                                                                                                                            $results = Start-ForensicAnalysis

                                                                                                                                                                            # Create a single-system HTML report
                                                                                                                                                                            New-ForensicHtmlReport -Results $results -OutputPath "C:\Reports\Forensic_Report.html"

                                                                                                                                                                            # Send the report securely via email
                                                                                                                                                                            Send-SecureForensicReport -ReportPath "C:\Reports\Forensic_Report.html" `
                                                                                                                                                                                                    -Recipients "security@company.com" `
                                                                                                                                                                                                                            -SMTPServer "smtp.company.com" `
                                                                                                                                                                                                                                                    -Credential (Get-Credential) `
                                                                                                                                                                                                                                                                            -UseTLS
                                                                                                                                                                                                                                                                            ```

                                                                                                                                                                                                                                                                            ### Secure Distribution

                                                                                                                                                                                                                                                                            Encrypt and distribute reports securely:

                                                                                                                                                                                                                                                                            ```powershell
                                                                                                                                                                                                                                                                            # Encrypt a report with a certificate
                                                                                                                                                                                                                                                                            Protect-ForensicReport -ReportPath "C:\Reports\Forensic_Report.html" `
                                                                                                                                                                                                                                                                                                 -OutputPath "C:\Secure\Encrypted_Report.zip" `
                                                                                                                                                                                                                                                                                                                      -CertificateThumbprint "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t"

                                                                                                                                                                                                                                                                                                                      # Encrypt with a password
                                                                                                                                                                                                                                                                                                                      $securePassword = Read-Host -AsSecureString -Prompt "Enter encryption password"
                                                                                                                                                                                                                                                                                                                      Protect-ForensicReport -ReportPath "C:\Reports\Forensic_Report.html" `
                                                                                                                                                                                                                                                                                                                                           -OutputPath "C:\Secure\Encrypted_Report.zip" `
                                                                                                                                                                                                                                                                                                                                                                -Password $securePassword
                                                                                                                                                                                                                                                                                                                                                                ```

                                                                                                                                                                                                                                                                                                                                                                ## Modules

                                                                                                                                                                                                                                                                                                                                                                Windows Forensic Analyzer is organized into functional modules:

                                                                                                                                                                                                                                                                                                                                                                ### Core Module
                                                                                                                                                                                                                                                                                                                                                                - `Start-ForensicAnalysis` - Main function to initiate the analysis
                                                                                                                                                                                                                                                                                                                                                                - `Initialize-Environment` - Sets up the environment for analysis
                                                                                                                                                                                                                                                                                                                                                                - `Write-ForensicLog` - Logging function
                                                                                                                                                                                                                                                                                                                                                                - `Invoke-Cleanup` - Cleanup function
                                                                                                                                                                                                                                                                                                                                                                - `New-AnalysisReport` - Generates the text report

                                                                                                                                                                                                                                                                                                                                                                ### System Information Module
                                                                                                                                                                                                                                                                                                                                                                - `Get-SystemSpecifications` - Collects system hardware and OS information
                                                                                                                                                                                                                                                                                                                                                                - `Get-DriveHealthInfo` - Analyzes drive health and encryption status
                                                                                                                                                                                                                                                                                                                                                                - `Get-DetailedUserPermissions` - Gathers user account information
                                                                                                                                                                                                                                                                                                                                                                - `Get-ConnectedDevices` - Lists all connected hardware devices
                                                                                                                                                                                                                                                                                                                                                                - `Get-HostsFileEntries` - Examines hosts file for suspicious entries

                                                                                                                                                                                                                                                                                                                                                                ### Process Analysis Module
                                                                                                                                                                                                                                                                                                                                                                - `Get-RunningProcesses` - Collects information about running processes
                                                                                                                                                                                                                                                                                                                                                                - `Get-RunningProcessConnections` - Maps processes to network connections
                                                                                                                                                                                                                                                                                                                                                                - `Get-ServiceInformation` - Analyzes system services
                                                                                                                                                                                                                                                                                                                                                                - `Get-PowerShellHistory` - Examines PowerShell command history
                                                                                                                                                                                                                                                                                                                                                                - `Get-PowerShellLogs` - Collects PowerShell script block logs

                                                                                                                                                                                                                                                                                                                                                                ### Network Analysis Module
                                                                                                                                                                                                                                                                                                                                                                - `Get-NetworkConnections` - Gathers information about network connections
                                                                                                                                                                                                                                                                                                                                                                - `Find-UnusualPorts` - Identifies suspicious network ports
                                                                                                                                                                                                                                                                                                                                                                - `Get-NetworkUsage` - Monitors network traffic for anomalies
                                                                                                                                                                                                                                                                                                                                                                - `Get-DNSSettings` - Checks DNS configurations
                                                                                                                                                                                                                                                                                                                                                                - `Get-SMBShareAnalysis` - Analyzes shared folders

                                                                                                                                                                                                                                                                                                                                                                ### Security Configuration Module
                                                                                                                                                                                                                                                                                                                                                                - `Get-FirewallStatus` - Checks Windows Firewall configuration
                                                                                                                                                                                                                                                                                                                                                                - `Get-WindowsDefenderStatus` - Analyzes Windows Defender settings
                                                                                                                                                                                                                                                                                                                                                                - `Find-AMSIBypassAttempts` - Looks for AMSI bypass attempts
                                                                                                                                                                                                                                                                                                                                                                - `Get-SuspiciousDrivers` - Identifies unsigned or suspicious drivers
                                                                                                                                                                                                                                                                                                                                                                - `Find-UnusualCertificates` - Checks for unusual certificates

                                                                                                                                                                                                                                                                                                                                                                ### Persistence Detection Module
                                                                                                                                                                                                                                                                                                                                                                - `Get-ScheduledTaskInfo` - Collects scheduled task information
                                                                                                                                                                                                                                                                                                                                                                - `Find-SuspiciousScheduledTasks` - Identifies suspicious scheduled tasks
                                                                                                                                                                                                                                                                                                                                                                - `Get-StartupItems` - Examines system startup items
                                                                                                                                                                                                                                                                                                                                                                - `Get-RegistryPersistence` - Checks registry for persistence mechanisms
                                                                                                                                                                                                                                                                                                                                                                - `Get-WMIPersistence` - Looks for WMI persistence techniques
                                                                                                                                                                                                                                                                                                                                                                - `Get-AutorunLocations` - Examines all autorun locations

                                                                                                                                                                                                                                                                                                                                                                ### Malware Detection Module
                                                                                                                                                                                                                                                                                                                                                                - `Find-PotentialWebShells` - Searches for web shells
                                                                                                                                                                                                                                                                                                                                                                - `Get-RootKitIndicators` - Looks for signs of rootkits
                                                                                                                                                                                                                                                                                                                                                                - `Get-BrowserExtensions` - Analyzes browser extensions for suspicious behavior
                                                                                                                                                                                                                                                                                                                                                                - `Get-RecentlyDeletedFiles` - Examines recently deleted files

                                                                                                                                                                                                                                                                                                                                                                ### Reporting Module
                                                                                                                                                                                                                                                                                                                                                                - `New-ForensicHtmlReport` - Generates HTML report for a single system
                                                                                                                                                                                                                                                                                                                                                                - `New-MultiComputerForensicReport` - Creates consolidated multi-system reports

                                                                                                                                                                                                                                                                                                                                                                ### Scheduling and Distribution Module
                                                                                                                                                                                                                                                                                                                                                                - `Register-ForensicAnalysisSchedule` - Sets up scheduled analysis
                                                                                                                                                                                                                                                                                                                                                                - `Protect-ForensicReport` - Encrypts reports for secure storage
                                                                                                                                                                                                                                                                                                                                                                - `Send-SecureForensicReport` - Securely distributes reports

                                                                                                                                                                                                                                                                                                                                                                ## Output

                                                                                                                                                                                                                                                                                                                                                                By default, analysis results are stored in `C:\ForensicData` (or the specified output directory) with the following structure:

                                                                                                                                                                                                                                                                                                                                                                ```
                                                                                                                                                                                                                                                                                                                                                                ForensicData/
                                                                                                                                                                                                                                                                                                                                                                ├── ForensicAnalysisReport_[timestamp].txt     # Main text report with findings
                                                                                                                                                                                                                                                                                                                                                                ├── ForensicAnalysis_[timestamp].log           # Log file with analysis details
                                                                                                                                                                                                                                                                                                                                                                ├── ForensicReport_[timestamp].html            # HTML report (if generated)
                                                                                                                                                                                                                                                                                                                                                                ├── Processes_[timestamp].csv                  # Process information
                                                                                                                                                                                                                                                                                                                                                                ├── NetworkConnections_[timestamp].csv         # Network connection data
                                                                                                                                                                                                                                                                                                                                                                ├── ScheduledTasks_[timestamp].csv             # Scheduled tasks information
                                                                                                                                                                                                                                                                                                                                                                ├── WindowsDefender_[timestamp].csv            # Windows Defender status
                                                                                                                                                                                                                                                                                                                                                                ├── ...                                        # Other data files
                                                                                                                                                                                                                                                                                                                                                                └── EncryptedReport_[timestamp].zip            # Encrypted report (if enabled)
                                                                                                                                                                                                                                                                                                                                                                ```

                                                                                                                                                                                                                                                                                                                                                                ## Customization

                                                                                                                                                                                                                                                                                                                                                                ### Template Customization

                                                                                                                                                                                                                                                                                                                                                                The HTML reports use templates located in the `Templates` directory. You can customize these templates to match your organization's branding:

                                                                                                                                                                                                                                                                                                                                                                ```
                                                                                                                                                                                                                                                                                                                                                                Templates/
                                                                                                                                                                                                                                                                                                                                                                ├── css/
                                                                                                                                                                                                                                                                                                                                                                │   └── forensic-report.css          # Custom CSS styling
                                                                                                                                                                                                                                                                                                                                                                ├── js/
                                                                                                                                                                                                                                                                                                                                                                │   └── forensic-report.js           # JavaScript functionality
                                                                                                                                                                                                                                                                                                                                                                ├── single-device-template.html      # Template for single device reports
                                                                                                                                                                                                                                                                                                                                                                └── multi-device-template.html       # Template for multi-device reports
                                                                                                                                                                                                                                                                                                                                                                ```

                                                                                                                                                                                                                                                                                                                                                                ### Detection Rules

                                                                                                                                                                                                                                                                                                                                                                The analysis functions use detection rules that can be customized in the individual module files. For example, to add additional suspicious PowerShell patterns:

                                                                                                                                                                                                                                                                                                                                                                ```powershell
                                                                                                                                                                                                                                                                                                                                                                # In Get-PowerShellLogs.psm1
                                                                                                                                                                                                                                                                                                                                                                $suspiciousPatterns = @(
                                                                                                                                                                                                                                                                                                                                                                        'downloadstring',
                                                                                                                                                                                                                                                                                                                                                                            'invoke-expression',
                                                                                                                                                                                                                                                                                                                                                                                'iex ',
                                                                                                                                                                                                                                                                                                                                                                                    '-enc',
                                                                                                                                                                                                                                                                                                                                                                                        # Add your custom patterns here
                                                                                                                                                                                                                                                                                                                                                                                            'your-custom-pattern',
                                                                                                                                                                                                                                                                                                                                                                                                'another-pattern'
                                                                                                                                                                                                                                                                                                                                                                )
                                                                                                                                                                                                                                                                                                                                                                ```

                                                                                                                                                                                                                                                                                                                                                                ## Contributing

                                                                                                                                                                                                                                                                                                                                                                Contributions to Windows Forensic Analyzer are welcome! To contribute:

                                                                                                                                                                                                                                                                                                                                                                1. Fork the repository
                                                                                                                                                                                                                                                                                                                                                                2. Create a feature branch (`git checkout -b feature/amazing-feature`)
                                                                                                                                                                                                                                                                                                                                                                3. Make your changes
                                                                                                                                                                                                                                                                                                                                                                4. Run tests (if available)
                                                                                                                                                                                                                                                                                                                                                                5. Commit your changes (`git commit -m 'Add amazing feature'`)
                                                                                                                                                                                                                                                                                                                                                                6. Push to the branch (`git push origin feature/amazing-feature`)
                                                                                                                                                                                                                                                                                                                                                                7. Open a Pull Request

                                                                                                                                                                                                                                                                                                                                                                Please ensure your code follows the project's style guidelines and includes appropriate documentation.

                                                                                                                                                                                                                                                                                                                                                                ## Security Considerations

                                                                                                                                                                                                                                                                                                                                                                - This tool requires administrator privileges to collect comprehensive forensic data
                                                                                                                                                                                                                                                                                                                                                                - Data collected may contain sensitive information about the system configuration
                                                                                                                                                                                                                                                                                                                                                                - When emailing reports, always use encryption to protect sensitive data
                                                                                                                                                                                                                                                                                                                                                                - Consider legal and privacy implications before deploying in a corporate environment
 - Ensure you have proper authorization before analyzing systems

## License
This project is licensed under the MIT License - see the LICENSE file for details.

**Disclaimer:** This tool is intended for legitimate security testing, forensic investigation, and system administration with proper authorization. Use of this tool on systems without explicit permission may violate computer crime laws.

The authors and contributors are not responsible for any misuse of this software or for any damage it might cause to systems or data.
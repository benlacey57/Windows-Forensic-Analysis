# Windows Forensic Analyzer

A comprehensive PowerShell toolkit for system forensic analysis, threat hunting, and security incident response on Windows systems. Automates the collection and analysis of forensic artifacts to identify potential security compromises.

[![Forensic Analyzer Banner](https://via.placeholder.com/800x200?text=Windows+Forensic+Analyzer)](https://via.placeholder.com)

License: MIT | [PowerShell Gallery](https://www.powershellgallery.com/packages/ForensicAnalyzer)

## Table of Contents

-   [Overview](#overview)
-   [Features](#features)
-   [Requirements](#requirements)
-   [Installation](#installation)
    -   [Install from PowerShell Gallery (Recommended)](#install-from-powershell-gallery-recommended)
    -   [Manual Installation](#manual-installation)
    -   [System-wide Installation](#system-wide-installation)
-   [Usage](#usage)
    -   [Basic Usage](#basic-usage)
    -   [Advanced Usage](#advanced-usage)
    -   [Scheduled Analysis](#scheduled-analysis)
    -   [Multi-System Analysis](#multi-system-analysis)
    -   [Report Generation](#report-generation)
    -   [Secure Distribution](#secure-distribution)
-   [Modules](#modules)
    -   [Core Module](#core-module)
    -   [System Information Modules](#system-information-modules)
    -   [Security Analysis Modules](#security-analysis-modules)
    -   [Persistence Mechanisms Modules](#persistence-mechanisms-modules)
    -   [Network Analysis Modules](#network-analysis-modules)
    -   [Process Analysis Modules](#process-analysis-modules)
    -   [Activity Analysis Modules](#activity-analysis-modules)
    -   [Web Server Analysis Modules](#web-server-analysis-modules)
    -   [Reporting Modules](#reporting-modules)
    -   [Utility Modules](#utility-modules)
-   [Output](#output)
-   [Customization](#customization)
-   [Contributing](#contributing)
-   [Security Considerations](#security-considerations)

## Overview

Windows Forensic Analyzer is a powerful PowerShell toolkit designed to streamline forensic analysis, threat hunting, and security incident response on Windows systems. It automates the collection and analysis of critical forensic artifacts, enabling security professionals, system administrators, and incident responders to quickly assess systems for signs of compromise. The modular framework allows for flexible deployment and execution, with results presented in interactive, mobile-responsive HTML reports that highlight key findings for further investigation.

## Features

-   **System Information:** Gathers comprehensive system specifications, drive health, user account details, and hardware inventory.
-   **Security Analysis:** Evaluates Windows Firewall, Defender, installed security patches, certificate stores, and detects AMSI bypass attempts.
-   **Persistence Mechanisms:** Identifies potential backdoors, startup items, registry persistence, WMI event subscriptions, and DLL hijacking opportunities.
-   **Network Analysis:** Analyzes active network connections, unusual ports, DNS settings, SMB shares, and detects remote access services.
-   **Process Analysis:** Examines running processes, loaded modules, recently modified executables, and potential rootkit indicators.
-   **Activity Analysis:** Tracks PowerShell command history, browser extensions, recently deleted files, USB device history, and shadow copies.
-   **Web Server Analysis:** Detects potential web shells, suspicious configurations, and unauthorized file access points.
-   **Reporting:** Generates interactive HTML reports with summary dashboards and mobile-responsive design.
-   **Multi-System Analysis:** Facilitates analysis across multiple systems with consolidated reporting.
-   **Secure Distribution:** Encrypts reports with certificates or passwords for secure distribution.
-   **Scheduled Analysis:** Automates regular forensic scans with scheduled tasks.

## Requirements

-   Windows 7/Server 2012 R2 or later
-   PowerShell 5.1 or later
-   Administrator privileges on the target system
-   Approximately 50MB of free disk space for the toolkit
-   Additional space for storing analysis results (varies based on system)

## Installation

### Install from PowerShell Gallery (Recommended)

```powershell
Install-Module -Name ForensicAnalyzer -Scope CurrentUser

Manual Installation
 * Clone the repository or download the ZIP file.
 * Extract the contents to a directory of your choice.
 * Import the module:
Import-Module "C:\Path\To\ForensicAnalyzer\ForensicAnalyzer.psd1"

System-wide Installation
 * Navigate to the directory containing the module.
cd C:\Path\To\ForensicAnalyzer

 * Run the installer:
.\Install-ForensicAnalyzer.ps1

Usage
Basic Usage
Run a basic analysis of the local system:
Import-Module ForensicAnalyzer
Start-ForensicAnalysis

Run a quick scan:
Start-ForensicAnalysis -QuickScan

Advanced Usage
Customize the analysis with additional parameters:
Start-ForensicAnalysis -OutputDirectory "D:\ForensicData" -IncludeMemoryDump
Start-ForensicAnalysis -EventHours 72 -RecentExeDays 14
Start-ForensicAnalysis -GenerateHtmlReport
Start-ForensicAnalysis -SecureResults -CertificateThumbprint "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t"

Scheduled Analysis
Schedule regular forensic scans:
Register-ForensicAnalysisSchedule -ScheduleType Daily -Time "23:00" -QuickScan
Register-ForensicAnalysisSchedule -ScheduleType Weekly -DayOfWeek Saturday -Time "22:00" `
                                -CentralRepository "\\Server\Share\ForensicResults" `
                                -SecureReporting `
                                -ReportRecipients "security@company.com" `
                                -SMTPServer "smtp.company.com" `
                                -SMTPCredential (Get-Credential)

Multi-System Analysis
Analyze multiple systems on your network:
$computers = @("Workstation01", "Server01", "LaptopXYZ")
$computerData = @{}
foreach ($computer in $computers) {
    Write-Host "Analyzing $computer..."
    Invoke-Command -ComputerName $computer -ScriptBlock {
        Import-Module ForensicAnalyzer
        Start-ForensicAnalysis -OutputDirectory "C:\ForensicData"
    }
    $computerData[$computer] = "\\$computer\C$\ForensicData"
}
New-MultiComputerForensicReport -ComputerData $computerData -OutputPath "D:\Reports\MultiSystemReport.html"

Report Generation
Generate rich HTML reports:
$results = Start-ForensicAnalysis
New-ForensicHtmlReport -Results $results -OutputPath "C:\Reports\Forensic_Report.html"
Send-SecureForensicReport -ReportPath "C:\Reports\Forensic_Report.html" `
                        -Recipients "security@company.com" `
                        -SMTPServer "smtp.company.com" `
                        -Credential (Get-Credential) `
                        -UseTLS

Secure Distribution
Encrypt and distribute reports securely:
Protect-ForensicReport -ReportPath "C:\Reports\Forensic_Report.html" `
                     -OutputPath "C:\Secure\Encrypted_Report.zip" `
                     -CertificateThumbprint "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t"
$securePassword = Read-Host -AsSecureString -Prompt "Enter encryption password"
Protect-ForensicReport -ReportPath "C:\Reports\Forensic_Report.html" `
                     -OutputPath "C:\Secure\Encrypted_Report.zip" `
                     -Password $securePassword

Modules
Windows Forensic Analyzer is organized into functional modules:
Core Module
 * Start-ForensicAnalysis: Main function to initiate the analysis.
 * Initialize-Environment: Sets up the environment for analysis.
 * Write-ForensicLog: Logging function.
System Information Modules
 * Get-SystemInfo: Retrieves detailed system information.
 * Get-DriveInfo: Gathers drive health and space usage.
 * Get-UserInfo: Collects user account and permission details.
 * Get-HardwareInfo: Lists connected devices and hardware inventory.
Security Analysis Modules
 * Get-FirewallRules: Analyzes Windows Firewall rules.
 * Get-DefenderStatus: Assesses Windows Defender configuration.
 * Get-InstalledPatches: Lists installed security updates.
 * Get-CertificateStore: Analyzes certificate stores.
 * Get-AmsiBypass: Detects AMSI bypass attempts.
Persistence Mechanisms Modules
 * Get-ScheduledTasks: Analyzes scheduled tasks.
 * Get-StartupItems: Lists startup items.
 * Get-RegistryPersistence: Examines registry persistence techniques.
 * Get-WMIPersistence: Analyzes WMI event subscriptions.
 * Get-EnvironmentVariables: Checks environment variable manipulations.
 * Get-DllHijacking: Identifies DLL hijacking opportunities.
Network Analysis Modules
 * Get-NetworkConnections: Lists active network connections.
 * Get-UnusualPorts: Detects unusual network ports.
 * Get-DnsSettings: Analyzes DNS settings.
 * Get-SmbShares: Lists SMB shares.
 * Get-RemoteAccessServices: Detects remote access services.
Process Analysis Modules
 * Get-Processes: Lists running processes and loaded modules.
 * Get-RecentlyModifiedExecutables: Finds recently modified executables.
 * Get-ProcessNetworkMappings: Maps processes to network connections.
 * Get-DriverVerification: Verifies drivers and kernel modules.
 * Get-RootkitIndicators: Detects potential rootkit indicators.
Activity Analysis Modules
 * Get-PowerShellHistory: Analyzes PowerShell command history.
 * Get-BrowserExtensions: Lists browser extensions.
 * Get-RecentlyDeletedFiles: Finds recently deleted files.
 * Get-UsbHistory: Lists USB device history.
 * Get-ShadowCopies: Analyzes shadow copies.
Web Server Analysis Modules
 * Get-Webshells: Detects potential web shells.
 * Get-WebServerConfig: Analyzes web server configurations.
 * Get-WebAccessPoints: Lists web access points.
Reporting Modules
 * New-ForensicHtmlReport: Generates HTML reports.
 * New-MultiComputerForensicReport: Generates multi-system reports.
 * Send-SecureForensicReport: Sends reports securely via email.
Utility Modules
 * Protect-ForensicReport: Encrypts reports.
 * Unprotect-ForensicReport: Decrypts reports.
 * Register-ForensicAnalysisSchedule: Schedules forensic scans.
Output
The toolkit generates CSV files for each analysis module and consolidates the results into interactive HTML reports. The reports highlight critical findings and provide detailed information for further investigation.
Customization
The modular design allows for easy customization. You can modify existing modules or create new ones to suit your specific needs.
Contributing
Contributions are welcome! Please submit pull requests or open issues for bug reports and feature requests.
Security Considerations
 * Run the toolkit with administrator privileges.
 * Securely store and distribute forensic data.
 * Regularly review audit logs and reports.
 * Keep the toolkit updated to detect new threats.
 * Be aware of the potential for false positives.
 * Use secure communication channels when sending reports.
 * Encrypt sensitive data.

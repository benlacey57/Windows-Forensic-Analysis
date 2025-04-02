<#
.SYNOPSIS
    Generates HTML report for a single system forensic analysis
    
.DESCRIPTION
    Creates an interactive HTML report with Bootstrap styling, showing passed and failed checks
    with summary cards and responsive design for both desktop and mobile viewing.
    
.PARAMETER Results
    Hashtable containing the output file paths from Start-ForensicAnalysis
    
.PARAMETER OutputPath
    Path where the HTML report will be saved
        
.PARAMETER ComputerName
    Name of the computer being analyzed (defaults to local computer)
    
.PARAMETER TemplatePath
    Path to the templates directory (defaults to Templates subdirectory)
    
.EXAMPLE
    $results = Start-ForensicAnalysis
    New-ForensicHtmlReport -Results $results -OutputPath "C:\Reports\Forensic_Report.html"
    
.NOTES
    Author: ForensicAnalyzer Team
    Version: 1.0
    Requires the forensic data previously collected by Start-ForensicAnalysis
#>

function New-ForensicHtmlReport {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Results,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = "$script:outputDir\ForensicReport_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
        
        [Parameter(Mandatory=$false)]
        [string]$ComputerName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory=$false)]
        [string]$TemplatePath = (Join-Path -Path $PSScriptRoot -ChildPath "..\Templates")
    )
    
    Write-ForensicLog "Generating HTML report for $ComputerName using Bootstrap templates..."
    
    # Verify template path exists
    if (-not (Test-Path $TemplatePath)) {
        Write-ForensicLog "Template path not found: $TemplatePath" -Severity "Error"
        return $null
    }
    
    # Load template content
    $templateFile = Join-Path -Path $TemplatePath -ChildPath "single-device-template.html"
    if (-not (Test-Path $templateFile)) {
        Write-ForensicLog "Template file not found: $templateFile" -Severity "Error"
        return $null
    }
    
    $templateContent = Get-Content -Path $templateFile -Raw
    
    # Generate report ID
    $reportId = [System.Guid]::NewGuid().ToString()
    
    # Replace basic placeholders
    $templateContent = $templateContent.Replace("{{REPORT_TITLE}}", "Forensic Analysis Report - $ComputerName")
    $templateContent = $templateContent.Replace("{{COMPUTER_NAME}}", $ComputerName)
    $templateContent = $templateContent.Replace("{{ANALYSIS_DATE}}", (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
    $templateContent = $templateContent.Replace("{{GENERATION_DATE}}", (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
    $templateContent = $templateContent.Replace("{{GENERATED_BY}}", $env:USERNAME)
    $templateContent = $templateContent.Replace("{{REPORT_ID}}", $reportId)
    $templateContent = $templateContent.Replace("{{TEMPLATE_PATH}}", $TemplatePath)
    
    # Count issues and calculate health score
    $criticalIssuesCount = 0
    $warningIssuesCount = 0
    $passedChecksCount = 0
    $criticalIssuesList = ""
    $warningIssuesList = ""
    
    # Parse the main analysis report for findings
    $mainReport = $Results["Report"]
    $reportContent = Get-Content -Path $mainReport -Raw
    
    # Extract findings for issue counts
    if ($reportContent -match "POTENTIAL SIGNS OF COMPROMISE DETECTED:(.*?)(?:\r?\n){2}") {
        $suspiciousFindings = $Matches[1].Trim() -split "`n"
        
        foreach ($finding in $suspiciousFindings) {
            $finding = $finding.Trim()
            
            # Categorize severity based on keywords
            if ($finding -match "backdoor|rootkit|web shell|malware|trojan|unusual port|suspicious PowerShell|disabled") {
                $criticalIssuesCount++
                $criticalIssuesList += "<div class='issue-item issue-item-critical'><i class='fa-solid fa-triangle-exclamation me-2'></i>$finding</div>"
            }
            else {
                $warningIssuesCount++
                $warningIssuesList += "<div class='issue-item issue-item-warning'><i class='fa-solid fa-exclamation me-2'></i>$finding</div>"
            }
        }
    }
    
    # Calculate overall health score based on issues found
    $totalChecks = 20 # Approximated number of total checks
    $passedChecksCount = $totalChecks - ($criticalIssuesCount + $warningIssuesCount)
    $healthScore = [Math]::Max(0, [Math]::Min(100, [Math]::Round(100 * ($passedChecksCount / $totalChecks))))
    
    # Determine health status and classes
    $overallHealthClass = ""
    $overallHealthIcon = ""
    $overallHealthStatus = ""
    
    if ($criticalIssuesCount -gt 0) {
        $overallHealthClass = "bg-danger text-white"
        $overallHealthIcon = "fa-virus"
        $overallHealthStatus = "Critical issues detected"
    }
    elseif ($warningIssuesCount -gt 0) {
        $overallHealthClass = "bg-warning"
        $overallHealthIcon = "fa-exclamation-triangle"
        $overallHealthStatus = "Warnings detected"
    }
    else {
        $overallHealthClass = "bg-success text-white"
        $overallHealthIcon = "fa-shield-check"
        $overallHealthStatus = "System appears healthy"
    }
    
    # Set critical issues card class based on count
    $criticalIssuesClass = if ($criticalIssuesCount -gt 0) { "bg-danger text-white" } else { "bg-light" }
    
    # Set warning issues card class based on count
    $warningIssuesClass = if ($warningIssuesCount -gt 0) { "bg-warning" } else { "bg-light" }
    
    # Replace summary cards placeholders
    $templateContent = $templateContent.Replace("{{OVERALL_HEALTH_CLASS}}", $overallHealthClass)
    $templateContent = $templateContent.Replace("{{OVERALL_HEALTH_ICON}}", $overallHealthIcon)
    $templateContent = $templateContent.Replace("{{OVERALL_HEALTH_SCORE}}", $healthScore)
    $templateContent = $templateContent.Replace("{{OVERALL_HEALTH_STATUS}}", $overallHealthStatus)
    
    $templateContent = $templateContent.Replace("{{CRITICAL_ISSUES_CLASS}}", $criticalIssuesClass)
    $templateContent = $templateContent.Replace("{{CRITICAL_ISSUES_COUNT}}", $criticalIssuesCount)
    $templateContent = $templateContent.Replace("{{CRITICAL_ISSUES_LIST}}", $criticalIssuesList)
    
    $templateContent = $templateContent.Replace("{{WARNING_ISSUES_CLASS}}", $warningIssuesClass)
    $templateContent = $templateContent.Replace("{{WARNING_ISSUES_COUNT}}", $warningIssuesCount)
    $templateContent = $templateContent.Replace("{{WARNING_ISSUES_LIST}}", $warningIssuesList)
    
    $templateContent = $templateContent.Replace("{{PASSED_CHECKS_COUNT}}", $passedChecksCount)
    
    # Generate System Information content
    $systemInfoContent = GenerateSystemInfoContent -Results $Results
    $templateContent = $templateContent.Replace("{{SYSTEM_INFORMATION_CONTENT}}", $systemInfoContent)
    
    # Generate Security Configuration content
    $securityContent = GenerateSecurityContent -Results $Results
    $templateContent = $templateContent.Replace("{{SECURITY_CONFIGURATION_CONTENT}}", $securityContent)
    
    # Generate Network Analysis content
    $networkContent = GenerateNetworkContent -Results $Results
    $templateContent = $templateContent.Replace("{{NETWORK_ANALYSIS_CONTENT}}", $networkContent)
    
    # Generate Process Analysis content
    $processContent = GenerateProcessContent -Results $Results
    $templateContent = $templateContent.Replace("{{PROCESS_ANALYSIS_CONTENT}}", $processContent)
    
    # Generate Persistence Mechanisms content
    $persistenceContent = GeneratePersistenceContent -Results $Results
    $templateContent = $templateContent.Replace("{{PERSISTENCE_MECHANISMS_CONTENT}}", $persistenceContent)
    
    # Generate Evidence of Compromise content
    $compromiseContent = GenerateCompromiseContent -Results $Results
    $templateContent = $templateContent.Replace("{{EVIDENCE_OF_COMPROMISE_CONTENT}}", $compromiseContent)
    
    # Create the output directory if it doesn't exist
    $outputDir = Split-Path -Path $OutputPath -Parent
    if (-not (Test-Path $outputDir)) {
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
    }
    
    # Save the HTML report
    $templateContent | Out-File -FilePath $OutputPath -Encoding utf8
    
    Write-ForensicLog "HTML report generated successfully: $OutputPath"
    return $OutputPath
}

# Helper function to generate System Information section
function GenerateSystemInfoContent {
    param([hashtable]$Results)
    
    $content = "<div class='mt-4'>"
    
    # System Specifications
    if ($Results.ContainsKey("SystemSpecs")) {
        $systemSpecs = Get-Content -Path $Results["SystemSpecs"] -Raw | ConvertFrom-Json
        
        $content += @"
<div class="card mb-4">
    <div class="card-header">
        <h4 class="mb-0">System Specifications</h4>
    </div>
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-striped table-hover sortable">
                <thead>
                    <tr>
                        <th>Property</th>
                        <th>Value</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Operating System</td>
                        <td>$($systemSpecs.OperatingSystem.Caption) $($systemSpecs.OperatingSystem.Version)</td>
                    </tr>
                    <tr>
                        <td>Computer Manufacturer</td>
                        <td>$($systemSpecs.ComputerSystem.Manufacturer) $($systemSpecs.ComputerSystem.Model)</td>
                    </tr>
                    <tr>
                        <td>Processor</td>
                        <td>$($systemSpecs.Processor.Name)</td>
                    </tr>
                    <tr>
                        <td>Memory</td>
                        <td>$($systemSpecs.OperatingSystem.TotalMemoryGB) GB</td>
                    </tr>
                    <tr>
                        <td>BIOS Version</td>
                        <td>$($systemSpecs.BIOS.SMBIOSBIOSVersion)</td>
                    </tr>
                    <tr>
                        <td>Last Boot Time</td>
                        <td>$($systemSpecs.OperatingSystem.LastBootUpTime)</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>
"@
    }
    
    # Add more system information sections here...
    
    $content += "</div>"
    return $content
}

# Helper function to generate Security Configuration section
function GenerateSecurityContent {
    param([hashtable]$Results)
    
    $content = "<div class='mt-4'>"
    
    # Add security configuration sections here...
    
    $content += "</div>"
    return $content
}

# Helper function to generate Network Analysis section
function GenerateNetworkContent {
    param([hashtable]$Results)
    
    $content = "<div class='mt-4'>"
    
    # Add network analysis sections here...
    
    $content += "</div>"
    return $content
}

# Helper function to generate Process Analysis section
function GenerateProcessContent {
    param([hashtable]$Results)
    
    $content = "<div class='mt-4'>"
    
    # Add process analysis sections here...
    
    $content += "</div>"
    return $content
}

# Helper function to generate Persistence Mechanisms section
function GeneratePersistenceContent {
    param([hashtable]$Results)
    
    $content = "<div class='mt-4'>"
    
    # Add persistence mechanisms sections here...
    
    $content += "</div>"
    return $content
}

# Helper function to generate Evidence of Compromise section
function GenerateCompromiseContent {
    param([hashtable]$Results)
    
    $content = "<div class='mt-4'>"
    
    # Add evidence of compromise sections here...
    
    $content += "</div>"
    return $content
}

# Export function
Export-ModuleMember -Function New-ForensicHtmlReport
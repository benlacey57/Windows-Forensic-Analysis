@{
    RootModule = 'ForensicAnalyzer.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'a1b2c3d4-e5f6-7890-a1b2-c3d4e5f67890'
    Author = 'Forensic Analyzer Team'
    CompanyName = 'Your Company'
    Copyright = '(c) 2025. All rights reserved.'
    Description = 'A PowerShell module for windows forensic analysis and security investigations'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Start-ForensicAnalysis',
        'New-ForensicHtmlReport',
        'New-MultiComputerForensicReport',
        'Register-ForensicAnalysisSchedule',
        'Protect-ForensicReport',
        'Send-SecureForensicReport'
    )
    CmdletsToExport = @()
    VariablesToExport = '*'
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('Forensics', 'Security', 'Analysis')
            ProjectUri = 'https://github.com/benlacey57/ForensicAnalyzer'
            LicenseUri = 'https://github.com/benlacey57/ForensicAnalyzer/LICENSE'
        }
    }
}
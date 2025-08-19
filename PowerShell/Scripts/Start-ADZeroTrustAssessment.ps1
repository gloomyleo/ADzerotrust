# Start-ADZeroTrustAssessment.ps1
# ADZero Trust - Main Assessment Orchestration Script
# Author: Moazzam Jafri
# Description: Comprehensive Active Directory Zero Trust Assessment Tool

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\ADZeroTrust_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [string]$Domain = $env:USERDOMAIN,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Quick", "Standard", "Comprehensive")]
    [string]$AssessmentType = "Standard",
    
    [Parameter(Mandatory=$false)]
    [switch]$GenerateRoadmap = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportReports = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "",
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = ".\ADZeroTrust_Logs"
)

# Script information
$ScriptInfo = @{
    Name = "ADZero Trust Assessment Tool"
    Version = "1.0"
    Author = "Moazzam Jafri"
    Description = "Comprehensive Active Directory Zero Trust Assessment and Roadmap Generator"
    Copyright = "© 2025 Moazzam Jafri. Created for the cybersecurity community."
    License = "MIT License"
    GitHub = "https://github.com/moazzamjafri/ADZeroTrust"
}

# Display banner
function Show-Banner {
    $banner = @"

    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                              ADZero Trust                                     ║
    ║                   Active Directory Zero Trust Assessment Tool                 ║
    ║                                                                               ║
    ║                            Author: Moazzam Jafri                              ║
    ║                          25+ Years in Cybersecurity                          ║
    ║                        A Community Contribution                               ║
    ║                                                                               ║
    ║    "Empowering organizations to transition from traditional perimeter-based   ║
    ║     security to modern Zero Trust architectures through comprehensive         ║
    ║     assessment and actionable roadmaps."                                      ║
    ║                                                                               ║
    ║                              Version: $($ScriptInfo.Version)                                    ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Cyan
}

# Initialize logging
function Write-ADZTLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] [Main] $Message"
    Write-Host $logMessage -ForegroundColor $(
        switch ($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            default { "White" }
        }
    )
    if (!(Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
    Add-Content -Path "$LogPath\ADZeroTrust_Main.log" -Value $logMessage
}

# Load configuration
function Load-Configuration {
    param([string]$ConfigPath)
    
    if ($ConfigPath -and (Test-Path $ConfigPath)) {
        try {
            $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
            Write-ADZTLog "Configuration loaded from: $ConfigPath" "SUCCESS"
            return $config
        } catch {
            Write-ADZTLog "Failed to load configuration: $($_.Exception.Message)" "ERROR"
            return $null
        }
    }
    
    # Default configuration
    return @{
        AssessmentModules = @{
            ADInfoGatherer = @{ Enabled = $true; Detailed = ($AssessmentType -eq "Comprehensive") }
            IdentityAnalyzer = @{ Enabled = $true; StaleAccountThreshold = 90 }
            PermissionAssessor = @{ Enabled = $true; IncludeShares = $true; IncludeRegistry = ($AssessmentType -ne "Quick") }
            SecurityAuditor = @{ Enabled = $true; IncludeNetworkScan = ($AssessmentType -eq "Comprehensive"); IncludeServiceScan = $true }
        }
        RoadmapGeneration = @{
            Enabled = $GenerateRoadmap
            TimelineMonths = 12
            PriorityFocus = "Security"
        }
        Reporting = @{
            GenerateExecutiveSummary = $true
            GenerateTechnicalReport = $true
            GenerateComplianceReport = $true
            ExportFormats = @("JSON", "Markdown", "HTML")
        }
    }
}

# Check prerequisites
function Test-Prerequisites {
    Write-ADZTLog "Checking prerequisites..." "INFO"
    
    $prerequisites = @{
        PowerShellVersion = $PSVersionTable.PSVersion.Major -ge 5
        ActiveDirectoryModule = $null -ne (Get-Module -ListAvailable -Name ActiveDirectory)
        AdminRights = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        DomainConnectivity = $false
        OutputPathWritable = $false
    }
    
    # Test domain connectivity
    try {
        $domainInfo = Get-ADDomain -Identity $Domain -ErrorAction SilentlyContinue
        $prerequisites.DomainConnectivity = $domainInfo -ne $null
    } catch {
        Write-ADZTLog "Domain connectivity test failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Test output path
    try {
        if (!(Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
        $testFile = "$OutputPath\test_$(Get-Random).tmp"
        "test" | Out-File -FilePath $testFile -ErrorAction SilentlyContinue
        if (Test-Path $testFile) {
            Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
            $prerequisites.OutputPathWritable = $true
        }
    } catch {
        Write-ADZTLog "Output path test failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Report prerequisites
    Write-ADZTLog "Prerequisites Check Results:" "INFO"
    Write-ADZTLog "  PowerShell Version 5+: $(if ($prerequisites.PowerShellVersion) { "✓ PASS" } else { "✗ FAIL" })" "INFO"
    Write-ADZTLog "  Active Directory Module: $(if ($prerequisites.ActiveDirectoryModule) { "✓ PASS" } else { "✗ FAIL" })" "INFO"
    Write-ADZTLog "  Administrator Rights: $(if ($prerequisites.AdminRights) { "✓ PASS" } else { "✗ FAIL" })" "INFO"
    Write-ADZTLog "  Domain Connectivity: $(if ($prerequisites.DomainConnectivity) { "✓ PASS" } else { "✗ FAIL" })" "INFO"
    Write-ADZTLog "  Output Path Writable: $(if ($prerequisites.OutputPathWritable) { "✓ PASS" } else { "✗ FAIL" })" "INFO"
    
    $criticalFailed = !$prerequisites.PowerShellVersion -or !$prerequisites.OutputPathWritable
    $warningFailed = !$prerequisites.ActiveDirectoryModule -or !$prerequisites.DomainConnectivity -or !$prerequisites.AdminRights
    
    if ($criticalFailed) {
        Write-ADZTLog "Critical prerequisites failed. Assessment cannot continue." "ERROR"
        return $false
    }
    
    if ($warningFailed) {
        Write-ADZTLog "Some prerequisites failed. Assessment may have limited functionality." "WARNING"
    }
    
    return $true
}

# Execute assessment module
function Invoke-AssessmentModule {
    param(
        [string]$ModuleName,
        [string]$ModulePath,
        [hashtable]$ModuleConfig
    )
    
    Write-ADZTLog "Starting $ModuleName assessment..." "INFO"
    
    try {
        $moduleParams = @{
            OutputPath = $OutputPath
            Domain = $Domain
            LogPath = $LogPath
        }
        
        # Add module-specific parameters
        switch ($ModuleName) {
            "ADInfoGatherer" {
                if ($ModuleConfig.Detailed) { $moduleParams.Detailed = $true }
            }
            "IdentityAnalyzer" {
                $moduleParams.StaleAccountThreshold = $ModuleConfig.StaleAccountThreshold
            }
            "PermissionAssessor" {
                $moduleParams.IncludeShares = $ModuleConfig.IncludeShares
                $moduleParams.IncludeRegistry = $ModuleConfig.IncludeRegistry
            }
            "SecurityAuditor" {
                $moduleParams.IncludeNetworkScan = $ModuleConfig.IncludeNetworkScan
                $moduleParams.IncludeServiceScan = $ModuleConfig.IncludeServiceScan
            }
        }
        
        # Execute the module
        $result = & $ModulePath @moduleParams
        
        Write-ADZTLog "$ModuleName assessment completed successfully" "SUCCESS"
        return $result
    } catch {
        Write-ADZTLog "$ModuleName assessment failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# Generate consolidated assessment report
function New-ConsolidatedReport {
    param(
        [hashtable]$AssessmentResults,
        [hashtable]$Configuration
    )
    
    Write-ADZTLog "Generating consolidated assessment report..." "INFO"
    
    $consolidatedResults = @{
        AssessmentInfo = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Domain = $Domain
            AssessmentType = $AssessmentType
            Version = $ScriptInfo.Version
            Author = $ScriptInfo.Author
            ToolName = $ScriptInfo.Name
        }
        ExecutiveSummary = @{}
        DetailedFindings = @{}
        RiskAssessment = @{}
        ComplianceStatus = @{}
        ZeroTrustMaturity = @{}
        Recommendations = @()
        ImplementationRoadmap = @{}
    }
    
    # Aggregate data from all modules
    $totalIdentities = 0
    $totalHighRiskItems = 0
    $totalRecommendations = 0
    $overallRiskScore = 0
    $moduleCount = 0
    
    foreach ($moduleName in $AssessmentResults.Keys) {
        $moduleResult = $AssessmentResults[$moduleName]
        if ($moduleResult) {
            $moduleCount++
            
            # Aggregate statistics
            switch ($moduleName) {
                "ADInfoGatherer" {
                    if ($moduleResult.Summary) {
                        $totalIdentities += $moduleResult.Summary.TotalUsers
                        $consolidatedResults.DetailedFindings.DomainInfo = $moduleResult.DomainInfo
                        $consolidatedResults.DetailedFindings.ForestInfo = $moduleResult.ForestInfo
                    }
                }
                "IdentityAnalyzer" {
                    if ($moduleResult.IdentityRiskMatrix) {
                        $totalHighRiskItems += $moduleResult.IdentityRiskMatrix.HighRiskCount
                        $consolidatedResults.DetailedFindings.IdentityRisks = $moduleResult.IdentityRiskMatrix
                    }
                }
                "PermissionAssessor" {
                    if ($moduleResult.PermissionRiskMatrix) {
                        $totalHighRiskItems += $moduleResult.PermissionRiskMatrix.HighRiskCount
                        $consolidatedResults.DetailedFindings.PermissionRisks = $moduleResult.PermissionRiskMatrix
                    }
                }
                "SecurityAuditor" {
                    if ($moduleResult.SecurityBaseline) {
                        $consolidatedResults.DetailedFindings.SecurityBaseline = $moduleResult.SecurityBaseline
                    }
                }
            }
            
            # Aggregate recommendations
            if ($moduleResult.Recommendations) {
                $consolidatedResults.Recommendations += $moduleResult.Recommendations
                $totalRecommendations += $moduleResult.Recommendations.Count
            }
            
            # Aggregate Zero Trust readiness scores
            if ($moduleResult.ZeroTrustReadiness -and $moduleResult.ZeroTrustReadiness.OverallReadiness) {
                $overallRiskScore += $moduleResult.ZeroTrustReadiness.OverallReadiness.Score
            }
        }
    }
    
    # Calculate overall metrics
    $consolidatedResults.ExecutiveSummary = @{
        TotalIdentitiesAnalyzed = $totalIdentities
        HighRiskItemsIdentified = $totalHighRiskItems
        TotalRecommendations = $totalRecommendations
        CriticalRecommendations = ($consolidatedResults.Recommendations | Where-Object { $_.Priority -eq "Critical" }).Count
        HighPriorityRecommendations = ($consolidatedResults.Recommendations | Where-Object { $_.Priority -eq "High" }).Count
        OverallZeroTrustScore = if ($moduleCount -gt 0) { [math]::Round($overallRiskScore / $moduleCount, 2) } else { 0 }
        AssessmentCompleteness = [math]::Round(($AssessmentResults.Keys.Count / 4) * 100, 2)  # 4 total modules
    }
    
    # Determine overall maturity level
    $overallScore = $consolidatedResults.ExecutiveSummary.OverallZeroTrustScore
    $consolidatedResults.ExecutiveSummary.ZeroTrustMaturityLevel = if ($overallScore -ge 80) { 
        "Advanced" 
    } elseif ($overallScore -ge 60) { 
        "Intermediate" 
    } elseif ($overallScore -ge 40) { 
        "Initial" 
    } else { 
        "Traditional" 
    }
    
    # Risk assessment
    $consolidatedResults.RiskAssessment = @{
        OverallRiskLevel = if ($totalHighRiskItems -ge 20) { "High" } elseif ($totalHighRiskItems -ge 10) { "Medium" } else { "Low" }
        CriticalRiskFactors = @()
        RiskTrends = @{
            IdentityRisk = if ($AssessmentResults.IdentityAnalyzer -and $AssessmentResults.IdentityAnalyzer.IdentityRiskMatrix) { 
                $AssessmentResults.IdentityAnalyzer.IdentityRiskMatrix.HighRiskCount 
            } else { 0 }
            PermissionRisk = if ($AssessmentResults.PermissionAssessor -and $AssessmentResults.PermissionAssessor.PermissionRiskMatrix) { 
                $AssessmentResults.PermissionAssessor.PermissionRiskMatrix.HighRiskCount 
            } else { 0 }
            ConfigurationRisk = 0  # Would be calculated from security audit results
        }
    }
    
    # Compliance status
    $consolidatedResults.ComplianceStatus = @{
        NIST = @{ Score = 0; Status = "Needs Assessment" }
        CIS = @{ Score = 0; Status = "Needs Assessment" }
        ISO27001 = @{ Score = 0; Status = "Needs Assessment" }
    }
    
    if ($AssessmentResults.SecurityAuditor -and $AssessmentResults.SecurityAuditor.ComplianceChecks) {
        $compliance = $AssessmentResults.SecurityAuditor.ComplianceChecks
        $consolidatedResults.ComplianceStatus.NIST = @{
            Score = $compliance.NIST.OverallScore
            Status = if ($compliance.NIST.OverallScore -ge 80) { "Compliant" } elseif ($compliance.NIST.OverallScore -ge 60) { "Partially Compliant" } else { "Non-Compliant" }
        }
        $consolidatedResults.ComplianceStatus.CIS = @{
            Score = $compliance.CIS.OverallScore
            Status = if ($compliance.CIS.OverallScore -ge 80) { "Compliant" } elseif ($compliance.CIS.OverallScore -ge 60) { "Partially Compliant" } else { "Non-Compliant" }
        }
    }
    
    return $consolidatedResults
}

# Generate Zero Trust implementation roadmap
function New-ZeroTrustRoadmap {
    param(
        [hashtable]$ConsolidatedResults,
        [hashtable]$Configuration
    )
    
    Write-ADZTLog "Generating Zero Trust implementation roadmap..." "INFO"
    
    $roadmap = @{
        RoadmapInfo = @{
            GeneratedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            TimelineMonths = $Configuration.RoadmapGeneration.TimelineMonths
            CurrentMaturityLevel = $ConsolidatedResults.ExecutiveSummary.ZeroTrustMaturityLevel
            TargetMaturityLevel = "Advanced"
            PriorityFocus = $Configuration.RoadmapGeneration.PriorityFocus
        }
        Phases = @()
        Milestones = @()
        ResourceRequirements = @{}
        SuccessMetrics = @()
    }
    
    # Define roadmap phases based on current maturity and findings
    $phases = @()
    
    # Phase 1: Foundation (0-3 months)
    $phase1Tasks = @()
    $criticalRecommendations = $ConsolidatedResults.Recommendations | Where-Object { $_.Priority -eq "Critical" }
    foreach ($rec in $criticalRecommendations) {
        $phase1Tasks += @{
            Task = $rec.Recommendation
            Category = $rec.Category
            ZeroTrustPrinciple = $rec.ZeroTrustPrinciple
            EstimatedEffort = "High"
            Dependencies = @()
        }
    }
    
    $phases += @{
        PhaseNumber = 1
        PhaseName = "Foundation Security"
        Duration = "0-3 months"
        Objective = "Address critical security gaps and establish baseline security controls"
        Tasks = $phase1Tasks
        Deliverables = @(
            "Critical security vulnerabilities remediated",
            "Basic access controls implemented",
            "Security monitoring baseline established",
            "Incident response procedures updated"
        )
        SuccessCriteria = @(
            "All critical recommendations addressed",
            "Zero high-risk security findings",
            "Basic monitoring and alerting operational"
        )
    }
    
    # Phase 2: Identity and Access Management (3-6 months)
    $phase2Tasks = @(
        @{
            Task = "Implement multi-factor authentication for all privileged accounts"
            Category = "Identity Security"
            ZeroTrustPrinciple = "Verify Explicitly"
            EstimatedEffort = "Medium"
            Dependencies = @("Phase 1 completion")
        },
        @{
            Task = "Deploy privileged access management (PAM) solution"
            Category = "Access Control"
            ZeroTrustPrinciple = "Use Least Privilege Access"
            EstimatedEffort = "High"
            Dependencies = @("MFA implementation")
        },
        @{
            Task = "Implement identity governance and administration (IGA)"
            Category = "Identity Lifecycle"
            ZeroTrustPrinciple = "Verify Explicitly"
            EstimatedEffort = "High"
            Dependencies = @("PAM deployment")
        }
    )
    
    $phases += @{
        PhaseNumber = 2
        PhaseName = "Identity and Access Management"
        Duration = "3-6 months"
        Objective = "Establish comprehensive identity verification and least privilege access controls"
        Tasks = $phase2Tasks
        Deliverables = @(
            "MFA enabled for all privileged accounts",
            "PAM solution operational",
            "Identity lifecycle management processes",
            "Regular access reviews implemented"
        )
        SuccessCriteria = @(
            "100% MFA compliance for privileged accounts",
            "Privileged access sessions monitored and recorded",
            "Automated identity provisioning and deprovisioning"
        )
    }
    
    # Phase 3: Data Protection and Network Security (6-9 months)
    $phase3Tasks = @(
        @{
            Task = "Implement data classification and labeling"
            Category = "Data Protection"
            ZeroTrustPrinciple = "Assume Breach"
            EstimatedEffort = "Medium"
            Dependencies = @("Phase 2 completion")
        },
        @{
            Task = "Deploy data loss prevention (DLP) solution"
            Category = "Data Protection"
            ZeroTrustPrinciple = "Assume Breach"
            EstimatedEffort = "High"
            Dependencies = @("Data classification")
        },
        @{
            Task = "Implement network micro-segmentation"
            Category = "Network Security"
            ZeroTrustPrinciple = "Assume Breach"
            EstimatedEffort = "High"
            Dependencies = @("Network assessment")
        }
    )
    
    $phases += @{
        PhaseNumber = 3
        PhaseName = "Data Protection and Network Security"
        Duration = "6-9 months"
        Objective = "Implement comprehensive data protection and network segmentation"
        Tasks = $phase3Tasks
        Deliverables = @(
            "Data classification policies and procedures",
            "DLP solution protecting sensitive data",
            "Network micro-segmentation implemented",
            "Encryption at rest and in transit"
        )
        SuccessCriteria = @(
            "All sensitive data classified and protected",
            "Zero data loss incidents",
            "Network traffic properly segmented and monitored"
        )
    }
    
    # Phase 4: Advanced Monitoring and Analytics (9-12 months)
    $phase4Tasks = @(
        @{
            Task = "Deploy advanced threat detection and response"
            Category = "Security Monitoring"
            ZeroTrustPrinciple = "Assume Breach"
            EstimatedEffort = "High"
            Dependencies = @("Phase 3 completion")
        },
        @{
            Task = "Implement user and entity behavior analytics (UEBA)"
            Category = "Behavioral Analytics"
            ZeroTrustPrinciple = "Verify Explicitly"
            EstimatedEffort = "Medium"
            Dependencies = @("SIEM deployment")
        },
        @{
            Task = "Establish continuous compliance monitoring"
            Category = "Compliance"
            ZeroTrustPrinciple = "Verify Explicitly"
            EstimatedEffort = "Medium"
            Dependencies = @("Monitoring infrastructure")
        }
    )
    
    $phases += @{
        PhaseNumber = 4
        PhaseName = "Advanced Monitoring and Analytics"
        Duration = "9-12 months"
        Objective = "Implement advanced security monitoring and continuous improvement"
        Tasks = $phase4Tasks
        Deliverables = @(
            "Advanced threat detection operational",
            "UEBA solution analyzing user behavior",
            "Continuous compliance monitoring",
            "Automated incident response workflows"
        )
        SuccessCriteria = @(
            "Mean time to detection (MTTD) < 1 hour",
            "Mean time to response (MTTR) < 4 hours",
            "Continuous compliance score > 95%"
        )
    }
    
    $roadmap.Phases = $phases
    
    # Define milestones
    $roadmap.Milestones = @(
        @{
            Milestone = "Critical Security Baseline Achieved"
            TargetDate = (Get-Date).AddMonths(3).ToString("yyyy-MM-dd")
            Description = "All critical security vulnerabilities addressed"
            SuccessCriteria = @("Zero critical findings", "Basic monitoring operational")
        },
        @{
            Milestone = "Identity Security Maturity Achieved"
            TargetDate = (Get-Date).AddMonths(6).ToString("yyyy-MM-dd")
            Description = "Comprehensive identity and access management implemented"
            SuccessCriteria = @("100% MFA compliance", "PAM operational", "IGA processes established")
        },
        @{
            Milestone = "Data Protection Maturity Achieved"
            TargetDate = (Get-Date).AddMonths(9).ToString("yyyy-MM-dd")
            Description = "Comprehensive data protection and network security implemented"
            SuccessCriteria = @("Data classification complete", "DLP operational", "Network segmentation implemented")
        },
        @{
            Milestone = "Zero Trust Advanced Maturity Achieved"
            TargetDate = (Get-Date).AddMonths(12).ToString("yyyy-MM-dd")
            Description = "Advanced Zero Trust architecture fully operational"
            SuccessCriteria = @("UEBA operational", "Continuous monitoring", "Automated response")
        }
    )
    
    # Resource requirements
    $roadmap.ResourceRequirements = @{
        Personnel = @{
            SecurityArchitect = "1 FTE for 12 months"
            SecurityEngineer = "2 FTE for 12 months"
            IdentitySpecialist = "1 FTE for 6 months"
            NetworkSpecialist = "1 FTE for 6 months"
            ComplianceSpecialist = "0.5 FTE for 12 months"
        }
        Technology = @{
            PAMSolution = "Enterprise PAM platform license and implementation"
            SIEMSolution = "SIEM platform upgrade or new deployment"
            DLPSolution = "Data loss prevention platform"
            UEBASolution = "User and entity behavior analytics platform"
            NetworkSecurity = "Network segmentation and monitoring tools"
        }
        Budget = @{
            Phase1 = "$50,000 - $100,000"
            Phase2 = "$200,000 - $400,000"
            Phase3 = "$300,000 - $500,000"
            Phase4 = "$150,000 - $300,000"
            Total = "$700,000 - $1,300,000"
        }
    }
    
    # Success metrics
    $roadmap.SuccessMetrics = @(
        @{
            Metric = "Zero Trust Maturity Score"
            Baseline = $ConsolidatedResults.ExecutiveSummary.OverallZeroTrustScore
            Target = 90
            Measurement = "Quarterly assessment using ADZero Trust tool"
        },
        @{
            Metric = "Critical Security Findings"
            Baseline = $ConsolidatedResults.ExecutiveSummary.HighRiskItemsIdentified
            Target = 0
            Measurement = "Monthly security assessment"
        },
        @{
            Metric = "MFA Compliance Rate"
            Baseline = "TBD"
            Target = 100
            Measurement = "Monthly identity audit"
        },
        @{
            Metric = "Mean Time to Detection (MTTD)"
            Baseline = "TBD"
            Target = "< 1 hour"
            Measurement = "Security incident analysis"
        },
        @{
            Metric = "Mean Time to Response (MTTR)"
            Baseline = "TBD"
            Target = "< 4 hours"
            Measurement = "Security incident analysis"
        }
    )
    
    return $roadmap
}

# Export reports in various formats
function Export-AssessmentReports {
    param(
        [hashtable]$ConsolidatedResults,
        [hashtable]$Roadmap,
        [hashtable]$Configuration
    )
    
    Write-ADZTLog "Exporting assessment reports..." "INFO"
    
    $exportedFiles = @()
    
    # Export JSON results
    try {
        $jsonOutput = @{
            ConsolidatedResults = $ConsolidatedResults
            ImplementationRoadmap = $Roadmap
            ExportInfo = @{
                ExportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                ToolVersion = $ScriptInfo.Version
                Author = $ScriptInfo.Author
            }
        } | ConvertTo-Json -Depth 10
        
        $jsonFile = "$OutputPath\ADZeroTrust_Complete_Assessment.json"
        $jsonOutput | Out-File -FilePath $jsonFile -Encoding UTF8
        $exportedFiles += $jsonFile
        Write-ADZTLog "JSON report exported: $jsonFile" "SUCCESS"
    } catch {
        Write-ADZTLog "Failed to export JSON report: $($_.Exception.Message)" "ERROR"
    }
    
    # Export Executive Summary
    try {
        $executiveSummary = @"
# ADZero Trust Assessment - Executive Summary

**Assessment Date:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")  
**Domain:** $Domain  
**Assessment Type:** $AssessmentType  
**Generated by:** $($ScriptInfo.Name) v$($ScriptInfo.Version)  
**Author:** $($ScriptInfo.Author)

## Executive Overview

This executive summary presents the key findings from a comprehensive Zero Trust assessment of the Active Directory environment. The assessment evaluated current security posture against Zero Trust principles and industry best practices.

### Key Metrics

| Metric | Value |
|--------|-------|
| **Overall Zero Trust Maturity** | $($ConsolidatedResults.ExecutiveSummary.ZeroTrustMaturityLevel) ($($ConsolidatedResults.ExecutiveSummary.OverallZeroTrustScore)%) |
| **Total Identities Analyzed** | $($ConsolidatedResults.ExecutiveSummary.TotalIdentitiesAnalyzed) |
| **High-Risk Items Identified** | $($ConsolidatedResults.ExecutiveSummary.HighRiskItemsIdentified) |
| **Critical Recommendations** | $($ConsolidatedResults.ExecutiveSummary.CriticalRecommendations) |
| **High Priority Recommendations** | $($ConsolidatedResults.ExecutiveSummary.HighPriorityRecommendations) |
| **Assessment Completeness** | $($ConsolidatedResults.ExecutiveSummary.AssessmentCompleteness)% |

### Risk Assessment

**Overall Risk Level:** $($ConsolidatedResults.RiskAssessment.OverallRiskLevel)

The assessment identified $($ConsolidatedResults.ExecutiveSummary.HighRiskItemsIdentified) high-risk items that require immediate attention. These findings span across identity management, permission configurations, and security controls.

### Compliance Status

| Framework | Score | Status |
|-----------|-------|--------|
| **NIST Cybersecurity Framework** | $($ConsolidatedResults.ComplianceStatus.NIST.Score)% | $($ConsolidatedResults.ComplianceStatus.NIST.Status) |
| **CIS Controls** | $($ConsolidatedResults.ComplianceStatus.CIS.Score)% | $($ConsolidatedResults.ComplianceStatus.CIS.Status) |
| **ISO 27001** | $($ConsolidatedResults.ComplianceStatus.ISO27001.Score)% | $($ConsolidatedResults.ComplianceStatus.ISO27001.Status) |

### Critical Recommendations

The following critical recommendations require immediate executive attention and resource allocation:

$($ConsolidatedResults.Recommendations | Where-Object { $_.Priority -eq "Critical" } | ForEach-Object { "**$($_.Category):** $($_.Recommendation)" } | Out-String)

### Implementation Roadmap

A comprehensive 12-month implementation roadmap has been developed with the following phases:

1. **Foundation Security (0-3 months)** - Address critical security gaps
2. **Identity and Access Management (3-6 months)** - Implement comprehensive IAM controls
3. **Data Protection and Network Security (6-9 months)** - Deploy data protection and segmentation
4. **Advanced Monitoring and Analytics (9-12 months)** - Implement advanced security monitoring

### Investment Requirements

**Estimated Total Investment:** $($Roadmap.ResourceRequirements.Budget.Total)

This investment will significantly improve the organization's security posture and align with modern Zero Trust principles, reducing cyber risk and ensuring regulatory compliance.

### Next Steps

1. **Immediate (Next 30 days)**
   - Review and approve critical recommendations
   - Allocate resources for Phase 1 implementation
   - Establish project governance and oversight

2. **Short-term (Next 90 days)**
   - Begin Phase 1 implementation
   - Procure necessary technology solutions
   - Engage implementation partners if needed

3. **Long-term (Next 12 months)**
   - Execute full roadmap implementation
   - Monitor progress against success metrics
   - Conduct quarterly assessments for continuous improvement

---
*This assessment was conducted using ADZero Trust, a community contribution by Moazzam Jafri, leveraging 25+ years of cybersecurity expertise.*
"@

        $execSummaryFile = "$OutputPath\ADZeroTrust_Executive_Summary.md"
        $executiveSummary | Out-File -FilePath $execSummaryFile -Encoding UTF8
        $exportedFiles += $execSummaryFile
        Write-ADZTLog "Executive summary exported: $execSummaryFile" "SUCCESS"
    } catch {
        Write-ADZTLog "Failed to export executive summary: $($_.Exception.Message)" "ERROR"
    }
    
    # Export Implementation Roadmap
    try {
        $roadmapReport = @"
# ADZero Trust Implementation Roadmap

**Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")  
**Current Maturity Level:** $($Roadmap.RoadmapInfo.CurrentMaturityLevel)  
**Target Maturity Level:** $($Roadmap.RoadmapInfo.TargetMaturityLevel)  
**Timeline:** $($Roadmap.RoadmapInfo.TimelineMonths) months

## Implementation Phases

$($Roadmap.Phases | ForEach-Object {
    $phase = $_
    @"
### Phase $($phase.PhaseNumber): $($phase.PhaseName)
**Duration:** $($phase.Duration)  
**Objective:** $($phase.Objective)

**Key Tasks:**
$($phase.Tasks | ForEach-Object { "- $($_.Task) ($($_.Category))" } | Out-String)

**Deliverables:**
$($phase.Deliverables | ForEach-Object { "- $_" } | Out-String)

**Success Criteria:**
$($phase.SuccessCriteria | ForEach-Object { "- $_" } | Out-String)

"@
} | Out-String)

## Milestones

$($Roadmap.Milestones | ForEach-Object {
    @"
### $($_.Milestone)
**Target Date:** $($_.TargetDate)  
**Description:** $($_.Description)

**Success Criteria:**
$($_.SuccessCriteria | ForEach-Object { "- $_" } | Out-String)
"@
} | Out-String)

## Resource Requirements

### Personnel
$($Roadmap.ResourceRequirements.Personnel.Keys | ForEach-Object { "- **$($_):** $($Roadmap.ResourceRequirements.Personnel[$_])" } | Out-String)

### Technology
$($Roadmap.ResourceRequirements.Technology.Keys | ForEach-Object { "- **$($_):** $($Roadmap.ResourceRequirements.Technology[$_])" } | Out-String)

### Budget Estimates
$($Roadmap.ResourceRequirements.Budget.Keys | ForEach-Object { "- **$($_):** $($Roadmap.ResourceRequirements.Budget[$_])" } | Out-String)

## Success Metrics

$($Roadmap.SuccessMetrics | ForEach-Object {
    @"
### $($_.Metric)
- **Baseline:** $($_.Baseline)
- **Target:** $($_.Target)
- **Measurement:** $($_.Measurement)

"@
} | Out-String)

---
*Roadmap generated by ADZero Trust - A community contribution by Moazzam Jafri*
"@

        $roadmapFile = "$OutputPath\ADZeroTrust_Implementation_Roadmap.md"
        $roadmapReport | Out-File -FilePath $roadmapFile -Encoding UTF8
        $exportedFiles += $roadmapFile
        Write-ADZTLog "Implementation roadmap exported: $roadmapFile" "SUCCESS"
    } catch {
        Write-ADZTLog "Failed to export implementation roadmap: $($_.Exception.Message)" "ERROR"
    }
    
    return $exportedFiles
}

# Main execution function
function Start-Assessment {
    try {
        # Show banner
        Show-Banner
        
        Write-ADZTLog "Starting ADZero Trust Assessment" "INFO"
        Write-ADZTLog "Assessment Type: $AssessmentType" "INFO"
        Write-ADZTLog "Target Domain: $Domain" "INFO"
        Write-ADZTLog "Output Path: $OutputPath" "INFO"
        
        # Load configuration
        $config = Load-Configuration -ConfigPath $ConfigFile
        if (!$config) {
            Write-ADZTLog "Using default configuration" "WARNING"
        }
        
        # Check prerequisites
        if (!(Test-Prerequisites)) {
            Write-ADZTLog "Prerequisites check failed. Exiting." "ERROR"
            return
        }
        
        # Initialize results collection
        $assessmentResults = @{}
        
        # Get module paths
        $moduleBasePath = Split-Path -Parent $PSScriptRoot
        $modulePaths = @{
            "ADInfoGatherer" = "$moduleBasePath\Modules\AD-InfoGatherer.ps1"
            "IdentityAnalyzer" = "$moduleBasePath\Modules\Identity-Analyzer.ps1"
            "PermissionAssessor" = "$moduleBasePath\Modules\Permission-Assessor.ps1"
            "SecurityAuditor" = "$moduleBasePath\Modules\Security-Auditor.ps1"
        }
        
        # Execute assessment modules
        foreach ($moduleName in $config.AssessmentModules.Keys) {
            $moduleConfig = $config.AssessmentModules[$moduleName]
            
            if ($moduleConfig.Enabled -and $modulePaths.ContainsKey($moduleName)) {
                $modulePath = $modulePaths[$moduleName]
                
                if (Test-Path $modulePath) {
                    $result = Invoke-AssessmentModule -ModuleName $moduleName -ModulePath $modulePath -ModuleConfig $moduleConfig
                    if ($result) {
                        $assessmentResults[$moduleName] = $result
                    }
                } else {
                    Write-ADZTLog "Module not found: $modulePath" "ERROR"
                }
            } else {
                Write-ADZTLog "Module $moduleName is disabled or not configured" "INFO"
            }
        }
        
        # Generate consolidated report
        $consolidatedResults = New-ConsolidatedReport -AssessmentResults $assessmentResults -Configuration $config
        
        # Generate roadmap if requested
        $roadmap = $null
        if ($config.RoadmapGeneration.Enabled) {
            $roadmap = New-ZeroTrustRoadmap -ConsolidatedResults $consolidatedResults -Configuration $config
        }
        
        # Export reports
        $exportedFiles = @()
        if ($ExportReports) {
            $exportedFiles = Export-AssessmentReports -ConsolidatedResults $consolidatedResults -Roadmap $roadmap -Configuration $config
        }
        
        # Display completion summary
        Write-ADZTLog "" "INFO"
        Write-ADZTLog "========================================" "SUCCESS"
        Write-ADZTLog "ADZero Trust Assessment Completed!" "SUCCESS"
        Write-ADZTLog "========================================" "SUCCESS"
        Write-ADZTLog "" "INFO"
        Write-ADZTLog "Assessment Summary:" "INFO"
        Write-ADZTLog "  Modules Executed: $($assessmentResults.Keys.Count)" "INFO"
        Write-ADZTLog "  Zero Trust Maturity: $($consolidatedResults.ExecutiveSummary.ZeroTrustMaturityLevel) ($($consolidatedResults.ExecutiveSummary.OverallZeroTrustScore)%)" "INFO"
        Write-ADZTLog "  High-Risk Items: $($consolidatedResults.ExecutiveSummary.HighRiskItemsIdentified)" "INFO"
        Write-ADZTLog "  Total Recommendations: $($consolidatedResults.ExecutiveSummary.TotalRecommendations)" "INFO"
        Write-ADZTLog "" "INFO"
        Write-ADZTLog "Exported Files:" "INFO"
        foreach ($file in $exportedFiles) {
            Write-ADZTLog "  - $file" "SUCCESS"
        }
        Write-ADZTLog "" "INFO"
        Write-ADZTLog "Thank you for using ADZero Trust!" "SUCCESS"
        Write-ADZTLog "A community contribution by Moazzam Jafri" "SUCCESS"
        Write-ADZTLog "25+ years of cybersecurity expertise for the community" "SUCCESS"
        
    } catch {
        Write-ADZTLog "Assessment failed with error: $($_.Exception.Message)" "ERROR"
        Write-ADZTLog "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    }
}

# Execute the assessment
Start-Assessment


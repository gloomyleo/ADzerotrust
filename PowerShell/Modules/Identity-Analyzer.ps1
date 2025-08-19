# Identity-Analyzer.ps1
# ADZero Trust - Identity Analysis Module
# Author: Moazzam Jafri
# Description: Comprehensive identity analysis for human and non-human accounts in Zero Trust assessment

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\ADZeroTrust_Output",
    
    [Parameter(Mandatory=$false)]
    [string]$Domain = $env:USERDOMAIN,
    
    [Parameter(Mandatory=$false)]
    [int]$StaleAccountThreshold = 90,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = ".\ADZeroTrust_Logs"
)

# Import required modules
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# Initialize logging
function Write-ADZTLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] [Identity-Analyzer] $Message"
    Write-Host $logMessage
    if (!(Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
    Add-Content -Path "$LogPath\IdentityAnalyzer.log" -Value $logMessage
}

# Create output directory
if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-ADZTLog "Starting Identity Analysis for Zero Trust Assessment" "INFO"

# Initialize identity analysis results
$IdentityAnalysisResults = @{
    AnalysisInfo = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Domain = $Domain
        StaleAccountThreshold = $StaleAccountThreshold
        Version = "1.0"
        Author = "Moazzam Jafri - ADZero Trust"
    }
    HumanIdentities = @()
    NonHumanIdentities = @()
    PrivilegedAccounts = @()
    ServiceAccounts = @()
    SharedAccounts = @()
    OrphanedAccounts = @()
    IdentityRiskMatrix = @()
    GroupAnalysis = @()
    PermissionAnalysis = @()
    IdentityGovernance = @{}
    ZeroTrustReadiness = @{}
    Recommendations = @()
}

try {
    # Get all users with detailed properties
    Write-ADZTLog "Collecting all user accounts..." "INFO"
    $allUsers = Get-ADUser -Filter * -Properties *
    
    # Get all groups
    Write-ADZTLog "Collecting all groups..." "INFO"
    $allGroups = Get-ADGroup -Filter * -Properties *
    
    # Define privileged groups (can be customized)
    $privilegedGroups = @(
        "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
        "Account Operators", "Backup Operators", "Server Operators", "Print Operators",
        "DNS Admins", "Group Policy Creator Owners", "Cert Publishers"
    )
    
    # Define service account patterns
    $serviceAccountPatterns = @("svc", "service", "sql", "iis", "app", "web", "db", "backup", "monitor")
    
    # Define shared account patterns
    $sharedAccountPatterns = @("shared", "common", "generic", "temp", "test", "admin")

    # Analyze Human Identities
    Write-ADZTLog "Analyzing human identities..." "INFO"
    foreach ($user in $allUsers) {
        # Determine if this is likely a human account
        $isHumanAccount = $true
        
        # Check for service account indicators
        foreach ($pattern in $serviceAccountPatterns) {
            if ($user.Name -match $pattern -or $user.SamAccountName -match $pattern) {
                $isHumanAccount = $false
                break
            }
        }
        
        # Check for shared account indicators
        foreach ($pattern in $sharedAccountPatterns) {
            if ($user.Name -match $pattern -or $user.SamAccountName -match $pattern) {
                $isHumanAccount = $false
                break
            }
        }
        
        # Check if account has service principal names (likely service account)
        if ($user.ServicePrincipalNames.Count -gt 0) {
            $isHumanAccount = $false
        }
        
        # Get user's group memberships
        $userGroups = Get-ADPrincipalGroupMembership -Identity $user.SamAccountName -ErrorAction SilentlyContinue
        $groupNames = @($userGroups | ForEach-Object { $_.Name })
        
        # Check for privileged access
        $isPrivileged = $false
        $privilegedGroupMemberships = @()
        foreach ($privGroup in $privilegedGroups) {
            if ($groupNames -contains $privGroup) {
                $isPrivileged = $true
                $privilegedGroupMemberships += $privGroup
            }
        }
        
        # Calculate account age
        $accountAge = if ($user.whenCreated) { 
            (Get-Date) - $user.whenCreated 
        } else { 
            $null 
        }
        
        # Calculate days since last logon
        $daysSinceLastLogon = if ($user.LastLogonDate) { 
            ((Get-Date) - $user.LastLogonDate).Days 
        } else { 
            999 
        }
        
        # Calculate password age
        $passwordAge = if ($user.PasswordLastSet) { 
            ((Get-Date) - $user.PasswordLastSet).Days 
        } else { 
            999 
        }
        
        # Risk assessment
        $riskFactors = @()
        $riskScore = 0
        
        # Account status risks
        if (!$user.Enabled) { $riskFactors += "AccountDisabled"; $riskScore += 5 }
        if ($user.PasswordNotRequired) { $riskFactors += "PasswordNotRequired"; $riskScore += 20 }
        if ($user.PasswordNeverExpires) { $riskFactors += "PasswordNeverExpires"; $riskScore += 15 }
        if ($user.CannotChangePassword) { $riskFactors += "CannotChangePassword"; $riskScore += 10 }
        if ($user.AccountLockoutTime) { $riskFactors += "AccountLocked"; $riskScore += 5 }
        
        # Authentication risks
        if (!$user.SmartcardLogonRequired -and $isPrivileged) { $riskFactors += "PrivilegedWithoutSmartcard"; $riskScore += 25 }
        if ($user.TrustedForDelegation) { $riskFactors += "TrustedForDelegation"; $riskScore += 20 }
        if ($user.DoesNotRequirePreAuth) { $riskFactors += "DoesNotRequirePreAuth"; $riskScore += 30 }
        
        # Activity risks
        if ($daysSinceLastLogon -gt $StaleAccountThreshold) { $riskFactors += "StaleAccount"; $riskScore += 15 }
        if ($user.BadLogonCount -gt 5) { $riskFactors += "HighBadLogonCount"; $riskScore += 10 }
        if ($passwordAge -gt 365) { $riskFactors += "OldPassword"; $riskScore += 10 }
        
        # Privilege risks
        if ($isPrivileged) { $riskScore += 10 }
        if ($privilegedGroupMemberships.Count -gt 2) { $riskFactors += "MultiplePrivilegedGroups"; $riskScore += 15 }
        
        # Create identity object
        $identityInfo = @{
            Name = $user.Name
            SamAccountName = $user.SamAccountName
            UserPrincipalName = $user.UserPrincipalName
            DistinguishedName = $user.DistinguishedName
            IdentityType = if ($isHumanAccount) { "Human" } else { "NonHuman" }
            Enabled = $user.Enabled
            
            # Authentication Information
            PasswordLastSet = $user.PasswordLastSet
            PasswordAge = $passwordAge
            PasswordNeverExpires = $user.PasswordNeverExpires
            PasswordNotRequired = $user.PasswordNotRequired
            SmartcardLogonRequired = $user.SmartcardLogonRequired
            TrustedForDelegation = $user.TrustedForDelegation
            DoesNotRequirePreAuth = $user.DoesNotRequirePreAuth
            
            # Activity Information
            LastLogonDate = $user.LastLogonDate
            DaysSinceLastLogon = $daysSinceLastLogon
            BadLogonCount = $user.BadLogonCount
            LastBadPasswordAttempt = $user.LastBadPasswordAttempt
            AccountLockoutTime = $user.AccountLockoutTime
            
            # Account Information
            CreationDate = $user.whenCreated
            AccountAge = if ($accountAge) { $accountAge.Days } else { $null }
            ModificationDate = $user.whenChanged
            AccountExpirationDate = $user.AccountExpirationDate
            
            # Organizational Information
            Department = $user.Department
            Title = $user.Title
            Manager = $user.Manager
            Company = $user.Company
            Office = $user.Office
            
            # Group Memberships
            Groups = $groupNames
            GroupCount = $groupNames.Count
            IsPrivileged = $isPrivileged
            PrivilegedGroups = $privilegedGroupMemberships
            
            # Service Account Information
            ServicePrincipalNames = $user.ServicePrincipalNames
            IsServiceAccount = ($user.ServicePrincipalNames.Count -gt 0)
            
            # Risk Assessment
            RiskFactors = $riskFactors
            RiskScore = $riskScore
            RiskLevel = if ($riskScore -ge 50) { "High" } elseif ($riskScore -ge 25) { "Medium" } else { "Low" }
            
            # Zero Trust Readiness
            MFAEnabled = $user.SmartcardLogonRequired
            ConditionalAccessReady = ($user.SmartcardLogonRequired -or $user.Enabled)
            PrivilegedAccessManaged = ($isPrivileged -and $user.SmartcardLogonRequired)
        }
        
        # Categorize identity
        if ($isHumanAccount) {
            $IdentityAnalysisResults.HumanIdentities += $identityInfo
        } else {
            $IdentityAnalysisResults.NonHumanIdentities += $identityInfo
        }
        
        # Add to privileged accounts if applicable
        if ($isPrivileged) {
            $IdentityAnalysisResults.PrivilegedAccounts += $identityInfo
        }
        
        # Add to service accounts if applicable
        if ($identityInfo.IsServiceAccount) {
            $IdentityAnalysisResults.ServiceAccounts += $identityInfo
        }
        
        # Check for shared accounts
        $isSharedAccount = $false
        foreach ($pattern in $sharedAccountPatterns) {
            if ($user.Name -match $pattern -or $user.SamAccountName -match $pattern) {
                $isSharedAccount = $true
                break
            }
        }
        if ($isSharedAccount) {
            $IdentityAnalysisResults.SharedAccounts += $identityInfo
        }
        
        # Check for orphaned accounts (no group memberships except Domain Users)
        if ($groupNames.Count -le 1 -and $groupNames -contains "Domain Users") {
            $IdentityAnalysisResults.OrphanedAccounts += $identityInfo
        }
    }

    # Analyze Groups
    Write-ADZTLog "Analyzing group structure and memberships..." "INFO"
    foreach ($group in $allGroups) {
        $members = Get-ADGroupMember -Identity $group.SamAccountName -ErrorAction SilentlyContinue
        $memberCount = $members.Count
        
        # Analyze member types
        $humanMembers = 0
        $serviceAccountMembers = 0
        $computerMembers = 0
        $groupMembers = 0
        
        foreach ($member in $members) {
            switch ($member.objectClass) {
                "user" { 
                    if ($member.Name -match ($serviceAccountPatterns -join "|")) {
                        $serviceAccountMembers++
                    } else {
                        $humanMembers++
                    }
                }
                "computer" { $computerMembers++ }
                "group" { $groupMembers++ }
            }
        }
        
        # Check if group is privileged
        $isPrivilegedGroup = $privilegedGroups -contains $group.Name
        
        # Calculate group risk
        $groupRiskFactors = @()
        $groupRiskScore = 0
        
        if ($isPrivilegedGroup) { $groupRiskScore += 20 }
        if ($memberCount -eq 0) { $groupRiskFactors += "EmptyGroup"; $groupRiskScore += 5 }
        if ($memberCount -gt 50 -and $isPrivilegedGroup) { $groupRiskFactors += "LargePrivilegedGroup"; $groupRiskScore += 15 }
        if ($serviceAccountMembers -gt 0 -and $isPrivilegedGroup) { $groupRiskFactors += "ServiceAccountsInPrivilegedGroup"; $groupRiskScore += 20 }
        if ($groupMembers -gt 5) { $groupRiskFactors += "NestedGroups"; $groupRiskScore += 10 }
        
        $groupInfo = @{
            Name = $group.Name
            SamAccountName = $group.SamAccountName
            DistinguishedName = $group.DistinguishedName
            GroupCategory = $group.GroupCategory
            GroupScope = $group.GroupScope
            Description = $group.Description
            
            # Membership Analysis
            TotalMembers = $memberCount
            HumanMembers = $humanMembers
            ServiceAccountMembers = $serviceAccountMembers
            ComputerMembers = $computerMembers
            NestedGroups = $groupMembers
            
            # Classification
            IsPrivileged = $isPrivilegedGroup
            IsEmpty = ($memberCount -eq 0)
            
            # Dates
            CreationDate = $group.whenCreated
            ModificationDate = $group.whenChanged
            ManagedBy = $group.ManagedBy
            
            # Risk Assessment
            RiskFactors = $groupRiskFactors
            RiskScore = $groupRiskScore
            RiskLevel = if ($groupRiskScore -ge 30) { "High" } elseif ($groupRiskScore -ge 15) { "Medium" } else { "Low" }
        }
        
        $IdentityAnalysisResults.GroupAnalysis += $groupInfo
    }

    # Create Identity Risk Matrix
    Write-ADZTLog "Creating identity risk matrix..." "INFO"
    $allIdentities = $IdentityAnalysisResults.HumanIdentities + $IdentityAnalysisResults.NonHumanIdentities
    
    $riskMatrix = @{
        HighRiskIdentities = @($allIdentities | Where-Object { $_.RiskLevel -eq "High" })
        MediumRiskIdentities = @($allIdentities | Where-Object { $_.RiskLevel -eq "Medium" })
        LowRiskIdentities = @($allIdentities | Where-Object { $_.RiskLevel -eq "Low" })
        
        # Risk by category
        PrivilegedHighRisk = @($allIdentities | Where-Object { $_.IsPrivileged -and $_.RiskLevel -eq "High" })
        ServiceAccountHighRisk = @($allIdentities | Where-Object { $_.IsServiceAccount -and $_.RiskLevel -eq "High" })
        StaleAccounts = @($allIdentities | Where-Object { $_.RiskFactors -contains "StaleAccount" })
        AccountsWithoutMFA = @($allIdentities | Where-Object { !$_.MFAEnabled -and $_.IsPrivileged })
        
        # Statistics
        TotalIdentities = $allIdentities.Count
        HighRiskCount = ($allIdentities | Where-Object { $_.RiskLevel -eq "High" }).Count
        MediumRiskCount = ($allIdentities | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        LowRiskCount = ($allIdentities | Where-Object { $_.RiskLevel -eq "Low" }).Count
    }
    
    $IdentityAnalysisResults.IdentityRiskMatrix = $riskMatrix

    # Analyze Identity Governance
    Write-ADZTLog "Analyzing identity governance posture..." "INFO"
    $totalUsers = $allIdentities.Count
    $enabledUsers = ($allIdentities | Where-Object { $_.Enabled }).Count
    $privilegedUsers = ($allIdentities | Where-Object { $_.IsPrivileged }).Count
    $mfaEnabledPrivileged = ($allIdentities | Where-Object { $_.IsPrivileged -and $_.MFAEnabled }).Count
    $staleAccounts = ($allIdentities | Where-Object { $_.RiskFactors -contains "StaleAccount" }).Count
    
    $governanceMetrics = @{
        AccountHygiene = @{
            TotalAccounts = $totalUsers
            EnabledAccounts = $enabledUsers
            DisabledAccounts = $totalUsers - $enabledUsers
            StaleAccounts = $staleAccounts
            StaleAccountPercentage = if ($totalUsers -gt 0) { [math]::Round(($staleAccounts / $totalUsers) * 100, 2) } else { 0 }
        }
        
        PrivilegedAccessManagement = @{
            TotalPrivilegedAccounts = $privilegedUsers
            PrivilegedWithMFA = $mfaEnabledPrivileged
            PrivilegedWithoutMFA = $privilegedUsers - $mfaEnabledPrivileged
            MFACompliancePercentage = if ($privilegedUsers -gt 0) { [math]::Round(($mfaEnabledPrivileged / $privilegedUsers) * 100, 2) } else { 0 }
        }
        
        ServiceAccountGovernance = @{
            TotalServiceAccounts = $IdentityAnalysisResults.ServiceAccounts.Count
            PrivilegedServiceAccounts = ($IdentityAnalysisResults.ServiceAccounts | Where-Object { $_.IsPrivileged }).Count
            ServiceAccountsWithOldPasswords = ($IdentityAnalysisResults.ServiceAccounts | Where-Object { $_.PasswordAge -gt 365 }).Count
        }
        
        GroupGovernance = @{
            TotalGroups = $IdentityAnalysisResults.GroupAnalysis.Count
            PrivilegedGroups = ($IdentityAnalysisResults.GroupAnalysis | Where-Object { $_.IsPrivileged }).Count
            EmptyGroups = ($IdentityAnalysisResults.GroupAnalysis | Where-Object { $_.IsEmpty }).Count
            LargePrivilegedGroups = ($IdentityAnalysisResults.GroupAnalysis | Where-Object { $_.IsPrivileged -and $_.TotalMembers -gt 10 }).Count
        }
    }
    
    $IdentityAnalysisResults.IdentityGovernance = $governanceMetrics

    # Assess Zero Trust Readiness
    Write-ADZTLog "Assessing Zero Trust readiness..." "INFO"
    $zeroTrustMetrics = @{
        VerifyExplicitly = @{
            MFAAdoption = @{
                Score = if ($privilegedUsers -gt 0) { [math]::Round(($mfaEnabledPrivileged / $privilegedUsers) * 100, 2) } else { 100 }
                Status = if ($privilegedUsers -gt 0 -and ($mfaEnabledPrivileged / $privilegedUsers) -ge 0.9) { "Good" } elseif ($privilegedUsers -gt 0 -and ($mfaEnabledPrivileged / $privilegedUsers) -ge 0.5) { "Fair" } else { "Poor" }
                Recommendation = "Enable MFA for all privileged accounts"
            }
            
            AccountHygiene = @{
                Score = if ($totalUsers -gt 0) { [math]::Round((($totalUsers - $staleAccounts) / $totalUsers) * 100, 2) } else { 100 }
                Status = if ($totalUsers -gt 0 -and (($totalUsers - $staleAccounts) / $totalUsers) -ge 0.9) { "Good" } elseif ($totalUsers -gt 0 -and (($totalUsers - $staleAccounts) / $totalUsers) -ge 0.7) { "Fair" } else { "Poor" }
                Recommendation = "Regularly review and clean up stale accounts"
            }
        }
        
        LeastPrivilegeAccess = @{
            PrivilegedAccountManagement = @{
                Score = if ($totalUsers -gt 0) { [math]::Round((($totalUsers - $privilegedUsers) / $totalUsers) * 100, 2) } else { 100 }
                Status = if ($totalUsers -gt 0 -and ($privilegedUsers / $totalUsers) -le 0.05) { "Good" } elseif ($totalUsers -gt 0 -and ($privilegedUsers / $totalUsers) -le 0.1) { "Fair" } else { "Poor" }
                Recommendation = "Minimize privileged account usage and implement just-in-time access"
            }
            
            ServiceAccountGovernance = @{
                Score = if ($IdentityAnalysisResults.ServiceAccounts.Count -gt 0) { 
                    $managedServiceAccounts = ($IdentityAnalysisResults.ServiceAccounts | Where-Object { !$_.IsPrivileged }).Count
                    [math]::Round(($managedServiceAccounts / $IdentityAnalysisResults.ServiceAccounts.Count) * 100, 2) 
                } else { 100 }
                Status = "Needs Assessment"
                Recommendation = "Implement managed service accounts and remove unnecessary privileges"
            }
        }
        
        AssumeBreach = @{
            IdentityProtection = @{
                Score = if ($allIdentities.Count -gt 0) { 
                    $protectedIdentities = ($allIdentities | Where-Object { $_.RiskLevel -eq "Low" }).Count
                    [math]::Round(($protectedIdentities / $allIdentities.Count) * 100, 2) 
                } else { 100 }
                Status = if ($allIdentities.Count -gt 0 -and ($protectedIdentities / $allIdentities.Count) -ge 0.8) { "Good" } elseif ($allIdentities.Count -gt 0 -and ($protectedIdentities / $allIdentities.Count) -ge 0.6) { "Fair" } else { "Poor" }
                Recommendation = "Reduce identity risk factors through policy enforcement and monitoring"
            }
        }
    }
    
    # Calculate overall Zero Trust readiness score
    $overallScore = 0
    $scoreCount = 0
    
    foreach ($principle in $zeroTrustMetrics.Keys) {
        foreach ($metric in $zeroTrustMetrics[$principle].Keys) {
            $overallScore += $zeroTrustMetrics[$principle][$metric].Score
            $scoreCount++
        }
    }
    
    $zeroTrustMetrics.OverallReadiness = @{
        Score = if ($scoreCount -gt 0) { [math]::Round($overallScore / $scoreCount, 2) } else { 0 }
        MaturityLevel = if ($scoreCount -gt 0) {
            $avgScore = $overallScore / $scoreCount
            if ($avgScore -ge 80) { "Advanced" } elseif ($avgScore -ge 60) { "Intermediate" } elseif ($avgScore -ge 40) { "Initial" } else { "Traditional" }
        } else { "Unknown" }
    }
    
    $IdentityAnalysisResults.ZeroTrustReadiness = $zeroTrustMetrics

    # Generate Recommendations
    Write-ADZTLog "Generating identity-focused recommendations..." "INFO"
    $recommendations = @()
    
    # High-risk identity recommendations
    if ($riskMatrix.HighRiskCount -gt 0) {
        $recommendations += @{
            Category = "Identity Risk Management"
            Priority = "Critical"
            Issue = "$($riskMatrix.HighRiskCount) identities classified as high-risk"
            Recommendation = "Immediately review and remediate high-risk identities"
            ZeroTrustPrinciple = "Verify Explicitly"
            AffectedCount = $riskMatrix.HighRiskCount
            Implementation = @(
                "Review each high-risk identity for necessity",
                "Implement additional authentication controls",
                "Consider disabling or removing unnecessary accounts",
                "Enable monitoring and alerting for high-risk accounts"
            )
        }
    }
    
    # MFA compliance for privileged accounts
    if ($governanceMetrics.PrivilegedAccessManagement.MFACompliancePercentage -lt 100) {
        $recommendations += @{
            Category = "Multi-Factor Authentication"
            Priority = "High"
            Issue = "$($governanceMetrics.PrivilegedAccessManagement.PrivilegedWithoutMFA) privileged accounts without MFA"
            Recommendation = "Enable MFA for all privileged accounts"
            ZeroTrustPrinciple = "Verify Explicitly"
            AffectedCount = $governanceMetrics.PrivilegedAccessManagement.PrivilegedWithoutMFA
            Implementation = @(
                "Deploy smartcard or certificate-based authentication",
                "Configure conditional access policies",
                "Implement FIDO2 or Windows Hello for Business",
                "Establish MFA bypass procedures for emergencies"
            )
        }
    }
    
    # Stale account cleanup
    if ($governanceMetrics.AccountHygiene.StaleAccountPercentage -gt 10) {
        $recommendations += @{
            Category = "Account Lifecycle Management"
            Priority = "Medium"
            Issue = "$($governanceMetrics.AccountHygiene.StaleAccounts) stale accounts ($($governanceMetrics.AccountHygiene.StaleAccountPercentage)% of total)"
            Recommendation = "Implement automated account lifecycle management"
            ZeroTrustPrinciple = "Use Least Privilege Access"
            AffectedCount = $governanceMetrics.AccountHygiene.StaleAccounts
            Implementation = @(
                "Establish regular account review processes",
                "Implement automated account disabling for inactive accounts",
                "Deploy identity governance and administration (IGA) solution",
                "Create account recertification workflows"
            )
        }
    }
    
    # Service account governance
    if ($governanceMetrics.ServiceAccountGovernance.PrivilegedServiceAccounts -gt 0) {
        $recommendations += @{
            Category = "Service Account Security"
            Priority = "High"
            Issue = "$($governanceMetrics.ServiceAccountGovernance.PrivilegedServiceAccounts) service accounts with privileged access"
            Recommendation = "Implement managed service accounts and least privilege principles"
            ZeroTrustPrinciple = "Use Least Privilege Access"
            AffectedCount = $governanceMetrics.ServiceAccountGovernance.PrivilegedServiceAccounts
            Implementation = @(
                "Migrate to Group Managed Service Accounts (gMSA)",
                "Review and minimize service account permissions",
                "Implement service account password rotation",
                "Monitor service account usage and access patterns"
            )
        }
    }
    
    # Large privileged groups
    if ($governanceMetrics.GroupGovernance.LargePrivilegedGroups -gt 0) {
        $recommendations += @{
            Category = "Privileged Access Management"
            Priority = "Medium"
            Issue = "$($governanceMetrics.GroupGovernance.LargePrivilegedGroups) privileged groups with excessive membership"
            Recommendation = "Implement role-based access control and just-in-time access"
            ZeroTrustPrinciple = "Use Least Privilege Access"
            AffectedCount = $governanceMetrics.GroupGovernance.LargePrivilegedGroups
            Implementation = @(
                "Review privileged group memberships",
                "Implement Privileged Access Management (PAM) solution",
                "Create time-limited privileged access workflows",
                "Establish regular access reviews and certifications"
            )
        }
    }
    
    # Empty groups cleanup
    if ($governanceMetrics.GroupGovernance.EmptyGroups -gt 5) {
        $recommendations += @{
            Category = "Group Management"
            Priority = "Low"
            Issue = "$($governanceMetrics.GroupGovernance.EmptyGroups) empty groups identified"
            Recommendation = "Clean up unused groups to reduce attack surface"
            ZeroTrustPrinciple = "Use Least Privilege Access"
            AffectedCount = $governanceMetrics.GroupGovernance.EmptyGroups
            Implementation = @(
                "Review empty groups for business necessity",
                "Remove unused groups after stakeholder approval",
                "Implement group lifecycle management processes",
                "Establish regular group cleanup procedures"
            )
        }
    }
    
    $IdentityAnalysisResults.Recommendations = $recommendations

    Write-ADZTLog "Identity analysis completed successfully" "INFO"

} catch {
    Write-ADZTLog "Error during identity analysis: $($_.Exception.Message)" "ERROR"
    $IdentityAnalysisResults.Error = $_.Exception.Message
}

# Export results to JSON
$jsonOutput = $IdentityAnalysisResults | ConvertTo-Json -Depth 10
$outputFile = "$OutputPath\Identity_Analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$jsonOutput | Out-File -FilePath $outputFile -Encoding UTF8

Write-ADZTLog "Results exported to: $outputFile" "INFO"

# Export detailed identity report
$identityReport = @"
# ADZero Trust Identity Analysis Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Domain: $($IdentityAnalysisResults.AnalysisInfo.Domain)

## Executive Summary
This report provides a comprehensive analysis of identity security posture within the Active Directory environment, focusing on Zero Trust principles and identity risk management.

### Key Findings
- **Total Identities Analyzed**: $($IdentityAnalysisResults.IdentityRiskMatrix.TotalIdentities)
- **Human Identities**: $($IdentityAnalysisResults.HumanIdentities.Count)
- **Non-Human Identities**: $($IdentityAnalysisResults.NonHumanIdentities.Count)
- **Privileged Accounts**: $($IdentityAnalysisResults.PrivilegedAccounts.Count)
- **Service Accounts**: $($IdentityAnalysisResults.ServiceAccounts.Count)

### Risk Distribution
- **High Risk Identities**: $($IdentityAnalysisResults.IdentityRiskMatrix.HighRiskCount)
- **Medium Risk Identities**: $($IdentityAnalysisResults.IdentityRiskMatrix.MediumRiskCount)
- **Low Risk Identities**: $($IdentityAnalysisResults.IdentityRiskMatrix.LowRiskCount)

### Zero Trust Readiness
- **Overall Maturity Level**: $($IdentityAnalysisResults.ZeroTrustReadiness.OverallReadiness.MaturityLevel)
- **Readiness Score**: $($IdentityAnalysisResults.ZeroTrustReadiness.OverallReadiness.Score)%

## Identity Governance Metrics

### Account Hygiene
- **Enabled Accounts**: $($IdentityAnalysisResults.IdentityGovernance.AccountHygiene.EnabledAccounts)
- **Disabled Accounts**: $($IdentityAnalysisResults.IdentityGovernance.AccountHygiene.DisabledAccounts)
- **Stale Accounts**: $($IdentityAnalysisResults.IdentityGovernance.AccountHygiene.StaleAccounts) ($($IdentityAnalysisResults.IdentityGovernance.AccountHygiene.StaleAccountPercentage)%)

### Privileged Access Management
- **Total Privileged Accounts**: $($IdentityAnalysisResults.IdentityGovernance.PrivilegedAccessManagement.TotalPrivilegedAccounts)
- **Privileged Accounts with MFA**: $($IdentityAnalysisResults.IdentityGovernance.PrivilegedAccessManagement.PrivilegedWithMFA)
- **MFA Compliance**: $($IdentityAnalysisResults.IdentityGovernance.PrivilegedAccessManagement.MFACompliancePercentage)%

### Service Account Governance
- **Total Service Accounts**: $($IdentityAnalysisResults.IdentityGovernance.ServiceAccountGovernance.TotalServiceAccounts)
- **Privileged Service Accounts**: $($IdentityAnalysisResults.IdentityGovernance.ServiceAccountGovernance.PrivilegedServiceAccounts)
- **Service Accounts with Old Passwords**: $($IdentityAnalysisResults.IdentityGovernance.ServiceAccountGovernance.ServiceAccountsWithOldPasswords)

## Critical Recommendations
$($recommendations | Where-Object { $_.Priority -eq "Critical" } | ForEach-Object { "### $($_.Category)`n**Issue**: $($_.Issue)`n**Recommendation**: $($_.Recommendation)`n" } | Out-String)

## High Priority Recommendations
$($recommendations | Where-Object { $_.Priority -eq "High" } | ForEach-Object { "### $($_.Category)`n**Issue**: $($_.Issue)`n**Recommendation**: $($_.Recommendation)`n" } | Out-String)

## Zero Trust Implementation Roadmap

Based on the identity analysis, the following phases are recommended for Zero Trust implementation:

### Phase 1: Foundation (0-3 months)
1. **Enable MFA for all privileged accounts**
2. **Implement account lifecycle management**
3. **Clean up stale and unnecessary accounts**
4. **Establish identity governance processes**

### Phase 2: Enhancement (3-6 months)
1. **Deploy Privileged Access Management (PAM) solution**
2. **Implement conditional access policies**
3. **Migrate to managed service accounts**
4. **Establish regular access reviews**

### Phase 3: Optimization (6-12 months)
1. **Implement just-in-time access**
2. **Deploy identity protection and monitoring**
3. **Establish zero trust network access**
4. **Implement continuous compliance monitoring**

For detailed technical implementation guidance and complete analysis results, please review the JSON output file.

---
*Report generated by ADZero Trust Identity Analyzer*
*Author: Moazzam Jafri*
"@

$reportFile = "$OutputPath\Identity_Analysis_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').md"
$identityReport | Out-File -FilePath $reportFile -Encoding UTF8

Write-ADZTLog "Identity analysis report exported to: $reportFile" "INFO"
Write-ADZTLog "Identity Analysis completed" "INFO"

# Return the results object for pipeline usage
return $IdentityAnalysisResults


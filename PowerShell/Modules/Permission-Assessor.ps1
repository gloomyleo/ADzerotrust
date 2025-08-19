# Permission-Assessor.ps1
# ADZero Trust - Permission Assessment Module
# Author: Moazzam Jafri
# Description: Comprehensive permission and access control analysis for Zero Trust assessment

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\ADZeroTrust_Output",
    
    [Parameter(Mandatory=$false)]
    [string]$Domain = $env:USERDOMAIN,
    
    [Parameter(Mandatory=$false)]
    [string[]]$TargetPaths = @("C:\", "D:\"),
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeShares = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeRegistry = $false,
    
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
    $logMessage = "[$timestamp] [$Level] [Permission-Assessor] $Message"
    Write-Host $logMessage
    if (!(Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
    Add-Content -Path "$LogPath\PermissionAssessor.log" -Value $logMessage
}

# Helper function to analyze ACL
function Analyze-ACL {
    param(
        [System.Security.AccessControl.FileSystemSecurity]$ACL,
        [string]$Path
    )
    
    $aclAnalysis = @{
        Path = $Path
        Owner = $ACL.Owner
        AccessRules = @()
        InheritanceEnabled = !$ACL.AreAccessRulesProtected
        RiskFactors = @()
        RiskScore = 0
    }
    
    foreach ($rule in $ACL.Access) {
        $ruleInfo = @{
            IdentityReference = $rule.IdentityReference.Value
            FileSystemRights = $rule.FileSystemRights.ToString()
            AccessControlType = $rule.AccessControlType.ToString()
            IsInherited = $rule.IsInherited
            InheritanceFlags = $rule.InheritanceFlags.ToString()
            PropagationFlags = $rule.PropagationFlags.ToString()
        }
        
        # Analyze risk factors for this rule
        if ($rule.IdentityReference.Value -eq "Everyone" -or $rule.IdentityReference.Value -eq "Users") {
            $aclAnalysis.RiskFactors += "BroadAccess"
            $aclAnalysis.RiskScore += 15
        }
        
        if ($rule.FileSystemRights -match "FullControl" -and $rule.AccessControlType -eq "Allow") {
            $aclAnalysis.RiskFactors += "FullControlAccess"
            $aclAnalysis.RiskScore += 10
        }
        
        if ($rule.IdentityReference.Value -match "ANONYMOUS" -or $rule.IdentityReference.Value -match "NULL SID") {
            $aclAnalysis.RiskFactors += "AnonymousAccess"
            $aclAnalysis.RiskScore += 25
        }
        
        $aclAnalysis.AccessRules += $ruleInfo
    }
    
    # Additional risk factors
    if ($ACL.Owner -match "Administrator" -and $Path -notmatch "Windows|Program Files") {
        $aclAnalysis.RiskFactors += "AdminOwnership"
        $aclAnalysis.RiskScore += 5
    }
    
    $aclAnalysis.RiskLevel = if ($aclAnalysis.RiskScore -ge 30) { "High" } elseif ($aclAnalysis.RiskScore -ge 15) { "Medium" } else { "Low" }
    
    return $aclAnalysis
}

# Helper function to get effective permissions
function Get-EffectivePermissions {
    param(
        [string]$Path,
        [string]$Identity
    )
    
    try {
        $acl = Get-Acl -Path $Path -ErrorAction SilentlyContinue
        if (!$acl) { return $null }
        
        $effectiveRights = @()
        foreach ($rule in $acl.Access) {
            if ($rule.IdentityReference.Value -eq $Identity -or 
                $rule.IdentityReference.Value -eq "Everyone" -or
                $rule.IdentityReference.Value -eq "Users") {
                
                $effectiveRights += @{
                    Rights = $rule.FileSystemRights.ToString()
                    Type = $rule.AccessControlType.ToString()
                    Source = $rule.IdentityReference.Value
                }
            }
        }
        
        return $effectiveRights
    } catch {
        return $null
    }
}

# Create output directory
if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-ADZTLog "Starting Permission Assessment for Zero Trust Analysis" "INFO"

# Initialize permission analysis results
$PermissionAnalysisResults = @{
    AssessmentInfo = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Domain = $Domain
        TargetPaths = $TargetPaths
        IncludeShares = $IncludeShares
        IncludeRegistry = $IncludeRegistry
        Version = "1.0"
        Author = "Moazzam Jafri - ADZero Trust"
    }
    FileSystemPermissions = @()
    SharePermissions = @()
    RegistryPermissions = @()
    EffectivePermissions = @()
    PermissionRiskMatrix = @{}
    DataClassification = @()
    AccessPatterns = @()
    ZeroTrustCompliance = @{}
    Recommendations = @()
}

try {
    # Analyze File System Permissions
    Write-ADZTLog "Analyzing file system permissions..." "INFO"
    
    foreach ($targetPath in $TargetPaths) {
        if (!(Test-Path $targetPath)) {
            Write-ADZTLog "Target path not found: $targetPath" "WARNING"
            continue
        }
        
        Write-ADZTLog "Scanning permissions for: $targetPath" "INFO"
        
        # Get top-level directories and key system folders
        $foldersToScan = @()
        
        if ($targetPath -eq "C:\") {
            $foldersToScan = @(
                "C:\Users",
                "C:\Program Files",
                "C:\Program Files (x86)",
                "C:\Windows\System32",
                "C:\Windows\SysWOW64",
                "C:\ProgramData",
                "C:\Temp",
                "C:\inetpub"
            )
        } else {
            # For other drives, scan root and immediate subdirectories
            $foldersToScan = @($targetPath)
            try {
                $subFolders = Get-ChildItem -Path $targetPath -Directory -ErrorAction SilentlyContinue | Select-Object -First 10
                $foldersToScan += $subFolders.FullName
            } catch {
                Write-ADZTLog "Unable to enumerate subdirectories in $targetPath" "WARNING"
            }
        }
        
        foreach ($folder in $foldersToScan) {
            if (!(Test-Path $folder)) { continue }
            
            try {
                $acl = Get-Acl -Path $folder -ErrorAction SilentlyContinue
                if ($acl) {
                    $aclAnalysis = Analyze-ACL -ACL $acl -Path $folder
                    $PermissionAnalysisResults.FileSystemPermissions += $aclAnalysis
                }
            } catch {
                Write-ADZTLog "Unable to analyze ACL for: $folder - $($_.Exception.Message)" "WARNING"
            }
        }
    }

    # Analyze Share Permissions
    if ($IncludeShares) {
        Write-ADZTLog "Analyzing network share permissions..." "INFO"
        
        try {
            $shares = Get-SmbShare -ErrorAction SilentlyContinue
            foreach ($share in $shares) {
                if ($share.Name -in @("ADMIN$", "C$", "IPC$", "print$")) {
                    continue  # Skip administrative shares
                }
                
                $shareInfo = @{
                    ShareName = $share.Name
                    Path = $share.Path
                    Description = $share.Description
                    ShareType = $share.ShareType
                    ShareState = $share.ShareState
                    Availability = $share.Availability
                    CachingMode = $share.CachingMode
                    CATimeout = $share.CATimeout
                    ConcurrentUserLimit = $share.ConcurrentUserLimit
                    CurrentUsers = $share.CurrentUsers
                    SharePermissions = @()
                    NTFSPermissions = @()
                    RiskFactors = @()
                    RiskScore = 0
                }
                
                # Get share permissions
                try {
                    $shareAccess = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
                    foreach ($access in $shareAccess) {
                        $sharePermission = @{
                            AccountName = $access.AccountName
                            AccessControlType = $access.AccessControlType
                            AccessRight = $access.AccessRight
                        }
                        $shareInfo.SharePermissions += $sharePermission
                        
                        # Analyze share permission risks
                        if ($access.AccountName -eq "Everyone" -and $access.AccessRight -ne "Read") {
                            $shareInfo.RiskFactors += "EveryoneWriteAccess"
                            $shareInfo.RiskScore += 20
                        }
                        
                        if ($access.AccountName -eq "Everyone" -and $access.AccessRight -eq "Full") {
                            $shareInfo.RiskFactors += "EveryoneFullAccess"
                            $shareInfo.RiskScore += 30
                        }
                        
                        if ($access.AccountName -match "Guest" -and $access.AccessControlType -eq "Allow") {
                            $shareInfo.RiskFactors += "GuestAccess"
                            $shareInfo.RiskScore += 25
                        }
                    }
                } catch {
                    Write-ADZTLog "Unable to get share permissions for: $($share.Name)" "WARNING"
                }
                
                # Get NTFS permissions for the share path
                if (Test-Path $share.Path) {
                    try {
                        $ntfsAcl = Get-Acl -Path $share.Path -ErrorAction SilentlyContinue
                        if ($ntfsAcl) {
                            $ntfsAnalysis = Analyze-ACL -ACL $ntfsAcl -Path $share.Path
                            $shareInfo.NTFSPermissions = $ntfsAnalysis
                            $shareInfo.RiskScore += $ntfsAnalysis.RiskScore
                        }
                    } catch {
                        Write-ADZTLog "Unable to analyze NTFS permissions for share path: $($share.Path)" "WARNING"
                    }
                }
                
                # Additional risk factors
                if ($share.Name -match "temp|tmp|public|shared" -and $shareInfo.RiskScore -eq 0) {
                    $shareInfo.RiskFactors += "PotentiallyUnsecureShare"
                    $shareInfo.RiskScore += 10
                }
                
                if ($share.ConcurrentUserLimit -eq 0) {
                    $shareInfo.RiskFactors += "UnlimitedConcurrentUsers"
                    $shareInfo.RiskScore += 5
                }
                
                $shareInfo.RiskLevel = if ($shareInfo.RiskScore -ge 30) { "High" } elseif ($shareInfo.RiskScore -ge 15) { "Medium" } else { "Low" }
                
                $PermissionAnalysisResults.SharePermissions += $shareInfo
            }
        } catch {
            Write-ADZTLog "Unable to enumerate network shares: $($_.Exception.Message)" "WARNING"
        }
    }

    # Analyze Registry Permissions (if requested)
    if ($IncludeRegistry) {
        Write-ADZTLog "Analyzing registry permissions..." "INFO"
        
        $registryKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SYSTEM\CurrentControlSet\Services",
            "HKLM:\SOFTWARE\Policies",
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        )
        
        foreach ($regKey in $registryKeys) {
            try {
                if (Test-Path $regKey) {
                    $regAcl = Get-Acl -Path $regKey -ErrorAction SilentlyContinue
                    if ($regAcl) {
                        $regAnalysis = @{
                            RegistryPath = $regKey
                            Owner = $regAcl.Owner
                            AccessRules = @()
                            RiskFactors = @()
                            RiskScore = 0
                        }
                        
                        foreach ($rule in $regAcl.Access) {
                            $ruleInfo = @{
                                IdentityReference = $rule.IdentityReference.Value
                                RegistryRights = $rule.RegistryRights.ToString()
                                AccessControlType = $rule.AccessControlType.ToString()
                                IsInherited = $rule.IsInherited
                            }
                            $regAnalysis.AccessRules += $ruleInfo
                            
                            # Analyze registry permission risks
                            if ($rule.IdentityReference.Value -eq "Users" -and $rule.RegistryRights -match "FullControl|Write") {
                                $regAnalysis.RiskFactors += "UsersWriteAccess"
                                $regAnalysis.RiskScore += 15
                            }
                            
                            if ($rule.IdentityReference.Value -eq "Everyone" -and $rule.RegistryRights -match "Write|FullControl") {
                                $regAnalysis.RiskFactors += "EveryoneWriteAccess"
                                $regAnalysis.RiskScore += 20
                            }
                        }
                        
                        $regAnalysis.RiskLevel = if ($regAnalysis.RiskScore -ge 20) { "High" } elseif ($regAnalysis.RiskScore -ge 10) { "Medium" } else { "Low" }
                        $PermissionAnalysisResults.RegistryPermissions += $regAnalysis
                    }
                }
            } catch {
                Write-ADZTLog "Unable to analyze registry key: $regKey - $($_.Exception.Message)" "WARNING"
            }
        }
    }

    # Analyze Effective Permissions for Key Identities
    Write-ADZTLog "Analyzing effective permissions for key identities..." "INFO"
    
    # Get privileged users and service accounts
    $keyIdentities = @()
    try {
        $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Administrators", "Backup Operators")
        foreach ($group in $privilegedGroups) {
            try {
                $groupMembers = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
                foreach ($member in $groupMembers) {
                    if ($member.objectClass -eq "user") {
                        $keyIdentities += $member.SamAccountName
                    }
                }
            } catch {
                Write-ADZTLog "Unable to get members of group: $group" "WARNING"
            }
        }
        
        # Add service accounts
        $serviceAccounts = Get-ADUser -Filter * -Properties ServicePrincipalNames | Where-Object { $_.ServicePrincipalNames.Count -gt 0 }
        $keyIdentities += $serviceAccounts.SamAccountName
        
        # Remove duplicates
        $keyIdentities = $keyIdentities | Sort-Object -Unique
        
    } catch {
        Write-ADZTLog "Unable to enumerate key identities: $($_.Exception.Message)" "WARNING"
        $keyIdentities = @("Administrator", "Guest")
    }
    
    # Analyze effective permissions for key paths
    $keyPaths = @("C:\Windows\System32", "C:\Program Files", "C:\Users", "C:\ProgramData")
    
    foreach ($identity in ($keyIdentities | Select-Object -First 10)) {  # Limit to first 10 for performance
        foreach ($path in $keyPaths) {
            if (Test-Path $path) {
                $effectivePerms = Get-EffectivePermissions -Path $path -Identity $identity
                if ($effectivePerms) {
                    $effectivePermInfo = @{
                        Identity = $identity
                        Path = $path
                        EffectiveRights = $effectivePerms
                        HasFullControl = ($effectivePerms | Where-Object { $_.Rights -match "FullControl" -and $_.Type -eq "Allow" }) -ne $null
                        HasWriteAccess = ($effectivePerms | Where-Object { $_.Rights -match "Write|Modify|FullControl" -and $_.Type -eq "Allow" }) -ne $null
                        RiskLevel = "Low"
                    }
                    
                    # Assess risk
                    if ($effectivePermInfo.HasFullControl -and $path -match "System32|Program Files") {
                        $effectivePermInfo.RiskLevel = "High"
                    } elseif ($effectivePermInfo.HasWriteAccess -and $path -match "System32|Program Files") {
                        $effectivePermInfo.RiskLevel = "Medium"
                    }
                    
                    $PermissionAnalysisResults.EffectivePermissions += $effectivePermInfo
                }
            }
        }
    }

    # Create Permission Risk Matrix
    Write-ADZTLog "Creating permission risk matrix..." "INFO"
    
    $allPermissions = $PermissionAnalysisResults.FileSystemPermissions + $PermissionAnalysisResults.SharePermissions + $PermissionAnalysisResults.RegistryPermissions
    
    $riskMatrix = @{
        HighRiskPermissions = @($allPermissions | Where-Object { $_.RiskLevel -eq "High" })
        MediumRiskPermissions = @($allPermissions | Where-Object { $_.RiskLevel -eq "Medium" })
        LowRiskPermissions = @($allPermissions | Where-Object { $_.RiskLevel -eq "Low" })
        
        # Risk by category
        FileSystemHighRisk = @($PermissionAnalysisResults.FileSystemPermissions | Where-Object { $_.RiskLevel -eq "High" })
        ShareHighRisk = @($PermissionAnalysisResults.SharePermissions | Where-Object { $_.RiskLevel -eq "High" })
        RegistryHighRisk = @($PermissionAnalysisResults.RegistryPermissions | Where-Object { $_.RiskLevel -eq "High" })
        
        # Common risk factors
        BroadAccessIssues = @($allPermissions | Where-Object { $_.RiskFactors -contains "BroadAccess" })
        FullControlIssues = @($allPermissions | Where-Object { $_.RiskFactors -contains "FullControlAccess" })
        AnonymousAccessIssues = @($allPermissions | Where-Object { $_.RiskFactors -contains "AnonymousAccess" })
        
        # Statistics
        TotalPermissionsAnalyzed = $allPermissions.Count
        HighRiskCount = ($allPermissions | Where-Object { $_.RiskLevel -eq "High" }).Count
        MediumRiskCount = ($allPermissions | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        LowRiskCount = ($allPermissions | Where-Object { $_.RiskLevel -eq "Low" }).Count
    }
    
    $PermissionAnalysisResults.PermissionRiskMatrix = $riskMatrix

    # Data Classification Analysis
    Write-ADZTLog "Performing data classification analysis..." "INFO"
    
    $sensitiveDataPatterns = @{
        "PersonalData" = @("*ssn*", "*social*", "*passport*", "*license*")
        "FinancialData" = @("*credit*", "*bank*", "*account*", "*financial*", "*payment*")
        "HealthData" = @("*medical*", "*health*", "*patient*", "*hipaa*")
        "ConfidentialData" = @("*confidential*", "*secret*", "*classified*", "*restricted*")
        "BackupData" = @("*backup*", "*bak*", "*.bak")
        "DatabaseData" = @("*.mdb", "*.accdb", "*.sql", "*.db")
        "ConfigurationData" = @("*.config", "*.ini", "*.conf", "*password*", "*credential*")
    }
    
    foreach ($category in $sensitiveDataPatterns.Keys) {
        $patterns = $sensitiveDataPatterns[$category]
        $foundLocations = @()
        
        foreach ($fsPermission in $PermissionAnalysisResults.FileSystemPermissions) {
            foreach ($pattern in $patterns) {
                if ($fsPermission.Path -like $pattern) {
                    $foundLocations += $fsPermission.Path
                }
            }
        }
        
        if ($foundLocations.Count -gt 0) {
            $dataClassInfo = @{
                Category = $category
                Locations = $foundLocations
                LocationCount = $foundLocations.Count
                RiskLevel = if ($category -in @("PersonalData", "FinancialData", "HealthData")) { "High" } else { "Medium" }
                ProtectionRecommendation = switch ($category) {
                    "PersonalData" { "Implement data encryption and access controls per privacy regulations" }
                    "FinancialData" { "Apply PCI DSS controls and encryption requirements" }
                    "HealthData" { "Implement HIPAA-compliant access controls and encryption" }
                    "ConfidentialData" { "Apply information classification and DLP policies" }
                    "BackupData" { "Secure backup storage with encryption and access controls" }
                    "DatabaseData" { "Implement database security controls and encryption" }
                    "ConfigurationData" { "Secure configuration files and credential storage" }
                    default { "Apply appropriate data protection controls" }
                }
            }
            $PermissionAnalysisResults.DataClassification += $dataClassInfo
        }
    }

    # Zero Trust Compliance Assessment
    Write-ADZTLog "Assessing Zero Trust compliance..." "INFO"
    
    $zeroTrustCompliance = @{
        DataProtection = @{
            EncryptionImplementation = @{
                Score = 0  # Would need additional tools to assess encryption
                Status = "Needs Assessment"
                Recommendation = "Implement data encryption at rest and in transit"
            }
            
            AccessControls = @{
                Score = if ($riskMatrix.TotalPermissionsAnalyzed -gt 0) { 
                    [math]::Round((($riskMatrix.TotalPermissionsAnalyzed - $riskMatrix.HighRiskCount) / $riskMatrix.TotalPermissionsAnalyzed) * 100, 2) 
                } else { 100 }
                Status = if ($riskMatrix.HighRiskCount -eq 0) { "Good" } elseif ($riskMatrix.HighRiskCount -le 5) { "Fair" } else { "Poor" }
                Recommendation = "Review and remediate high-risk permission configurations"
            }
            
            DataClassification = @{
                Score = if ($PermissionAnalysisResults.DataClassification.Count -gt 0) { 50 } else { 0 }
                Status = if ($PermissionAnalysisResults.DataClassification.Count -gt 0) { "Partial" } else { "Not Implemented" }
                Recommendation = "Implement comprehensive data classification and labeling"
            }
        }
        
        LeastPrivilegeAccess = @{
            PermissionRightSizing = @{
                Score = if ($riskMatrix.TotalPermissionsAnalyzed -gt 0) { 
                    [math]::Round((($riskMatrix.TotalPermissionsAnalyzed - $riskMatrix.HighRiskCount - $riskMatrix.MediumRiskCount) / $riskMatrix.TotalPermissionsAnalyzed) * 100, 2) 
                } else { 100 }
                Status = if (($riskMatrix.HighRiskCount + $riskMatrix.MediumRiskCount) -eq 0) { "Good" } elseif (($riskMatrix.HighRiskCount + $riskMatrix.MediumRiskCount) -le 10) { "Fair" } else { "Poor" }
                Recommendation = "Implement least privilege access principles across all resources"
            }
            
            ShareSecurity = @{
                Score = if ($PermissionAnalysisResults.SharePermissions.Count -gt 0) { 
                    $secureShares = ($PermissionAnalysisResults.SharePermissions | Where-Object { $_.RiskLevel -eq "Low" }).Count
                    [math]::Round(($secureShares / $PermissionAnalysisResults.SharePermissions.Count) * 100, 2) 
                } else { 100 }
                Status = if ($PermissionAnalysisResults.SharePermissions.Count -eq 0) { "N/A" } else { "Needs Review" }
                Recommendation = "Review and secure network share permissions"
            }
        }
        
        AssumeBreachPreparation = @{
            PermissionMonitoring = @{
                Score = 0  # Would need additional tools to assess monitoring
                Status = "Needs Implementation"
                Recommendation = "Implement permission and access monitoring solutions"
            }
            
            DataLossPrevention = @{
                Score = if ($PermissionAnalysisResults.DataClassification.Count -gt 0) { 25 } else { 0 }
                Status = "Needs Implementation"
                Recommendation = "Deploy data loss prevention (DLP) solutions for sensitive data"
            }
        }
    }
    
    # Calculate overall compliance score
    $totalScore = 0
    $scoreCount = 0
    
    foreach ($principle in $zeroTrustCompliance.Keys) {
        foreach ($metric in $zeroTrustCompliance[$principle].Keys) {
            $totalScore += $zeroTrustCompliance[$principle][$metric].Score
            $scoreCount++
        }
    }
    
    $zeroTrustCompliance.OverallCompliance = @{
        Score = if ($scoreCount -gt 0) { [math]::Round($totalScore / $scoreCount, 2) } else { 0 }
        MaturityLevel = if ($scoreCount -gt 0) {
            $avgScore = $totalScore / $scoreCount
            if ($avgScore -ge 80) { "Advanced" } elseif ($avgScore -ge 60) { "Intermediate" } elseif ($avgScore -ge 40) { "Initial" } else { "Traditional" }
        } else { "Unknown" }
    }
    
    $PermissionAnalysisResults.ZeroTrustCompliance = $zeroTrustCompliance

    # Generate Recommendations
    Write-ADZTLog "Generating permission-focused recommendations..." "INFO"
    $recommendations = @()
    
    # High-risk permissions
    if ($riskMatrix.HighRiskCount -gt 0) {
        $recommendations += @{
            Category = "Permission Security"
            Priority = "Critical"
            Issue = "$($riskMatrix.HighRiskCount) high-risk permission configurations identified"
            Recommendation = "Immediately review and remediate high-risk permissions"
            ZeroTrustPrinciple = "Use Least Privilege Access"
            AffectedCount = $riskMatrix.HighRiskCount
            Implementation = @(
                "Review permissions granting broad access (Everyone, Users groups)",
                "Remove unnecessary Full Control permissions",
                "Implement principle of least privilege",
                "Establish regular permission reviews and audits"
            )
        }
    }
    
    # Anonymous access issues
    if ($riskMatrix.AnonymousAccessIssues.Count -gt 0) {
        $recommendations += @{
            Category = "Anonymous Access"
            Priority = "Critical"
            Issue = "$($riskMatrix.AnonymousAccessIssues.Count) resources with anonymous access detected"
            Recommendation = "Remove anonymous access permissions immediately"
            ZeroTrustPrinciple = "Verify Explicitly"
            AffectedCount = $riskMatrix.AnonymousAccessIssues.Count
            Implementation = @(
                "Identify and remove anonymous access permissions",
                "Implement authentication requirements for all resources",
                "Review and secure guest account access",
                "Monitor for unauthorized access attempts"
            )
        }
    }
    
    # Share security issues
    if ($PermissionAnalysisResults.SharePermissions.Count -gt 0) {
        $insecureShares = ($PermissionAnalysisResults.SharePermissions | Where-Object { $_.RiskLevel -ne "Low" }).Count
        if ($insecureShares -gt 0) {
            $recommendations += @{
                Category = "Network Share Security"
                Priority = "High"
                Issue = "$insecureShares network shares with security concerns"
                Recommendation = "Secure network share permissions and access controls"
                ZeroTrustPrinciple = "Use Least Privilege Access"
                AffectedCount = $insecureShares
                Implementation = @(
                    "Review share permissions and remove excessive access",
                    "Implement share-level and NTFS permission alignment",
                    "Consider disabling unnecessary shares",
                    "Enable share access auditing and monitoring"
                )
            }
        }
    }
    
    # Sensitive data protection
    if ($PermissionAnalysisResults.DataClassification.Count -gt 0) {
        $highRiskData = ($PermissionAnalysisResults.DataClassification | Where-Object { $_.RiskLevel -eq "High" }).Count
        if ($highRiskData -gt 0) {
            $recommendations += @{
                Category = "Data Protection"
                Priority = "High"
                Issue = "$highRiskData categories of sensitive data identified without adequate protection"
                Recommendation = "Implement data classification and protection controls"
                ZeroTrustPrinciple = "Assume Breach"
                AffectedCount = $highRiskData
                Implementation = @(
                    "Implement data encryption for sensitive information",
                    "Deploy data loss prevention (DLP) solutions",
                    "Establish data classification policies",
                    "Implement access controls based on data sensitivity"
                )
            }
        }
    }
    
    # Registry security
    if ($PermissionAnalysisResults.RegistryPermissions.Count -gt 0) {
        $registryRisks = ($PermissionAnalysisResults.RegistryPermissions | Where-Object { $_.RiskLevel -ne "Low" }).Count
        if ($registryRisks -gt 0) {
            $recommendations += @{
                Category = "Registry Security"
                Priority = "Medium"
                Issue = "$registryRisks registry keys with elevated security risks"
                Recommendation = "Secure registry permissions and access controls"
                ZeroTrustPrinciple = "Use Least Privilege Access"
                AffectedCount = $registryRisks
                Implementation = @(
                    "Review and restrict registry write permissions",
                    "Remove unnecessary user access to system registry keys",
                    "Implement registry monitoring and auditing",
                    "Establish registry backup and recovery procedures"
                )
            }
        }
    }
    
    # Broad access permissions
    if ($riskMatrix.BroadAccessIssues.Count -gt 0) {
        $recommendations += @{
            Category = "Access Control"
            Priority = "Medium"
            Issue = "$($riskMatrix.BroadAccessIssues.Count) resources with overly broad access permissions"
            Recommendation = "Implement granular access controls and remove broad permissions"
            ZeroTrustPrinciple = "Use Least Privilege Access"
            AffectedCount = $riskMatrix.BroadAccessIssues.Count
            Implementation = @(
                "Replace 'Everyone' and 'Users' group permissions with specific user/group assignments",
                "Implement role-based access control (RBAC)",
                "Establish regular access reviews and certifications",
                "Deploy privileged access management (PAM) solutions"
            )
        }
    }
    
    $PermissionAnalysisResults.Recommendations = $recommendations

    Write-ADZTLog "Permission assessment completed successfully" "INFO"

} catch {
    Write-ADZTLog "Error during permission assessment: $($_.Exception.Message)" "ERROR"
    $PermissionAnalysisResults.Error = $_.Exception.Message
}

# Export results to JSON
$jsonOutput = $PermissionAnalysisResults | ConvertTo-Json -Depth 10
$outputFile = "$OutputPath\Permission_Analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$jsonOutput | Out-File -FilePath $outputFile -Encoding UTF8

Write-ADZTLog "Results exported to: $outputFile" "INFO"

# Export permission analysis report
$permissionReport = @"
# ADZero Trust Permission Analysis Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Domain: $($PermissionAnalysisResults.AssessmentInfo.Domain)

## Executive Summary
This report provides a comprehensive analysis of permission and access control configurations within the environment, focusing on Zero Trust principles and data protection requirements.

### Key Findings
- **File System Permissions Analyzed**: $($PermissionAnalysisResults.FileSystemPermissions.Count)
- **Network Shares Analyzed**: $($PermissionAnalysisResults.SharePermissions.Count)
- **Registry Keys Analyzed**: $($PermissionAnalysisResults.RegistryPermissions.Count)
- **Effective Permissions Evaluated**: $($PermissionAnalysisResults.EffectivePermissions.Count)

### Risk Distribution
- **High Risk Permissions**: $($PermissionAnalysisResults.PermissionRiskMatrix.HighRiskCount)
- **Medium Risk Permissions**: $($PermissionAnalysisResults.PermissionRiskMatrix.MediumRiskCount)
- **Low Risk Permissions**: $($PermissionAnalysisResults.PermissionRiskMatrix.LowRiskCount)

### Zero Trust Compliance
- **Overall Compliance Score**: $($PermissionAnalysisResults.ZeroTrustCompliance.OverallCompliance.Score)%
- **Maturity Level**: $($PermissionAnalysisResults.ZeroTrustCompliance.OverallCompliance.MaturityLevel)

## Permission Risk Analysis

### Critical Risk Factors
- **Anonymous Access Issues**: $($PermissionAnalysisResults.PermissionRiskMatrix.AnonymousAccessIssues.Count)
- **Broad Access Issues**: $($PermissionAnalysisResults.PermissionRiskMatrix.BroadAccessIssues.Count)
- **Full Control Issues**: $($PermissionAnalysisResults.PermissionRiskMatrix.FullControlIssues.Count)

### Data Classification Results
$($PermissionAnalysisResults.DataClassification | ForEach-Object { "- **$($_.Category)**: $($_.LocationCount) locations identified (Risk Level: $($_.RiskLevel))" } | Out-String)

## Zero Trust Compliance Metrics

### Data Protection
- **Access Controls Score**: $($PermissionAnalysisResults.ZeroTrustCompliance.DataProtection.AccessControls.Score)% ($($PermissionAnalysisResults.ZeroTrustCompliance.DataProtection.AccessControls.Status))
- **Data Classification Score**: $($PermissionAnalysisResults.ZeroTrustCompliance.DataProtection.DataClassification.Score)% ($($PermissionAnalysisResults.ZeroTrustCompliance.DataProtection.DataClassification.Status))

### Least Privilege Access
- **Permission Right-sizing Score**: $($PermissionAnalysisResults.ZeroTrustCompliance.LeastPrivilegeAccess.PermissionRightSizing.Score)% ($($PermissionAnalysisResults.ZeroTrustCompliance.LeastPrivilegeAccess.PermissionRightSizing.Status))
- **Share Security Score**: $($PermissionAnalysisResults.ZeroTrustCompliance.LeastPrivilegeAccess.ShareSecurity.Score)% ($($PermissionAnalysisResults.ZeroTrustCompliance.LeastPrivilegeAccess.ShareSecurity.Status))

## Critical Recommendations
$($recommendations | Where-Object { $_.Priority -eq "Critical" } | ForEach-Object { "### $($_.Category)`n**Issue**: $($_.Issue)`n**Recommendation**: $($_.Recommendation)`n**Implementation Steps**:`n$($_.Implementation | ForEach-Object { "- $_" } | Out-String)" } | Out-String)

## High Priority Recommendations
$($recommendations | Where-Object { $_.Priority -eq "High" } | ForEach-Object { "### $($_.Category)`n**Issue**: $($_.Issue)`n**Recommendation**: $($_.Recommendation)`n**Implementation Steps**:`n$($_.Implementation | ForEach-Object { "- $_" } | Out-String)" } | Out-String)

## Zero Trust Implementation Roadmap

### Phase 1: Critical Security (0-1 month)
1. **Remove anonymous access permissions**
2. **Remediate high-risk permission configurations**
3. **Secure administrative shares and registry keys**
4. **Implement emergency access controls**

### Phase 2: Access Control Enhancement (1-3 months)
1. **Implement least privilege access principles**
2. **Deploy role-based access control (RBAC)**
3. **Secure network shares and file systems**
4. **Establish permission monitoring and auditing**

### Phase 3: Data Protection (3-6 months)
1. **Implement data classification and labeling**
2. **Deploy data loss prevention (DLP) solutions**
3. **Enable encryption for sensitive data**
4. **Establish data governance policies**

### Phase 4: Advanced Controls (6-12 months)
1. **Deploy privileged access management (PAM)**
2. **Implement just-in-time access controls**
3. **Enable advanced threat protection**
4. **Establish continuous compliance monitoring**

For detailed technical analysis and complete results, please review the JSON output file.

---
*Report generated by ADZero Trust Permission Assessor*
*Author: Moazzam Jafri*
"@

$reportFile = "$OutputPath\Permission_Analysis_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').md"
$permissionReport | Out-File -FilePath $reportFile -Encoding UTF8

Write-ADZTLog "Permission analysis report exported to: $reportFile" "INFO"
Write-ADZTLog "Permission Assessment completed" "INFO"

# Return the results object for pipeline usage
return $PermissionAnalysisResults


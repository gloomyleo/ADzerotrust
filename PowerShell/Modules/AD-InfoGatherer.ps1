# AD-InfoGatherer.ps1
# ADZero Trust - Active Directory Information Gathering Module
# Author: Moazzam Jafri
# Description: Comprehensive Active Directory information collection for Zero Trust assessment

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\ADZeroTrust_Output",
    
    [Parameter(Mandatory=$false)]
    [string]$Domain = $env:USERDOMAIN,
    
    [Parameter(Mandatory=$false)]
    [switch]$Detailed = $false,
    
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
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    if (!(Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
    Add-Content -Path "$LogPath\ADInfoGatherer.log" -Value $logMessage
}

# Create output directory
if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-ADZTLog "Created output directory: $OutputPath"
}

Write-ADZTLog "Starting AD Zero Trust Information Gathering" "INFO"
Write-ADZTLog "Target Domain: $Domain" "INFO"

# Initialize results object
$ADAssessmentResults = @{
    AssessmentInfo = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Domain = $Domain
        AssessmentType = if ($Detailed) { "Detailed" } else { "Standard" }
        Version = "1.0"
        Author = "Moazzam Jafri - ADZero Trust"
    }
    DomainInfo = @{}
    ForestInfo = @{}
    DomainControllers = @()
    OrganizationalUnits = @()
    Groups = @()
    Users = @()
    ServiceAccounts = @()
    Computers = @()
    GroupPolicies = @()
    TrustRelationships = @()
    DNSConfiguration = @{}
    SecuritySettings = @{}
    Recommendations = @()
}

try {
    # Gather Domain Information
    Write-ADZTLog "Collecting domain information..." "INFO"
    $domainInfo = Get-ADDomain -Identity $Domain
    $ADAssessmentResults.DomainInfo = @{
        Name = $domainInfo.Name
        DNSRoot = $domainInfo.DNSRoot
        NetBIOSName = $domainInfo.NetBIOSName
        DomainMode = $domainInfo.DomainMode
        ForestMode = $domainInfo.Forest
        PDCEmulator = $domainInfo.PDCEmulator
        RIDMaster = $domainInfo.RIDMaster
        InfrastructureMaster = $domainInfo.InfrastructureMaster
        CreationDate = $domainInfo.whenCreated
        LastLogonReplicationInterval = $domainInfo.LastLogonReplicationInterval
        DistinguishedName = $domainInfo.DistinguishedName
        ObjectGUID = $domainInfo.ObjectGUID
    }

    # Gather Forest Information
    Write-ADZTLog "Collecting forest information..." "INFO"
    $forestInfo = Get-ADForest
    $ADAssessmentResults.ForestInfo = @{
        Name = $forestInfo.Name
        ForestMode = $forestInfo.ForestMode
        SchemaMaster = $forestInfo.SchemaMaster
        DomainNamingMaster = $forestInfo.DomainNamingMaster
        Domains = $forestInfo.Domains
        Sites = $forestInfo.Sites
        GlobalCatalogs = $forestInfo.GlobalCatalogs
        RootDomain = $forestInfo.RootDomain
        UPNSuffixes = $forestInfo.UPNSuffixes
    }

    # Gather Domain Controllers
    Write-ADZTLog "Collecting domain controller information..." "INFO"
    $domainControllers = Get-ADDomainController -Filter *
    foreach ($dc in $domainControllers) {
        $dcInfo = @{
            Name = $dc.Name
            HostName = $dc.HostName
            IPv4Address = $dc.IPv4Address
            IPv6Address = $dc.IPv6Address
            Site = $dc.Site
            OperatingSystem = $dc.OperatingSystem
            OperatingSystemVersion = $dc.OperatingSystemVersion
            IsGlobalCatalog = $dc.IsGlobalCatalog
            IsReadOnly = $dc.IsReadOnly
            Roles = $dc.OperationMasterRoles
            LastLogonDate = $dc.LastLogonDate
            Enabled = $dc.Enabled
        }
        $ADAssessmentResults.DomainControllers += $dcInfo
    }

    # Gather Organizational Units
    Write-ADZTLog "Collecting organizational unit information..." "INFO"
    $organizationalUnits = Get-ADOrganizationalUnit -Filter * -Properties *
    foreach ($ou in $organizationalUnits) {
        $ouInfo = @{
            Name = $ou.Name
            DistinguishedName = $ou.DistinguishedName
            Description = $ou.Description
            CreationDate = $ou.whenCreated
            ModificationDate = $ou.whenChanged
            ProtectedFromDeletion = $ou.ProtectedFromAccidentalDeletion
            LinkedGroupPolicyObjects = $ou.LinkedGroupPolicyObjects
            ManagedBy = $ou.ManagedBy
        }
        $ADAssessmentResults.OrganizationalUnits += $ouInfo
    }

    # Gather Groups
    Write-ADZTLog "Collecting group information..." "INFO"
    $groups = Get-ADGroup -Filter * -Properties *
    foreach ($group in $groups) {
        $members = Get-ADGroupMember -Identity $group.SamAccountName -ErrorAction SilentlyContinue
        $groupInfo = @{
            Name = $group.Name
            SamAccountName = $group.SamAccountName
            DistinguishedName = $group.DistinguishedName
            GroupCategory = $group.GroupCategory
            GroupScope = $group.GroupScope
            Description = $group.Description
            MemberCount = $members.Count
            Members = @($members | ForEach-Object { $_.SamAccountName })
            CreationDate = $group.whenCreated
            ModificationDate = $group.whenChanged
            ManagedBy = $group.ManagedBy
            IsPrivileged = ($group.Name -match "Admin|Domain|Enterprise|Schema")
        }
        $ADAssessmentResults.Groups += $groupInfo
    }

    # Gather Users
    Write-ADZTLog "Collecting user account information..." "INFO"
    $users = Get-ADUser -Filter * -Properties *
    foreach ($user in $users) {
        $userGroups = Get-ADPrincipalGroupMembership -Identity $user.SamAccountName -ErrorAction SilentlyContinue
        $userInfo = @{
            Name = $user.Name
            SamAccountName = $user.SamAccountName
            UserPrincipalName = $user.UserPrincipalName
            DistinguishedName = $user.DistinguishedName
            Enabled = $user.Enabled
            PasswordLastSet = $user.PasswordLastSet
            PasswordNeverExpires = $user.PasswordNeverExpires
            PasswordNotRequired = $user.PasswordNotRequired
            LastLogonDate = $user.LastLogonDate
            LastBadPasswordAttempt = $user.LastBadPasswordAttempt
            BadLogonCount = $user.BadLogonCount
            AccountLockoutTime = $user.AccountLockoutTime
            CreationDate = $user.whenCreated
            ModificationDate = $user.whenChanged
            Department = $user.Department
            Title = $user.Title
            Manager = $user.Manager
            Groups = @($userGroups | ForEach-Object { $_.Name })
            IsPrivileged = ($userGroups | Where-Object { $_.Name -match "Admin|Domain|Enterprise|Schema" }).Count -gt 0
            IsServiceAccount = ($user.ServicePrincipalNames.Count -gt 0)
            AccountExpirationDate = $user.AccountExpirationDate
            CannotChangePassword = $user.CannotChangePassword
            SmartcardLogonRequired = $user.SmartcardLogonRequired
            TrustedForDelegation = $user.TrustedForDelegation
            HomeDrive = $user.HomeDrive
            HomeDirectory = $user.HomeDirectory
            ProfilePath = $user.ProfilePath
            ScriptPath = $user.ScriptPath
        }
        
        # Calculate risk factors
        $riskFactors = @()
        if ($user.PasswordNeverExpires) { $riskFactors += "PasswordNeverExpires" }
        if ($user.PasswordNotRequired) { $riskFactors += "PasswordNotRequired" }
        if (!$user.LastLogonDate -or $user.LastLogonDate -lt (Get-Date).AddDays(-90)) { $riskFactors += "StaleAccount" }
        if ($user.BadLogonCount -gt 5) { $riskFactors += "HighBadLogonCount" }
        if ($userInfo.IsPrivileged -and !$user.SmartcardLogonRequired) { $riskFactors += "PrivilegedWithoutSmartcard" }
        if ($user.TrustedForDelegation) { $riskFactors += "TrustedForDelegation" }
        
        $userInfo.RiskFactors = $riskFactors
        $userInfo.RiskScore = $riskFactors.Count * 10
        
        $ADAssessmentResults.Users += $userInfo
    }

    # Identify Service Accounts
    Write-ADZTLog "Identifying service accounts..." "INFO"
    $serviceAccounts = $users | Where-Object { $_.ServicePrincipalNames.Count -gt 0 -or $_.Name -match "svc|service|sql|iis|app" }
    foreach ($svcAccount in $serviceAccounts) {
        $svcInfo = @{
            Name = $svcAccount.Name
            SamAccountName = $svcAccount.SamAccountName
            ServicePrincipalNames = $svcAccount.ServicePrincipalNames
            LastLogonDate = $svcAccount.LastLogonDate
            PasswordLastSet = $svcAccount.PasswordLastSet
            PasswordNeverExpires = $svcAccount.PasswordNeverExpires
            Enabled = $svcAccount.Enabled
            TrustedForDelegation = $svcAccount.TrustedForDelegation
            Groups = @((Get-ADPrincipalGroupMembership -Identity $svcAccount.SamAccountName -ErrorAction SilentlyContinue) | ForEach-Object { $_.Name })
        }
        $ADAssessmentResults.ServiceAccounts += $svcInfo
    }

    # Gather Computer Accounts
    Write-ADZTLog "Collecting computer account information..." "INFO"
    $computers = Get-ADComputer -Filter * -Properties *
    foreach ($computer in $computers) {
        $computerInfo = @{
            Name = $computer.Name
            DNSHostName = $computer.DNSHostName
            DistinguishedName = $computer.DistinguishedName
            OperatingSystem = $computer.OperatingSystem
            OperatingSystemVersion = $computer.OperatingSystemVersion
            OperatingSystemServicePack = $computer.OperatingSystemServicePack
            LastLogonDate = $computer.LastLogonDate
            PasswordLastSet = $computer.PasswordLastSet
            Enabled = $computer.Enabled
            TrustedForDelegation = $computer.TrustedForDelegation
            CreationDate = $computer.whenCreated
            ModificationDate = $computer.whenChanged
            ServicePrincipalNames = $computer.ServicePrincipalNames
            ManagedBy = $computer.ManagedBy
        }
        
        # Determine computer type
        if ($computer.OperatingSystem -match "Server") {
            $computerInfo.Type = "Server"
        } elseif ($computer.OperatingSystem -match "Windows") {
            $computerInfo.Type = "Workstation"
        } else {
            $computerInfo.Type = "Unknown"
        }
        
        # Calculate staleness
        if (!$computer.LastLogonDate -or $computer.LastLogonDate -lt (Get-Date).AddDays(-90)) {
            $computerInfo.IsStale = $true
        } else {
            $computerInfo.IsStale = $false
        }
        
        $ADAssessmentResults.Computers += $computerInfo
    }

    # Gather Group Policy Information
    Write-ADZTLog "Collecting Group Policy information..." "INFO"
    try {
        Import-Module GroupPolicy -ErrorAction SilentlyContinue
        $groupPolicies = Get-GPO -All -ErrorAction SilentlyContinue
        foreach ($gpo in $groupPolicies) {
            $gpoInfo = @{
                DisplayName = $gpo.DisplayName
                Id = $gpo.Id
                GpoStatus = $gpo.GpoStatus
                CreationTime = $gpo.CreationTime
                ModificationTime = $gpo.ModificationTime
                Description = $gpo.Description
                Owner = $gpo.Owner
                WmiFilter = $gpo.WmiFilter
            }
            
            # Get GPO links
            try {
                $gpoLinks = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue
                if ($gpoLinks) {
                    $gpoInfo.LinksTo = @()
                    # Parse XML to extract link information (simplified)
                    $gpoInfo.HasLinks = $true
                } else {
                    $gpoInfo.HasLinks = $false
                }
            } catch {
                $gpoInfo.HasLinks = $false
            }
            
            $ADAssessmentResults.GroupPolicies += $gpoInfo
        }
    } catch {
        Write-ADZTLog "Group Policy module not available or insufficient permissions" "WARNING"
    }

    # Gather Trust Relationships
    Write-ADZTLog "Collecting trust relationship information..." "INFO"
    try {
        $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue
        foreach ($trust in $trusts) {
            $trustInfo = @{
                Name = $trust.Name
                TrustType = $trust.TrustType
                TrustDirection = $trust.Direction
                ForestTransitive = $trust.ForestTransitive
                SelectiveAuthentication = $trust.SelectiveAuthentication
                SIDFilteringForestAware = $trust.SIDFilteringForestAware
                SIDFilteringQuarantined = $trust.SIDFilteringQuarantined
                TGTDelegation = $trust.TGTDelegation
                TrustAttributes = $trust.TrustAttributes
                CreationDate = $trust.whenCreated
                ModificationDate = $trust.whenChanged
            }
            $ADAssessmentResults.TrustRelationships += $trustInfo
        }
    } catch {
        Write-ADZTLog "Unable to collect trust information - insufficient permissions" "WARNING"
    }

    # Gather DNS Configuration
    Write-ADZTLog "Collecting DNS configuration..." "INFO"
    try {
        $dnsZones = Get-DnsServerZone -ErrorAction SilentlyContinue
        $ADAssessmentResults.DNSConfiguration = @{
            Zones = @()
            Forwarders = @()
        }
        
        foreach ($zone in $dnsZones) {
            $zoneInfo = @{
                ZoneName = $zone.ZoneName
                ZoneType = $zone.ZoneType
                DynamicUpdate = $zone.DynamicUpdate
                SecureSecondaries = $zone.SecureSecondaries
                IsAutoCreated = $zone.IsAutoCreated
                IsDsIntegrated = $zone.IsDsIntegrated
                IsReverseLookupZone = $zone.IsReverseLookupZone
                IsSigned = $zone.IsSigned
            }
            $ADAssessmentResults.DNSConfiguration.Zones += $zoneInfo
        }
        
        $forwarders = Get-DnsServerForwarder -ErrorAction SilentlyContinue
        if ($forwarders) {
            $ADAssessmentResults.DNSConfiguration.Forwarders = $forwarders.IPAddress
        }
    } catch {
        Write-ADZTLog "Unable to collect DNS information - insufficient permissions or DNS role not installed" "WARNING"
    }

    # Gather Security Settings
    Write-ADZTLog "Collecting security configuration..." "INFO"
    $ADAssessmentResults.SecuritySettings = @{
        PasswordPolicy = @{}
        AccountLockoutPolicy = @{}
        KerberosPolicy = @{}
        AuditPolicy = @{}
    }

    try {
        # Password Policy
        $passwordPolicy = Get-ADDefaultDomainPasswordPolicy
        $ADAssessmentResults.SecuritySettings.PasswordPolicy = @{
            ComplexityEnabled = $passwordPolicy.ComplexityEnabled
            LockoutDuration = $passwordPolicy.LockoutDuration
            LockoutObservationWindow = $passwordPolicy.LockoutObservationWindow
            LockoutThreshold = $passwordPolicy.LockoutThreshold
            MaxPasswordAge = $passwordPolicy.MaxPasswordAge
            MinPasswordAge = $passwordPolicy.MinPasswordAge
            MinPasswordLength = $passwordPolicy.MinPasswordLength
            PasswordHistoryCount = $passwordPolicy.PasswordHistoryCount
            ReversibleEncryptionEnabled = $passwordPolicy.ReversibleEncryptionEnabled
        }
    } catch {
        Write-ADZTLog "Unable to collect password policy information" "WARNING"
    }

    # Generate Security Recommendations
    Write-ADZTLog "Generating security recommendations..." "INFO"
    $recommendations = @()

    # Check for weak password policies
    if ($ADAssessmentResults.SecuritySettings.PasswordPolicy.MinPasswordLength -lt 12) {
        $recommendations += @{
            Category = "Password Policy"
            Severity = "High"
            Issue = "Minimum password length is less than 12 characters"
            Recommendation = "Increase minimum password length to at least 12 characters"
            ZeroTrustPrinciple = "Verify Explicitly"
        }
    }

    # Check for privileged accounts without smartcard requirement
    $privilegedWithoutSmartcard = $ADAssessmentResults.Users | Where-Object { $_.IsPrivileged -and !$_.SmartcardLogonRequired }
    if ($privilegedWithoutSmartcard.Count -gt 0) {
        $recommendations += @{
            Category = "Identity Security"
            Severity = "High"
            Issue = "$($privilegedWithoutSmartcard.Count) privileged accounts do not require smartcard authentication"
            Recommendation = "Enable smartcard requirement for all privileged accounts"
            ZeroTrustPrinciple = "Verify Explicitly"
            AffectedAccounts = $privilegedWithoutSmartcard.SamAccountName
        }
    }

    # Check for stale accounts
    $staleAccounts = $ADAssessmentResults.Users | Where-Object { $_.RiskFactors -contains "StaleAccount" }
    if ($staleAccounts.Count -gt 0) {
        $recommendations += @{
            Category = "Account Hygiene"
            Severity = "Medium"
            Issue = "$($staleAccounts.Count) user accounts have not logged in within 90 days"
            Recommendation = "Review and disable or remove stale accounts"
            ZeroTrustPrinciple = "Use Least Privilege Access"
        }
    }

    # Check for accounts with passwords that never expire
    $passwordNeverExpires = $ADAssessmentResults.Users | Where-Object { $_.PasswordNeverExpires }
    if ($passwordNeverExpires.Count -gt 0) {
        $recommendations += @{
            Category = "Password Security"
            Severity = "Medium"
            Issue = "$($passwordNeverExpires.Count) accounts have passwords set to never expire"
            Recommendation = "Enable password expiration for all accounts or implement alternative authentication methods"
            ZeroTrustPrinciple = "Verify Explicitly"
        }
    }

    # Check for service accounts in privileged groups
    $privilegedServiceAccounts = $ADAssessmentResults.ServiceAccounts | Where-Object { 
        $_.Groups | Where-Object { $_ -match "Admin|Domain|Enterprise|Schema" }
    }
    if ($privilegedServiceAccounts.Count -gt 0) {
        $recommendations += @{
            Category = "Service Account Security"
            Severity = "High"
            Issue = "$($privilegedServiceAccounts.Count) service accounts have privileged group memberships"
            Recommendation = "Review service account permissions and implement least privilege access"
            ZeroTrustPrinciple = "Use Least Privilege Access"
        }
    }

    # Check for computers with delegation enabled
    $delegationEnabled = $ADAssessmentResults.Computers | Where-Object { $_.TrustedForDelegation }
    if ($delegationEnabled.Count -gt 0) {
        $recommendations += @{
            Category = "Delegation Security"
            Severity = "Medium"
            Issue = "$($delegationEnabled.Count) computers are trusted for delegation"
            Recommendation = "Review delegation settings and implement constrained delegation where possible"
            ZeroTrustPrinciple = "Assume Breach"
        }
    }

    $ADAssessmentResults.Recommendations = $recommendations

    # Generate summary statistics
    $ADAssessmentResults.Summary = @{
        TotalUsers = $ADAssessmentResults.Users.Count
        EnabledUsers = ($ADAssessmentResults.Users | Where-Object { $_.Enabled }).Count
        PrivilegedUsers = ($ADAssessmentResults.Users | Where-Object { $_.IsPrivileged }).Count
        ServiceAccounts = $ADAssessmentResults.ServiceAccounts.Count
        TotalGroups = $ADAssessmentResults.Groups.Count
        PrivilegedGroups = ($ADAssessmentResults.Groups | Where-Object { $_.IsPrivileged }).Count
        TotalComputers = $ADAssessmentResults.Computers.Count
        Servers = ($ADAssessmentResults.Computers | Where-Object { $_.Type -eq "Server" }).Count
        Workstations = ($ADAssessmentResults.Computers | Where-Object { $_.Type -eq "Workstation" }).Count
        StaleComputers = ($ADAssessmentResults.Computers | Where-Object { $_.IsStale }).Count
        DomainControllers = $ADAssessmentResults.DomainControllers.Count
        OrganizationalUnits = $ADAssessmentResults.OrganizationalUnits.Count
        GroupPolicies = $ADAssessmentResults.GroupPolicies.Count
        TrustRelationships = $ADAssessmentResults.TrustRelationships.Count
        HighRiskRecommendations = ($recommendations | Where-Object { $_.Severity -eq "High" }).Count
        MediumRiskRecommendations = ($recommendations | Where-Object { $_.Severity -eq "Medium" }).Count
        LowRiskRecommendations = ($recommendations | Where-Object { $_.Severity -eq "Low" }).Count
    }

    Write-ADZTLog "Assessment completed successfully" "INFO"

} catch {
    Write-ADZTLog "Error during assessment: $($_.Exception.Message)" "ERROR"
    $ADAssessmentResults.Error = $_.Exception.Message
}

# Export results to JSON
$jsonOutput = $ADAssessmentResults | ConvertTo-Json -Depth 10
$outputFile = "$OutputPath\AD_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$jsonOutput | Out-File -FilePath $outputFile -Encoding UTF8

Write-ADZTLog "Results exported to: $outputFile" "INFO"

# Export summary report
$summaryReport = @"
# ADZero Trust Assessment Summary Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Domain: $($ADAssessmentResults.DomainInfo.Name)

## Environment Overview
- Total Users: $($ADAssessmentResults.Summary.TotalUsers)
- Enabled Users: $($ADAssessmentResults.Summary.EnabledUsers)
- Privileged Users: $($ADAssessmentResults.Summary.PrivilegedUsers)
- Service Accounts: $($ADAssessmentResults.Summary.ServiceAccounts)
- Total Computers: $($ADAssessmentResults.Summary.TotalComputers)
- Domain Controllers: $($ADAssessmentResults.Summary.DomainControllers)

## Security Recommendations
- High Risk Issues: $($ADAssessmentResults.Summary.HighRiskRecommendations)
- Medium Risk Issues: $($ADAssessmentResults.Summary.MediumRiskRecommendations)
- Low Risk Issues: $($ADAssessmentResults.Summary.LowRiskRecommendations)

## Top Recommendations
$($recommendations | Where-Object { $_.Severity -eq "High" } | ForEach-Object { "- $($_.Issue): $($_.Recommendation)" } | Select-Object -First 5 | Out-String)

For detailed analysis, please review the complete JSON output file.
"@

$summaryFile = "$OutputPath\AD_Assessment_Summary_$(Get-Date -Format 'yyyyMMdd_HHmmss').md"
$summaryReport | Out-File -FilePath $summaryFile -Encoding UTF8

Write-ADZTLog "Summary report exported to: $summaryFile" "INFO"
Write-ADZTLog "AD Zero Trust Information Gathering completed" "INFO"

# Return the results object for pipeline usage
return $ADAssessmentResults


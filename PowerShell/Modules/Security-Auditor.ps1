# Security-Auditor.ps1
# ADZero Trust - Security Configuration Auditor Module
# Author: Moazzam Jafri
# Description: Comprehensive security configuration and policy auditing for Zero Trust assessment

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\ADZeroTrust_Output",
    
    [Parameter(Mandatory=$false)]
    [string]$Domain = $env:USERDOMAIN,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeNetworkScan = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeServiceScan = $true,
    
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
    $logMessage = "[$timestamp] [$Level] [Security-Auditor] $Message"
    Write-Host $logMessage
    if (!(Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
    Add-Content -Path "$LogPath\SecurityAuditor.log" -Value $logMessage
}

# Helper function to check Windows security features
function Test-WindowsSecurityFeature {
    param(
        [string]$FeatureName,
        [string]$RegistryPath,
        [string]$ValueName,
        [object]$ExpectedValue
    )
    
    try {
        if (Test-Path $RegistryPath) {
            $actualValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue
            if ($actualValue) {
                return @{
                    Feature = $FeatureName
                    Status = if ($actualValue.$ValueName -eq $ExpectedValue) { "Enabled" } else { "Disabled" }
                    ActualValue = $actualValue.$ValueName
                    ExpectedValue = $ExpectedValue
                    Compliant = ($actualValue.$ValueName -eq $ExpectedValue)
                }
            }
        }
        return @{
            Feature = $FeatureName
            Status = "Not Found"
            ActualValue = $null
            ExpectedValue = $ExpectedValue
            Compliant = $false
        }
    } catch {
        return @{
            Feature = $FeatureName
            Status = "Error"
            ActualValue = $null
            ExpectedValue = $ExpectedValue
            Compliant = $false
            Error = $_.Exception.Message
        }
    }
}

# Helper function to analyze service configuration
function Analyze-ServiceSecurity {
    param(
        [string]$ServiceName
    )
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (!$service) { return $null }
        
        $serviceInfo = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        
        $analysis = @{
            ServiceName = $ServiceName
            DisplayName = $service.DisplayName
            Status = $service.Status
            StartType = $service.StartType
            ServiceType = if ($serviceInfo) { $serviceInfo.ServiceType } else { "Unknown" }
            StartName = if ($serviceInfo) { $serviceInfo.StartName } else { "Unknown" }
            PathName = if ($serviceInfo) { $serviceInfo.PathName } else { "Unknown" }
            RiskFactors = @()
            RiskScore = 0
        }
        
        # Analyze security risks
        if ($serviceInfo.StartName -eq "LocalSystem") {
            $analysis.RiskFactors += "RunsAsLocalSystem"
            $analysis.RiskScore += 15
        }
        
        if ($service.StartType -eq "Automatic" -and $service.Status -eq "Stopped") {
            $analysis.RiskFactors += "AutoStartButStopped"
            $analysis.RiskScore += 5
        }
        
        if ($serviceInfo.PathName -and $serviceInfo.PathName -notmatch "^`".*`"$" -and $serviceInfo.PathName -match " ") {
            $analysis.RiskFactors += "UnquotedServicePath"
            $analysis.RiskScore += 20
        }
        
        if ($serviceInfo.StartName -match "Administrator|Admin") {
            $analysis.RiskFactors += "RunsAsAdmin"
            $analysis.RiskScore += 25
        }
        
        $analysis.RiskLevel = if ($analysis.RiskScore -ge 30) { "High" } elseif ($analysis.RiskScore -ge 15) { "Medium" } else { "Low" }
        
        return $analysis
    } catch {
        return $null
    }
}

# Create output directory
if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-ADZTLog "Starting Security Configuration Audit for Zero Trust Assessment" "INFO"

# Initialize security audit results
$SecurityAuditResults = @{
    AuditInfo = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Domain = $Domain
        ComputerName = $env:COMPUTERNAME
        IncludeNetworkScan = $IncludeNetworkScan
        IncludeServiceScan = $IncludeServiceScan
        Version = "1.0"
        Author = "Moazzam Jafri - ADZero Trust"
    }
    PasswordPolicies = @{}
    AccountPolicies = @{}
    AuditPolicies = @{}
    SecurityOptions = @{}
    WindowsSecurityFeatures = @()
    ServiceSecurity = @()
    NetworkSecurity = @{}
    EncryptionStatus = @{}
    ComplianceChecks = @{}
    ZeroTrustReadiness = @{}
    SecurityBaseline = @{}
    Recommendations = @()
}

try {
    # Audit Password Policies
    Write-ADZTLog "Auditing password policies..." "INFO"
    
    try {
        $defaultPasswordPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
        if ($defaultPasswordPolicy) {
            $SecurityAuditResults.PasswordPolicies = @{
                ComplexityEnabled = $defaultPasswordPolicy.ComplexityEnabled
                LockoutDuration = $defaultPasswordPolicy.LockoutDuration.TotalMinutes
                LockoutObservationWindow = $defaultPasswordPolicy.LockoutObservationWindow.TotalMinutes
                LockoutThreshold = $defaultPasswordPolicy.LockoutThreshold
                MaxPasswordAge = $defaultPasswordPolicy.MaxPasswordAge.TotalDays
                MinPasswordAge = $defaultPasswordPolicy.MinPasswordAge.TotalDays
                MinPasswordLength = $defaultPasswordPolicy.MinPasswordLength
                PasswordHistoryCount = $defaultPasswordPolicy.PasswordHistoryCount
                ReversibleEncryptionEnabled = $defaultPasswordPolicy.ReversibleEncryptionEnabled
                
                # Compliance assessment
                ComplexityCompliant = $defaultPasswordPolicy.ComplexityEnabled
                LengthCompliant = ($defaultPasswordPolicy.MinPasswordLength -ge 12)
                AgeCompliant = ($defaultPasswordPolicy.MaxPasswordAge.TotalDays -le 365 -and $defaultPasswordPolicy.MaxPasswordAge.TotalDays -gt 0)
                HistoryCompliant = ($defaultPasswordPolicy.PasswordHistoryCount -ge 12)
                LockoutCompliant = ($defaultPasswordPolicy.LockoutThreshold -gt 0 -and $defaultPasswordPolicy.LockoutThreshold -le 10)
                ReversibleEncryptionCompliant = (!$defaultPasswordPolicy.ReversibleEncryptionEnabled)
            }
        }
        
        # Check for Fine-Grained Password Policies
        $fineGrainedPolicies = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
        $SecurityAuditResults.PasswordPolicies.FineGrainedPolicies = @()
        foreach ($fgpp in $fineGrainedPolicies) {
            $fgppInfo = @{
                Name = $fgpp.Name
                Precedence = $fgpp.Precedence
                MinPasswordLength = $fgpp.MinPasswordLength
                ComplexityEnabled = $fgpp.ComplexityEnabled
                MaxPasswordAge = $fgpp.MaxPasswordAge.TotalDays
                AppliesTo = $fgpp.AppliesTo
            }
            $SecurityAuditResults.PasswordPolicies.FineGrainedPolicies += $fgppInfo
        }
        
    } catch {
        Write-ADZTLog "Unable to retrieve password policies: $($_.Exception.Message)" "WARNING"
    }

    # Audit Account Policies
    Write-ADZTLog "Auditing account policies..." "INFO"
    
    $accountPolicies = @{
        # Kerberos Policy
        KerberosMaxTicketAge = $null
        KerberosMaxRenewalAge = $null
        KerberosMaxClockSkew = $null
        
        # Account Lockout Policy (already covered in password policies)
        LockoutDuration = $SecurityAuditResults.PasswordPolicies.LockoutDuration
        LockoutThreshold = $SecurityAuditResults.PasswordPolicies.LockoutThreshold
        LockoutObservationWindow = $SecurityAuditResults.PasswordPolicies.LockoutObservationWindow
    }
    
    # Try to get Kerberos policy from registry
    try {
        $kerberosPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -ErrorAction SilentlyContinue
        if ($kerberosPolicy) {
            $accountPolicies.KerberosMaxTicketAge = $kerberosPolicy.MaxTicketAge
            $accountPolicies.KerberosMaxRenewalAge = $kerberosPolicy.MaxRenewalAge
            $accountPolicies.KerberosMaxClockSkew = $kerberosPolicy.MaxClockSkew
        }
    } catch {
        Write-ADZTLog "Unable to retrieve Kerberos policy settings" "WARNING"
    }
    
    $SecurityAuditResults.AccountPolicies = $accountPolicies

    # Audit Security Options
    Write-ADZTLog "Auditing security options..." "INFO"
    
    $securityOptions = @{
        # Network security options
        LmCompatibilityLevel = $null
        NtlmMinClientSec = $null
        NtlmMinServerSec = $null
        RequireSignOrSeal = $null
        
        # Interactive logon options
        DontDisplayLastUserName = $null
        RequireCtrlAltDel = $null
        MachineInactivityLimit = $null
        
        # Network access options
        RestrictAnonymous = $null
        RestrictAnonymousSAM = $null
        EveryoneIncludesAnonymous = $null
        
        # Account options
        EnableGuestAccount = $null
        RenameAdminAccount = $null
        RenameGuestAccount = $null
    }
    
    # Check various security settings from registry
    $securitySettings = @{
        "LmCompatibilityLevel" = @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Value = "LmCompatibilityLevel" }
        "NtlmMinClientSec" = @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Value = "NtlmMinClientSec" }
        "NtlmMinServerSec" = @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Value = "NtlmMinServerSec" }
        "RequireSignOrSeal" = @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Value = "RequireSignOrSeal" }
        "DontDisplayLastUserName" = @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Value = "DontDisplayLastUserName" }
        "RequireCtrlAltDel" = @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Value = "DisableCAD" }
        "RestrictAnonymous" = @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Value = "RestrictAnonymous" }
        "RestrictAnonymousSAM" = @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Value = "RestrictAnonymousSAM" }
        "EveryoneIncludesAnonymous" = @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Value = "EveryoneIncludesAnonymous" }
    }
    
    foreach ($setting in $securitySettings.Keys) {
        try {
            $regPath = $securitySettings[$setting].Path
            $valueName = $securitySettings[$setting].Value
            
            if (Test-Path $regPath) {
                $value = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
                if ($value) {
                    $securityOptions[$setting] = $value.$valueName
                }
            }
        } catch {
            Write-ADZTLog "Unable to read security setting: $setting" "WARNING"
        }
    }
    
    $SecurityAuditResults.SecurityOptions = $securityOptions

    # Audit Windows Security Features
    Write-ADZTLog "Auditing Windows security features..." "INFO"
    
    $securityFeatures = @(
        @{ Name = "Windows Defender"; Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender"; Value = "DisableAntiSpyware"; Expected = 0 },
        @{ Name = "Windows Firewall Domain"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"; Value = "EnableFirewall"; Expected = 1 },
        @{ Name = "Windows Firewall Private"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"; Value = "EnableFirewall"; Expected = 1 },
        @{ Name = "Windows Firewall Public"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"; Value = "EnableFirewall"; Expected = 1 },
        @{ Name = "UAC"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Value = "EnableLUA"; Expected = 1 },
        @{ Name = "UAC Admin Approval Mode"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Value = "FilterAdministratorToken"; Expected = 1 },
        @{ Name = "DEP"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Value = "ExecuteOptions"; Expected = 3 },
        @{ Name = "ASLR"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Value = "MoveImages"; Expected = 1 },
        @{ Name = "SMB Signing Required"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Value = "RequireSecuritySignature"; Expected = 1 },
        @{ Name = "LDAP Signing Required"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"; Value = "LDAPServerIntegrity"; Expected = 2 }
    )
    
    foreach ($feature in $securityFeatures) {
        $result = Test-WindowsSecurityFeature -FeatureName $feature.Name -RegistryPath $feature.Path -ValueName $feature.Value -ExpectedValue $feature.Expected
        $SecurityAuditResults.WindowsSecurityFeatures += $result
    }

    # Audit Service Security
    if ($IncludeServiceScan) {
        Write-ADZTLog "Auditing service security configurations..." "INFO"
        
        $criticalServices = @(
            "Spooler", "RemoteRegistry", "Telnet", "SNMP", "SSDPSRV", "upnphost",
            "Browser", "Messenger", "NetDDE", "NetDDEdsdm", "RpcSs", "W32Time",
            "Themes", "AudioSrv", "Fax", "TapiSrv", "SCardSvr", "Schedule",
            "Alerter", "ClipSrv", "Dhcp", "Dnscache", "EventLog", "lanmanserver",
            "lanmanworkstation", "LmHosts", "PlugPlay", "ProtectedStorage",
            "RasMan", "RpcLocator", "SamSs", "seclogon", "SENS", "SharedAccess",
            "ShellHWDetection", "Spooler", "srservice", "SSDPSRV", "stisvc",
            "TrkWks", "upnphost", "UPS", "VSS", "WinMgmt", "Wmi", "WmdmPmSN",
            "Wuauserv", "WZCSVC", "xmlprov"
        )
        
        foreach ($serviceName in $criticalServices) {
            $serviceAnalysis = Analyze-ServiceSecurity -ServiceName $serviceName
            if ($serviceAnalysis) {
                $SecurityAuditResults.ServiceSecurity += $serviceAnalysis
            }
        }
    }

    # Audit Network Security
    Write-ADZTLog "Auditing network security configurations..." "INFO"
    
    $networkSecurity = @{
        FirewallProfiles = @{}
        NetworkShares = @()
        OpenPorts = @()
        NetworkProtocols = @{}
    }
    
    # Check Windows Firewall profiles
    try {
        $firewallProfiles = @("Domain", "Private", "Public")
        foreach ($profile in $firewallProfiles) {
            $profileStatus = Get-NetFirewallProfile -Name $profile -ErrorAction SilentlyContinue
            if ($profileStatus) {
                $networkSecurity.FirewallProfiles[$profile] = @{
                    Enabled = $profileStatus.Enabled
                    DefaultInboundAction = $profileStatus.DefaultInboundAction
                    DefaultOutboundAction = $profileStatus.DefaultOutboundAction
                    AllowInboundRules = $profileStatus.AllowInboundRules
                    AllowLocalFirewallRules = $profileStatus.AllowLocalFirewallRules
                    AllowLocalIPsecRules = $profileStatus.AllowLocalIPsecRules
                    AllowUserApps = $profileStatus.AllowUserApps
                    AllowUserPorts = $profileStatus.AllowUserPorts
                    AllowUnicastResponseToMulticast = $profileStatus.AllowUnicastResponseToMulticast
                    NotifyOnListen = $profileStatus.NotifyOnListen
                    EnableStealthModeForIPsec = $profileStatus.EnableStealthModeForIPsec
                    LogAllowed = $profileStatus.LogAllowed
                    LogBlocked = $profileStatus.LogBlocked
                    LogIgnored = $profileStatus.LogIgnored
                    LogFileName = $profileStatus.LogFileName
                    LogMaxSizeKilobytes = $profileStatus.LogMaxSizeKilobytes
                }
            }
        }
    } catch {
        Write-ADZTLog "Unable to retrieve firewall profile information" "WARNING"
    }
    
    # Check network shares
    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue
        foreach ($share in $shares) {
            if ($share.Name -notin @("ADMIN$", "C$", "IPC$", "print$")) {
                $shareInfo = @{
                    Name = $share.Name
                    Path = $share.Path
                    Description = $share.Description
                    ShareType = $share.ShareType
                    CurrentUsers = $share.CurrentUsers
                    CachingMode = $share.CachingMode
                }
                $networkSecurity.NetworkShares += $shareInfo
            }
        }
    } catch {
        Write-ADZTLog "Unable to enumerate network shares" "WARNING"
    }
    
    # Check for open ports (basic check)
    if ($IncludeNetworkScan) {
        try {
            $openPorts = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | 
                         Select-Object LocalAddress, LocalPort, OwningProcess | 
                         Sort-Object LocalPort -Unique
            
            foreach ($port in $openPorts) {
                $process = Get-Process -Id $port.OwningProcess -ErrorAction SilentlyContinue
                $portInfo = @{
                    LocalAddress = $port.LocalAddress
                    LocalPort = $port.LocalPort
                    OwningProcess = $port.OwningProcess
                    ProcessName = if ($process) { $process.ProcessName } else { "Unknown" }
                    ProcessPath = if ($process) { $process.Path } else { "Unknown" }
                }
                $networkSecurity.OpenPorts += $portInfo
            }
        } catch {
            Write-ADZTLog "Unable to enumerate open ports" "WARNING"
        }
    }
    
    $SecurityAuditResults.NetworkSecurity = $networkSecurity

    # Audit Encryption Status
    Write-ADZTLog "Auditing encryption configurations..." "INFO"
    
    $encryptionStatus = @{
        BitLockerStatus = @{}
        EFSStatus = @{}
        TLSConfiguration = @{}
        CertificateStore = @{}
    }
    
    # Check BitLocker status
    try {
        $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
        foreach ($volume in $bitlockerVolumes) {
            $encryptionStatus.BitLockerStatus[$volume.MountPoint] = @{
                VolumeStatus = $volume.VolumeStatus
                EncryptionPercentage = $volume.EncryptionPercentage
                KeyProtector = $volume.KeyProtector
                AutoUnlockEnabled = $volume.AutoUnlockEnabled
                ProtectionStatus = $volume.ProtectionStatus
            }
        }
    } catch {
        Write-ADZTLog "BitLocker module not available or insufficient permissions" "WARNING"
    }
    
    # Check EFS status
    try {
        $efsInfo = @{
            EFSEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EFS" -Name "EfsConfiguration" -ErrorAction SilentlyContinue) -ne $null
            EFSPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableEFS" -ErrorAction SilentlyContinue
        }
        $encryptionStatus.EFSStatus = $efsInfo
    } catch {
        Write-ADZTLog "Unable to check EFS configuration" "WARNING"
    }
    
    # Check TLS configuration
    try {
        $tlsConfig = @{
            TLS10Enabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
            TLS11Enabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
            TLS12Enabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
            TLS13Enabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
        }
        $encryptionStatus.TLSConfiguration = $tlsConfig
    } catch {
        Write-ADZTLog "Unable to check TLS configuration" "WARNING"
    }
    
    $SecurityAuditResults.EncryptionStatus = $encryptionStatus

    # Compliance Checks
    Write-ADZTLog "Performing compliance checks..." "INFO"
    
    $complianceChecks = @{
        NIST = @{
            PasswordComplexity = $SecurityAuditResults.PasswordPolicies.ComplexityCompliant
            PasswordLength = $SecurityAuditResults.PasswordPolicies.LengthCompliant
            AccountLockout = $SecurityAuditResults.PasswordPolicies.LockoutCompliant
            AuditLogging = $false  # Would need additional checks
            AccessControl = $false  # Would need additional checks
            OverallScore = 0
        }
        CIS = @{
            PasswordPolicy = $SecurityAuditResults.PasswordPolicies.ComplexityCompliant -and $SecurityAuditResults.PasswordPolicies.LengthCompliant
            AccountPolicy = $SecurityAuditResults.PasswordPolicies.LockoutCompliant
            SecurityOptions = $false  # Would need comprehensive checks
            WindowsFirewall = $false  # Check firewall status
            ServicesConfiguration = $false  # Would need service analysis
            OverallScore = 0
        }
        ISO27001 = @{
            AccessControl = $false
            Cryptography = $false
            OperationsSecurity = $false
            CommunicationsSecurity = $false
            SystemAcquisition = $false
            OverallScore = 0
        }
    }
    
    # Calculate NIST compliance score
    $nistChecks = @($complianceChecks.NIST.PasswordComplexity, $complianceChecks.NIST.PasswordLength, $complianceChecks.NIST.AccountLockout)
    $complianceChecks.NIST.OverallScore = [math]::Round(($nistChecks | Where-Object { $_ }).Count / $nistChecks.Count * 100, 2)
    
    # Calculate CIS compliance score
    $cisChecks = @($complianceChecks.CIS.PasswordPolicy, $complianceChecks.CIS.AccountPolicy)
    $complianceChecks.CIS.OverallScore = [math]::Round(($cisChecks | Where-Object { $_ }).Count / $cisChecks.Count * 100, 2)
    
    $SecurityAuditResults.ComplianceChecks = $complianceChecks

    # Zero Trust Readiness Assessment
    Write-ADZTLog "Assessing Zero Trust readiness..." "INFO"
    
    $zeroTrustReadiness = @{
        VerifyExplicitly = @{
            StrongAuthentication = @{
                Score = if ($SecurityAuditResults.PasswordPolicies.ComplexityCompliant -and $SecurityAuditResults.PasswordPolicies.LengthCompliant) { 70 } else { 30 }
                Status = if ($SecurityAuditResults.PasswordPolicies.ComplexityCompliant -and $SecurityAuditResults.PasswordPolicies.LengthCompliant) { "Good" } else { "Poor" }
                Recommendation = "Implement multi-factor authentication and strong password policies"
            }
            
            DeviceCompliance = @{
                Score = 0  # Would need device management assessment
                Status = "Needs Assessment"
                Recommendation = "Implement device compliance and management solutions"
            }
            
            UserBehaviorAnalytics = @{
                Score = 0  # Would need UBA solution assessment
                Status = "Not Implemented"
                Recommendation = "Deploy user and entity behavior analytics (UEBA) solutions"
            }
        }
        
        LeastPrivilegeAccess = @{
            PrivilegedAccessManagement = @{
                Score = 0  # Would need PAM assessment
                Status = "Needs Assessment"
                Recommendation = "Implement privileged access management (PAM) solutions"
            }
            
            JustInTimeAccess = @{
                Score = 0  # Would need JIT assessment
                Status = "Not Implemented"
                Recommendation = "Deploy just-in-time access controls"
            }
            
            RoleBasedAccess = @{
                Score = 0  # Would need RBAC assessment
                Status = "Needs Assessment"
                Recommendation = "Implement comprehensive role-based access control"
            }
        }
        
        AssumeBreachPreparation = @{
            NetworkSegmentation = @{
                Score = if ($SecurityAuditResults.NetworkSecurity.FirewallProfiles.Domain.Enabled) { 40 } else { 0 }
                Status = if ($SecurityAuditResults.NetworkSecurity.FirewallProfiles.Domain.Enabled) { "Basic" } else { "Poor" }
                Recommendation = "Implement micro-segmentation and zero trust network architecture"
            }
            
            EncryptionEverywhere = @{
                Score = 0  # Would need comprehensive encryption assessment
                Status = "Needs Assessment"
                Recommendation = "Implement end-to-end encryption for data at rest and in transit"
            }
            
            ContinuousMonitoring = @{
                Score = 0  # Would need monitoring solution assessment
                Status = "Not Implemented"
                Recommendation = "Deploy comprehensive security monitoring and SIEM solutions"
            }
        }
    }
    
    # Calculate overall Zero Trust readiness
    $totalScore = 0
    $scoreCount = 0
    
    foreach ($principle in $zeroTrustReadiness.Keys) {
        foreach ($metric in $zeroTrustReadiness[$principle].Keys) {
            $totalScore += $zeroTrustReadiness[$principle][$metric].Score
            $scoreCount++
        }
    }
    
    $zeroTrustReadiness.OverallReadiness = @{
        Score = if ($scoreCount -gt 0) { [math]::Round($totalScore / $scoreCount, 2) } else { 0 }
        MaturityLevel = if ($scoreCount -gt 0) {
            $avgScore = $totalScore / $scoreCount
            if ($avgScore -ge 80) { "Advanced" } elseif ($avgScore -ge 60) { "Intermediate" } elseif ($avgScore -ge 40) { "Initial" } else { "Traditional" }
        } else { "Unknown" }
    }
    
    $SecurityAuditResults.ZeroTrustReadiness = $zeroTrustReadiness

    # Security Baseline Assessment
    Write-ADZTLog "Performing security baseline assessment..." "INFO"
    
    $securityBaseline = @{
        WindowsSecurityBaseline = @{
            CompliantFeatures = ($SecurityAuditResults.WindowsSecurityFeatures | Where-Object { $_.Compliant }).Count
            TotalFeatures = $SecurityAuditResults.WindowsSecurityFeatures.Count
            CompliancePercentage = if ($SecurityAuditResults.WindowsSecurityFeatures.Count -gt 0) { 
                [math]::Round((($SecurityAuditResults.WindowsSecurityFeatures | Where-Object { $_.Compliant }).Count / $SecurityAuditResults.WindowsSecurityFeatures.Count) * 100, 2) 
            } else { 0 }
        }
        
        ServiceSecurityBaseline = @{
            LowRiskServices = ($SecurityAuditResults.ServiceSecurity | Where-Object { $_.RiskLevel -eq "Low" }).Count
            MediumRiskServices = ($SecurityAuditResults.ServiceSecurity | Where-Object { $_.RiskLevel -eq "Medium" }).Count
            HighRiskServices = ($SecurityAuditResults.ServiceSecurity | Where-Object { $_.RiskLevel -eq "High" }).Count
            TotalServices = $SecurityAuditResults.ServiceSecurity.Count
        }
        
        NetworkSecurityBaseline = @{
            FirewallEnabled = ($SecurityAuditResults.NetworkSecurity.FirewallProfiles.Values | Where-Object { $_.Enabled }).Count
            TotalProfiles = $SecurityAuditResults.NetworkSecurity.FirewallProfiles.Count
            SecureShares = ($SecurityAuditResults.NetworkSecurity.NetworkShares | Where-Object { $_.Name -notmatch "temp|tmp|public" }).Count
            TotalShares = $SecurityAuditResults.NetworkSecurity.NetworkShares.Count
        }
    }
    
    $SecurityAuditResults.SecurityBaseline = $securityBaseline

    # Generate Recommendations
    Write-ADZTLog "Generating security recommendations..." "INFO"
    $recommendations = @()
    
    # Password policy recommendations
    if (!$SecurityAuditResults.PasswordPolicies.ComplexityCompliant) {
        $recommendations += @{
            Category = "Password Policy"
            Priority = "High"
            Issue = "Password complexity is not enabled"
            Recommendation = "Enable password complexity requirements"
            ZeroTrustPrinciple = "Verify Explicitly"
            Implementation = @(
                "Enable password complexity in Group Policy",
                "Require passwords to contain uppercase, lowercase, numbers, and symbols",
                "Consider implementing passphrase policies",
                "Deploy multi-factor authentication"
            )
        }
    }
    
    if (!$SecurityAuditResults.PasswordPolicies.LengthCompliant) {
        $recommendations += @{
            Category = "Password Policy"
            Priority = "High"
            Issue = "Minimum password length is less than 12 characters"
            Recommendation = "Increase minimum password length to at least 12 characters"
            ZeroTrustPrinciple = "Verify Explicitly"
            Implementation = @(
                "Update Group Policy to require minimum 12-character passwords",
                "Consider implementing 14+ character requirements for privileged accounts",
                "Educate users on creating strong passphrases",
                "Implement password strength meters"
            )
        }
    }
    
    # Account lockout recommendations
    if (!$SecurityAuditResults.PasswordPolicies.LockoutCompliant) {
        $recommendations += @{
            Category = "Account Security"
            Priority = "Medium"
            Issue = "Account lockout policy is not properly configured"
            Recommendation = "Configure appropriate account lockout thresholds and duration"
            ZeroTrustPrinciple = "Verify Explicitly"
            Implementation = @(
                "Set account lockout threshold between 5-10 failed attempts",
                "Configure lockout duration of 15-30 minutes",
                "Implement account lockout observation window",
                "Monitor for brute force attacks"
            )
        }
    }
    
    # Windows security features
    $nonCompliantFeatures = $SecurityAuditResults.WindowsSecurityFeatures | Where-Object { !$_.Compliant }
    if ($nonCompliantFeatures.Count -gt 0) {
        $recommendations += @{
            Category = "Windows Security Features"
            Priority = "High"
            Issue = "$($nonCompliantFeatures.Count) Windows security features are not properly configured"
            Recommendation = "Enable and configure essential Windows security features"
            ZeroTrustPrinciple = "Assume Breach"
            AffectedFeatures = $nonCompliantFeatures.Feature
            Implementation = @(
                "Enable Windows Defender and ensure real-time protection",
                "Configure Windows Firewall for all network profiles",
                "Enable User Account Control (UAC)",
                "Configure Data Execution Prevention (DEP) and ASLR",
                "Enable SMB and LDAP signing requirements"
            )
        }
    }
    
    # Service security recommendations
    $highRiskServices = $SecurityAuditResults.ServiceSecurity | Where-Object { $_.RiskLevel -eq "High" }
    if ($highRiskServices.Count -gt 0) {
        $recommendations += @{
            Category = "Service Security"
            Priority = "High"
            Issue = "$($highRiskServices.Count) services identified with high security risks"
            Recommendation = "Review and secure high-risk service configurations"
            ZeroTrustPrinciple = "Use Least Privilege Access"
            AffectedServices = $highRiskServices.ServiceName
            Implementation = @(
                "Review services running as LocalSystem or Administrator",
                "Fix unquoted service paths vulnerabilities",
                "Disable unnecessary services",
                "Implement service account management",
                "Configure service recovery options securely"
            )
        }
    }
    
    # Network security recommendations
    $disabledFirewalls = $SecurityAuditResults.NetworkSecurity.FirewallProfiles.Values | Where-Object { !$_.Enabled }
    if ($disabledFirewalls.Count -gt 0) {
        $recommendations += @{
            Category = "Network Security"
            Priority = "Critical"
            Issue = "$($disabledFirewalls.Count) Windows Firewall profiles are disabled"
            Recommendation = "Enable Windows Firewall for all network profiles"
            ZeroTrustPrinciple = "Assume Breach"
            Implementation = @(
                "Enable Windows Firewall for Domain, Private, and Public profiles",
                "Configure appropriate inbound and outbound rules",
                "Enable firewall logging and monitoring",
                "Implement network segmentation strategies",
                "Deploy advanced firewall solutions for enhanced protection"
            )
        }
    }
    
    # Encryption recommendations
    if ($SecurityAuditResults.EncryptionStatus.BitLockerStatus.Count -eq 0) {
        $recommendations += @{
            Category = "Data Encryption"
            Priority = "High"
            Issue = "BitLocker encryption is not configured"
            Recommendation = "Implement disk encryption using BitLocker"
            ZeroTrustPrinciple = "Assume Breach"
            Implementation = @(
                "Enable BitLocker on all system drives",
                "Configure appropriate key protectors (TPM, PIN, USB)",
                "Implement BitLocker management and recovery procedures",
                "Consider encrypting data drives and removable media",
                "Deploy certificate-based encryption for sensitive files"
            )
        }
    }
    
    # Compliance recommendations
    if ($SecurityAuditResults.ComplianceChecks.NIST.OverallScore -lt 80) {
        $recommendations += @{
            Category = "Compliance"
            Priority = "Medium"
            Issue = "NIST Cybersecurity Framework compliance is below recommended levels"
            Recommendation = "Improve alignment with NIST Cybersecurity Framework"
            ZeroTrustPrinciple = "Verify Explicitly"
            Implementation = @(
                "Conduct comprehensive NIST CSF assessment",
                "Implement missing security controls",
                "Establish continuous monitoring and improvement processes",
                "Develop incident response and recovery capabilities",
                "Provide security awareness training"
            )
        }
    }
    
    $SecurityAuditResults.Recommendations = $recommendations

    Write-ADZTLog "Security audit completed successfully" "INFO"

} catch {
    Write-ADZTLog "Error during security audit: $($_.Exception.Message)" "ERROR"
    $SecurityAuditResults.Error = $_.Exception.Message
}

# Export results to JSON
$jsonOutput = $SecurityAuditResults | ConvertTo-Json -Depth 10
$outputFile = "$OutputPath\Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$jsonOutput | Out-File -FilePath $outputFile -Encoding UTF8

Write-ADZTLog "Results exported to: $outputFile" "INFO"

# Export security audit report
$securityReport = @"
# ADZero Trust Security Audit Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Computer: $($SecurityAuditResults.AuditInfo.ComputerName)
Domain: $($SecurityAuditResults.AuditInfo.Domain)

## Executive Summary
This report provides a comprehensive security configuration audit focusing on Zero Trust principles and industry best practices.

### Security Posture Overview
- **Windows Security Features Compliance**: $($SecurityAuditResults.SecurityBaseline.WindowsSecurityBaseline.CompliancePercentage)%
- **Password Policy Compliance**: $(if ($SecurityAuditResults.PasswordPolicies.ComplexityCompliant -and $SecurityAuditResults.PasswordPolicies.LengthCompliant) { "Compliant" } else { "Non-Compliant" })
- **Zero Trust Readiness Level**: $($SecurityAuditResults.ZeroTrustReadiness.OverallReadiness.MaturityLevel)
- **Overall Readiness Score**: $($SecurityAuditResults.ZeroTrustReadiness.OverallReadiness.Score)%

## Password Policy Assessment

### Current Configuration
- **Complexity Enabled**: $($SecurityAuditResults.PasswordPolicies.ComplexityEnabled)
- **Minimum Length**: $($SecurityAuditResults.PasswordPolicies.MinPasswordLength) characters
- **Maximum Age**: $($SecurityAuditResults.PasswordPolicies.MaxPasswordAge) days
- **History Count**: $($SecurityAuditResults.PasswordPolicies.PasswordHistoryCount)
- **Lockout Threshold**: $($SecurityAuditResults.PasswordPolicies.LockoutThreshold)
- **Lockout Duration**: $($SecurityAuditResults.PasswordPolicies.LockoutDuration) minutes

### Compliance Status
- **Complexity**: $(if ($SecurityAuditResults.PasswordPolicies.ComplexityCompliant) { "✓ Compliant" } else { "✗ Non-Compliant" })
- **Length**: $(if ($SecurityAuditResults.PasswordPolicies.LengthCompliant) { "✓ Compliant" } else { "✗ Non-Compliant" })
- **Age**: $(if ($SecurityAuditResults.PasswordPolicies.AgeCompliant) { "✓ Compliant" } else { "✗ Non-Compliant" })
- **History**: $(if ($SecurityAuditResults.PasswordPolicies.HistoryCompliant) { "✓ Compliant" } else { "✗ Non-Compliant" })
- **Lockout**: $(if ($SecurityAuditResults.PasswordPolicies.LockoutCompliant) { "✓ Compliant" } else { "✗ Non-Compliant" })

## Windows Security Features Status
$($SecurityAuditResults.WindowsSecurityFeatures | ForEach-Object { "- **$($_.Feature)**: $($_.Status) $(if ($_.Compliant) { "✓" } else { "✗" })" } | Out-String)

## Service Security Analysis
- **Total Services Analyzed**: $($SecurityAuditResults.SecurityBaseline.ServiceSecurityBaseline.TotalServices)
- **High Risk Services**: $($SecurityAuditResults.SecurityBaseline.ServiceSecurityBaseline.HighRiskServices)
- **Medium Risk Services**: $($SecurityAuditResults.SecurityBaseline.ServiceSecurityBaseline.MediumRiskServices)
- **Low Risk Services**: $($SecurityAuditResults.SecurityBaseline.ServiceSecurityBaseline.LowRiskServices)

## Network Security Configuration

### Firewall Status
$($SecurityAuditResults.NetworkSecurity.FirewallProfiles.Keys | ForEach-Object { "- **$_ Profile**: $(if ($SecurityAuditResults.NetworkSecurity.FirewallProfiles[$_].Enabled) { "Enabled ✓" } else { "Disabled ✗" })" } | Out-String)

### Network Shares
- **Total Shares**: $($SecurityAuditResults.SecurityBaseline.NetworkSecurityBaseline.TotalShares)
- **Secure Shares**: $($SecurityAuditResults.SecurityBaseline.NetworkSecurityBaseline.SecureShares)

## Compliance Assessment

### NIST Cybersecurity Framework
- **Overall Score**: $($SecurityAuditResults.ComplianceChecks.NIST.OverallScore)%
- **Password Complexity**: $(if ($SecurityAuditResults.ComplianceChecks.NIST.PasswordComplexity) { "✓ Compliant" } else { "✗ Non-Compliant" })
- **Password Length**: $(if ($SecurityAuditResults.ComplianceChecks.NIST.PasswordLength) { "✓ Compliant" } else { "✗ Non-Compliant" })
- **Account Lockout**: $(if ($SecurityAuditResults.ComplianceChecks.NIST.AccountLockout) { "✓ Compliant" } else { "✗ Non-Compliant" })

### CIS Controls
- **Overall Score**: $($SecurityAuditResults.ComplianceChecks.CIS.OverallScore)%
- **Password Policy**: $(if ($SecurityAuditResults.ComplianceChecks.CIS.PasswordPolicy) { "✓ Compliant" } else { "✗ Non-Compliant" })
- **Account Policy**: $(if ($SecurityAuditResults.ComplianceChecks.CIS.AccountPolicy) { "✓ Compliant" } else { "✗ Non-Compliant" })

## Zero Trust Readiness Assessment

### Verify Explicitly
- **Strong Authentication**: $($SecurityAuditResults.ZeroTrustReadiness.VerifyExplicitly.StrongAuthentication.Score)% ($($SecurityAuditResults.ZeroTrustReadiness.VerifyExplicitly.StrongAuthentication.Status))
- **Device Compliance**: $($SecurityAuditResults.ZeroTrustReadiness.VerifyExplicitly.DeviceCompliance.Score)% ($($SecurityAuditResults.ZeroTrustReadiness.VerifyExplicitly.DeviceCompliance.Status))

### Use Least Privilege Access
- **Privileged Access Management**: $($SecurityAuditResults.ZeroTrustReadiness.LeastPrivilegeAccess.PrivilegedAccessManagement.Score)% ($($SecurityAuditResults.ZeroTrustReadiness.LeastPrivilegeAccess.PrivilegedAccessManagement.Status))
- **Just-in-Time Access**: $($SecurityAuditResults.ZeroTrustReadiness.LeastPrivilegeAccess.JustInTimeAccess.Score)% ($($SecurityAuditResults.ZeroTrustReadiness.LeastPrivilegeAccess.JustInTimeAccess.Status))

### Assume Breach
- **Network Segmentation**: $($SecurityAuditResults.ZeroTrustReadiness.AssumeBreachPreparation.NetworkSegmentation.Score)% ($($SecurityAuditResults.ZeroTrustReadiness.AssumeBreachPreparation.NetworkSegmentation.Status))
- **Encryption Everywhere**: $($SecurityAuditResults.ZeroTrustReadiness.AssumeBreachPreparation.EncryptionEverywhere.Score)% ($($SecurityAuditResults.ZeroTrustReadiness.AssumeBreachPreparation.EncryptionEverywhere.Status))

## Critical Recommendations
$($recommendations | Where-Object { $_.Priority -eq "Critical" } | ForEach-Object { "### $($_.Category)`n**Issue**: $($_.Issue)`n**Recommendation**: $($_.Recommendation)`n**Implementation**:`n$($_.Implementation | ForEach-Object { "- $_" } | Out-String)" } | Out-String)

## High Priority Recommendations
$($recommendations | Where-Object { $_.Priority -eq "High" } | ForEach-Object { "### $($_.Category)`n**Issue**: $($_.Issue)`n**Recommendation**: $($_.Recommendation)`n**Implementation**:`n$($_.Implementation | ForEach-Object { "- $_" } | Out-String)" } | Out-String)

## Zero Trust Implementation Roadmap

### Phase 1: Foundation Security (0-1 month)
1. **Enable critical Windows security features**
2. **Configure strong password policies**
3. **Enable Windows Firewall on all profiles**
4. **Secure high-risk services**

### Phase 2: Access Control Enhancement (1-3 months)
1. **Implement multi-factor authentication**
2. **Deploy privileged access management**
3. **Configure account lockout policies**
4. **Implement service account management**

### Phase 3: Data Protection (3-6 months)
1. **Enable BitLocker disk encryption**
2. **Implement data classification**
3. **Deploy data loss prevention**
4. **Configure secure network protocols**

### Phase 4: Advanced Monitoring (6-12 months)
1. **Deploy SIEM and security monitoring**
2. **Implement user behavior analytics**
3. **Enable continuous compliance monitoring**
4. **Establish incident response capabilities**

For detailed technical analysis and complete results, please review the JSON output file.

---
*Report generated by ADZero Trust Security Auditor*
*Author: Moazzam Jafri*
"@

$reportFile = "$OutputPath\Security_Audit_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').md"
$securityReport | Out-File -FilePath $reportFile -Encoding UTF8

Write-ADZTLog "Security audit report exported to: $reportFile" "INFO"
Write-ADZTLog "Security Audit completed" "INFO"

# Return the results object for pipeline usage
return $SecurityAuditResults


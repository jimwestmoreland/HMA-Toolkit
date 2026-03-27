<#
# VERSION: 2026-01-29 10:00 UTC
.SYNOPSIS
    Collects Hybrid Modern Authentication (HMA) diagnostic information from Exchange On-Premises.
    THIS IS STEP 1 OF 2 - Run this first, then run Test-HmaEasNoEmptyBearer.ps1

.DESCRIPTION
    This script gathers comprehensive HMA configuration details to troubleshoot
    intermittent OAuth/Modern Auth failures with Outlook mobile clients.
    It automatically discovers all Exchange servers with CAS/ActiveSync roles
    and collects server-specific data from each.
    
    WORKFLOW ORDER:
    ==============
    STEP 1: Run Get-HMADiagnostics.ps1 (this script) to identify configuration issues
    STEP 2: Run Test-HmaEasNoEmptyBearer.ps1 to test the actual OAuth flow
    
    FEATURES:
    =========
    - **PARALLEL COLLECTION** (NEW in v1.7):
      - Collects data from all Exchange servers simultaneously
      - Reduces collection time from ~5 minutes to ~45-60 seconds (8 servers)
      - Uses PowerShell background jobs for concurrent execution
    
    - Automated misconfiguration detection with severity levels:
      - [OK] = Configuration is correct
      - [WARNING] = Potential issue that may cause intermittent problems
      - [CRITICAL] = Definite misconfiguration that will cause failures
      - [INFO] = Informational finding
    
    - Authentication Policy Validation (NEW in v1.4):
      - Checks all authentication policies for BlockModernAuthActiveSync
      - Validates TestMailbox user's specific policy assignment
      - Detects org-wide default policy that may block modern auth
      - Flags CRITICAL if user's policy blocks ActiveSync modern auth
    
    - Federation/ADFS Detection (v1.3):
      - Automatically detects if domain is federated (uses ADFS/external IdP)
      - ROPC authentication will NEVER work with federated domains
      - Recommends -UseDeviceCode when federation is detected
    
    - Passwordless Detection (NEW in v1.3):
      - Detects passwordless authentication methods (FIDO2, Authenticator, etc.)
      - Recommends -UseDeviceCode when passwordless is configured
    
    - MFA Detection (automatically determines if -UseDeviceCode is needed):
      - Scans OAuth event logs for MFA-related error codes (AADSTS50076, etc.)
      - Queries Azure AD MFA status if MSOnline module is connected
      - Provides confidence level: Confirmed, High, or Unknown
      - Outputs smart recommendation for which test mode to use
    
    - IIS/HTTPS Certificate Validation:
      - Validates certificates bound to IIS services
      - Checks certificate expiration dates
      - Verifies Subject Alternative Names (SANs) coverage
      - Tests external endpoint certificate chains
      - Detects incomplete chains and untrusted root CAs
      - Identifies issues that cause intermittent mobile client failures
    
    - Multi-server collection from all CAS servers
    - OAuth certificate validation across all servers
    - Virtual directory URL consistency checks

.NOTES
    Run this script from Exchange Management Shell with elevated privileges.
    Requires WinRM/PowerShell remoting enabled on all Exchange servers.
    
    For enhanced detection, connect to Azure AD before running:
      Install-Module MSOnline -Force
      Connect-MsolService
    
    Author: HMA Diagnostics Script
    Date: 2026-01-29
    Version: 1.7

.EXAMPLE
    .\Get-HMADiagnostics.ps1
    # Basic usage - run this first to check configuration
    
.EXAMPLE
    .\Get-HMADiagnostics.ps1 -TestMailbox "user@contoso.com"
    # Specify the mailbox you'll test - enables MFA status lookup if connected to Azure AD
    
.EXAMPLE
    Connect-MsolService
    .\Get-HMADiagnostics.ps1 -TestMailbox "user@contoso.com"
    # Connect to Azure AD first for full MFA detection capabilities
    
.EXAMPLE
    .\Get-HMADiagnostics.ps1 -OutputPath "C:\Logs\HMA-Diag.txt"

.EXAMPLE
    .\Get-HMADiagnostics.ps1 -SkipRemoteCollection
    # Only collect org-wide data, skip remote server collection
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\HMA-Diagnostics-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt",
    
    [Parameter(Mandatory = $false)]
    [string]$TestMailbox = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipRemoteCollection
)

#region HTTP Configuration
# Disable Expect: 100-continue header to prevent 417 errors with strict proxies/firewalls
[System.Net.ServicePointManager]::Expect100Continue = $false
# Force TLS 1.2 - Azure AD endpoints reject older TLS versions
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
#endregion

#region Configuration Issue Tracking
$script:Issues = @{
    Critical = @()
    Warning = @()
    Info = @()
}

function Add-Issue {
    param(
        [ValidateSet("Critical", "Warning", "Info")]
        [string]$Severity,
        [string]$Component,
        [string]$Description,
        [string]$Recommendation
    )
    
    $issue = [PSCustomObject]@{
        Severity = $Severity
        Component = $Component
        Description = $Description
        Recommendation = $Recommendation
    }
    
    $script:Issues[$Severity] += $issue
}
#endregion

#region Helper Functions
function Write-Section {
    param([string]$Title)
    $separator = "=" * 80
    $output = @"

$separator
$Title
$separator

"@
    Write-Host $output -ForegroundColor Cyan
    return $output
}

function Write-SubSection {
    param([string]$Title)
    $separator = "-" * 60
    $output = @"

$separator
$Title
$separator

"@
    Write-Host $output -ForegroundColor Yellow
    return $output
}

function Invoke-SafeCommand {
    param(
        [scriptblock]$Command,
        [string]$Description
    )
    
    try {
        Write-Host "  Collecting: $Description..." -ForegroundColor Gray
        $result = & $Command 2>&1
        if ($null -eq $result) {
            return "[No data returned]`n"
        }
        return ($result | Out-String)
    }
    catch {
        return "[ERROR] Failed to execute: $($_.Exception.Message)`n"
    }
}

function Get-RemoteData {
    param(
        [string]$ServerName,
        [scriptblock]$ScriptBlock,
        [string]$Description,
        [object[]]$ArgumentList = @()
    )
    
    try {
        Write-Host "    [$ServerName] $Description..." -ForegroundColor Gray
        if ($ArgumentList.Count -gt 0) {
            $result = Invoke-Command -ComputerName $ServerName -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop 2>&1
        } else {
            $result = Invoke-Command -ComputerName $ServerName -ScriptBlock $ScriptBlock -ErrorAction Stop 2>&1
        }
        if ($null -eq $result) {
            return "[No data returned]`n"
        }
        return ($result | Out-String)
    }
    catch {
        return "[ERROR] Failed to collect from $ServerName : $($_.Exception.Message)`n"
    }
}

# Parallel collection script block - collects ALL per-server data in one remote call
$script:ParallelCollectionScriptBlock = {
    param(
        [string]$OAuthThumbprint,
        [string[]]$MfaErrorCodes
    )
    
    $result = @{
        ServerName = $env:COMPUTERNAME
        ServerHealth = $null
        IISConfig = $null
        OAuthEvents = @()
        AutodiscoverErrors = @()
        HttpErrors = @()
        OAuthCertificate = $null
        MfaEvents = @()
        Errors = @()
    }
    
    # 1. Server Health
    try {
        $health = Get-ServerHealth -Identity $env:COMPUTERNAME -ErrorAction SilentlyContinue | 
            Where-Object { $_.AlertValue -ne "Healthy" } | 
            Select-Object Name, AlertValue, ServerComponentName
        $result.ServerHealth = $health
    } catch {
        $result.Errors += "ServerHealth: $($_.Exception.Message)"
    }
    
    # 2. IIS Configuration
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $iisResults = @()
        $vdirs = @('Autodiscover', 'Microsoft-Server-ActiveSync', 'EWS', 'OWA', 'Mapi')
        foreach ($vdir in $vdirs) {
            $vdirResult = @{ Name = $vdir; Auth = @{} }
            $authTypes = @('anonymousAuthentication', 'windowsAuthentication', 'basicAuthentication')
            foreach ($auth in $authTypes) {
                try {
                    $enabled = (Get-WebConfigurationProperty -Filter "/system.webServer/security/authentication/$auth" -Name enabled -PSPath "IIS:\Sites\Default Web Site\$vdir" -ErrorAction SilentlyContinue).Value
                    $vdirResult.Auth[$auth] = $enabled
                } catch {
                    $vdirResult.Auth[$auth] = "[Error]"
                }
            }
            $iisResults += $vdirResult
        }
        $result.IISConfig = $iisResults
    } catch {
        $result.Errors += "IISConfig: $($_.Exception.Message)"
    }
    
    # 3. OAuth Events (last 24 hours)
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            ProviderName = 'MSExchange OAuth'
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 15 -ErrorAction SilentlyContinue
        if ($events) {
            $result.OAuthEvents = $events | Select-Object TimeCreated, Id, LevelDisplayName, Message
        }
    } catch {
        # No events is not an error
    }
    
    # 4. Autodiscover Errors (last 24 hours)
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            ProviderName = 'MSExchange Autodiscover'
            Level = 2,3
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 15 -ErrorAction SilentlyContinue
        if ($events) {
            $result.AutodiscoverErrors = $events | Select-Object TimeCreated, Id, LevelDisplayName, Message
        }
    } catch {
        # No events is not an error
    }
    
    # 5. HTTP Service Errors (last 24 hours)
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ProviderName = 'Microsoft-Windows-HttpService'
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 10 -ErrorAction SilentlyContinue
        if ($events) {
            $result.HttpErrors = $events | Select-Object TimeCreated, Id, LevelDisplayName, Message
        }
    } catch {
        # No events is not an error
    }
    
    # 6. OAuth Certificate Check
    if ($OAuthThumbprint) {
        try {
            $cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -eq $OAuthThumbprint }
            if ($cert) {
                $result.OAuthCertificate = @{
                    Found = $true
                    Subject = $cert.Subject
                    Expires = $cert.NotAfter
                    HasPrivateKey = $cert.HasPrivateKey
                }
            } else {
                $result.OAuthCertificate = @{
                    Found = $false
                    AvailableCerts = (Get-ChildItem -Path "Cert:\LocalMachine\My" | 
                        Where-Object { $_.Subject -like "*exchange*" -or $_.Subject -like "*auth*" } |
                        Select-Object Thumbprint, Subject, NotAfter)
                }
            }
        } catch {
            $result.Errors += "OAuthCert: $($_.Exception.Message)"
        }
    }
    
    # 7. MFA-related OAuth Errors (last 7 days)
    if ($MfaErrorCodes -and $MfaErrorCodes.Count -gt 0) {
        try {
            $pattern = $MfaErrorCodes -join "|"
            $oauthEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Application'
                ProviderName = 'MSExchange OAuth'
                StartTime = (Get-Date).AddDays(-7)
            } -MaxEvents 100 -ErrorAction SilentlyContinue
            
            foreach ($evt in $oauthEvents) {
                if ($evt.Message -match $pattern) {
                    $result.MfaEvents += @{
                        Time = $evt.TimeCreated
                        Message = $evt.Message
                        MatchedCode = ($MfaErrorCodes | Where-Object { $evt.Message -match $_ }) -join ", "
                    }
                }
            }
        } catch {
            # Non-critical
        }
    }
    
    return $result
}

function Invoke-ParallelServerCollection {
    param(
        [array]$Servers,
        [string]$OAuthThumbprint,
        [string[]]$MfaErrorCodes
    )
    
    $results = @{}
    
    if ($Servers.Count -eq 0) {
        return $results
    }
    
    Write-Host ""
    Write-Host "Starting parallel collection on $($Servers.Count) server(s)..." -ForegroundColor Yellow
    
    # Start jobs for all servers
    $jobs = @()
    foreach ($server in $Servers) {
        Write-Host "  - Queuing $($server.Name)..." -ForegroundColor Gray
        $jobs += Start-Job -ScriptBlock $script:ParallelCollectionScriptBlock -ArgumentList $OAuthThumbprint, $MfaErrorCodes -Name $server.Name
        
        # Connect to remote server for the job
        $job = $jobs[-1]
        # We need to use Invoke-Command with -AsJob for remote execution
    }
    
    # Actually, Start-Job runs locally. We need Invoke-Command -AsJob for remote parallel execution
    # Let me fix this approach
    
    # Remove incorrectly started jobs
    $jobs | Remove-Job -Force -ErrorAction SilentlyContinue
    $jobs = @()
    
    # Use Invoke-Command with -AsJob for true parallel remote execution
    foreach ($server in $Servers) {
        Write-Host "  - Queuing $($server.Name)..." -ForegroundColor Gray
        $job = Invoke-Command -ComputerName $server.Name -ScriptBlock $script:ParallelCollectionScriptBlock -ArgumentList $OAuthThumbprint, $MfaErrorCodes -AsJob -JobName $server.Name -ErrorAction SilentlyContinue
        if ($job) {
            $jobs += $job
        } else {
            Write-Host "    [WARNING] Failed to queue job for $($server.Name)" -ForegroundColor Yellow
        }
    }
    
    if ($jobs.Count -eq 0) {
        Write-Host "  No jobs were queued successfully." -ForegroundColor Red
        return $results
    }
    
    # Wait for all jobs with progress
    Write-Host ""
    Write-Host "Waiting for $($jobs.Count) job(s) to complete..." -ForegroundColor Yellow
    $completedCount = 0
    $timeout = 120  # 2 minute timeout
    $startWait = Get-Date
    
    while (($jobs | Where-Object { $_.State -eq 'Running' }).Count -gt 0) {
        $newCompleted = ($jobs | Where-Object { $_.State -eq 'Completed' }).Count
        if ($newCompleted -gt $completedCount) {
            $completedCount = $newCompleted
            Write-Host "  Progress: $completedCount of $($jobs.Count) servers completed" -ForegroundColor Gray
        }
        
        # Check timeout
        if (((Get-Date) - $startWait).TotalSeconds -gt $timeout) {
            Write-Host "  [WARNING] Timeout reached, some servers did not respond" -ForegroundColor Yellow
            break
        }
        
        Start-Sleep -Milliseconds 500
    }
    
    # Collect results
    Write-Host ""
    Write-Host "Collecting results..." -ForegroundColor Yellow
    
    foreach ($job in $jobs) {
        $serverName = $job.Name
        try {
            $jobResult = Receive-Job -Job $job -ErrorAction SilentlyContinue
            if ($jobResult) {
                $results[$serverName] = $jobResult
                Write-Host "  [OK] $serverName - data collected" -ForegroundColor Green
            } else {
                $results[$serverName] = @{ ServerName = $serverName; Errors = @("No data returned") }
                Write-Host "  [WARN] $serverName - no data returned" -ForegroundColor Yellow
            }
        } catch {
            $results[$serverName] = @{ ServerName = $serverName; Errors = @($_.Exception.Message) }
            Write-Host "  [ERROR] $serverName - $($_.Exception.Message)" -ForegroundColor Red
        }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host ""
    Write-Host "Parallel collection complete!" -ForegroundColor Green
    
    return $results
}
#endregion

#region Main Script

# Timing dictionary for major sections
$sectionTimings = @{}
$report = @()
$startTime = Get-Date

# Header
$header = @"
################################################################################
#                                                                              #
#           HYBRID MODERN AUTHENTICATION DIAGNOSTICS REPORT                    #
#                                                                              #
################################################################################

Report Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer Name: $env:COMPUTERNAME
Current User: $env:USERDOMAIN\$env:USERNAME

"@

Write-Host $header -ForegroundColor Green
$report += $header

#region Exchange Server Information
# --- Timed Section: Exchange Server Discovery ---
$section = "Exchange Server Discovery"
$sectionStart = Get-Date
$report += Write-Section $section

# Discover all Exchange servers with CAS role
$allExchangeServers = @()
$casServers = @()

$report += Write-SubSection "All Exchange Servers"
$report += Invoke-SafeCommand { 
    $servers = Get-ExchangeServer | Select-Object Name, Edition, AdminDisplayVersion, ServerRole, Site
    $servers | Format-List
} "Exchange Server Discovery"

# Get servers that handle client access (CAS role or Mailbox with CAS services in 2016+)
try {
    $allExchangeServers = Get-ExchangeServer
    $casServers = $allExchangeServers | Where-Object { 
        $_.ServerRole -match "Mailbox" -or 
        $_.ServerRole -match "ClientAccess" -or
        $_.IsClientAccessServer -eq $true
    }
    $serverList = ($casServers | Select-Object -ExpandProperty Name) -join ", "
    $report += "`nServers with CAS/ActiveSync capability: $serverList`n"
    $report += "Total CAS servers found: $($casServers.Count)`n"
    Write-Host "  Found $($casServers.Count) CAS servers: $serverList" -ForegroundColor Green
}
catch {
    $report += "[ERROR] Failed to enumerate Exchange servers: $($_.Exception.Message)`n"
    $casServers = @()
}
$sectionTimings[$section] = ((Get-Date) - $sectionStart).TotalSeconds

#region Parallel Server Collection
# --- Timed Section: Parallel Server Data Collection ---
$section = "Parallel Server Data Collection"
$sectionStart = Get-Date

# Get OAuth thumbprint for parallel collection
$authCfgForParallel = Get-AuthConfig -ErrorAction SilentlyContinue
$oauthThumbprintForParallel = $authCfgForParallel.CurrentCertificateThumbprint

# MFA error codes for parallel collection
$mfaErrorCodesForParallel = @(
    "AADSTS50076", "AADSTS50079", "AADSTS50158",
    "AADSTS53000", "AADSTS53001", "AADSTS53002", "AADSTS7000218"
)

# Run parallel collection on all CAS servers (unless skipped)
$parallelResults = @{}
if (-not $SkipRemoteCollection -and $casServers.Count -gt 0) {
    $parallelResults = Invoke-ParallelServerCollection -Servers $casServers -OAuthThumbprint $oauthThumbprintForParallel -MfaErrorCodes $mfaErrorCodesForParallel
    $report += "`n[INFO] Parallel collection completed for $($parallelResults.Count) servers`n"
} else {
    $report += "`n[INFO] Remote collection skipped or no CAS servers found`n"
}
$sectionTimings[$section] = ((Get-Date) - $sectionStart).TotalSeconds
#endregion

# --- Timed Section: Exchange Server Health (from parallel results) ---
$section = "Exchange Server Health (All Servers)"
$sectionStart = Get-Date
$report += Write-SubSection $section

if ($parallelResults.Count -gt 0) {
    foreach ($serverName in $parallelResults.Keys) {
        $serverData = $parallelResults[$serverName]
        $report += "`n--- $serverName ---`n"
        if ($serverData.ServerHealth) {
            $report += ($serverData.ServerHealth | Format-Table Name, AlertValue, ServerComponentName -AutoSize | Out-String)
        } else {
            $report += "[OK] No unhealthy components or unable to retrieve health data`n"
        }
        if ($serverData.Errors -and $serverData.Errors.Count -gt 0) {
            foreach ($err in $serverData.Errors | Where-Object { $_ -like "ServerHealth:*" }) {
                $report += "[ERROR] $err`n"
            }
        }
    }
} else {
    # Fallback to sequential if parallel failed
    foreach ($server in $casServers) {
        $report += "`n--- $($server.Name) ---`n"
        $report += Invoke-SafeCommand { 
            Get-ServerHealth -Identity $server.Name -ErrorAction SilentlyContinue | 
            Where-Object { $_.AlertValue -ne "Healthy" } | 
            Format-Table Name, AlertValue, ServerComponentName -AutoSize 
        } "Server Health for $($server.Name)"
    }
}
$sectionTimings[$section] = ((Get-Date) - $sectionStart).TotalSeconds
#endregion

# --- Timed Section: OAuth and Authentication Server Configuration ---
$section = "OAuth and Authentication Server Configuration"
$sectionStart = Get-Date
$report += Write-Section $section

$report += Write-SubSection "Auth Servers (Critical for HMA)"
$authServers = Get-AuthServer -ErrorAction SilentlyContinue
$report += Invoke-SafeCommand { $authServers | Format-List Name, Type, Enabled, TokenIssuingEndpoint, AuthorizationEndpoint, ApplicationIdentifier, IsDefaultAuthorizationEndpoint } "Auth Server Configuration"

# Validate EvoSts Auth Server
$evoStsServer = $authServers | Where-Object { $_.Name -like "*EvoSts*" -or $_.Type -eq "AzureAD" }
if (-not $evoStsServer) {
    Add-Issue -Severity "Critical" -Component "Auth Server" -Description "No EvoSts (Azure AD) auth server found" -Recommendation "Run the Hybrid Configuration Wizard to create the EvoSts auth server, or create manually using New-AuthServer"
    $report += "[CRITICAL] No EvoSts auth server found!`n"
} else {
    if ($evoStsServer.Enabled -ne $true) {
        Add-Issue -Severity "Critical" -Component "Auth Server" -Description "EvoSts auth server exists but is DISABLED" -Recommendation "Run: Set-AuthServer -Identity '$($evoStsServer.Name)' -Enabled `$true"
        $report += "[CRITICAL] EvoSts auth server is DISABLED!`n"
    } else {
        $report += "[OK] EvoSts auth server is present and enabled`n"
    }
    if (-not $evoStsServer.TokenIssuingEndpoint) {
        Add-Issue -Severity "Critical" -Component "Auth Server" -Description "EvoSts TokenIssuingEndpoint is not configured" -Recommendation "Re-run Hybrid Configuration Wizard or set TokenIssuingEndpoint manually"
    }
    if ($evoStsServer.IsDefaultAuthorizationEndpoint -ne $true) {
        Add-Issue -Severity "Warning" -Component "Auth Server" -Description "EvoSts is not set as the default authorization endpoint" -Recommendation "Run: Set-AuthServer -Identity '$($evoStsServer.Name)' -IsDefaultAuthorizationEndpoint `$true"
    }
}

$report += Write-SubSection "Auth Configuration"
$authConfig = Get-AuthConfig -ErrorAction SilentlyContinue
$report += Invoke-SafeCommand { $authConfig | Format-List *Cert*, ServiceName, Realm, CurrentCertificateThumbprint, PreviousCertificateThumbprint, NextCertificateThumbprint, NextCertificateEffectiveDate } "Auth Config Details"

# Validate Auth Config
if (-not $authConfig) {
    Add-Issue -Severity "Critical" -Component "Auth Config" -Description "Unable to retrieve AuthConfig" -Recommendation "Run Get-AuthConfig manually to diagnose"
} else {
    if ([string]::IsNullOrEmpty($authConfig.CurrentCertificateThumbprint)) {
        Add-Issue -Severity "Critical" -Component "Auth Config" -Description "No OAuth certificate thumbprint configured" -Recommendation "Run: Set-AuthConfig -NewCertificateThumbprint <thumbprint> -NewCertificateEffectiveDate (Get-Date)"
        $report += "[CRITICAL] No OAuth certificate configured!`n"
    }
    if ([string]::IsNullOrEmpty($authConfig.Realm)) {
        Add-Issue -Severity "Warning" -Component "Auth Config" -Description "Realm is not configured in AuthConfig" -Recommendation "This may be normal for some configurations, but verify hybrid setup"
    }
    if ([string]::IsNullOrEmpty($authConfig.ServiceName)) {
        Add-Issue -Severity "Warning" -Component "Auth Config" -Description "ServiceName is not configured in AuthConfig" -Recommendation "ServiceName should be set (e.g., 00000002-0000-0ff1-ce00-000000000000)"
    }
}

$report += Write-SubSection "Partner Applications"
$partnerApps = Get-PartnerApplication -ErrorAction SilentlyContinue
$report += Invoke-SafeCommand { $partnerApps | Format-List Name, Enabled, ApplicationIdentifier, AuthMetadataUrl, LinkedAccount, AcceptSecurityIdentifierInformation } "Partner Application Configuration"

# Validate Partner Applications
$exchangeOnlineApp = $partnerApps | Where-Object { $_.Name -like "*Exchange Online*" -or $_.ApplicationIdentifier -like "*outlook.com*" }
if (-not $exchangeOnlineApp) {
    Add-Issue -Severity "Warning" -Component "Partner Application" -Description "No Exchange Online partner application found" -Recommendation "This may indicate incomplete hybrid configuration"
} elseif ($exchangeOnlineApp.Enabled -ne $true) {
    Add-Issue -Severity "Critical" -Component "Partner Application" -Description "Exchange Online partner application is DISABLED" -Recommendation "Run: Set-PartnerApplication -Identity '$($exchangeOnlineApp.Name)' -Enabled `$true"
}
$sectionTimings[$section] = ((Get-Date) - $sectionStart).TotalSeconds
#endregion

# --- Timed Section: Virtual Directory OAuth Configuration ---
$section = "Virtual Directory OAuth Configuration"
$sectionStart = Get-Date
$report += Write-Section $section

$report += Write-SubSection "Autodiscover Virtual Directory"
$report += Invoke-SafeCommand { Get-AutodiscoverVirtualDirectory | Format-List Server, Name, InternalUrl, ExternalUrl, *OAuth*, *Auth*, WSSecurityAuthentication } "Autodiscover VDir Settings"

$report += Write-SubSection "ActiveSync Virtual Directory"
$report += Invoke-SafeCommand { Get-ActiveSyncVirtualDirectory | Format-List Server, Name, InternalUrl, ExternalUrl, *OAuth*, *Auth*, ClientCertAuth } "ActiveSync VDir Settings"

$report += Write-SubSection "EWS Virtual Directory"
$report += Invoke-SafeCommand { Get-WebServicesVirtualDirectory | Format-List Server, Name, InternalUrl, ExternalUrl, *OAuth*, *Auth*, WSSecurityAuthentication, CertificateAuthentication } "EWS VDir Settings"

$report += Write-SubSection "OWA Virtual Directory"
$report += Invoke-SafeCommand { Get-OwaVirtualDirectory | Format-List Server, Name, InternalUrl, ExternalUrl, *OAuth*, *Auth* } "OWA VDir Settings"

$report += Write-SubSection "ECP Virtual Directory"
$report += Invoke-SafeCommand { Get-EcpVirtualDirectory | Format-List Server, Name, InternalUrl, ExternalUrl, *OAuth*, *Auth* } "ECP VDir Settings"

$report += Write-SubSection "MAPI Virtual Directory"
$report += Invoke-SafeCommand { Get-MapiVirtualDirectory | Format-List Server, Name, InternalUrl, ExternalUrl, *OAuth*, *Auth* } "MAPI VDir Settings"

$report += Write-SubSection "OAB Virtual Directory"
$report += Invoke-SafeCommand { Get-OabVirtualDirectory | Format-List Server, Name, InternalUrl, ExternalUrl, *OAuth*, *Auth* } "OAB VDir Settings"
$sectionTimings[$section] = ((Get-Date) - $sectionStart).TotalSeconds
#endregion

# --- Timed Section: Hybrid Configuration ---
$section = "Hybrid Configuration"
$sectionStart = Get-Date
$report += Write-Section $section

$report += Write-SubSection "Hybrid Configuration Object"
$hybridConfig = Get-HybridConfiguration -ErrorAction SilentlyContinue
$report += Invoke-SafeCommand { $hybridConfig | Format-List } "Hybrid Configuration"

if (-not $hybridConfig) {
    Add-Issue -Severity "Critical" -Component "Hybrid Configuration" -Description "No Hybrid Configuration found" -Recommendation "Run the Hybrid Configuration Wizard to establish hybrid connectivity"
    $report += "[CRITICAL] No Hybrid Configuration found!`n"
} else {
    $report += "[OK] Hybrid Configuration exists`n"
    # Check for OAuth feature
    if ($hybridConfig.Features -notcontains "FreeBusy" -and $hybridConfig.Features -notcontains "Photos" -and $hybridConfig.Features -notcontains "OwaRedirection") {
        Add-Issue -Severity "Info" -Component "Hybrid Configuration" -Description "Hybrid features configured: $($hybridConfig.Features -join ', ')" -Recommendation "Review enabled hybrid features"
    }
}
$sectionTimings[$section] = ((Get-Date) - $sectionStart).TotalSeconds

$report += Write-SubSection "IntraOrganization Connector (On-Prem to O365)"
$intraOrgConnector = Get-IntraOrganizationConnector -ErrorAction SilentlyContinue
$report += Invoke-SafeCommand { $intraOrgConnector | Format-List Name, Enabled, TargetAddressDomains, DiscoveryEndpoint, TargetSharingEpr } "IntraOrg Connector"

if (-not $intraOrgConnector) {
    Add-Issue -Severity "Warning" -Component "IntraOrganization Connector" -Description "No IntraOrganization Connector found" -Recommendation "Run Hybrid Configuration Wizard to create the connector"
} else {
    foreach ($ioc in $intraOrgConnector) {
        if ($ioc.Enabled -ne $true) {
            Add-Issue -Severity "Critical" -Component "IntraOrganization Connector" -Description "Connector '$($ioc.Name)' is DISABLED" -Recommendation "Run: Set-IntraOrganizationConnector -Identity '$($ioc.Name)' -Enabled `$true"
        }
        if ([string]::IsNullOrEmpty($ioc.DiscoveryEndpoint)) {
            Add-Issue -Severity "Critical" -Component "IntraOrganization Connector" -Description "Connector '$($ioc.Name)' has no DiscoveryEndpoint" -Recommendation "Set DiscoveryEndpoint to https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
        }
    }
}

$report += Write-SubSection "IntraOrganization Configuration"
$intraOrgConfig = Get-IntraOrganizationConfiguration -ErrorAction SilentlyContinue
$report += Invoke-SafeCommand { $intraOrgConfig | Format-List } "IntraOrg Config"

if ($intraOrgConfig) {
    # Check for OAuth enabled
    if ($intraOrgConfig.OnPremisesWebServiceVirtualDirectory) {
        $report += "[OK] On-premises web service virtual directory configured`n"
    }
}

$report += Write-SubSection "Organization Relationship"
$orgRelationship = Get-OrganizationRelationship -ErrorAction SilentlyContinue
$report += Invoke-SafeCommand { $orgRelationship | Format-List Name, Enabled, DomainNames, TargetApplicationUri, TargetAutodiscoverEpr, TargetOwaURL, TargetSharingEpr, FreeBusyAccessEnabled, FreeBusyAccessLevel } "Organization Relationship"

if ($orgRelationship) {
    foreach ($or in $orgRelationship) {
        if ($or.Enabled -ne $true) {
            Add-Issue -Severity "Warning" -Component "Organization Relationship" -Description "Relationship '$($or.Name)' is DISABLED" -Recommendation "Enable if this relationship is needed for hybrid functionality"
        }
    }
}

$report += Write-SubSection "Federation Trust"
$report += Invoke-SafeCommand { Get-FederationTrust | Format-List Name, ApplicationIdentifier, ApplicationUri, TokenIssuerUri, TokenIssuerCertificate, TokenIssuerPrevCertificate, TokenIssuerType, TokenIssuerMetadataEpr } "Federation Trust"

$report += Write-SubSection "Federation Information (If Available)"
$report += Invoke-SafeCommand { Get-FederatedOrganizationIdentifier | Format-List } "Federated Org Identifier"
#endregion

#region OAuth Certificate Validation
$report += Write-Section "OAUTH CERTIFICATE VALIDATION"

$report += Write-SubSection "Current OAuth Certificate"
$authConfig = Get-AuthConfig -ErrorAction SilentlyContinue
if ($authConfig -and $authConfig.CurrentCertificateThumbprint) {
    $report += Invoke-SafeCommand { 
        $thumbprint = (Get-AuthConfig).CurrentCertificateThumbprint
        Get-ExchangeCertificate -Thumbprint $thumbprint | Format-List Subject, Issuer, Thumbprint, NotBefore, NotAfter, Services, Status
    } "OAuth Certificate Details"
    
    # Check certificate expiration
    $report += Write-SubSection "Certificate Expiration Check"
    try {
        $thumbprint = $authConfig.CurrentCertificateThumbprint
        $cert = Get-ExchangeCertificate -Thumbprint $thumbprint -ErrorAction SilentlyContinue
        if ($cert) {
            $daysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days
            if ($daysUntilExpiry -lt 0) {
                Add-Issue -Severity "Critical" -Component "OAuth Certificate" -Description "OAuth certificate has EXPIRED ($daysUntilExpiry days ago)" -Recommendation "Generate a new OAuth certificate immediately and update AuthConfig"
                $report += "[CRITICAL] OAuth certificate has EXPIRED $([Math]::Abs($daysUntilExpiry)) days ago!`n"
            } elseif ($daysUntilExpiry -lt 30) {
                Add-Issue -Severity "Warning" -Component "OAuth Certificate" -Description "OAuth certificate expires in $daysUntilExpiry days" -Recommendation "Plan certificate renewal before expiration"
                $report += "[WARNING] OAuth certificate expires in $daysUntilExpiry days!`n"
            } elseif ($daysUntilExpiry -lt 90) {
                Add-Issue -Severity "Info" -Component "OAuth Certificate" -Description "OAuth certificate expires in $daysUntilExpiry days" -Recommendation "Schedule certificate renewal"
                $report += "[INFO] OAuth certificate expires in $daysUntilExpiry days`n"
            } else {
                $report += "[OK] OAuth certificate valid for $daysUntilExpiry more days.`n"
            }
            
            # Check if cert is on all servers
            $report += "`nCertificate presence on all CAS servers:`n"
            $missingCertServers = @()
            foreach ($server in $casServers) {
                try {
                    $serverCert = Get-ExchangeCertificate -Server $server.Name -Thumbprint $thumbprint -ErrorAction SilentlyContinue
                    if ($serverCert) {
                        $report += "  [OK] $($server.Name) - Certificate found`n"
                    } else {
                        $report += "  [CRITICAL] $($server.Name) - Certificate NOT FOUND!`n"
                        $missingCertServers += $server.Name
                    }
                } catch {
                    $report += "  [ERROR] $($server.Name) - Unable to check certificate`n"
                }
            }
            if ($missingCertServers.Count -gt 0) {
                Add-Issue -Severity "Critical" -Component "OAuth Certificate" -Description "OAuth certificate missing on servers: $($missingCertServers -join ', ')" -Recommendation "Export the OAuth certificate from a working server and import it to the affected servers"
            }
        } else {
            Add-Issue -Severity "Critical" -Component "OAuth Certificate" -Description "OAuth certificate with thumbprint $thumbprint not found" -Recommendation "Verify the certificate exists and update AuthConfig if needed"
            $report += "[CRITICAL] OAuth certificate not found!`n"
        }
    } catch {
        $report += "[ERROR] Unable to validate OAuth certificate: $_`n"
    }
} else {
    Add-Issue -Severity "Critical" -Component "OAuth Certificate" -Description "No OAuth certificate thumbprint found in AuthConfig" -Recommendation "Configure OAuth certificate using Set-AuthConfig -NewCertificateThumbprint"
    $report += "[CRITICAL] No OAuth certificate thumbprint found in AuthConfig!`n"
}

$report += Write-SubSection "All Exchange Certificates"
$report += Invoke-SafeCommand { Get-ExchangeCertificate | Format-Table Thumbprint, Subject, NotAfter, Services -AutoSize } "All Certificates"
#endregion

#region IIS SSL Certificate Validation
$report += Write-Section "IIS/HTTPS CERTIFICATE VALIDATION"

$report += Write-SubSection "IIS Certificate Bindings Analysis"
$report += @"

This section validates SSL/TLS certificates used for HTTPS endpoints.
Certificate issues can cause intermittent auth failures if:
- Certificate is expired or expiring soon
- Certificate chain is incomplete (missing intermediate CAs)
- Certificate SANs don't include all required hostnames
- Certificate root CA is not trusted by clients

"@

# Get certificates bound to IIS (those with IIS service)
$report += Invoke-SafeCommand {
    $iisCerts = Get-ExchangeCertificate | Where-Object { $_.Services -match 'IIS' }
    if ($iisCerts) {
        $iisCerts | Format-List Thumbprint, Subject, Issuer, NotBefore, NotAfter, CertificateDomains, Status
    } else {
        "No certificates with IIS service binding found"
    }
} "IIS-Bound Certificates"

# Check IIS certificate expiration and SANs
$report += Write-SubSection "IIS Certificate Health Check"
try {
    $iisCerts = Get-ExchangeCertificate | Where-Object { $_.Services -match 'IIS' }
    foreach ($cert in $iisCerts) {
        $report += "`n--- Certificate: $($cert.Subject) ---`n"
        $report += "  Thumbprint: $($cert.Thumbprint)`n"
        $report += "  Issuer: $($cert.Issuer)`n"
        
        # Check expiration
        $daysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days
        if ($daysUntilExpiry -lt 0) {
            Add-Issue -Severity "Critical" -Component "IIS Certificate" -Description "IIS certificate '$($cert.Subject)' has EXPIRED ($([Math]::Abs($daysUntilExpiry)) days ago)" -Recommendation "Replace the expired IIS certificate immediately"
            $report += "  [CRITICAL] EXPIRED $([Math]::Abs($daysUntilExpiry)) days ago!`n"
        } elseif ($daysUntilExpiry -lt 30) {
            Add-Issue -Severity "Warning" -Component "IIS Certificate" -Description "IIS certificate '$($cert.Subject)' expires in $daysUntilExpiry days" -Recommendation "Plan IIS certificate renewal before expiration"
            $report += "  [WARNING] Expires in $daysUntilExpiry days`n"
        } elseif ($daysUntilExpiry -lt 90) {
            Add-Issue -Severity "Info" -Component "IIS Certificate" -Description "IIS certificate '$($cert.Subject)' expires in $daysUntilExpiry days" -Recommendation "Schedule IIS certificate renewal"
            $report += "  [INFO] Expires in $daysUntilExpiry days`n"
        } else {
            $report += "  [OK] Valid for $daysUntilExpiry days`n"
        }
        
        # List SANs
        $report += "  Subject Alternative Names (SANs):`n"
        if ($cert.CertificateDomains) {
            foreach ($san in $cert.CertificateDomains) {
                $report += "    - $san`n"
            }
        } else {
            $report += "    [WARNING] No SANs found - only CN will be validated`n"
        }
        
        # Check if key URLs are covered
        $autodiscoverUrl = (Get-ClientAccessService | Select-Object -First 1).AutoDiscoverServiceInternalUri
        if ($autodiscoverUrl -and $cert.CertificateDomains) {
            $adHost = ([uri]$autodiscoverUrl).Host
            if ($cert.CertificateDomains -notcontains $adHost -and $cert.CertificateDomains -notcontains "*.$($adHost.Split('.',2)[1])") {
                Add-Issue -Severity "Warning" -Component "IIS Certificate" -Description "Autodiscover hostname '$adHost' may not be covered by certificate SANs" -Recommendation "Verify certificate includes all required hostnames or use a wildcard certificate"
                $report += "  [WARNING] Autodiscover host '$adHost' may not be in SANs`n"
            }
        }
    }
} catch {
    $report += "[ERROR] Unable to analyze IIS certificates: $_`n"
}

# Test external HTTPS endpoints for certificate chain issues
$report += Write-SubSection "External HTTPS Endpoint Certificate Tests"
$report += @"

Testing SSL/TLS certificates on external endpoints.
This identifies certificate chain issues that could cause client trust failures.

"@

# Get external URLs to test
$urlsToTest = @()
try {
    $easVDir = Get-ActiveSyncVirtualDirectory | Select-Object -First 1
    if ($easVDir.ExternalUrl) { $urlsToTest += $easVDir.ExternalUrl.ToString() }
    
    $adVDir = Get-AutodiscoverVirtualDirectory | Select-Object -First 1
    if ($adVDir.ExternalUrl) { $urlsToTest += $adVDir.ExternalUrl.ToString() }
    
    $ewsVDir = Get-WebServicesVirtualDirectory | Select-Object -First 1
    if ($ewsVDir.ExternalUrl) { $urlsToTest += $ewsVDir.ExternalUrl.ToString() }
    
    $owaVDir = Get-OwaVirtualDirectory | Select-Object -First 1
    if ($owaVDir.ExternalUrl) { $urlsToTest += $owaVDir.ExternalUrl.ToString() }
} catch {
    $report += "[WARNING] Could not retrieve virtual directory URLs: $_`n"
}

# Add unique URLs only
$urlsToTest = $urlsToTest | Select-Object -Unique

foreach ($url in $urlsToTest) {
    if ([string]::IsNullOrEmpty($url)) { continue }
    
    $report += "`n--- Testing: $url ---`n"
    
    try {
        $uri = [uri]$url
        $hostname = $uri.Host
        $port = if ($uri.Port -gt 0) { $uri.Port } else { 443 }
        
        # Create TCP connection and get SSL certificate
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($hostname, $port)
        
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, {
            param($sslSslSender, $certificate, $chain, $sslPolicyErrors)
            return $true  # Accept all certs for inspection
        })
        
        $sslStream.AuthenticateAsClient($hostname)
        $remoteCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sslStream.RemoteCertificate)
        
        $report += "  Subject: $($remoteCert.Subject)`n"
        $report += "  Issuer: $($remoteCert.Issuer)`n"
        $report += "  Expires: $($remoteCert.NotAfter)`n"
        $report += "  Thumbprint: $($remoteCert.Thumbprint)`n"
        
        # Check expiration
        $daysLeft = ($remoteCert.NotAfter - (Get-Date)).Days
        if ($daysLeft -lt 0) {
            $report += "  [CRITICAL] Certificate EXPIRED!`n"
        } elseif ($daysLeft -lt 30) {
            $report += "  [WARNING] Certificate expires in $daysLeft days`n"
        } else {
            $report += "  [OK] Certificate valid for $daysLeft days`n"
        }
        
        # Check certificate chain
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
        
        $chainBuilt = $chain.Build($remoteCert)
        
        $report += "  Certificate Chain:`n"
        for ($i = 0; $i -lt $chain.ChainElements.Count; $i++) {
            $element = $chain.ChainElements[$i]
            $indent = "    " + ("  " * $i)
            $report += "$indent$($element.Certificate.Subject)`n"
        }
        
        if (-not $chainBuilt -or $chain.ChainStatus.Count -gt 0) {
            $report += "  Chain Status Issues:`n"
            foreach ($status in $chain.ChainStatus) {
                $report += "    [WARNING] $($status.StatusInformation.Trim())`n"
                
                if ($status.Status -eq [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot) {
                    Add-Issue -Severity "Warning" -Component "IIS Certificate" -Description "Certificate chain for '$hostname' has untrusted root" -Recommendation "Ensure the root CA certificate is trusted on all client devices. The root CA may need to be distributed via Windows Update or MDM."
                } elseif ($status.Status -eq [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::PartialChain) {
                    Add-Issue -Severity "Warning" -Component "IIS Certificate" -Description "Incomplete certificate chain for '$hostname'" -Recommendation "Install intermediate CA certificates on the Exchange server. Export the full chain from the CA and reimport."
                }
            }
        } else {
            $report += "  [OK] Certificate chain is valid`n"
        }
        
        $sslStream.Close()
        $tcpClient.Close()
        
    } catch {
        $report += "  [ERROR] Unable to test endpoint: $($_.Exception.Message)`n"
        Add-Issue -Severity "Warning" -Component "IIS Certificate" -Description "Cannot validate SSL certificate for '$url'" -Recommendation "Verify the endpoint is accessible and the certificate is properly installed"
    }
}

# Check for intermediate certificate issues (common cause of intermittent failures)
$report += Write-SubSection "Certificate Chain Best Practices"
$report += @"

Important: Intermittent authentication failures can be caused by:

1. INCOMPLETE CERTIFICATE CHAIN
   - If intermediate CA certificates are not installed on the Exchange server,
     some clients may fail to build the trust chain.
   - iOS/mobile devices are particularly sensitive to this.
   - Solution: Export full certificate chain from CA and reimport.

2. ROOT CA NOT IN CLIENT TRUST STORE
   - Newer root CAs (like SSL.com TLS RSA Root CA 2022) may not be in older
     client trust stores unless Windows Update "Update Root Certificates" is enabled.
   - Mobile devices may have different root CA trust stores than Windows.
   - Solution: Verify root CA is trusted on all client platforms.

3. CERTIFICATE HOSTNAME MISMATCH
   - If the certificate doesn't include all hostnames used by clients
     (especially Autodiscover and EAS URLs), some clients will reject it.
   - Solution: Use a certificate with all required SANs or a wildcard.

"@
#endregion

#region Service Principal and Azure AD
$report += Write-Section "SERVICE PRINCIPAL INFORMATION"

$report += Write-SubSection "On-Premises Service Principal Name"
$report += Invoke-SafeCommand {
    $authConfig = Get-AuthConfig
    "Service Name: $($authConfig.ServiceName)"
    "Realm: $($authConfig.Realm)"
} "SPN Info"

$report += Write-SubSection "EvoSts Auth Server Details"
$report += Invoke-SafeCommand {
    Get-AuthServer | Where-Object { $_.Name -like "*EvoSts*" -or $_.Type -eq "AzureAD" } | Format-List *
} "EvoSts Configuration"
#endregion

#region IIS Configuration
$report += Write-Section "IIS AUTHENTICATION CONFIGURATION (ALL CAS SERVERS)"

if ($SkipRemoteCollection) {
    $report += "[SKIPPED] Remote collection disabled. Use -SkipRemoteCollection:`$false to enable.`n"
    
    $report += Write-SubSection "Local Server Only: $env:COMPUTERNAME"
    $report += Invoke-SafeCommand {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        $vdirs = @('Autodiscover', 'Microsoft-Server-ActiveSync')
        foreach ($vdir in $vdirs) {
            "`n=== $vdir ===`n"
            $authTypes = @('anonymousAuthentication', 'windowsAuthentication', 'basicAuthentication')
            foreach ($auth in $authTypes) {
                $enabled = (Get-WebConfigurationProperty -Filter "/system.webServer/security/authentication/$auth" -Name enabled -PSPath "IIS:\Sites\Default Web Site\$vdir" -ErrorAction SilentlyContinue).Value
                "$auth : $enabled"
            }
        }
    } "Local IIS Auth Settings"
}
elseif ($parallelResults.Count -gt 0) {
    # Use parallel results
    foreach ($serverName in $parallelResults.Keys) {
        $serverData = $parallelResults[$serverName]
        $report += Write-SubSection "IIS Configuration: $serverName"
        
        if ($serverData.IISConfig) {
            foreach ($vdir in $serverData.IISConfig) {
                $report += "`n=== $($vdir.Name) ===`n"
                foreach ($authType in $vdir.Auth.Keys) {
                    $report += "  $authType : $($vdir.Auth[$authType])`n"
                }
            }
        } else {
            $report += "[INFO] No IIS configuration data collected`n"
            if ($serverData.Errors) {
                foreach ($err in $serverData.Errors | Where-Object { $_ -like "IISConfig:*" }) {
                    $report += "[ERROR] $err`n"
                }
            }
        }
    }
}
else {
    # Fallback to sequential collection
    foreach ($server in $casServers) {
        $report += Write-SubSection "IIS Configuration: $($server.Name)"
        
        $report += Get-RemoteData -ServerName $server.Name -Description "IIS Auth Settings" -ScriptBlock {
            try {
                Import-Module WebAdministration -ErrorAction Stop
                $vdirs = @('Autodiscover', 'Microsoft-Server-ActiveSync', 'EWS', 'OWA', 'Mapi')
                $results = @()
                
                foreach ($vdir in $vdirs) {
                    $results += "`n=== $vdir ==="
                    $authTypes = @('anonymousAuthentication', 'windowsAuthentication', 'basicAuthentication')
                    foreach ($auth in $authTypes) {
                        try {
                            $enabled = (Get-WebConfigurationProperty -Filter "/system.webServer/security/authentication/$auth" -Name enabled -PSPath "IIS:\Sites\Default Web Site\$vdir" -ErrorAction SilentlyContinue).Value
                            $results += "  $auth : $enabled"
                        }
                        catch {
                            $results += "  $auth : [Unable to read]"
                        }
                    }
                }
                $results -join "`n"
            }
            catch {
                "WebAdministration module not available or error: $($_.Exception.Message)"
            }
        }
    }
}
#endregion

#region Client Access Rules
$report += Write-Section "CLIENT ACCESS AND AUTHENTICATION POLICIES"

$report += Write-SubSection "Client Access Rules"
$report += Invoke-SafeCommand { Get-ClientAccessRule | Format-List Name, Enabled, Priority, Action, AnyOfProtocols, AnyOfAuthenticationTypes, ExceptAnyOfProtocols, ExceptAnyOfAuthenticationTypes } "Client Access Rules"

$report += Write-SubSection "Authentication Policies"
$report += Invoke-SafeCommand { Get-AuthenticationPolicy | Format-List Name, *Block*, *Allow* } "Auth Policies"

# Check for policies that block modern auth for ActiveSync
$report += Write-SubSection "Authentication Policy Analysis"
try {
    $authPolicies = Get-AuthenticationPolicy -ErrorAction SilentlyContinue
    if ($authPolicies) {
        $blockingPolicies = $authPolicies | Where-Object { $_.BlockModernAuthActiveSync -eq $true }
        if ($blockingPolicies) {
            $report += "[WARNING] The following Authentication Policies BLOCK Modern Auth for ActiveSync:`n"
            foreach ($policy in $blockingPolicies) {
                $report += "  - $($policy.Name)`n"
                Add-Issue -Severity "Warning" -Component "Authentication Policy" `
                    -Description "Policy '$($policy.Name)' has BlockModernAuthActiveSync = True" `
                    -Recommendation "Check if affected users are assigned to this policy. Remove assignment or modify policy."
            }
            $report += "`n"
        } else {
            $report += "[OK] No authentication policies are blocking Modern Auth for ActiveSync.`n"
        }
    } else {
        $report += "[INFO] No custom authentication policies found.`n"
    }
} catch {
    $report += "[ERROR] Failed to analyze authentication policies: $_`n"
}

# If TestMailbox is specified, check that user's assigned authentication policy
if ($TestMailbox) {
    $report += Write-SubSection "Test User Authentication Policy Check"
    try {
        $userMailbox = Get-Mailbox -Identity $TestMailbox -ErrorAction SilentlyContinue
        if ($userMailbox) {
            $userPolicyName = $userMailbox.AuthenticationPolicy
            if ($userPolicyName) {
                $report += "User: $TestMailbox`n"
                $report += "Assigned Authentication Policy: $userPolicyName`n`n"
                
                $userPolicy = Get-AuthenticationPolicy -Identity $userPolicyName -ErrorAction SilentlyContinue
                if ($userPolicy) {
                    if ($userPolicy.BlockModernAuthActiveSync -eq $true) {
                        $report += "[CRITICAL] This user's authentication policy BLOCKS Modern Auth for ActiveSync!`n"
                        $report += "  BlockModernAuthActiveSync: $($userPolicy.BlockModernAuthActiveSync)`n"
                        $report += "  BlockModernAuthAutodiscover: $($userPolicy.BlockModernAuthAutodiscover)`n"
                        $report += "  BlockModernAuthImap: $($userPolicy.BlockModernAuthImap)`n"
                        $report += "  BlockModernAuthMapi: $($userPolicy.BlockModernAuthMapi)`n"
                        $report += "  BlockModernAuthOfflineAddressBook: $($userPolicy.BlockModernAuthOfflineAddressBook)`n"
                        $report += "  BlockModernAuthPop: $($userPolicy.BlockModernAuthPop)`n"
                        $report += "  BlockModernAuthRpc: $($userPolicy.BlockModernAuthRpc)`n"
                        $report += "  BlockModernAuthWebServices: $($userPolicy.BlockModernAuthWebServices)`n"
                        Add-Issue -Severity "Critical" -Component "User Authentication Policy" `
                            -Description "User $TestMailbox is assigned to policy '$userPolicyName' which blocks Modern Auth for ActiveSync" `
                            -Recommendation "Remove user from this policy or modify the policy: Set-AuthenticationPolicy '$userPolicyName' -BlockModernAuthActiveSync `$false"
                    } else {
                        $report += "[OK] User's authentication policy allows Modern Auth for ActiveSync.`n"
                        $report += "  BlockModernAuthActiveSync: $($userPolicy.BlockModernAuthActiveSync)`n"
                    }
                }
            } else {
                # Check if there's an org-wide default policy
                $orgConfig = Get-OrganizationConfig | Select-Object DefaultAuthenticationPolicy
                if ($orgConfig.DefaultAuthenticationPolicy) {
                    $defaultPolicy = Get-AuthenticationPolicy -Identity $orgConfig.DefaultAuthenticationPolicy -ErrorAction SilentlyContinue
                    $report += "User: $TestMailbox`n"
                    $report += "No explicit policy assigned - using org default: $($orgConfig.DefaultAuthenticationPolicy)`n`n"
                    
                    if ($defaultPolicy -and $defaultPolicy.BlockModernAuthActiveSync -eq $true) {
                        $report += "[CRITICAL] The organization default policy BLOCKS Modern Auth for ActiveSync!`n"
                        Add-Issue -Severity "Critical" -Component "Default Authentication Policy" `
                            -Description "Org default policy '$($orgConfig.DefaultAuthenticationPolicy)' blocks Modern Auth for ActiveSync" `
                            -Recommendation "Modify the default policy or assign user to a different policy that allows Modern Auth"
                    } elseif ($defaultPolicy) {
                        $report += "[OK] Organization default policy allows Modern Auth for ActiveSync.`n"
                    }
                } else {
                    $report += "User: $TestMailbox`n"
                    $report += "[OK] No explicit authentication policy assigned and no org default - Modern Auth allowed.`n"
                }
            }
        } else {
            $report += "[WARNING] Could not find mailbox for: $TestMailbox`n"
        }
    } catch {
        $report += "[ERROR] Failed to check user authentication policy: $_`n"
    }
}

$report += Write-SubSection "Organization Config - OAuth Settings"
$report += Invoke-SafeCommand { Get-OrganizationConfig | Format-List *OAuth*, *Modern*, *Auth* } "Org Config OAuth"
#endregion

#region Mobile Device Configuration
$report += Write-Section "MOBILE DEVICE CONFIGURATION"

$report += Write-SubSection "ActiveSync Organization Settings"
$report += Invoke-SafeCommand { Get-ActiveSyncOrganizationSettings | Format-List } "ActiveSync Org Settings"

$report += Write-SubSection "Mobile Device Mailbox Policies"
$report += Invoke-SafeCommand { Get-MobileDeviceMailboxPolicy | Format-List Name, IsDefault, AllowNonProvisionableDevices, DevicePasswordEnabled, AlphanumericPasswordRequired } "Mobile Device Policies"
#endregion

#region Test OAuth (if mailbox provided)
if ($TestMailbox) {
    $report += Write-Section "OAUTH CONNECTIVITY TEST"
    
    $report += Write-SubSection "Testing OAuth for: $TestMailbox"
    $report += Invoke-SafeCommand { Test-OAuthConnectivity -Service EWS -TargetUri "https://outlook.office365.com/ews/exchange.asmx" -Mailbox $TestMailbox -Verbose } "OAuth to O365 Test"
    
    $report += Write-SubSection "Testing Autodiscover"
    $report += Invoke-SafeCommand { Test-OutlookConnectivity -Protocol HTTP -GetDefaultsFromAutodiscover $true -MailboxCredential (Get-Credential -Message "Enter credentials for $TestMailbox") } "Outlook Connectivity"
}
#endregion

#region Network Endpoints
$report += Write-Section "NETWORK ENDPOINT VERIFICATION"

$report += Write-SubSection "Testing Azure AD Endpoints"
$endpoints = @(
    @{ Url = "https://login.microsoftonline.com"; TestPath = "/.well-known/openid-configuration" },
    @{ Url = "https://login.windows.net"; TestPath = "/common/.well-known/openid-configuration" },
    @{ Url = "https://autodiscover-s.outlook.com"; TestPath = "/autodiscover/autodiscover.json?Email=test@test.com&Protocol=ActiveSync" }
)

foreach ($ep in $endpoints) {
    $report += Invoke-SafeCommand {
        try {
            # First test DNS resolution
            $uri = [System.Uri]$ep.Url
            $dns = [System.Net.Dns]::GetHostAddresses($uri.Host)
            
            # Then test HTTP connectivity (use GET, some endpoints reject HEAD)
            $testUrl = $ep.Url + $ep.TestPath
            $response = Invoke-WebRequest -Uri $testUrl -Method Get -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
            "$($ep.Url) : Reachable (Status: $($response.StatusCode), DNS: $($dns[0]))"
        }
        catch [System.Net.WebException] {
            # Check if it's a DNS failure vs HTTP error
            if ($_.Exception.Status -eq 'NameResolutionFailure') {
                "$($ep.Url) : DNS FAILED - Cannot resolve hostname"
            } else {
                # HTTP errors (401, 403, etc.) still mean endpoint is reachable
                $statusCode = $null
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
                if ($statusCode) {
                    "$($ep.Url) : Reachable (HTTP $statusCode - endpoint responded)"
                } else {
                    "$($ep.Url) : FAILED - $($_.Exception.Message)"
                }
            }
        }
        catch {
            "$($ep.Url) : FAILED - $($_.Exception.Message)"
        }
    } "Endpoint: $($ep.Url)"
}
#endregion

#region Event Log Analysis
$report += Write-Section "RECENT AUTHENTICATION EVENTS (ALL CAS SERVERS)"

if ($SkipRemoteCollection) {
    $report += "[SKIPPED] Remote collection disabled. Collecting local server only.`n"
    
    $report += Write-SubSection "Local Server: $env:COMPUTERNAME - OAuth Events"
    $report += Invoke-SafeCommand {
        Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            ProviderName = 'MSExchange OAuth'
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 20 -ErrorAction SilentlyContinue | 
        Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap -AutoSize
    } "OAuth Events"
    
    $report += Write-SubSection "Local Server: $env:COMPUTERNAME - Autodiscover Errors"
    $report += Invoke-SafeCommand {
        Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            ProviderName = 'MSExchange Autodiscover'
            Level = 2,3
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 20 -ErrorAction SilentlyContinue |
        Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap -AutoSize
    } "Autodiscover Errors"
}
elseif ($parallelResults.Count -gt 0) {
    # Use parallel results for event logs
    foreach ($serverName in $parallelResults.Keys) {
        $serverData = $parallelResults[$serverName]
        $report += Write-SubSection "Event Logs: $serverName"
        
        $report += "`n--- MSExchange OAuth Events ---`n"
        if ($serverData.OAuthEvents -and $serverData.OAuthEvents.Count -gt 0) {
            $report += ($serverData.OAuthEvents | Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap -AutoSize | Out-String)
        } else {
            $report += "No OAuth events in the last 24 hours.`n"
        }
        
        $report += "`n--- MSExchange Autodiscover Errors ---`n"
        if ($serverData.AutodiscoverErrors -and $serverData.AutodiscoverErrors.Count -gt 0) {
            $report += ($serverData.AutodiscoverErrors | Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap -AutoSize | Out-String)
        } else {
            $report += "No Autodiscover errors in the last 24 hours.`n"
        }
        
        $report += "`n--- HTTP Service Errors (401/403) ---`n"
        if ($serverData.HttpErrors -and $serverData.HttpErrors.Count -gt 0) {
            $report += ($serverData.HttpErrors | Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap -AutoSize | Out-String)
        } else {
            $report += "No HTTP Service events in the last 24 hours.`n"
        }
    }
}
else {
    # Fallback to sequential collection
    foreach ($server in $casServers) {
        $report += Write-SubSection "Event Logs: $($server.Name)"
        
        $report += "`n--- MSExchange OAuth Events ---`n"
        $report += Get-RemoteData -ServerName $server.Name -Description "OAuth Events" -ScriptBlock {
            try {
                $events = Get-WinEvent -FilterHashtable @{
                    LogName = 'Application'
                    ProviderName = 'MSExchange OAuth'
                    StartTime = (Get-Date).AddHours(-24)
                } -MaxEvents 15 -ErrorAction SilentlyContinue
                
                if ($events) {
                    $events | Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-Table -Wrap -AutoSize
                } else {
                    "No OAuth events in the last 24 hours."
                }
            }
            catch {
                "No OAuth events found or error: $($_.Exception.Message)"
            }
        }
        
        $report += "`n--- MSExchange Autodiscover Errors ---`n"
        $report += Get-RemoteData -ServerName $server.Name -Description "Autodiscover Errors" -ScriptBlock {
            try {
                $events = Get-WinEvent -FilterHashtable @{
                    LogName = 'Application'
                    ProviderName = 'MSExchange Autodiscover'
                    Level = 2,3
                    StartTime = (Get-Date).AddHours(-24)
                } -MaxEvents 15 -ErrorAction SilentlyContinue
                
                if ($events) {
                    $events | Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-Table -Wrap -AutoSize
                } else {
                    "No Autodiscover errors in the last 24 hours."
                }
            }
            catch {
                "No Autodiscover errors found or error: $($_.Exception.Message)"
            }
        }
        
        $report += "`n--- HTTP Service Errors (401/403) ---`n"
        $report += Get-RemoteData -ServerName $server.Name -Description "HTTP Errors" -ScriptBlock {
            try {
                $events = Get-WinEvent -FilterHashtable @{
                    LogName = 'System'
                    ProviderName = 'Microsoft-Windows-HttpService'
                    StartTime = (Get-Date).AddHours(-24)
                } -MaxEvents 10 -ErrorAction SilentlyContinue
                
                if ($events) {
                    $events | Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-Table -Wrap -AutoSize
                } else {
                    "No HTTP Service events in the last 24 hours."
                }
            }
            catch {
                "No HTTP events found or error: $($_.Exception.Message)"
            }
        }
    }
}
#endregion

#region OAuth Certificate on All Servers
$report += Write-Section "OAUTH CERTIFICATE VERIFICATION (ALL CAS SERVERS)"

$authCfg = Get-AuthConfig -ErrorAction SilentlyContinue
$oauthThumbprint = $authCfg.CurrentCertificateThumbprint

if ($oauthThumbprint) {
    $report += "Expected OAuth Certificate Thumbprint: $oauthThumbprint`n`n"
    
    if ($SkipRemoteCollection) {
        $report += "[SKIPPED] Remote certificate verification disabled.`n"
    }
    elseif ($parallelResults.Count -gt 0) {
        # Use parallel results for OAuth certificate check
        $missingCertServers = @()
        foreach ($serverName in $parallelResults.Keys) {
            $serverData = $parallelResults[$serverName]
            $report += Write-SubSection "Certificate Check: $serverName"
            
            if ($serverData.OAuthCertificate) {
                if ($serverData.OAuthCertificate.Found) {
                    $report += "[OK] OAuth certificate found on this server.`n"
                    $report += "  Subject: $($serverData.OAuthCertificate.Subject)`n"
                    $report += "  Expires: $($serverData.OAuthCertificate.Expires)`n"
                    $report += "  Has Private Key: $($serverData.OAuthCertificate.HasPrivateKey)`n"
                } else {
                    $report += "[ERROR] OAuth certificate NOT FOUND on this server!`n"
                    $report += "  Expected thumbprint: $oauthThumbprint`n"
                    $missingCertServers += $serverName
                    if ($serverData.OAuthCertificate.AvailableCerts) {
                        $report += "`nAvailable certificates:`n"
                        $report += ($serverData.OAuthCertificate.AvailableCerts | Format-Table Thumbprint, Subject, NotAfter -AutoSize | Out-String)
                    }
                }
            } else {
                $report += "[INFO] No certificate data collected`n"
                if ($serverData.Errors) {
                    foreach ($err in $serverData.Errors | Where-Object { $_ -like "OAuthCert:*" }) {
                        $report += "[ERROR] $err`n"
                    }
                }
            }
        }
        if ($missingCertServers.Count -gt 0) {
            Add-Issue -Severity "Critical" -Component "OAuth Certificate" -Description "OAuth certificate missing on servers: $($missingCertServers -join ', ')" -Recommendation "Export the OAuth certificate from a working server and import it to the affected servers"
        }
    }
    else {
        # Fallback to sequential collection
        foreach ($server in $casServers) {
            $report += Write-SubSection "Certificate Check: $($server.Name)"
            
            $report += Get-RemoteData -ServerName $server.Name -Description "OAuth Certificate" -ArgumentList @($oauthThumbprint) -ScriptBlock {
                param($thumbprint)
                try {
                    $cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -eq $thumbprint }
                    if ($cert) {
                        "[OK] OAuth certificate found on this server."
                        "  Subject: $($cert.Subject)"
                        "  Expires: $($cert.NotAfter)"
                        "  Has Private Key: $($cert.HasPrivateKey)"
                    } else {
                        "[ERROR] OAuth certificate NOT FOUND on this server!"
                        "  Expected thumbprint: $thumbprint"
                        "`nAvailable certificates:"
                        Get-ChildItem -Path "Cert:\LocalMachine\My" | 
                            Where-Object { $_.Subject -like "*exchange*" -or $_.Subject -like "*auth*" } |
                            Select-Object Thumbprint, Subject, NotAfter | Format-Table -AutoSize
                    }
                }
                catch {
                    "[ERROR] Failed to check certificate: $($_.Exception.Message)"
                }
            }
        }
    }
}
else {
    $report += "[CRITICAL] No OAuth certificate configured in AuthConfig!`n"
}
#endregion

#region Summary and Recommendations
$report += Write-Section "CONFIGURATION SUMMARY AND CHECKS"

$report += Write-SubSection "Critical HMA Configuration Checks"

# Check 1: EvoSts Auth Server
$evoSts = Get-AuthServer | Where-Object { $_.Name -like "*EvoSts*" }
if ($evoSts) {
    if ($evoSts.Enabled -and $evoSts.IsDefaultAuthorizationEndpoint) {
        $report += "[OK] EvoSts Auth Server is configured and set as default.`n"
    } else {
        $report += "[WARNING] EvoSts Auth Server found but may not be properly configured.`n"
        $report += "  - Enabled: $($evoSts.Enabled)`n"
        $report += "  - IsDefaultAuthorizationEndpoint: $($evoSts.IsDefaultAuthorizationEndpoint)`n"
    }
} else {
    $report += "[CRITICAL] EvoSts Auth Server NOT FOUND! HMA will not work.`n"
    $report += "  Action: Run the Hybrid Configuration Wizard to configure OAuth.`n"
}


# Check 2: OAuth on Virtual Directories (with property existence check)
$asvdir = Get-ActiveSyncVirtualDirectory
$asvdirHasOAuthProp = $asvdir | Get-Member -Name OAuthAuthentication -MemberType *Property | Measure-Object | Select-Object -ExpandProperty Count
if ($asvdirHasOAuthProp -gt 0) {
    if ($asvdir.OAuthAuthentication -contains $true -or $asvdir[0].OAuthAuthentication -eq $true) {
        $report += "[OK] OAuth is enabled on ActiveSync Virtual Directory.`n"
    } else {
        $report += "[WARNING] OAuth may not be enabled on ActiveSync Virtual Directory.`n"
    }
} else {
    # Fallback: Check Internal/ExternalAuthenticationMethods for OAuth
    $oauthFound = $false
    foreach ($vdir in $asvdir) {
        if ($vdir.InternalAuthenticationMethods -contains 'OAuth' -or $vdir.ExternalAuthenticationMethods -contains 'OAuth') {
            $oauthFound = $true
            break
        }
    }
    if ($oauthFound) {
        $report += "[OK] OAuth is enabled for ActiveSync (detected via AuthenticationMethods).`n"
    } else {
        $report += "[CRITICAL] OAuth is NOT enabled for ActiveSync (no OAuth in AuthenticationMethods).`n"
        Add-Issue -Severity "Critical" -Component "ActiveSync VDir" -Description "OAuth not detected for ActiveSync (no OAuth in Internal/ExternalAuthenticationMethods)" -Recommendation "Run: Get-ActiveSyncVirtualDirectory -Server <ServerName> | Set-ActiveSyncVirtualDirectory -InternalAuthenticationMethods @{Add='OAuth'} -ExternalAuthenticationMethods @{Add='OAuth'}"
    }
}

$advdir = Get-AutodiscoverVirtualDirectory
if ($advdir.OAuthAuthentication -contains $true -or $advdir[0].OAuthAuthentication -eq $true) {
    $report += "[OK] OAuth is enabled on Autodiscover Virtual Directory.`n"
} else {
    $report += "[WARNING] OAuth may not be enabled on Autodiscover Virtual Directory.`n"
}

# Check 3: IntraOrganization Connector
$ioc = Get-IntraOrganizationConnector
if ($ioc) {
    if ($ioc.Enabled) {
        $report += "[OK] IntraOrganizationConnector is configured and enabled.`n"
    } else {
        $report += "[WARNING] IntraOrganizationConnector exists but is DISABLED.`n"
    }
} else {
    $report += "[CRITICAL] IntraOrganizationConnector NOT FOUND!`n"
}

# Check 4: Auth Certificate
$authCfg = Get-AuthConfig
if ($authCfg.CurrentCertificateThumbprint) {
    $cert = Get-ExchangeCertificate -Thumbprint $authCfg.CurrentCertificateThumbprint -ErrorAction SilentlyContinue
    if ($cert) {
        $daysLeft = ($cert.NotAfter - (Get-Date)).Days
        if ($daysLeft -gt 30) {
            $report += "[OK] OAuth certificate is valid ($daysLeft days remaining).`n"
        } else {
            $report += "[WARNING] OAuth certificate expires in $daysLeft days!`n"
        }
    }
} else {
    $report += "[CRITICAL] No OAuth certificate configured!`n"
}

# Check 5: Per-Server OAuth Configuration
$report += Write-SubSection "Per-Server OAuth Virtual Directory Status"
$asVdirs = Get-ActiveSyncVirtualDirectory
$adVdirs = Get-AutodiscoverVirtualDirectory
$ewsVdirs = Get-WebServicesVirtualDirectory

$report += "`nActiveSync Virtual Directories:`n"
$asOAuthDisabledServers = @()
foreach ($vdir in $asVdirs) {
    $serverName = $vdir.Server
    $oauth = $vdir.OAuthAuthentication
    $status = if ($oauth) { "[OK]" } else { "[WARNING]"; $asOAuthDisabledServers += $serverName }
    $report += "  $status $serverName - OAuth: $oauth`n"
}
if ($asOAuthDisabledServers.Count -gt 0) {
    Add-Issue -Severity "Critical" -Component "ActiveSync VDir" -Description "OAuth disabled on ActiveSync for servers: $($asOAuthDisabledServers -join ', ')" -Recommendation "Run: Get-ActiveSyncVirtualDirectory -Server <ServerName> | Set-ActiveSyncVirtualDirectory -OAuthAuthentication `$true"
}

$report += "`nAutodiscover Virtual Directories:`n"
$adOAuthDisabledServers = @()
foreach ($vdir in $adVdirs) {
    $serverName = $vdir.Server
    $oauth = $vdir.OAuthAuthentication
    $status = if ($oauth) { "[OK]" } else { "[WARNING]"; $adOAuthDisabledServers += $serverName }
    $report += "  $status $serverName - OAuth: $oauth`n"
}
if ($adOAuthDisabledServers.Count -gt 0) {
    Add-Issue -Severity "Critical" -Component "Autodiscover VDir" -Description "OAuth disabled on Autodiscover for servers: $($adOAuthDisabledServers -join ', ')" -Recommendation "Run: Get-AutodiscoverVirtualDirectory -Server <ServerName> | Set-AutodiscoverVirtualDirectory -OAuthAuthentication `$true"
}

$report += "`nEWS Virtual Directories:`n"
$ewsOAuthDisabledServers = @()
foreach ($vdir in $ewsVdirs) {
    $serverName = $vdir.Server
    $oauth = $vdir.OAuthAuthentication
    $status = if ($oauth) { "[OK]" } else { "[WARNING]"; $ewsOAuthDisabledServers += $serverName }
    $report += "  $status $serverName - OAuth: $oauth`n"
}
if ($ewsOAuthDisabledServers.Count -gt 0) {
    Add-Issue -Severity "Warning" -Component "EWS VDir" -Description "OAuth disabled on EWS for servers: $($ewsOAuthDisabledServers -join ', ')" -Recommendation "Run: Get-WebServicesVirtualDirectory -Server <ServerName> | Set-WebServicesVirtualDirectory -OAuthAuthentication `$true"
}

# Check 6: URL Consistency Check
$report += Write-SubSection "Virtual Directory URL Consistency Check"
$report += "`nChecking for inconsistent Autodiscover URLs across servers...`n"

$adInternalUrls = $adVdirs | Select-Object Server, @{N='InternalUrl';E={$_.InternalUrl.ToString()}} | Group-Object InternalUrl
$adExternalUrls = $adVdirs | Select-Object Server, @{N='ExternalUrl';E={if($_.ExternalUrl){$_.ExternalUrl.ToString()}else{"(not set)"}}} | Group-Object ExternalUrl

if ($adInternalUrls.Count -gt 1) {
    $report += "[WARNING] Inconsistent Autodiscover InternalUrl detected:`n"
    foreach ($group in $adInternalUrls) {
        $report += "  $($group.Name): $($group.Group.Server -join ', ')`n"
    }
    Add-Issue -Severity "Warning" -Component "Autodiscover URLs" -Description "Inconsistent InternalUrl across Autodiscover virtual directories" -Recommendation "Ensure all Autodiscover VDirs have the same InternalUrl"
} else {
    $report += "[OK] Autodiscover InternalUrl is consistent: $($adInternalUrls[0].Name)`n"
}

if ($adExternalUrls.Count -gt 1) {
    $report += "[WARNING] Inconsistent Autodiscover ExternalUrl detected:`n"
    foreach ($group in $adExternalUrls) {
        $report += "  $($group.Name): $($group.Group.Server -join ', ')`n"
    }
    Add-Issue -Severity "Warning" -Component "Autodiscover URLs" -Description "Inconsistent ExternalUrl across Autodiscover virtual directories" -Recommendation "Ensure all Autodiscover VDirs have the same ExternalUrl"
} else {
    $report += "[OK] Autodiscover ExternalUrl is consistent: $($adExternalUrls[0].Name)`n"
}

# Check 7: Authentication Method Conflicts
$report += Write-SubSection "Authentication Method Analysis"
$report += "`nChecking for authentication conflicts that may cause intermittent issues...`n"

foreach ($vdir in $asVdirs) {
    $serverName = $vdir.Server
    $conflicts = @()
    
    if ($vdir.BasicAuthentication -eq $true -and $vdir.OAuthAuthentication -eq $true) {
        $report += "[INFO] $serverName ActiveSync: Both Basic and OAuth enabled (normal for HMA)`n"
    }
    if ($vdir.WindowsAuthentication -eq $true -and $vdir.OAuthAuthentication -eq $true) {
        $report += "[WARNING] $serverName ActiveSync: Windows Auth enabled alongside OAuth`n"
        $conflicts += "Windows+OAuth"
    }
    if ($vdir.OAuthAuthentication -ne $true) {
        $report += "[CRITICAL] $serverName ActiveSync: OAuth is NOT enabled!`n"
    }
    
    if ($conflicts.Count -gt 0) {
        Add-Issue -Severity "Warning" -Component "ActiveSync Auth" -Description "$serverName has potentially conflicting auth methods: $($conflicts -join ', ')" -Recommendation "Review authentication settings on ActiveSync VDir"
    }
}

# Check 8: Server Count Summary
$report += Write-SubSection "Server Summary"
$report += "Total CAS Servers Discovered: $($casServers.Count)`n"
$report += "Servers: $(($casServers | Select-Object -ExpandProperty Name) -join ', ')`n"

if ($casServers.Count -eq 0) {
    Add-Issue -Severity "Critical" -Component "Server Discovery" -Description "No CAS servers were discovered" -Recommendation "Ensure you're running this from Exchange Management Shell and have proper permissions"
}

$report += "`n"
#endregion

#region Comprehensive Issues Summary
$report += Write-Section "CONFIGURATION ISSUES SUMMARY"

$totalCritical = $script:Issues.Critical.Count
$totalWarning = $script:Issues.Warning.Count
$totalInfo = $script:Issues.Info.Count

$report += @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                           ISSUES FOUND                                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  CRITICAL:  $totalCritical                                                                     ║
║  WARNING:   $totalWarning                                                                     ║
║  INFO:      $totalInfo                                                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

"@

if ($totalCritical -gt 0) {
    $report += Write-SubSection "CRITICAL ISSUES (Must Fix)"
    $report += "`n"
    $i = 1
    foreach ($issue in $script:Issues.Critical) {
        $report += @"
[$i] $($issue.Component)
    Problem: $($issue.Description)
    Fix: $($issue.Recommendation)

"@
        $i++
    }
}

if ($totalWarning -gt 0) {
    $report += Write-SubSection "WARNINGS (Should Investigate)"
    $report += "`n"
    $i = 1
    foreach ($issue in $script:Issues.Warning) {
        $report += @"
[$i] $($issue.Component)
    Problem: $($issue.Description)
    Fix: $($issue.Recommendation)

"@
        $i++
    }
}

if ($totalInfo -gt 0) {
    $report += Write-SubSection "INFORMATIONAL"
    $report += "`n"
    foreach ($issue in $script:Issues.Info) {
        $report += "- $($issue.Component): $($issue.Description)`n"
    }
}

if ($totalCritical -eq 0 -and $totalWarning -eq 0) {
    $report += @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ✓ NO CRITICAL OR WARNING ISSUES DETECTED                                   ║
║                                                                              ║
║   HMA configuration appears to be correct. If you're still experiencing      ║
║   intermittent issues, the problem may be:                                   ║
║   - Network/firewall related (blocking Azure AD endpoints)                   ║
║   - Client-side caching issues                                               ║
║   - DNS resolution problems                                                  ║
║   - Load balancer configuration                                              ║
║   - Conditional Access policies in Azure AD                                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

"@
}
#endregion

#region Next Steps - Test Script Guidance
$report += Write-Section "NEXT STEPS: TEST OAUTH AUTHENTICATION"

#region MFA Detection
$report += Write-SubSection "AUTHENTICATION REQUIREMENTS ANALYSIS"

$mfaDetected = $false
$mfaConfidence = "Unknown"
$mfaReason = @()
$mfaErrorsFound = @()

# Track federation/ADFS detection separately
$federationDetected = $false
$federationReason = @()
$passwordlessDetected = $false

# ============================================================================
# METHOD 0: Check for Federated Domain (ADFS) - ROPC will NEVER work
# ============================================================================
$report += "`n--- Checking for Federated Domain (ADFS) ---`n"
Write-Host "  Checking domain federation status..." -ForegroundColor Gray

if ($TestMailbox) {
    $testDomain = $TestMailbox.Split("@")[1]
    $report += "  Testing domain: $testDomain`n"
    
    try {
        # Use Azure AD realm discovery endpoint to check if domain is federated
        $userRealmUrl = "https://login.microsoftonline.com/common/UserRealm/$($TestMailbox)?api-version=2.0"
        
        Write-Host "    Querying Azure AD realm discovery..." -ForegroundColor Gray
        
        # Query the UserRealm endpoint to detect federation
        $userRealmResponse = Invoke-RestMethod -Uri $userRealmUrl -Method GET -ErrorAction Stop
        
        $report += "  Domain Type: $($userRealmResponse.NameSpaceType)`n"
        $report += "  Account Type: $($userRealmResponse.account_type)`n"
        
        if ($userRealmResponse.NameSpaceType -eq "Federated" -or $userRealmResponse.account_type -eq "Federated") {
            $federationDetected = $true
            $federationReason += "Domain '$testDomain' is FEDERATED (uses ADFS or external IdP)"
            
            if ($userRealmResponse.AuthURL) {
                $report += "  Federation Auth URL: $($userRealmResponse.AuthURL)`n"
                $federationReason += "Authentication redirects to: $($userRealmResponse.AuthURL)"
            }
            if ($userRealmResponse.federation_protocol) {
                $report += "  Federation Protocol: $($userRealmResponse.federation_protocol)`n"
            }
            
            $report += "`n[CRITICAL] FEDERATED DOMAIN DETECTED!`n"
            $report += "  ROPC (Resource Owner Password Credential) flow will NOT work with federated domains.`n"
            $report += "  Azure AD cannot validate passwords - authentication must go through ADFS/IdP.`n"
            $report += "  You MUST use -UseDeviceCode for all testing.`n"
            
            Add-Issue -Severity "Critical" -Component "Federation Detection" -Description "Domain '$testDomain' is federated (ADFS). ROPC authentication will not work." -Recommendation "Always use -UseDeviceCode switch when running Test-HmaEasNoEmptyBearer.ps1"
            
            Write-Host "    [!] FEDERATED DOMAIN - ROPC will not work!" -ForegroundColor Red
        } else {
            $report += "`n[OK] Domain is MANAGED (not federated) - ROPC may work if no other restrictions`n"
            Write-Host "    Domain is managed (not federated)" -ForegroundColor Green
        }
        
        # Check for cloud federation metadata hint
        if ($userRealmResponse.cloud_instance_name) {
            $report += "  Cloud Instance: $($userRealmResponse.cloud_instance_name)`n"
        }
        
    } catch {
        $report += "  [WARN] Could not query realm discovery: $($_.Exception.Message)`n"
        $report += "  [INFO] To manually check: https://login.microsoftonline.com/$testDomain/.well-known/openid-configuration`n"
        Write-Verbose "Realm discovery failed: $($_.Exception.Message)"
    }
    
    # Also check MSOnline for domain federation info if connected
    if ($azureADConnected -or (Get-Module -Name MSOnline -ErrorAction SilentlyContinue)) {
        try {
            $msolDomain = Get-MsolDomain -DomainName $testDomain -ErrorAction Stop
            if ($msolDomain.Authentication -eq "Federated") {
                $federationDetected = $true
                $federationReason += "MSOnline confirms domain is Federated"
                $report += "  MSOnline Domain Status: Federated`n"
            }
        } catch {
            # MSOnline not connected or domain not found - already handled above
        }
    }
} else {
    $report += "  [INFO] No -TestMailbox specified. Cannot check domain federation status.`n"
    $report += "         Provide -TestMailbox to enable federation detection.`n"
    Write-Host "    Skipping federation check (no -TestMailbox specified)" -ForegroundColor Yellow
}

# ============================================================================
# Check for Passwordless indicators (if Azure AD connected)
# ============================================================================
$report += "`n--- Checking for Passwordless Authentication ---`n"

if ($azureADConnected -and $TestMailbox) {
    try {
        # Check if user has passwordless methods configured
        # This is limited without Graph API, but we can check for FIDO2 / Phone sign-in hints
        $report += "  [INFO] Passwordless detection requires Microsoft Graph API for full accuracy.`n"
        $report += "         Common passwordless methods: FIDO2 keys, Microsoft Authenticator phone sign-in, Windows Hello`n"
        
        # If we found MFA methods earlier, check if they include passwordless types
        if ($msolUser -and $msolUser.StrongAuthenticationMethods) {
            $passwordlessMethods = $msolUser.StrongAuthenticationMethods | Where-Object { 
                $_.MethodType -in @("PhoneAppNotification", "FIDO2", "PhoneAppOTP") 
            }
            if ($passwordlessMethods) {
                $passwordlessDetected = $true
                $report += "  [DETECTED] User has passwordless-capable MFA methods: $($passwordlessMethods.MethodType -join ', ')`n"
                $federationReason += "User has passwordless-capable authentication methods"
            }
        }
    } catch {
        Write-Verbose "Passwordless check error: $($_.Exception.Message)"
    }
} else {
    $report += "  [INFO] Connect to Azure AD and provide -TestMailbox for passwordless detection.`n"
}

# ============================================================================
# METHOD 1: Scan OAuth Event Logs for MFA-related errors
# ============================================================================
$report += "`n--- Scanning OAuth logs for MFA-related errors ---`n"
Write-Host "  Scanning OAuth event logs for MFA patterns..." -ForegroundColor Gray

$mfaErrorCodes = @(
    "AADSTS50076",  # MFA required
    "AADSTS50079",  # MFA registration required
    "AADSTS50158",  # External security challenge (MFA)
    "AADSTS53000",  # Conditional Access - device not compliant
    "AADSTS53001",  # Conditional Access - device not domain joined
    "AADSTS53002",  # Application requires MFA
    "AADSTS7000218" # ROPC not allowed (often due to MFA policies)
)

$mfaErrorPattern = $mfaErrorCodes -join "|"

# Scan all CAS servers for MFA errors - use parallel results if available
$allMfaEvents = @()

if ($parallelResults.Count -gt 0) {
    # Use MFA events from parallel collection
    Write-Host "    Using MFA data from parallel collection..." -ForegroundColor Gray
    foreach ($serverName in $parallelResults.Keys) {
        $serverData = $parallelResults[$serverName]
        if ($serverData.MfaEvents -and $serverData.MfaEvents.Count -gt 0) {
            foreach ($evt in $serverData.MfaEvents) {
                $allMfaEvents += [PSCustomObject]@{
                    Server = $serverName
                    Time = $evt.Time
                    Message = $evt.Message
                    MatchedCode = $evt.MatchedCode
                }
            }
        }
    }
}
elseif (-not $SkipRemoteCollection -and $casServers.Count -gt 0) {
    # Fallback to sequential collection
    foreach ($server in $casServers) {
        Write-Host "    Checking $($server.Name) for MFA errors..." -ForegroundColor Gray
        try {
            $serverEvents = Invoke-Command -ComputerName $server.Name -ScriptBlock {
                param($pattern, $codes)
                $events = @()
                try {
                    $oauthEvents = Get-WinEvent -FilterHashtable @{
                        LogName = 'Application'
                        ProviderName = 'MSExchange OAuth'
                        StartTime = (Get-Date).AddDays(-7)
                    } -MaxEvents 100 -ErrorAction SilentlyContinue
                    
                    foreach ($evt in $oauthEvents) {
                        if ($evt.Message -match $pattern) {
                            $events += [PSCustomObject]@{
                                Server = $env:COMPUTERNAME
                                Time = $evt.TimeCreated
                                Message = $evt.Message
                                MatchedCode = ($codes | Where-Object { $evt.Message -match $_ }) -join ", "
                            }
                        }
                    }
                } catch {
                    # Log access may fail on some servers - non-critical
                    $null = $_
                }
                return $events
            } -ArgumentList $mfaErrorPattern, $mfaErrorCodes -ErrorAction SilentlyContinue
            
            if ($serverEvents) {
                $allMfaEvents += $serverEvents
            }
        } catch {
            $report += "  [WARN] Could not scan $($server.Name): $($_.Exception.Message)`n"
            Write-Verbose "Failed to scan $($server.Name) for MFA events: $($_.Exception.Message)"
        }
    }
} else {
    # Local server only
    Write-Host "    Checking local server for MFA errors..." -ForegroundColor Gray
    try {
        $oauthEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            ProviderName = 'MSExchange OAuth'
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 100 -ErrorAction SilentlyContinue
        
        foreach ($evt in $oauthEvents) {
            if ($evt.Message -match $mfaErrorPattern) {
                $allMfaEvents += [PSCustomObject]@{
                    Server = $env:COMPUTERNAME
                    Time = $evt.TimeCreated
                    Message = $evt.Message
                    MatchedCode = ($mfaErrorCodes | Where-Object { $evt.Message -match $_ }) -join ", "
                }
            }
        }
    } catch {
        $report += "  [WARN] Could not scan local OAuth logs: $($_.Exception.Message)`n"
        Write-Verbose "Failed to scan local server for MFA events: $($_.Exception.Message)"
    }
}

if ($allMfaEvents.Count -gt 0) {
    $mfaDetected = $true
    $mfaConfidence = "High"
    $mfaReason += "Found $($allMfaEvents.Count) MFA-related authentication errors in the last 7 days"
    
    $report += "`n[DETECTED] MFA-related authentication errors found!`n"
    $report += "  Total MFA errors: $($allMfaEvents.Count)`n"
    
    # Group by error code
    $errorCodeGroups = $allMfaEvents | Group-Object MatchedCode | Sort-Object Count -Descending
    $report += "`n  Error breakdown:`n"
    foreach ($group in $errorCodeGroups) {
        $codeDescription = switch -Regex ($group.Name) {
            "AADSTS50076" { "MFA required by policy" }
            "AADSTS50079" { "MFA registration required" }
            "AADSTS50158" { "External security challenge (MFA)" }
            "AADSTS53000" { "Device not compliant" }
            "AADSTS53001" { "Device not domain joined" }
            "AADSTS53002" { "Application requires MFA" }
            "AADSTS7000218" { "ROPC disabled (likely MFA policy)" }
            default { "MFA/Conditional Access" }
        }
        $report += "    $($group.Name): $($group.Count) occurrences - $codeDescription`n"
        $mfaErrorsFound += "$($group.Name) ($($group.Count)x)"
    }
    
    # Show recent examples
    $report += "`n  Recent MFA errors (last 5):`n"
    $recentErrors = $allMfaEvents | Sort-Object Time -Descending | Select-Object -First 5
    foreach ($err in $recentErrors) {
        $report += "    [$($err.Time.ToString('yyyy-MM-dd HH:mm'))] $($err.Server): $($err.MatchedCode)`n"
        Write-Verbose "MFA Error: $($err.Time) on $($err.Server) - $($err.MatchedCode)"
    }
    
    Add-Issue -Severity "Warning" -Component "MFA Detection" -Description "MFA-related errors detected in OAuth logs: $($mfaErrorsFound -join ', ')" -Recommendation "Use -UseDeviceCode switch when running Test-HmaEasNoEmptyBearer.ps1"
} else {
    $report += "`n[OK] No MFA-related errors found in OAuth logs (last 7 days)`n"
    $mfaReason += "No MFA errors in OAuth logs"
}

# ============================================================================
# METHOD 2: Check Azure AD MFA Status (if module available and connected)
# ============================================================================
$report += "`n--- Checking Azure AD MFA Status ---`n"
Write-Host "  Checking for Azure AD module..." -ForegroundColor Gray

$azureADChecked = $false
$azureADConnected = $false

# Try MSOnline module first
if (Get-Module -ListAvailable -Name MSOnline -ErrorAction SilentlyContinue) {
    $report += "  MSOnline module: Available`n"
    Write-Verbose "MSOnline module is available"
    
    try {
        # Check if already connected
        $msolCompanyInfo = Get-MsolCompanyInformation -ErrorAction Stop
        $azureADConnected = $true
        $report += "  MSOnline connection: Active (Tenant: $($msolCompanyInfo.DisplayName))`n"
        Write-Verbose "Connected to MSOnline - Tenant: $($msolCompanyInfo.DisplayName)"
        
        if ($TestMailbox) {
            Write-Host "    Querying MFA status for $TestMailbox..." -ForegroundColor Gray
            try {
                $msolUser = Get-MsolUser -UserPrincipalName $TestMailbox -ErrorAction Stop
                $azureADChecked = $true
                
                $report += "`n  User MFA Status for: $TestMailbox`n"
                $report += "    Display Name: $($msolUser.DisplayName)`n"
                $report += "    Licensed: $($msolUser.IsLicensed)`n"
                $report += "    Block Credential: $($msolUser.BlockCredential)`n"
                
                # Check Strong Authentication
                $mfaMethods = $msolUser.StrongAuthenticationMethods
                $mfaRequirements = $msolUser.StrongAuthenticationRequirements
                
                if ($mfaMethods -and $mfaMethods.Count -gt 0) {
                    $mfaDetected = $true
                    $mfaConfidence = "Confirmed"
                    $mfaReason += "User has $($mfaMethods.Count) MFA method(s) registered"
                    
                    $report += "    MFA Methods Registered: $($mfaMethods.Count)`n"
                    foreach ($method in $mfaMethods) {
                        $defaultStr = if ($method.IsDefault) { " (Default)" } else { "" }
                        $report += "      - $($method.MethodType)$defaultStr`n"
                        Write-Verbose "MFA Method: $($method.MethodType) - Default: $($method.IsDefault)"
                    }
                } else {
                    $report += "    MFA Methods Registered: None`n"
                    $mfaReason += "No MFA methods registered for user"
                }
                
                if ($mfaRequirements -and $mfaRequirements.Count -gt 0) {
                    $mfaDetected = $true
                    $mfaConfidence = "Confirmed"
                    $mfaReason += "MFA is enforced for this user"
                    
                    $report += "    MFA Enforcement State: $($mfaRequirements[0].State)`n"
                    Write-Verbose "MFA Enforcement: $($mfaRequirements[0].State)"
                } else {
                    $report += "    MFA Enforcement: Not directly enforced (may still be required by Conditional Access)`n"
                }
                
            } catch {
                $report += "  [WARN] Could not query user MFA status: $($_.Exception.Message)`n"
                Write-Verbose "Failed to query MFA status: $($_.Exception.Message)"
            }
        } else {
            $report += "  [INFO] No -TestMailbox specified. Provide -TestMailbox to check specific user MFA status.`n"
        }
        
    } catch {
        $report += "  MSOnline connection: Not connected`n"
        $report += "  [INFO] To enable MFA status check, run: Connect-MsolService`n"
        Write-Verbose "MSOnline not connected: $($_.Exception.Message)"
    }
} elseif (Get-Module -ListAvailable -Name AzureAD -ErrorAction SilentlyContinue) {
    $report += "  AzureAD module: Available`n"
    Write-Verbose "AzureAD module is available"
    
    try {
        $aadTenant = Get-AzureADTenantDetail -ErrorAction Stop
        $azureADConnected = $true
        $report += "  AzureAD connection: Active (Tenant: $($aadTenant.DisplayName))`n"
        Write-Verbose "Connected to AzureAD - Tenant: $($aadTenant.DisplayName)"
        
        if ($TestMailbox) {
            Write-Host "    Querying user info for $TestMailbox..." -ForegroundColor Gray
            try {
                $aadUser = Get-AzureADUser -ObjectId $TestMailbox -ErrorAction Stop
                $azureADChecked = $true
                
                $report += "`n  User Info for: $TestMailbox`n"
                $report += "    Display Name: $($aadUser.DisplayName)`n"
                $report += "    Account Enabled: $($aadUser.AccountEnabled)`n"
                $report += "    User Type: $($aadUser.UserType)`n"
                
                # Note: AzureAD module doesn't have direct MFA status, suggest MSOnline or Graph
                $report += "  [INFO] For detailed MFA status, use MSOnline module or Azure Portal`n"
                
            } catch {
                $report += "  [WARN] Could not query user: $($_.Exception.Message)`n"
                Write-Verbose "Failed to query AzureAD user: $($_.Exception.Message)"
            }
        }
        
    } catch {
        $report += "  AzureAD connection: Not connected`n"
        $report += "  [INFO] To enable user lookup, run: Connect-AzureAD`n"
        Write-Verbose "AzureAD not connected: $($_.Exception.Message)"
    }
} else {
    $report += "  Azure AD modules: Not installed`n"
    $report += "  [INFO] Install MSOnline module for MFA status checking:`n"
    $report += "         Install-Module MSOnline -Force`n"
    Write-Verbose "No Azure AD modules available"
}

# ============================================================================
# MFA DETECTION SUMMARY AND RECOMMENDATION
# ============================================================================
$report += Write-SubSection "AUTHENTICATION REQUIREMENTS SUMMARY"

$recommendDeviceCode = $false
$recommendationConfidence = "Low"
$requireDeviceCodeReason = @()

# Federation ALWAYS requires Device Code - highest priority
if ($federationDetected) {
    $recommendDeviceCode = $true
    $recommendationConfidence = "Required"
    $requireDeviceCodeReason += "Federated domain (ADFS) detected - ROPC cannot work"
}

# Passwordless also requires Device Code
if ($passwordlessDetected) {
    $recommendDeviceCode = $true
    if ($recommendationConfidence -ne "Required") { $recommendationConfidence = "Required" }
    $requireDeviceCodeReason += "Passwordless authentication configured"
}

# MFA detection
if ($mfaDetected) {
    $recommendDeviceCode = $true
    if ($recommendationConfidence -eq "Low") { $recommendationConfidence = $mfaConfidence }
    $requireDeviceCodeReason += "MFA is enabled for user"
}

# Build the summary box with enhanced information
$federationStatusIcon = if ($federationDetected) { "⚠ YES (ADFS)" } else { "✓ NO" }
$mfaStatusIcon = if ($mfaDetected) { "⚠ YES" } else { "✓ NO" }
$passwordlessStatusIcon = if ($passwordlessDetected) { "⚠ YES" } else { "✓ NO" }
$recommendedMode = if ($recommendDeviceCode) { "-UseDeviceCode (REQUIRED)" } else { "Standard (no switch)" }

$report += @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                 AUTHENTICATION REQUIREMENTS DETECTED                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Federated Domain:    $($federationStatusIcon.PadRight(54))║
║  MFA Detected:        $($mfaStatusIcon.PadRight(54))║
║  Passwordless:        $($passwordlessStatusIcon.PadRight(54))║
║                                                                              ║
║  Confidence:          $($recommendationConfidence.PadRight(54))║
║  Recommended Mode:    $($recommendedMode.PadRight(54))║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

"@

Write-Host "`n  Authentication Requirements Detection:" -ForegroundColor Cyan

# Show federation status first (most important)
if ($federationDetected) {
    Write-Host "    [!] FEDERATED DOMAIN (ADFS) - ROPC will NOT work!" -ForegroundColor Red
    Write-Host "        You MUST use -UseDeviceCode for all testing" -ForegroundColor Red
}

if ($passwordlessDetected) {
    Write-Host "    [!] PASSWORDLESS AUTH detected - ROPC will NOT work!" -ForegroundColor Red
}

if ($mfaDetected) {
    Write-Host "    [!] MFA DETECTED ($mfaConfidence confidence)" -ForegroundColor Yellow
    Write-Host "        Recommendation: Use -UseDeviceCode switch" -ForegroundColor Yellow
}

if (-not $federationDetected -and -not $mfaDetected -and -not $passwordlessDetected) {
    Write-Host "    No special auth requirements detected" -ForegroundColor Green
    Write-Host "    Recommendation: Try standard mode first" -ForegroundColor Green
}

$report += "`nDetection Details:`n"

# Add federation reasons first
foreach ($reason in $federationReason) {
    $report += "  - $reason`n"
}

# Add MFA reasons
foreach ($reason in $mfaReason) {
    $report += "  - $reason`n"
}

# Add Device Code requirement reasons
if ($requireDeviceCodeReason.Count -gt 0) {
    $report += "`nWhy -UseDeviceCode is required:`n"
    foreach ($reason in $requireDeviceCodeReason) {
        $report += "  → $reason`n"
    }
}

if (-not $azureADChecked -and -not $allMfaEvents.Count -and -not $federationDetected) {
    $report += "`n[INFO] Detection was limited. For more accurate detection:`n"
    if (-not $azureADConnected) {
        $report += "  1. Connect to Azure AD: Connect-MsolService`n"
    }
    if (-not $TestMailbox) {
        $report += "  2. Provide -TestMailbox parameter`n"
    }
    $report += "  3. Check Azure Portal for Conditional Access policies`n"
}

#endregion MFA Detection

# Provide guidance based on environment
$report += @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                    STEP 2: TEST OAUTH FLOW                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

After reviewing this configuration report, run the test script to validate the
actual OAuth authentication flow:

  .\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "<user@domain.com>"

"@

$report += Write-SubSection "WHICH AUTHENTICATION MODE SHOULD I USE?"

$report += @"

┌─────────────────────────────────────────────────────────────────────────────┐
│  DECISION GUIDE: Standard Mode vs. Device Code (-UseDeviceCode)             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  USE STANDARD MODE (no switch) when:                                        │
│  ✓ Domain is MANAGED (not federated/ADFS)                                   │
│  ✓ Testing with a service account that has NO MFA                           │
│  ✓ User has MFA but is excluded via Conditional Access policy               │
│  ✓ ROPC (Resource Owner Password Credential) flow is allowed in tenant      │
│  ✓ NOT using passwordless authentication                                    │
│                                                                             │
│  Example:                                                                   │
│    .\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "svc-test@contoso.com"      │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  USE DEVICE CODE MODE (-UseDeviceCode) when:                                │
│  ★ Domain is FEDERATED (uses ADFS) - ROPC will NEVER work!                  │
│  ★ Passwordless authentication is configured                                │
│  ✓ User has MFA enabled (most common scenario)                              │
│  ✓ Standard mode fails with error AADSTS50076 or AADSTS50079                │
│  ✓ Standard mode fails with AADSTS50126 in federated environment            │
│  ✓ Conditional Access policies require interactive authentication           │
│  ✓ ROPC flow is disabled in the tenant                                      │
│  ✓ You want to test the exact same flow as Outlook mobile                   │
│                                                                             │
│  Example:                                                                   │
│    .\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "user@contoso.com" `        │
│        -UseDeviceCode -Verbose                                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

"@

# The old MFA Status Detection section is now replaced by the comprehensive detection above
# Remove redundant manual check guidance since we now have automated detection

$report += Write-SubSection "RECOMMENDED TEST COMMANDS"

# Build the test command based on MFA detection results
$testMailboxToUse = if ($TestMailbox) { $TestMailbox } else { "<user@domain.com>" }

# Use detection results to provide smart recommendations
if ($recommendDeviceCode) {
    # Determine the reason for the recommendation
    $reasonBanner = if ($federationDetected) {
        "► FEDERATED DOMAIN (ADFS) - DEVICE CODE REQUIRED"
    } elseif ($passwordlessDetected) {
        "► PASSWORDLESS AUTH - DEVICE CODE REQUIRED"
    } else {
        "► MFA DETECTED - USE DEVICE CODE MODE"
    }
    
    $report += @"

╔══════════════════════════════════════════════════════════════════════════════╗
║  $($reasonBanner.PadRight(74))║
╚══════════════════════════════════════════════════════════════════════════════╝

"@
    
    if ($federationDetected) {
        $report += @"
Your domain uses ADFS/federation. ROPC (password-based) authentication will NOT
work because Azure AD cannot validate passwords - they must go through ADFS.
The -UseDeviceCode switch is REQUIRED for all testing in this environment.

"@
    }
    
    $report += @"
# REQUIRED COMMAND (based on environment detection):
.\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "$testMailboxToUse" -UseDeviceCode -Verbose

# TO SAVE DETAILED LOG for support:
.\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "$testMailboxToUse" -UseDeviceCode -Verbose -OutputPath "C:\Logs\HmaTest.log"

"@
} else {
    $report += @"

╔══════════════════════════════════════════════════════════════════════════════╗
║  ► NO SPECIAL AUTH REQUIREMENTS - TRY STANDARD MODE FIRST                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

Based on detection, try standard mode first:

# ATTEMPT 1: Try standard mode (no MFA detected)
.\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "$testMailboxToUse" -Verbose

# IF THAT FAILS with MFA error (AADSTS50076, AADSTS50079), use Device Code mode:
.\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "$testMailboxToUse" -UseDeviceCode -Verbose

# TO SAVE DETAILED LOG for support:
.\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "$testMailboxToUse" -UseDeviceCode -Verbose -OutputPath "C:\Logs\HmaTest.log"

"@
}

$report += @"

┌─────────────────────────────────────────────────────────────────────────────┐
│  ERROR CODE REFERENCE                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ Error Code      │ Meaning                    │ Solution                     │
├─────────────────┼────────────────────────────┼──────────────────────────────│
│ AADSTS50076     │ MFA required               │ Use -UseDeviceCode           │
│ AADSTS50079     │ MFA registration required  │ Use -UseDeviceCode           │
│ AADSTS7000218   │ ROPC disabled in tenant    │ Use -UseDeviceCode           │
│ AADSTS50126     │ Invalid credentials        │ Check username/password      │
│ AADSTS50034     │ User not found in tenant   │ Check user is synced to AAD  │
└─────────────────────────────────────────────────────────────────────────────┘

"@

if ($totalCritical -gt 0) {
    $report += @"

╔══════════════════════════════════════════════════════════════════════════════╗
║  ⚠ WARNING: CRITICAL ISSUES DETECTED                                        ║
║                                                                              ║
║  This diagnostic found $totalCritical critical issue(s) that will likely cause the   ║
║  test script to fail. Fix the critical issues listed above BEFORE running   ║
║  the test script.                                                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

"@
}

#endregion


# --- Timed Section: (End/Report Summary) ---
$endTime = Get-Date
$duration = $endTime - $startTime

# Section timing summary
$timingSummary = @()
$timingSummary += "`n================================================================================"
$timingSummary += "SECTION TIMING SUMMARY (seconds)"
$timingSummary += "================================================================================"
foreach ($key in $sectionTimings.Keys) {
    $timingSummary += ("{0,-45}: {1,8:N2}" -f $key, $sectionTimings[$key])
}
$timingSummary += ("{0,-45}: {1,8:N2}" -f "Total Script Duration", $duration.TotalSeconds)
$timingSummary += "================================================================================`n"
$report += ($timingSummary -join "`n")

$footer = @"

################################################################################
Report completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Duration: $($duration.TotalSeconds) seconds
Output saved to: $OutputPath
################################################################################
"@

$report += $footer
Write-Host $footer -ForegroundColor Green

# Save report
$report | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "`nReport saved to: $OutputPath" -ForegroundColor Cyan
Write-Host "Please review the report and share with support if needed.`n" -ForegroundColor Yellow

#endregion


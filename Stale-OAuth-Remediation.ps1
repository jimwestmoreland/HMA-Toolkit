# VERSION: 2026-02-05 UTC
<#
.SYNOPSIS
    Diagnose and remediate stale OAuth certificate metadata on Exchange servers for HMA.

.DESCRIPTION
    This script addresses the "different certificate(s) have been found" errors
    (Event 2008) in MSExchange OAuth logs by first diagnosing the root cause,
    then refreshing authentication metadata if appropriate.
    
    NEW IN THIS VERSION:
    - Auto-detects all Exchange servers in the organization
    - Tests Azure AD connectivity FROM EACH SERVER to identify per-server issues
    - Generates a comprehensive diagnostic report showing:
      * Certificate cache status (stale vs current)
      * Per-server connectivity status
      * SSL inspection detection per server
      * Network path issues vs clean paths
    
    DIAGNOSTIC WORKFLOW:
    1. Auto-discovers all Exchange servers (or uses specified list)
    2. Fetches current certificates from Azure AD metadata endpoints
    3. Compares with certificates cached by Exchange Auth Servers
    4. Tests connectivity to Azure AD FROM EACH Exchange server
    5. Checks for SSL inspection (non-Microsoft certificate issuers)
    6. Generates summary report with per-server status
    7. Determines if cache is stale or if intermittent SSL inspection is occurring
    
    OUTCOMES:
    - STALE CACHE: Recommends and performs metadata refresh
    - SSL INSPECTION: Blocks remediation, advises to bypass SSL inspection
    - PARTIAL SSL INSPECTION: Some servers clean, some intercepted
    - CURRENT CACHE: Warns of intermittent SSL inspection, optional refresh
    
.PARAMETER TestMailbox
    Email address of a mailbox to use for OAuth connectivity testing.
    If provided, runs Test-OAuthConnectivity after remediation.

.PARAMETER ExchangeServers
    Specific Exchange server(s) to test. If not specified, auto-detects all servers.

.PARAMETER DiagnoseOnly
    Only perform diagnostic checks without making any changes.
    Shows whether cache is stale or if SSL inspection is detected.

.PARAMETER WhatIf
    Shows what would be done without making changes.

.PARAMETER Force
    Skip confirmation prompts and proceed with remediation even if cache appears current.

.PARAMETER LocalOnly
    Only test from the local server, skip auto-detection of other servers.

.PARAMETER CacheCheckOnly
    Simplified mode for restricted environments. Only compares cached certificates
    against live Azure AD certificates. Skips all remote server testing, connectivity
    checks, and SSL inspection detection. Produces a simple report showing cache
    status for each Auth Server. Ideal when WinRM, Invoke-Command, or network
    testing is blocked by security policies.

.PARAMETER QuickStatus
    Quick summary mode. Runs connectivity tests on all servers and displays only
    the per-server status table with cache and SSL status. Skips detailed analysis,
    recommendations, and remediation prompts. Useful for quick checks or monitoring.

.EXAMPLE
    .\Stale-OAuth-Remediation.ps1
    # Auto-detect all servers, diagnose, and show report

.EXAMPLE
    .\Stale-OAuth-Remediation.ps1 -DiagnoseOnly
    # Check all servers without making changes

.EXAMPLE
    .\Stale-OAuth-Remediation.ps1 -LocalOnly
    # Only test from the current server

.EXAMPLE
    .\Stale-OAuth-Remediation.ps1 -TestMailbox "user@contoso.com"
    # Diagnose, refresh metadata if needed, and test OAuth connectivity

.EXAMPLE
    .\Stale-OAuth-Remediation.ps1 -ExchangeServers "EX01","EX02" -Force
    # Test specific servers without prompts

.EXAMPLE
    .\Stale-OAuth-Remediation.ps1 -CacheCheckOnly
    # Simple cache vs Azure AD comparison only (for restricted environments)

.EXAMPLE
    .\Stale-OAuth-Remediation.ps1 -QuickStatus
    # Quick per-server status table only (no detailed analysis or remediation)

.NOTES
    Author: HMA Troubleshooting Toolkit
    Date: 2026-02-04
    
    Run from Exchange Management Shell with appropriate permissions.
    Requires WinRM access to remote Exchange servers for connectivity testing.
    
    This script addresses errors like:
    - Event 2008: "When retrieving metadata from the url '...', different certificate(s) have been found."
    - Event 2007: Connection errors to OAuth metadata endpoints
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$TestMailbox,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExchangeServers,
    
    [Parameter(Mandatory = $false)]
    [switch]$DiagnoseOnly,
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory = $false)]
    [switch]$Force,
    
    [Parameter(Mandatory = $false)]
    [switch]$LocalOnly,
    
    [Parameter(Mandatory = $false)]
    [switch]$CacheCheckOnly,
    
    [Parameter(Mandatory = $false)]
    [switch]$QuickStatus
)

#region Functions

function Write-Banner {
    param([string]$Text)
    $line = "=" * 78
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ""
}

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "[$Text]" -ForegroundColor Yellow
    Write-Host ("-" * 60) -ForegroundColor Gray
}

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info"
    )
    
    $colors = @{
        "Info"    = "White"
        "Success" = "Green"
        "Warning" = "Yellow"
        "Error"   = "Red"
    }
    $symbols = @{
        "Info"    = "[i]"
        "Success" = "[+]"
        "Warning" = "[!]"
        "Error"   = "[X]"
    }
    
    Write-Host "$($symbols[$Type]) $Message" -ForegroundColor $colors[$Type]
}

function Test-ExchangeManagementShell {
    try {
        $null = Get-Command Get-AuthServer -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Get-ExchangeServersAutoDetect {
    <#
    .SYNOPSIS
        Auto-detects all Exchange servers with ClientAccess role.
    #>
    Write-Section "Discovering Exchange Servers"
    
    try {
        $servers = Get-ExchangeServer -ErrorAction Stop | Where-Object {
            $_.ServerRole -match "Mailbox|ClientAccess" -or $_.IsClientAccessServer -eq $true
        } | Select-Object -ExpandProperty Name
        
        if ($servers) {
            Write-Status "Found $($servers.Count) Exchange server(s)" -Type Success
            $servers | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
            return $servers
        }
        else {
            Write-Status "No Exchange servers found" -Type Warning
            return @($env:COMPUTERNAME)
        }
    }
    catch {
        Write-Status "Could not auto-detect servers: $($_.Exception.Message)" -Type Warning
        Write-Status "Falling back to local server: $env:COMPUTERNAME" -Type Info
        return @($env:COMPUTERNAME)
    }
}

function Test-AzureADConnectivityFromServer {
    <#
    .SYNOPSIS
        Tests Azure AD metadata endpoint connectivity from a specific server.
    .DESCRIPTION
        Returns connectivity status and SSL inspection detection for each endpoint.
    #>
    param(
        [string]$ServerName,
        [string[]]$MetadataUrls
    )
    
    $result = @{
        Server = $ServerName
        Endpoints = @()
        OverallStatus = "Unknown"
        SSLInterceptionDetected = $false
        ConnectivityOK = $true
        Error = $null
    }
    
    # Script block to run on remote server
    $testScriptBlock = {
        param($Urls)
        
        $results = @()
        
        foreach ($url in $Urls) {
            $endpointResult = @{
                Url = $url
                Reachable = $false
                SSLInterception = $false
                SSLIssuer = $null
                ResponseTime = $null
                Error = $null
            }
            
            try {
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $request = [System.Net.HttpWebRequest]::Create($url)
                $request.Method = "HEAD"
                $request.Timeout = 15000
                $request.AllowAutoRedirect = $true
                
                try {
                    $response = $request.GetResponse()
                    $response.Close()
                    $endpointResult.Reachable = $true
                }
                catch [System.Net.WebException] {
                    # May still have certificate info
                    if ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::TrustFailure) {
                        $endpointResult.Reachable = $true  # Reachable but cert issue
                    }
                    else {
                        $endpointResult.Error = $_.Exception.Message
                    }
                }
                
                $stopwatch.Stop()
                $endpointResult.ResponseTime = $stopwatch.ElapsedMilliseconds
                
                # Check certificate
                $cert = $request.ServicePoint.Certificate
                if ($cert) {
                    $endpointResult.SSLIssuer = $cert.Issuer
                    if ($cert.Issuer -notmatch "Microsoft|DigiCert|Baltimore") {
                        $endpointResult.SSLInterception = $true
                    }
                }
            }
            catch {
                $endpointResult.Error = $_.Exception.Message
            }
            
            $results += $endpointResult
        }
        
        return $results
    }
    
    try {
        if ($ServerName -eq $env:COMPUTERNAME) {
            # Run locally
            $result.Endpoints = & $testScriptBlock -Urls $MetadataUrls
        }
        else {
            # Run remotely
            $result.Endpoints = Invoke-Command -ComputerName $ServerName -ScriptBlock $testScriptBlock -ArgumentList (,$MetadataUrls) -ErrorAction Stop
        }
        
        # Analyze results
        foreach ($ep in $result.Endpoints) {
            if (-not $ep.Reachable -and $ep.Error) {
                $result.ConnectivityOK = $false
            }
            if ($ep.SSLInterception) {
                $result.SSLInterceptionDetected = $true
            }
        }
        
        # Determine overall status
        if ($result.SSLInterceptionDetected) {
            $result.OverallStatus = "SSL_INSPECTION"
        }
        elseif (-not $result.ConnectivityOK) {
            $result.OverallStatus = "CONNECTIVITY_ERROR"
        }
        else {
            $result.OverallStatus = "OK"
        }
    }
    catch {
        $result.Error = $_.Exception.Message
        $result.OverallStatus = "UNREACHABLE"
        $result.ConnectivityOK = $false
    }
    
    return $result
}

function Test-AllServersConnectivity {
    <#
    .SYNOPSIS
        Tests Azure AD connectivity from all discovered Exchange servers.
    #>
    param(
        [string[]]$Servers,
        [object[]]$AuthServers
    )
    
    Write-Section "Testing Azure AD Connectivity From All Servers"
    Write-Host ""
    
    # Get metadata URLs from Auth Servers
    $metadataUrls = $AuthServers | Where-Object { $_.AuthMetadataUrl } | ForEach-Object { $_.AuthMetadataUrl }
    
    if (-not $metadataUrls) {
        $metadataUrls = @(
            "https://login.windows.net/common/federationmetadata/2007-06/federationmetadata.xml",
            "https://accounts.accesscontrol.windows.net/metadata/json/1"
        )
    }
    
    $allResults = @()
    
    foreach ($server in $Servers) {
        Write-Host "  Testing: $server... " -NoNewline
        
        $serverResult = Test-AzureADConnectivityFromServer -ServerName $server -MetadataUrls $metadataUrls
        $allResults += $serverResult
        
        switch ($serverResult.OverallStatus) {
            "OK" { Write-Host "OK" -ForegroundColor Green }
            "SSL_INSPECTION" { Write-Host "SSL INSPECTION DETECTED" -ForegroundColor Red }
            "CONNECTIVITY_ERROR" { Write-Host "CONNECTIVITY ERROR" -ForegroundColor Yellow }
            "UNREACHABLE" { Write-Host "UNREACHABLE" -ForegroundColor Red }
            default { Write-Host "UNKNOWN" -ForegroundColor Gray }
        }
    }
    
    return $allResults
}

function Show-DiagnosticReport {
    <#
    .SYNOPSIS
        Displays a comprehensive diagnostic report for all servers.
    #>
    param(
        [object[]]$ServerConnectivityResults,
        [object]$CacheAnalysis,
        [object[]]$AuthServers
    )
    
    Write-Host ""
    Write-Host "=" * 78 -ForegroundColor Cyan
    Write-Host "  DIAGNOSTIC SUMMARY REPORT" -ForegroundColor Cyan
    Write-Host "=" * 78 -ForegroundColor Cyan
    Write-Host ""
    
    # Cache Status Summary
    Write-Host "  CERTIFICATE CACHE STATUS (from Active Directory)" -ForegroundColor Yellow
    Write-Host "  " + ("-" * 60) -ForegroundColor Gray
    
    if ($CacheAnalysis.EmptyServers.Count -gt 0) {
        Write-Host "    Status: " -NoNewline
        Write-Host "EMPTY" -ForegroundColor Yellow
        Write-Host "    Empty Cache Auth Servers: $($CacheAnalysis.EmptyServers.Count)" -ForegroundColor Yellow
        foreach ($empty in $CacheAnalysis.EmptyServers) {
            Write-Host "      - $($empty.Name) (no certificate cached)" -ForegroundColor Yellow
        }
    }
    if ($CacheAnalysis.StaleServers.Count -gt 0) {
        Write-Host "    Status: " -NoNewline
        Write-Host "STALE" -ForegroundColor Red
        Write-Host "    Stale Auth Servers: $($CacheAnalysis.StaleServers.Count)" -ForegroundColor Red
        foreach ($stale in $CacheAnalysis.StaleServers) {
            Write-Host "      - $($stale.Name)" -ForegroundColor Red
        }
    }
    if ($CacheAnalysis.EmptyServers.Count -eq 0 -and $CacheAnalysis.StaleServers.Count -eq 0) {
        Write-Host "    Status: " -NoNewline
        Write-Host "CURRENT" -ForegroundColor Green
        Write-Host "    All cached certificates match Azure AD" -ForegroundColor Green
    }
    Write-Host ""
    
    # Per-Server Connectivity Table
    Write-Host "  PER-SERVER AZURE AD CONNECTIVITY" -ForegroundColor Yellow
    Write-Host ("  " + ("-" * 60)) -ForegroundColor Gray
    Write-Host ""
    $headerLine = "  {0,-18} {1,-12} {2,-12} {3,-12} {4}" -f "SERVER", "CONNECT", "SSL STATUS", "CACHE", "NOTES"
    Write-Host $headerLine -ForegroundColor White
    $separatorLine = "  {0,-18} {1,-12} {2,-12} {3,-12} {4}" -f "------", "-------", "----------", "-----", "-----"
    Write-Host $separatorLine -ForegroundColor Gray
    
    $serversWithIssues = @()
    $serversClean = @()
    
    # Determine cache status string
    $cacheStatusGlobal = if ($CacheAnalysis.EmptyServers.Count -gt 0) { "EMPTY" } elseif ($CacheAnalysis.StaleServers.Count -gt 0) { "STALE" } else { "CURRENT" }
    $cacheColorGlobal = if ($CacheAnalysis.EmptyServers.Count -gt 0 -or $CacheAnalysis.StaleServers.Count -gt 0) { "Yellow" } else { "Green" }
    
    foreach ($result in $ServerConnectivityResults) {
        $connStatus = if ($result.ConnectivityOK) { "OK" } else { "FAILED" }
        $connColor = if ($result.ConnectivityOK) { "Green" } else { "Red" }
        
        $sslStatus = if ($result.SSLInterceptionDetected) { "INTERCEPT" } else { "Clean" }
        $sslColor = if ($result.SSLInterceptionDetected) { "Red" } else { "Green" }
        
        # Cache status - if SSL intercepted, certs won't match during auth
        $cacheStatus = $cacheStatusGlobal
        $cacheColor = $cacheColorGlobal
        if ($result.SSLInterceptionDetected) {
            $cacheStatus = "N/A*"
            $cacheColor = "Gray"
        }
        
        $notes = ""
        if ($result.OverallStatus -eq "UNREACHABLE") {
            $notes = "Cannot reach server"
            $connStatus = "UNREACH"
            $connColor = "Yellow"
            $cacheStatus = "N/A"
            $cacheColor = "Gray"
        }
        elseif ($result.SSLInterceptionDetected) {
            $issuer = ($result.Endpoints | Where-Object { $_.SSLInterception } | Select-Object -First 1).SSLIssuer
            if ($issuer) {
                # Extract just the CN or O from the issuer
                if ($issuer -match "O=([^,]+)") { $notes = $matches[1] }
                elseif ($issuer -match "CN=([^,]+)") { $notes = $matches[1] }
                else { $notes = "Non-Microsoft CA" }
            }
        }
        
        Write-Host "  " -NoNewline
        Write-Host ("{0,-18}" -f $result.Server) -NoNewline -ForegroundColor White
        Write-Host ("{0,-12}" -f $connStatus) -NoNewline -ForegroundColor $connColor
        Write-Host ("{0,-12}" -f $sslStatus) -NoNewline -ForegroundColor $sslColor
        Write-Host ("{0,-12}" -f $cacheStatus) -NoNewline -ForegroundColor $cacheColor
        Write-Host $notes -ForegroundColor Gray
        
        if ($result.OverallStatus -ne "OK") {
            $serversWithIssues += $result
        }
        else {
            $serversClean += $result
        }
    }
    
    # Add footnote for N/A* if SSL interception detected
    $hasSSLInterception = $ServerConnectivityResults | Where-Object { $_.SSLInterceptionDetected }
    if ($hasSSLInterception.Count -gt 0) {
        Write-Host ""
        Write-Host "  * N/A = Cache status irrelevant when SSL inspection intercepts traffic" -ForegroundColor Gray
    }
    
    Write-Host ""
    
    # Summary counts
    Write-Host "  SUMMARY" -ForegroundColor Yellow
    Write-Host "  " + ("-" * 60) -ForegroundColor Gray
    Write-Host "    Total Servers Tested:     $($ServerConnectivityResults.Count)"
    Write-Host "    Servers with Clean Path:  " -NoNewline
    Write-Host "$($serversClean.Count)" -ForegroundColor Green
    Write-Host "    Servers with Issues:      " -NoNewline
    if ($serversWithIssues.Count -gt 0) {
        Write-Host "$($serversWithIssues.Count)" -ForegroundColor Red
    }
    else {
        Write-Host "0" -ForegroundColor Green
    }
    
    $sslInterceptionServers = $ServerConnectivityResults | Where-Object { $_.SSLInterceptionDetected }
    if ($sslInterceptionServers.Count -gt 0) {
        Write-Host "    SSL Inspection Detected:  " -NoNewline
        Write-Host "$($sslInterceptionServers.Count) server(s)" -ForegroundColor Red
    }
    
    Write-Host ""
    
    # Diagnosis
    Write-Host "  DIAGNOSIS" -ForegroundColor Yellow
    Write-Host "  " + ("-" * 60) -ForegroundColor Gray
    
    if ($CacheAnalysis.StaleServers.Count -gt 0 -and $serversClean.Count -gt 0) {
        Write-Host "    " -NoNewline
        Write-Host "STALE CACHE - REFRESH RECOMMENDED" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "    The certificate cache is outdated. At least one server has a clean" -ForegroundColor White
        Write-Host "    network path to Azure AD, so refreshing should succeed." -ForegroundColor White
    }
    elseif ($CacheAnalysis.StaleServers.Count -gt 0 -and $serversClean.Count -eq 0) {
        Write-Host "    " -NoNewline
        Write-Host "STALE CACHE + NO CLEAN PATH" -ForegroundColor Red
        Write-Host ""
        Write-Host "    The cache is stale AND all servers have connectivity issues." -ForegroundColor White
        Write-Host "    Fix network/SSL inspection first, then refresh metadata." -ForegroundColor White
    }
    elseif ($sslInterceptionServers.Count -gt 0 -and $sslInterceptionServers.Count -lt $ServerConnectivityResults.Count) {
        Write-Host "    " -NoNewline
        Write-Host "PARTIAL SSL INSPECTION" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "    Some servers can reach Azure AD cleanly, others are intercepted." -ForegroundColor White
        Write-Host "    This may cause INTERMITTENT OAuth failures depending on which" -ForegroundColor White
        Write-Host "    server handles the request." -ForegroundColor White
    }
    elseif ($sslInterceptionServers.Count -eq $ServerConnectivityResults.Count -and $sslInterceptionServers.Count -gt 0) {
        Write-Host "    " -NoNewline
        Write-Host "SSL INSPECTION ON ALL SERVERS" -ForegroundColor Red
        Write-Host ""
        Write-Host "    All servers are subject to SSL inspection. OAuth will fail" -ForegroundColor White
        Write-Host "    consistently until bypass rules are configured." -ForegroundColor White
    }
    elseif ($CacheAnalysis.CurrentServers.Count -gt 0 -and $serversClean.Count -eq $ServerConnectivityResults.Count) {
        Write-Host "    " -NoNewline
        Write-Host "INTERMITTENT SSL INSPECTION LIKELY" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "    Cache is current and all servers show clean connectivity NOW," -ForegroundColor White
        Write-Host "    but OAuth errors are still occurring. This suggests intermittent" -ForegroundColor White
        Write-Host "    SSL inspection that wasn't active during this test." -ForegroundColor White
    }
    else {
        Write-Host "    " -NoNewline
        Write-Host "ALL CLEAR" -ForegroundColor Green
        Write-Host ""
        Write-Host "    Cache is current and all servers have clean connectivity." -ForegroundColor White
    }
    
    Write-Host ""
    
    return @{
        ServersWithIssues = $serversWithIssues
        ServersClean = $serversClean
        SSLInterceptionServers = $sslInterceptionServers
    }
}

function Get-AuthServerDetails {
    Write-Section "Current Auth Server Configuration"
    
    try {
        $authServers = Get-AuthServer -ErrorAction Stop
        
        if ($authServers) {
            foreach ($server in $authServers) {
                Write-Host ""
                Write-Host "  Auth Server: " -NoNewline
                Write-Host "$($server.Name)" -ForegroundColor Cyan
                Write-Host "    Enabled:              $($server.Enabled)"
                Write-Host "    Type:                 $($server.Type)"
                Write-Host "    AuthMetadataUrl:      $($server.AuthMetadataUrl)"
                Write-Host "    IsDefaultAuthorizationEndpoint: $($server.IsDefaultAuthorizationEndpoint)"
                
                if ($server.CurrentCertificateThumbprint) {
                    Write-Host "    Current Cert Thumbprint:  $($server.CurrentCertificateThumbprint)"
                }
                if ($server.PreviousCertificateThumbprint) {
                    Write-Host "    Previous Cert Thumbprint: $($server.PreviousCertificateThumbprint)"
                }
                if ($server.NextCertificateThumbprint) {
                    Write-Host "    Next Cert Thumbprint:     $($server.NextCertificateThumbprint)"
                }
            }
            return $authServers
        }
        else {
            Write-Status "No Auth Servers configured!" -Type Error
            return $null
        }
    }
    catch {
        Write-Status "Failed to get Auth Servers: $($_.Exception.Message)" -Type Error
        return $null
    }
}

function Get-AuthConfigDetails {
    Write-Section "Auth Configuration Status"
    
    try {
        $authConfig = Get-AuthConfig -ErrorAction Stop
        
        Write-Host "  ServiceName:                    $($authConfig.ServiceName)"
        Write-Host "  CurrentCertificateThumbprint:   $($authConfig.CurrentCertificateThumbprint)"
        Write-Host "  PreviousCertificateThumbprint:  $($authConfig.PreviousCertificateThumbprint)"
        Write-Host "  NextCertificateThumbprint:      $($authConfig.NextCertificateThumbprint)"
        Write-Host "  CertificateEffectiveDate:       $($authConfig.CertificateEffectiveDate)"
        Write-Host "  CertificateExpiryDate:          $($authConfig.CertificateExpiryDate)"
        
        # Check if certificate is expiring soon
        if ($authConfig.CertificateExpiryDate) {
            $daysUntilExpiry = ($authConfig.CertificateExpiryDate - (Get-Date)).Days
            if ($daysUntilExpiry -lt 30) {
                Write-Status "Auth certificate expires in $daysUntilExpiry days!" -Type Warning
            }
            elseif ($daysUntilExpiry -lt 0) {
                Write-Status "Auth certificate has EXPIRED!" -Type Error
            }
            else {
                Write-Status "Auth certificate valid for $daysUntilExpiry days" -Type Success
            }
        }
        
        return $authConfig
    }
    catch {
        Write-Status "Failed to get Auth Config: $($_.Exception.Message)" -Type Error
        return $null
    }
}

function Invoke-RefreshAuthMetadata {
    param(
        [object[]]$AuthServers,
        [switch]$WhatIf
    )
    
    Write-Section "Refreshing OAuth Metadata"
    
    $results = @{
        Success = @()
        Failed  = @()
    }
    
    foreach ($server in $AuthServers) {
        $serverName = $server.Name
        
        if ($WhatIf) {
            Write-Status "Would refresh: $serverName (AuthMetadataUrl: $($server.AuthMetadataUrl))" -Type Info
            continue
        }
        
        Write-Host "  Refreshing: $serverName... " -NoNewline
        
        try {
            # Refresh the auth metadata
            Set-AuthServer -Identity $serverName -RefreshAuthMetadata -ErrorAction Stop
            
            Write-Host "SUCCESS" -ForegroundColor Green
            $results.Success += $serverName
            
            # Small delay between refreshes
            Start-Sleep -Milliseconds 500
        }
        catch {
            Write-Host "FAILED" -ForegroundColor Red
            Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
            $results.Failed += @{
                Name  = $serverName
                Error = $_.Exception.Message
            }
        }
    }
    
    return $results
}

function Test-OAuthConnectivity {
    param([string]$Mailbox)
    
    Write-Section "Testing OAuth Connectivity"
    
    if ([string]::IsNullOrWhiteSpace($Mailbox)) {
        Write-Status "No test mailbox specified, skipping OAuth connectivity test" -Type Info
        Write-Host "  Tip: Use -TestMailbox 'user@domain.com' to test connectivity"
        return $null
    }
    
    Write-Status "Testing OAuth to Exchange Online for: $Mailbox" -Type Info
    
    try {
        # Test EWS OAuth
        Write-Host "  Testing EWS OAuth... " -NoNewline
        $ewsResult = Test-OAuthConnectivity -Service EWS `
            -TargetUri "https://outlook.office365.com/ews/exchange.asmx" `
            -Mailbox $Mailbox -ErrorAction Stop
        
        if ($ewsResult.ResultType -eq "Success") {
            Write-Host "SUCCESS" -ForegroundColor Green
        }
        else {
            Write-Host "FAILED" -ForegroundColor Red
            Write-Host "    Result: $($ewsResult.ResultType)" -ForegroundColor Red
            Write-Host "    Detail: $($ewsResult.ResultDescription)" -ForegroundColor Red
        }
        
        # Test AutoDiscover OAuth
        Write-Host "  Testing AutoDiscover OAuth... " -NoNewline
        $adResult = Test-OAuthConnectivity -Service AutoD `
            -TargetUri "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc" `
            -Mailbox $Mailbox -ErrorAction Stop
        
        if ($adResult.ResultType -eq "Success") {
            Write-Host "SUCCESS" -ForegroundColor Green
        }
        else {
            Write-Host "FAILED" -ForegroundColor Red
            Write-Host "    Result: $($adResult.ResultType)" -ForegroundColor Red
            Write-Host "    Detail: $($adResult.ResultDescription)" -ForegroundColor Red
        }
        
        return @{
            EWS          = $ewsResult
            AutoDiscover = $adResult
        }
    }
    catch {
        Write-Status "OAuth connectivity test failed: $($_.Exception.Message)" -Type Error
        return $null
    }
}

function Invoke-RemoteRemediation {
    param(
        [string[]]$Servers,
        [string]$TestMailbox,
        [switch]$Force
    )
    
    Write-Section "Remote Server Remediation"
    
    $scriptBlock = {
        param($TestMailbox)
        
        try {
            # Add Exchange snapin if needed
            if (-not (Get-Command Get-AuthServer -ErrorAction SilentlyContinue)) {
                Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue
            }
            
            $results = @{
                Server    = $env:COMPUTERNAME
                Success   = @()
                Failed    = @()
                OAuthTest = $null
            }
            
            # Refresh all auth servers
            $authServers = Get-AuthServer
            foreach ($as in $authServers) {
                try {
                    Set-AuthServer -Identity $as.Name -RefreshAuthMetadata -ErrorAction Stop
                    $results.Success += $as.Name
                }
                catch {
                    $results.Failed += "$($as.Name): $($_.Exception.Message)"
                }
            }
            
            # Test OAuth if mailbox provided
            if ($TestMailbox) {
                try {
                    $ewsResult = Test-OAuthConnectivity -Service EWS `
                        -TargetUri "https://outlook.office365.com/ews/exchange.asmx" `
                        -Mailbox $TestMailbox -ErrorAction Stop
                    $results.OAuthTest = $ewsResult.ResultType
                }
                catch {
                    $results.OAuthTest = "Error: $($_.Exception.Message)"
                }
            }
            
            return $results
        }
        catch {
            return @{
                Server = $env:COMPUTERNAME
                Error  = $_.Exception.Message
            }
        }
    }
    
    foreach ($server in $Servers) {
        Write-Host ""
        Write-Host "  Processing: $server... " -NoNewline
        
        try {
            $result = Invoke-Command -ComputerName $server -ScriptBlock $scriptBlock -ArgumentList $TestMailbox -ErrorAction Stop
            
            if ($result.Error) {
                Write-Host "ERROR" -ForegroundColor Red
                Write-Host "    $($result.Error)" -ForegroundColor Red
            }
            elseif ($result.Failed.Count -gt 0) {
                Write-Host "PARTIAL" -ForegroundColor Yellow
                Write-Host "    Succeeded: $($result.Success -join ', ')" -ForegroundColor Green
                Write-Host "    Failed: $($result.Failed -join ', ')" -ForegroundColor Red
            }
            else {
                Write-Host "SUCCESS" -ForegroundColor Green
                Write-Host "    Refreshed: $($result.Success -join ', ')" -ForegroundColor Gray
                if ($result.OAuthTest) {
                    Write-Host "    OAuth Test: $($result.OAuthTest)" -ForegroundColor Gray
                }
            }
        }
        catch {
            Write-Host "FAILED" -ForegroundColor Red
            Write-Host "    Could not connect: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function Get-AzureADCertificatesFromMetadata {
    <#
    .SYNOPSIS
        Fetches current signing certificates from Azure AD metadata endpoints.
    #>
    param(
        [string]$MetadataUrl
    )
    
    $result = @{
        Url = $MetadataUrl
        Thumbprints = @()
        Error = $null
        SSLInterception = $false
        SSLIssuer = $null
    }
    
    try {
        # Force TLS 1.2
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        
        # Check the SSL certificate being presented
        $request = [System.Net.HttpWebRequest]::Create($MetadataUrl)
        $request.Method = "HEAD"
        $request.Timeout = 10000
        $request.AllowAutoRedirect = $true
        
        try {
            $response = $request.GetResponse()
            $response.Close()
            
            # Check the certificate
            $cert = $request.ServicePoint.Certificate
            if ($cert) {
                $issuer = $cert.Issuer
                $result.SSLIssuer = $issuer
                
                # Check if it's a Microsoft certificate
                if ($issuer -notmatch "Microsoft|DigiCert|Baltimore") {
                    $result.SSLInterception = $true
                }
            }
        }
        catch [System.Net.WebException] {
            # Connection may still have captured the cert
            $cert = $request.ServicePoint.Certificate
            if ($cert) {
                $result.SSLIssuer = $cert.Issuer
                if ($cert.Issuer -notmatch "Microsoft|DigiCert|Baltimore") {
                    $result.SSLInterception = $true
                }
            }
        }
        
        # Now fetch the actual metadata
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "HMA-Troubleshooting-Toolkit/1.0")
        $metadataContent = $webClient.DownloadString($MetadataUrl)
        
        # Parse based on URL type
        if ($MetadataUrl -match "\.xml$|federationmetadata") {
            # XML federation metadata
            $xml = [xml]$metadataContent
            $ns = @{
                "md" = "urn:oasis:names:tc:SAML:2.0:metadata"
                "ds" = "http://www.w3.org/2000/09/xmldsig#"
            }
            
            $certs = Select-Xml -Xml $xml -XPath "//ds:X509Certificate" -Namespace $ns
            foreach ($certNode in $certs) {
                $certBase64 = $certNode.Node.InnerText.Trim()
                try {
                    $certBytes = [System.Convert]::FromBase64String($certBase64)
                    $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$certBytes)
                    $result.Thumbprints += $x509.Thumbprint.ToUpper()
                }
                catch {
                    # Intentionally suppressed - skip invalid/malformed certificates in metadata
                    $null = $_.Exception
                }
            }
        }
        else {
            # JSON metadata (ACS style)
            $json = $metadataContent | ConvertFrom-Json
            if ($json.keys) {
                foreach ($key in $json.keys) {
                    if ($key.x5t) {
                        # x5t is base64url encoded thumbprint
                        $thumbprint = $key.x5t -replace '-', '+' -replace '_', '/'
                        # Pad if needed
                        switch ($thumbprint.Length % 4) {
                            2 { $thumbprint += "==" }
                            3 { $thumbprint += "=" }
                        }
                        try {
                            $bytes = [System.Convert]::FromBase64String($thumbprint)
                            $hex = ($bytes | ForEach-Object { $_.ToString("X2") }) -join ""
                            $result.Thumbprints += $hex.ToUpper()
                        }
                        catch {
                            # Try as-is
                            $result.Thumbprints += $key.x5t.ToUpper()
                        }
                    }
                    if ($key.x5c -and $key.x5c.Count -gt 0) {
                        try {
                            $certBytes = [System.Convert]::FromBase64String($key.x5c[0])
                            $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$certBytes)
                            if ($result.Thumbprints -notcontains $x509.Thumbprint.ToUpper()) {
                                $result.Thumbprints += $x509.Thumbprint.ToUpper()
                            }
                        }
                        catch {
                            # Intentionally suppressed - skip malformed x5c certificate data
                            $null = $_.Exception
                        }
                    }
                }
            }
        }
        
        $result.Thumbprints = $result.Thumbprints | Select-Object -Unique
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

function Compare-CachedVsLiveCertificates {
    <#
    .SYNOPSIS
        Compares Exchange cached certificates with live Azure AD certificates.
    .DESCRIPTION
        Returns analysis of whether cache is stale or if SSL inspection is likely.
    #>
    param(
        [object[]]$AuthServers
    )
    
    Write-Section "Certificate Cache Analysis"
    Write-Host ""
    Write-Host "  Comparing Exchange cached certificates with live Azure AD certificates..."
    Write-Host ""
    
    $analysisResults = @{
        StaleServers = @()
        EmptyServers = @()
        CurrentServers = @()
        SSLInterceptionDetected = $false
        SSLInterceptionEndpoints = @()
        Errors = @()
        Details = @()
    }
    
    foreach ($authServer in $AuthServers) {
        if (-not $authServer.AuthMetadataUrl) {
            continue
        }
        
        $serverName = $authServer.Name
        $metadataUrl = $authServer.AuthMetadataUrl
        $cachedThumbprint = $authServer.CurrentCertificateThumbprint
        
        Write-Host "  Checking: $serverName" -ForegroundColor Cyan
        Write-Host "    Metadata URL: $metadataUrl"
        Write-Host "    Cached Thumbprint: $(if ($cachedThumbprint) { $cachedThumbprint } else { '(none)' })"
        
        # Fetch live certificates
        $liveResult = Get-AzureADCertificatesFromMetadata -MetadataUrl $metadataUrl
        
        if ($liveResult.Error) {
            Write-Host "    Live Fetch: " -NoNewline
            Write-Host "ERROR - $($liveResult.Error)" -ForegroundColor Red
            $analysisResults.Errors += @{
                Server = $serverName
                Url = $metadataUrl
                Error = $liveResult.Error
            }
            continue
        }
        
        # Check for SSL interception first
        if ($liveResult.SSLInterception) {
            Write-Host "    SSL Certificate: " -NoNewline
            Write-Host "WARNING - Non-Microsoft issuer: $($liveResult.SSLIssuer)" -ForegroundColor Red
            $analysisResults.SSLInterceptionDetected = $true
            $analysisResults.SSLInterceptionEndpoints += @{
                Url = $metadataUrl
                Issuer = $liveResult.SSLIssuer
            }
        }
        else {
            Write-Host "    SSL Certificate: OK (Issuer: $($liveResult.SSLIssuer))" -ForegroundColor Gray
        }
        
        Write-Host "    Live Thumbprints: $($liveResult.Thumbprints.Count) found"
        
        # Compare cached vs live
        if ($cachedThumbprint) {
            $cachedUpper = $cachedThumbprint.ToUpper() -replace '\s', ''
            $isMatch = $liveResult.Thumbprints | Where-Object { $_ -eq $cachedUpper }
            
            if ($isMatch) {
                Write-Host "    Status: " -NoNewline
                Write-Host "CURRENT - Cached certificate matches Azure AD" -ForegroundColor Green
                $analysisResults.CurrentServers += @{
                    Name = $serverName
                    Thumbprint = $cachedThumbprint
                }
            }
            else {
                Write-Host "    Status: " -NoNewline
                Write-Host "STALE - Cached certificate NOT in Azure AD metadata" -ForegroundColor Yellow
                Write-Host "           Cached: $cachedUpper" -ForegroundColor Gray
                Write-Host "           Live:   $($liveResult.Thumbprints -join ', ')" -ForegroundColor Gray
                $analysisResults.StaleServers += @{
                    Name = $serverName
                    CachedThumbprint = $cachedThumbprint
                    LiveThumbprints = $liveResult.Thumbprints
                }
            }
        }
        else {
            Write-Host "    Status: " -NoNewline
            Write-Host "EMPTY - No certificate currently cached" -ForegroundColor Yellow
            $analysisResults.EmptyServers += @{
                Name = $serverName
                CachedThumbprint = $null
                LiveThumbprints = $liveResult.Thumbprints
            }
        }
        
        Write-Host ""
    }
    
    # Summary
    Write-Host "  " + ("-" * 58) -ForegroundColor Gray
    Write-Host ""
    
    if ($analysisResults.SSLInterceptionDetected) {
        Write-Status "SSL INSPECTION DETECTED on the following endpoints:" -Type Error
        foreach ($ep in $analysisResults.SSLInterceptionEndpoints) {
            Write-Host "    - $($ep.Url)" -ForegroundColor Red
            Write-Host "      Issuer: $($ep.Issuer)" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "  This indicates a proxy/firewall is intercepting Azure AD traffic." -ForegroundColor Yellow
        Write-Host "  Refreshing metadata will NOT fix the issue." -ForegroundColor Yellow
        Write-Host "  You must bypass SSL inspection for these endpoints." -ForegroundColor Yellow
        Write-Host ""
    }
    
    if ($analysisResults.EmptyServers.Count -gt 0 -and -not $analysisResults.SSLInterceptionDetected) {
        Write-Status "EMPTY CACHE DETECTED for $($analysisResults.EmptyServers.Count) Auth Server(s)" -Type Warning
        Write-Host "  No certificates cached. Refreshing metadata is required." -ForegroundColor Yellow
        Write-Host ""
    }
    
    if ($analysisResults.StaleServers.Count -gt 0 -and -not $analysisResults.SSLInterceptionDetected) {
        Write-Status "STALE CACHE DETECTED for $($analysisResults.StaleServers.Count) Auth Server(s)" -Type Warning
        Write-Host "  Cached certificates do not match Azure AD. Refreshing metadata is recommended." -ForegroundColor Yellow
        Write-Host ""
    }
    
    if ($analysisResults.CurrentServers.Count -gt 0 -and $analysisResults.StaleServers.Count -eq 0 -and $analysisResults.EmptyServers.Count -eq 0 -and -not $analysisResults.SSLInterceptionDetected) {
        Write-Status "Cache is CURRENT for all Auth Servers" -Type Success
        Write-Host ""
        Write-Host "  The cached certificates match what Azure AD is currently serving." -ForegroundColor Green
        Write-Host "  If you are still seeing 'different certificate' errors, this indicates:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "    >>> INTERMITTENT SSL INSPECTION <<<" -ForegroundColor Red
        Write-Host ""
        Write-Host "  A proxy or firewall is SOMETIMES intercepting traffic to Azure AD," -ForegroundColor Yellow
        Write-Host "  presenting different certificates, causing OAuth validation to fail." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  RECOMMENDED ACTIONS:" -ForegroundColor Cyan
        Write-Host "    1. Review proxy/firewall logs for traffic to these endpoints" -ForegroundColor White
        Write-Host "    2. Add permanent bypass rules for:" -ForegroundColor White
        Write-Host "         - login.microsoftonline.com" -ForegroundColor Gray
        Write-Host "         - login.windows.net" -ForegroundColor Gray
        Write-Host "         - accounts.accesscontrol.windows.net" -ForegroundColor Gray
        Write-Host "         - *.msftauth.net" -ForegroundColor Gray
        Write-Host "    3. Verify bypass is working during peak failure times" -ForegroundColor White
        Write-Host ""
    }
    
    if ($analysisResults.Errors.Count -gt 0) {
        Write-Status "Could not check $($analysisResults.Errors.Count) endpoint(s) due to errors" -Type Warning
        foreach ($err in $analysisResults.Errors) {
            Write-Host "    - $($err.Server): $($err.Error)" -ForegroundColor Gray
        }
        Write-Host ""
    }
    
    return $analysisResults
}

function Show-ManualRemediationSteps {
    <#
    .SYNOPSIS
        Displays manual remediation steps for the user to run on Exchange servers.
    #>
    param(
        [object[]]$AuthServers,
        [string[]]$ExchangeServers,
        [object[]]$StaleServers,
        [object[]]$CurrentServers
    )
    
    Write-Host ""
    Write-Host "=" * 78 -ForegroundColor Cyan
    Write-Host "  MANUAL REMEDIATION STEPS" -ForegroundColor Cyan
    Write-Host "=" * 78 -ForegroundColor Cyan
    Write-Host ""
    
    # Show summary of which Auth Servers need remediation
    if ($StaleServers -and $StaleServers.Count -gt 0) {
        Write-Host "  AUTH SERVERS REQUIRING REMEDIATION:" -ForegroundColor Yellow
        foreach ($stale in $StaleServers) {
            Write-Host "    [STALE] $($stale.Name)" -ForegroundColor Red
        }
        if ($CurrentServers -and $CurrentServers.Count -gt 0) {
            foreach ($current in $CurrentServers) {
                Write-Host "    [OK]    $($current.Name) - No action needed" -ForegroundColor Green
            }
        }
        Write-Host ""
    }
    
    Write-Host "  Run the following commands in Exchange Management Shell:" -ForegroundColor Yellow
    Write-Host ""
    
    # Build the list of stale Auth Server names for targeted remediation
    $staleNames = @()
    if ($StaleServers -and $StaleServers.Count -gt 0) {
        $staleNames = $StaleServers | ForEach-Object { $_.Name }
    }
    
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Gray
    Write-Host "  OPTION 1: Refresh only the stale Auth Servers (RECOMMENDED)" -ForegroundColor Cyan
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Gray
    Write-Host ""
    
    if ($staleNames.Count -gt 0) {
        foreach ($staleName in $staleNames) {
            Write-Host "  # Refresh: $staleName" -ForegroundColor White
            Write-Host "  Set-AuthServer -Identity '$staleName' -RefreshAuthMetadata" -ForegroundColor Gray
            Write-Host ""
        }
    }
    else {
        Write-Host "  # Refresh all Auth Servers" -ForegroundColor White
        Write-Host "  Get-AuthServer | Set-AuthServer -RefreshAuthMetadata" -ForegroundColor Gray
        Write-Host ""
    }
    
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Gray
    Write-Host "  OPTION 2: Refresh ALL Auth Servers" -ForegroundColor Cyan
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Get-AuthServer | Set-AuthServer -RefreshAuthMetadata" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Gray
    Write-Host "  VERIFICATION STEPS" -ForegroundColor Cyan
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Step 1: Verify the updated configuration" -ForegroundColor White
    Write-Host "    Get-AuthServer | Format-List Name,Enabled,AuthMetadataUrl,CurrentCertificateThumbprint" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Step 2: Test OAuth connectivity (optional)" -ForegroundColor White
    Write-Host "    Test-OAuthConnectivity -Service EWS ``" -ForegroundColor Gray
    Write-Host "      -TargetUri https://outlook.office365.com/ews/exchange.asmx ``" -ForegroundColor Gray
    Write-Host "      -Mailbox user@domain.com" -ForegroundColor Gray
    Write-Host ""
    
    # If multiple Exchange servers specified, show remote execution option
    if ($ExchangeServers -and $ExchangeServers.Count -gt 1) {
        Write-Host "  ----------------------------------------------------------------" -ForegroundColor Gray
        Write-Host "  MULTI-SERVER: Run from a single server via remoting" -ForegroundColor Yellow
        Write-Host "  ----------------------------------------------------------------" -ForegroundColor Gray
        Write-Host ""
        
        $serverList = "'$($ExchangeServers -join "', '")'"
        Write-Host "    `$servers = @($serverList)" -ForegroundColor Gray
        Write-Host "    foreach (`$srv in `$servers) {" -ForegroundColor Gray
        Write-Host "        Invoke-Command -ComputerName `$srv -ScriptBlock {" -ForegroundColor Gray
        if ($staleNames.Count -gt 0) {
            $staleList = "'$($staleNames -join "', '")'"
            Write-Host "            @($staleList) | ForEach-Object {" -ForegroundColor Gray
            Write-Host "                Set-AuthServer -Identity `$_ -RefreshAuthMetadata" -ForegroundColor Gray
            Write-Host "            }" -ForegroundColor Gray
        }
        else {
            Write-Host "            Get-AuthServer | Set-AuthServer -RefreshAuthMetadata" -ForegroundColor Gray
        }
        Write-Host "        }" -ForegroundColor Gray
        Write-Host "        Write-Host `"Completed: `$srv`" -ForegroundColor Green" -ForegroundColor Gray
        Write-Host "    }" -ForegroundColor Gray
        Write-Host ""
    }
    
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  After completing these steps:" -ForegroundColor Cyan
    Write-Host "    1. Wait 5-10 minutes for changes to propagate" -ForegroundColor White
    Write-Host "    2. Run Detect-ProxyAndSSLIssues.ps1 to verify errors are resolved" -ForegroundColor White
    Write-Host "    3. Monitor MSExchange OAuth event logs for any new errors" -ForegroundColor White
    Write-Host ""
}

#endregion Functions

#region Main

Write-Banner "STALE OAUTH CERTIFICATE REMEDIATION"
Write-Host "  This script refreshes OAuth metadata to resolve 'different certificate(s)'"
Write-Host "  errors in MSExchange OAuth event logs."
Write-Host ""

# Check for Exchange Management Shell
if (-not (Test-ExchangeManagementShell)) {
    Write-Status "This script must be run from Exchange Management Shell!" -Type Error
    Write-Host ""
    Write-Host "  Please run this script from:" -ForegroundColor Yellow
    Write-Host "    - Exchange Management Shell, or" -ForegroundColor Yellow
    Write-Host "    - PowerShell with Exchange snap-in loaded" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

#region CacheCheckOnly Mode
# Simplified mode for restricted environments - only compares cache vs Azure AD
if ($CacheCheckOnly) {
    Write-Host "  MODE: Cache Check Only (simplified for restricted environments)" -ForegroundColor Yellow
    Write-Host ""
    
    # Get Auth Server configuration
    $authServers = Get-AuthServerDetails
    if (-not $authServers) {
        Write-Status "Cannot proceed without Auth Server configuration" -Type Error
        exit 1
    }
    
    # Compare cached certificates vs live Azure AD
    $cacheAnalysis = Compare-CachedVsLiveCertificates -AuthServers $authServers
    
    # Display simple report
    Write-Section "CACHE STATUS REPORT"
    
    Write-Host ""
    Write-Host "  AUTH SERVER                 CACHE STATUS      DETAILS" -ForegroundColor White
    Write-Host "  ────────────────────────    ────────────      ───────────────────────────────" -ForegroundColor Gray
    
    foreach ($srv in $authServers) {
        $serverName = $srv.Name.PadRight(26)
        
        # Check if this server is stale, empty, or current
        $isStale = $cacheAnalysis.StaleServers | Where-Object { $_.Name -eq $srv.Name }
        $isEmpty = $cacheAnalysis.EmptyServers | Where-Object { $_.Name -eq $srv.Name }
        $isCurrent = $cacheAnalysis.CurrentServers | Where-Object { $_.Name -eq $srv.Name }
        
        if ($isEmpty) {
            $status = "EMPTY"
            $statusColor = "Yellow"
            $detail = "No certificate cached - needs refresh"
        }
        elseif ($isStale) {
            $status = "STALE"
            $statusColor = "Red"
            $thumbShort = $srv.CurrentCertificateThumbprint.Substring(0, [Math]::Min(8, $srv.CurrentCertificateThumbprint.Length))
            $detail = "Cached: $thumbShort... ≠ Azure AD"
        }
        elseif ($isCurrent) {
            $status = "CURRENT"
            $statusColor = "Green"
            if ($srv.CurrentCertificateThumbprint) {
                $thumbShort = $srv.CurrentCertificateThumbprint.Substring(0, [Math]::Min(8, $srv.CurrentCertificateThumbprint.Length))
                $detail = "Cached: $thumbShort... = Azure AD"
            } else {
                $detail = "Cache matches Azure AD"
            }
        }
        else {
            $status = "UNKNOWN"
            $statusColor = "Yellow"
            $detail = "Could not determine status"
        }
        
        Write-Host "  $serverName" -NoNewline
        Write-Host $status.PadRight(16) -ForegroundColor $statusColor -NoNewline
        Write-Host $detail -ForegroundColor Gray
    }
    
    Write-Host ""
    
    # Summary
    $staleCount = ($cacheAnalysis.StaleServers | Measure-Object).Count
    $currentCount = ($cacheAnalysis.CurrentServers | Measure-Object).Count
    $sslDetected = $cacheAnalysis.SSLInterceptionDetected
    
    Write-Host "  ────────────────────────────────────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host ""
    
    if ($sslDetected) {
        Write-Host "  ⚠ SSL INSPECTION DETECTED" -ForegroundColor Red
        Write-Host ""
        Write-Host "    Non-Microsoft certificate detected when fetching Azure AD metadata." -ForegroundColor White
        Write-Host "    This indicates SSL inspection is intercepting OAuth traffic." -ForegroundColor White
        Write-Host ""
        Write-Host "  RECOMMENDATION: Work with network team to bypass SSL inspection for:" -ForegroundColor Cyan
        Write-Host "    - login.microsoftonline.com" -ForegroundColor Gray
        Write-Host "    - login.windows.net" -ForegroundColor Gray
        Write-Host "    - accounts.accesscontrol.windows.net" -ForegroundColor Gray
    }
    elseif ($staleCount -gt 0) {
        Write-Host "  ⚠ STALE CACHE DETECTED" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "    $staleCount Auth Server(s) have outdated certificate cache." -ForegroundColor White
        Write-Host "    Refreshing OAuth metadata should resolve 'different certificate' errors." -ForegroundColor White
        Write-Host ""
        Write-Host "  RECOMMENDATION: Refresh metadata for stale Auth Servers:" -ForegroundColor Cyan
        foreach ($stale in $cacheAnalysis.StaleServers) {
            Write-Host "    Set-AuthServer -Identity '$($stale.Name)' -RefreshAuthMetadata" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "  ✓ ALL CACHES CURRENT" -ForegroundColor Green
        Write-Host ""
        Write-Host "    All $currentCount Auth Server(s) have up-to-date certificate cache." -ForegroundColor White
        Write-Host "    If OAuth errors persist, the issue is likely intermittent SSL inspection." -ForegroundColor White
        Write-Host ""
        Write-Host "  RECOMMENDATION: Run full diagnostics when environment permits, or" -ForegroundColor Cyan
        Write-Host "    work with network team to verify no SSL inspection is occurring." -ForegroundColor Cyan
    }
    
    Write-Host ""
    Write-Host "  NOTE: This simplified check did not test remote server connectivity" -ForegroundColor Yellow
    Write-Host "        or per-server SSL inspection. Run without -CacheCheckOnly for" -ForegroundColor Yellow
    Write-Host "        full diagnostics if your environment allows it." -ForegroundColor Yellow
    Write-Host ""
    
    exit 0
}
#endregion CacheCheckOnly Mode

#region QuickStatus Mode
# Quick summary mode - just runs tests and shows the status table
if ($QuickStatus) {
    Write-Host "  MODE: Quick Status (per-server connectivity summary)" -ForegroundColor Yellow
    Write-Host ""
    
    # Determine which servers to check
    $discoveredServers = @()
    if ($ExchangeServers -and $ExchangeServers.Count -gt 0) {
        $discoveredServers = $ExchangeServers
    }
    elseif ($LocalOnly) {
        $discoveredServers = @($env:COMPUTERNAME)
    }
    else {
        $discoveredServers = Get-ExchangeServersAutoDetect
    }
    
    # Get Auth Server configuration
    $authServers = Get-AuthServerDetails
    if (-not $authServers) {
        Write-Status "Cannot proceed without Auth Server configuration" -Type Error
        exit 1
    }
    
    # Analyze certificate cache vs live Azure AD
    $cacheAnalysis = Compare-CachedVsLiveCertificates -AuthServers $authServers
    
    # Test connectivity from all servers
    $serverConnectivityResults = Test-AllServersConnectivity -Servers $discoveredServers -AuthServers $authServers
    
    # Determine cache status
    $cacheStatusGlobal = if ($cacheAnalysis.EmptyServers.Count -gt 0) { "EMPTY" } elseif ($cacheAnalysis.StaleServers.Count -gt 0) { "STALE" } else { "CURRENT" }
    $cacheColorGlobal = if ($cacheAnalysis.EmptyServers.Count -gt 0 -or $cacheAnalysis.StaleServers.Count -gt 0) { "Yellow" } else { "Green" }
    
    # Display the status table
    Write-Section "PER-SERVER STATUS"
    Write-Host ""
    $headerLine = "  {0,-18} {1,-12} {2,-12} {3,-12} {4}" -f "SERVER", "CONNECT", "SSL STATUS", "CACHE", "NOTES"
    Write-Host $headerLine -ForegroundColor White
    $separatorLine = "  {0,-18} {1,-12} {2,-12} {3,-12} {4}" -f "------", "-------", "----------", "-----", "-----"
    Write-Host $separatorLine -ForegroundColor Gray
    
    $serversWithIssues = @()
    $serversClean = @()
    $sslInterceptionCount = 0
    
    foreach ($result in $serverConnectivityResults) {
        $connStatus = if ($result.ConnectivityOK) { "OK" } else { "FAILED" }
        $connColor = if ($result.ConnectivityOK) { "Green" } else { "Red" }
        
        $sslStatus = if ($result.SSLInterceptionDetected) { "INTERCEPT" } else { "Clean" }
        $sslColor = if ($result.SSLInterceptionDetected) { "Red" } else { "Green" }
        
        if ($result.SSLInterceptionDetected) { $sslInterceptionCount++ }
        
        $cacheStatus = $cacheStatusGlobal
        $cacheColor = $cacheColorGlobal
        if ($result.SSLInterceptionDetected) {
            $cacheStatus = "N/A*"
            $cacheColor = "Gray"
        }
        
        $notes = ""
        if ($result.OverallStatus -eq "UNREACHABLE") {
            $notes = "Cannot reach server"
            $connStatus = "UNREACH"
            $connColor = "Yellow"
            $cacheStatus = "N/A"
            $cacheColor = "Gray"
        }
        elseif ($result.SSLInterceptionDetected) {
            $issuer = ($result.Endpoints | Where-Object { $_.SSLInterception } | Select-Object -First 1).SSLIssuer
            if ($issuer) {
                if ($issuer -match "O=([^,]+)") { $notes = $matches[1] }
                elseif ($issuer -match "CN=([^,]+)") { $notes = $matches[1] }
                else { $notes = "Non-Microsoft CA" }
            }
        }
        
        Write-Host "  " -NoNewline
        Write-Host ("{0,-18}" -f $result.Server) -NoNewline -ForegroundColor White
        Write-Host ("{0,-12}" -f $connStatus) -NoNewline -ForegroundColor $connColor
        Write-Host ("{0,-12}" -f $sslStatus) -NoNewline -ForegroundColor $sslColor
        Write-Host ("{0,-12}" -f $cacheStatus) -NoNewline -ForegroundColor $cacheColor
        Write-Host $notes -ForegroundColor Gray
        
        if ($result.OverallStatus -ne "OK") {
            $serversWithIssues += $result
        }
        else {
            $serversClean += $result
        }
    }
    
    # Footnote for N/A*
    if ($sslInterceptionCount -gt 0) {
        Write-Host ""
        Write-Host "  * N/A = Cache status irrelevant when SSL inspection intercepts traffic" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "  ────────────────────────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Servers: $($serverConnectivityResults.Count) total | " -NoNewline
    Write-Host "$($serversClean.Count) OK" -ForegroundColor Green -NoNewline
    Write-Host " | " -NoNewline
    if ($serversWithIssues.Count -gt 0) {
        Write-Host "$($serversWithIssues.Count) issues" -ForegroundColor Red -NoNewline
    } else {
        Write-Host "0 issues" -ForegroundColor Green -NoNewline
    }
    Write-Host " | Cache: " -NoNewline
    Write-Host $cacheStatusGlobal -ForegroundColor $cacheColorGlobal -NoNewline
    if ($sslInterceptionCount -gt 0) {
        Write-Host " | " -NoNewline
        Write-Host "SSL Intercept: $sslInterceptionCount" -ForegroundColor Red
    }
    else {
        Write-Host ""
    }
    
    Write-Host ""
    exit 0
}
#endregion QuickStatus Mode

# Determine which servers to check
$discoveredServers = @()
if ($ExchangeServers -and $ExchangeServers.Count -gt 0) {
    # User specified servers
    $discoveredServers = $ExchangeServers
    Write-Status "Using specified servers: $($discoveredServers.Count) server(s)" -Type Info
}
elseif ($LocalOnly) {
    # Local only mode
    $discoveredServers = @($env:COMPUTERNAME)
    Write-Status "Local-only mode: $env:COMPUTERNAME" -Type Info
}
else {
    # Auto-detect all Exchange servers
    $discoveredServers = Get-ExchangeServersAutoDetect
}

# Step 1: Get Auth Server configuration (from AD - same for all servers)
$authServers = Get-AuthServerDetails
if (-not $authServers) {
    Write-Status "Cannot proceed without Auth Server configuration" -Type Error
    exit 1
}

# Step 2: Show Auth Config
$authConfig = Get-AuthConfigDetails

# Step 3: Analyze certificate cache vs live Azure AD (from local perspective)
$cacheAnalysis = Compare-CachedVsLiveCertificates -AuthServers $authServers

# Step 4: Test connectivity from ALL discovered servers
$serverConnectivityResults = Test-AllServersConnectivity -Servers $discoveredServers -AuthServers $authServers

# Step 5: Show comprehensive diagnostic report
$reportSummary = Show-DiagnosticReport -ServerConnectivityResults $serverConnectivityResults -CacheAnalysis $cacheAnalysis -AuthServers $authServers

# Determine if remediation is appropriate based on cache status
$shouldRemediate = $false
$remediationReason = ""
$skipRemainingTests = $false

# If cache is current (not stale), skip all remediation - the issue is SSL inspection
if ($cacheAnalysis.StaleServers.Count -eq 0 -and $cacheAnalysis.CurrentServers.Count -gt 0) {
    $skipRemainingTests = $true
    
    Write-Host ""
    Write-Host "=" * 78 -ForegroundColor Cyan
    Write-Host "  CONCLUSION: CACHE IS CURRENT - SSL INSPECTION IS THE ISSUE" -ForegroundColor Cyan
    Write-Host "=" * 78 -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  The certificate cache on all Auth Servers matches Azure AD." -ForegroundColor Green
    Write-Host "  Refreshing OAuth metadata will NOT fix the 'different certificate' errors." -ForegroundColor Yellow
    Write-Host ""
    
    # Summarize per-server SSL status
    $sslInterceptionCount = ($reportSummary.SSLInterceptionServers | Measure-Object).Count
    $cleanCount = ($reportSummary.ServersClean | Measure-Object).Count
    $totalServers = $serverConnectivityResults.Count
    
    if ($sslInterceptionCount -gt 0 -and $sslInterceptionCount -eq $totalServers) {
        Write-Host "  ROOT CAUSE: SSL INSPECTION ON ALL SERVERS" -ForegroundColor Red
        Write-Host ""
        Write-Host "  All $totalServers Exchange server(s) are subject to SSL inspection." -ForegroundColor White
        Write-Host "  OAuth authentication will fail consistently until bypass rules are added." -ForegroundColor White
    }
    elseif ($sslInterceptionCount -gt 0) {
        Write-Host "  ROOT CAUSE: PARTIAL SSL INSPECTION" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  $sslInterceptionCount of $totalServers server(s) are subject to SSL inspection." -ForegroundColor White
        Write-Host "  OAuth failures will be INTERMITTENT based on which server handles requests." -ForegroundColor White
        Write-Host ""
        Write-Host "  Servers with SSL interception:" -ForegroundColor Red
        foreach ($srv in $reportSummary.SSLInterceptionServers) {
            $issuer = ($srv.Endpoints | Where-Object { $_.SSLInterception } | Select-Object -First 1).SSLIssuer
            if ($issuer -match "O=([^,]+)") { $issuerShort = $matches[1] }
            elseif ($issuer -match "CN=([^,]+)") { $issuerShort = $matches[1] }
            else { $issuerShort = "Non-Microsoft CA" }
            Write-Host "    - $($srv.Server) ($issuerShort)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  ROOT CAUSE: INTERMITTENT SSL INSPECTION" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  All $cleanCount server(s) show clean connectivity NOW, but OAuth errors exist." -ForegroundColor White
        Write-Host "  This indicates SSL inspection is active at certain times or on certain paths." -ForegroundColor White
        Write-Host ""
        Write-Host "  Possible causes:" -ForegroundColor Yellow
        Write-Host "    - Time-based proxy rules (e.g., during business hours)" -ForegroundColor Gray
        Write-Host "    - Load balancer routing some traffic through inspection" -ForegroundColor Gray
        Write-Host "    - Failover to backup proxy with different configuration" -ForegroundColor Gray
        Write-Host "    - PAC file logic directing traffic inconsistently" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "  REQUIRED ACTION:" -ForegroundColor Cyan
    Write-Host "  Configure SSL inspection bypass for these endpoints:" -ForegroundColor White
    Write-Host "    - login.microsoftonline.com" -ForegroundColor Gray
    Write-Host "    - login.windows.net" -ForegroundColor Gray
    Write-Host "    - accounts.accesscontrol.windows.net" -ForegroundColor Gray
    Write-Host "    - *.msftauth.net" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  NO REMEDIATION NEEDED - This is a network configuration issue." -ForegroundColor Green
    Write-Host ""
}
elseif ($cacheAnalysis.SSLInterceptionDetected) {
    # SSL interception detected during local metadata fetch
    $skipRemainingTests = $true
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Red
    Write-Host "  SSL INSPECTION DETECTED ON METADATA ENDPOINTS" -ForegroundColor Red
    Write-Host "  ============================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Refreshing OAuth metadata will NOT resolve this issue." -ForegroundColor Yellow
    Write-Host "  The proxy/firewall is presenting non-Microsoft certificates." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  REQUIRED ACTION: Bypass SSL inspection for Azure AD endpoints." -ForegroundColor Cyan
    Write-Host ""
}
elseif ($cacheAnalysis.StaleServers.Count -gt 0) {
    # Stale cache detected - remediation is appropriate
    $shouldRemediate = $true
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Green
    Write-Host "  STALE CACHE CONFIRMED - REFRESH RECOMMENDED" -ForegroundColor Green
    Write-Host "  ============================================================" -ForegroundColor Green
    Write-Host ""
    $remediationReason = "Stale cache detected for $($cacheAnalysis.StaleServers.Count) Auth Server(s)"
}

# Handle DiagnoseOnly mode
if ($DiagnoseOnly) {
    Write-Section "Diagnosis Complete"
    Write-Status "DiagnoseOnly mode - no changes were made" -Type Info
    Write-Host ""
    
    if ($skipRemainingTests -or $cacheAnalysis.StaleServers.Count -eq 0) {
        Write-Host "  DIAGNOSIS: SSL Inspection is the root cause" -ForegroundColor Yellow
        Write-Host "  ACTION: Work with network team to bypass SSL inspection" -ForegroundColor Cyan
    }
    else {
        Write-Host "  DIAGNOSIS: Stale certificate cache confirmed" -ForegroundColor Green
        Write-Host "  RUN WITHOUT -DiagnoseOnly to refresh metadata" -ForegroundColor Cyan
    }
    Write-Host ""
    $shouldRemediate = $false
    $skipRemainingTests = $true
}

# Skip remediation if cache is current or SSL inspection detected
if (-not $skipRemainingTests -and $shouldRemediate) {
    # Determine which Auth Servers to refresh
    $serversToRefresh = @()
    if ($cacheAnalysis.StaleServers.Count -gt 0) {
        # Only refresh stale servers
        $staleNames = $cacheAnalysis.StaleServers | ForEach-Object { $_.Name }
        $serversToRefresh = $authServers | Where-Object { $staleNames -contains $_.Name }
    }
    else {
        # Refresh all (user explicitly requested)
        $serversToRefresh = $authServers
    }
    
    # Confirm remediation
    if (-not $Force -and -not $WhatIf -and $cacheAnalysis.StaleServers.Count -gt 0) {
        Write-Host ""
        Write-Host "  Auth Server Status:" -ForegroundColor Yellow
        foreach ($srv in $authServers) {
            $staleNames = $cacheAnalysis.StaleServers | ForEach-Object { $_.Name }
            if ($staleNames -contains $srv.Name) {
                Write-Host "    [STALE]   $($srv.Name) - WILL BE REFRESHED" -ForegroundColor Red
            }
            else {
                Write-Host "    [CURRENT] $($srv.Name) - No action needed" -ForegroundColor Green
            }
        }
        Write-Host ""
        Write-Host "  This will refresh OAuth metadata for $($serversToRefresh.Count) stale Auth Server(s)." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Options:" -ForegroundColor White
        Write-Host "    [Y] Yes - Proceed with automatic remediation" -ForegroundColor Green
        Write-Host "    [N] No  - Cancel and exit" -ForegroundColor Red
        Write-Host "    [M] Manual - Show manual steps to run yourself" -ForegroundColor Yellow
        Write-Host ""
        $confirm = Read-Host "  Your choice (Y/N/M)"
        
        if ($confirm -match '^[Mm]') {
            Write-Status "Showing manual remediation steps..." -Type Info
            Show-ManualRemediationSteps -AuthServers $authServers -StaleServers $cacheAnalysis.StaleServers -CurrentServers $cacheAnalysis.CurrentServers
            Write-Host "Manual steps displayed. Exiting without making changes." -ForegroundColor Cyan
            exit 0
        }
        elseif ($confirm -notmatch '^[Yy]') {
            Write-Status "Remediation cancelled by user" -Type Warning
            exit 0
        }
    }
    
    if ($remediationReason) {
        Write-Status "Proceeding: $remediationReason" -Type Info
    }
    
    # Refresh OAuth metadata (only stale servers)
    $refreshResults = Invoke-RefreshAuthMetadata -AuthServers $serversToRefresh -WhatIf:$WhatIf
    
    if (-not $WhatIf) {
        # Show updated configuration
        Write-Host ""
        Write-Status "Verifying updated configuration..." -Type Info
        Start-Sleep -Seconds 2
        
        $null = Get-AuthServerDetails
        
        # Test OAuth connectivity
        $null = Test-OAuthConnectivity -Mailbox $TestMailbox
    }
    
    # Summary
    Write-Section "Remediation Summary"
    
    if ($WhatIf) {
        Write-Status "WhatIf mode - no changes were made" -Type Info
    }
    else {
        if ($refreshResults.Success.Count -gt 0) {
            Write-Status "Successfully refreshed: $($refreshResults.Success -join ', ')" -Type Success
        }
        if ($refreshResults.Failed.Count -gt 0) {
            Write-Status "Failed to refresh: $(($refreshResults.Failed | ForEach-Object { $_.Name }) -join ', ')" -Type Error
        }
    }
}

# Show next steps based on what was done
Write-Host ""
Write-Host "=" * 78 -ForegroundColor Cyan
Write-Host "  NEXT STEPS" -ForegroundColor Cyan
Write-Host "=" * 78 -ForegroundColor Cyan
Write-Host ""

if ($skipRemainingTests -and -not $shouldRemediate) {
    # Cache was current or SSL inspection detected - network action needed
    Write-Host "  1. Work with your network/security team to implement SSL inspection bypass" -ForegroundColor White
    Write-Host "  2. Verify bypass is applied to ALL network paths from ALL Exchange servers" -ForegroundColor White
    Write-Host "  3. Run this script again to confirm all servers have clean connectivity" -ForegroundColor White
    Write-Host "  4. Run Detect-ProxyAndSSLIssues.ps1 to verify OAuth errors stop" -ForegroundColor White
}
else {
    Write-Host "  1. Wait 5-10 minutes for changes to propagate via AD replication" -ForegroundColor White
    Write-Host "  2. Run Detect-ProxyAndSSLIssues.ps1 again to verify errors are resolved" -ForegroundColor White
    Write-Host "  3. If errors persist, check network connectivity to:" -ForegroundColor White
    Write-Host "       - login.windows.net" -ForegroundColor Gray
    Write-Host "       - accounts.accesscontrol.windows.net" -ForegroundColor Gray
    Write-Host "       - login.microsoftonline.com" -ForegroundColor Gray
    Write-Host "  4. Verify no SSL inspection on Azure AD endpoints" -ForegroundColor White
}
Write-Host ""

if (-not $TestMailbox) {
    Write-Host "  TIP: Re-run with -TestMailbox 'user@domain.com' to verify OAuth works" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "Diagnosis complete." -ForegroundColor Green
Write-Host ""

#endregion Main
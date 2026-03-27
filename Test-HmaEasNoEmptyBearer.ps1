<#
# VERSION: 2026-01-27 09:00 UTC
.SYNOPSIS
    Tests Hybrid Modern Authentication for Exchange ActiveSync without sending empty bearer tokens.
    THIS IS STEP 2 OF 2 - Run Get-HMADiagnostics.ps1 first to check configuration!

.DESCRIPTION
    This script tests HMA/OAuth connectivity for Exchange ActiveSync by acquiring a real OAuth
    token BEFORE making requests to Exchange. Unlike the standard Test-HmaEas.ps1, this script
    does NOT send empty bearer token requests, making it compatible with environments that
    block or reset connections with empty Authorization headers.
    
    ═══════════════════════════════════════════════════════════════════════════════
    WORKFLOW ORDER:
    ═══════════════════════════════════════════════════════════════════════════════
    
    STEP 1: Run Get-HMADiagnostics.ps1 FIRST to:
            - Check HMA configuration on all Exchange servers
            - Identify misconfigurations that will cause this test to fail
            - Get guidance on whether to use -UseDeviceCode (MFA) switch
    
    STEP 2: Run this script (Test-HmaEasNoEmptyBearer.ps1) to:
            - Actually test the OAuth flow end-to-end
            - Validate token acquisition and Exchange connectivity
    
    ═══════════════════════════════════════════════════════════════════════════════

    The script supports two authentication modes:
    1. ROPC (Resource Owner Password Credential) - Default, requires password, NO MFA support
    2. Device Code Flow - Use -UseDeviceCode switch, SUPPORTS MFA!

    The script:
    1. Acquires an OAuth token from Azure AD (via ROPC or Device Code flow)
    2. Tests Autodiscover JSON endpoint with the token
    3. Tests ActiveSync endpoint with the token
    4. Validates the responses

    ═══════════════════════════════════════════════════════════════════════════════
    ACTION PLAN: DIAGNOSING INTERMITTENT HMA/OAUTH CONNECTION ISSUES
    ═══════════════════════════════════════════════════════════════════════════════
    
    STEP 1: UNDERSTAND THE SYMPTOM
    ──────────────────────────────
    Intermittent failures where Outlook iOS sometimes uses JSON autodiscover (works)
    and sometimes falls back to XML autodiscover (fails with 401) indicate the client
    is not consistently getting the OAuth flow initiated.
    
    STEP 2: CHOOSE YOUR AUTHENTICATION MODE
    ───────────────────────────────────────
    
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │ ROPC MODE (Default - No MFA)                                                │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │ USE WHEN:                                                                   │
    │   • Testing with a service account that has no MFA                          │
    │   • Automating tests in scripts/scheduled tasks                             │
    │   • Quick one-off tests where you can enter password                        │
    │                                                                             │
    │ LIMITATIONS:                                                                │
    │   • Will FAIL if user has MFA enforced                                      │
    │   • Will FAIL if ROPC is disabled in Azure AD tenant                        │
    │   • Will FAIL if Conditional Access blocks ROPC                             │
    │                                                                             │
    │ EXAMPLE:                                                                    │
    │   .\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "svc-test@contoso.com"       │
    └─────────────────────────────────────────────────────────────────────────────┘
    
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │ DEVICE CODE MODE (-UseDeviceCode - MFA Supported)                           │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │ USE WHEN:                                                                   │
    │   • Testing with a user account that has MFA enabled                        │
    │   • ROPC mode fails with AADSTS50076/50079 errors                           │
    │   • You need to test the exact same auth flow as Outlook mobile             │
    │   • Testing from a machine without GUI (authenticate on phone/other device) │
    │                                                                             │
    │ HOW IT WORKS:                                                               │
    │   1. Script displays a code (e.g., "ABC123XYZ")                             │
    │   2. Open https://microsoft.com/devicelogin on ANY device                   │
    │   3. Enter the code and sign in (complete MFA if prompted)                  │
    │   4. Script automatically continues after authentication                    │
    │                                                                             │
    │ EXAMPLE:                                                                    │
    │   .\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "user@contoso.com" `         │
    │       -UseDeviceCode -Verbose                                               │
    └─────────────────────────────────────────────────────────────────────────────┘
    
    STEP 3: RUN THE DIAGNOSTIC
    ──────────────────────────
    
    For intermittent issues, run the test MULTIPLE TIMES to catch both success and
    failure scenarios. Use -Verbose and -OutputPath to capture detailed logs:
    
        # Run 5 times with logging
        1..5 | ForEach-Object {
            .\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "user@contoso.com" `
                -UseDeviceCode -Verbose `
                -OutputPath "C:\Logs\HmaTest_Run$_.log"
            Start-Sleep -Seconds 30
        }
    
    STEP 4: ANALYZE RESULTS
    ───────────────────────
    
    SUCCESS indicators:
      [+] OAuth Token Acquisition - Token obtained from Azure AD
      [+] Autodiscover JSON - Got response with ActiveSync URL
      [+] ActiveSync OPTIONS - Server accepted OAuth token
    
    FAILURE indicators to investigate:
      [-] Token Acquisition - Check Azure AD config, MFA status, ROPC settings
      [-] Autodiscover JSON 401 - Check OAuth VDir config, EvoSts auth server
      [-] Autodiscover falls back to XML - HMA not properly configured
      [-] ActiveSync 401 - OAuth not enabled on ActiveSync virtual directory
    
    STEP 5: COMPARE WITH SERVER-SIDE LOGS
    ──────────────────────────────────────
    
    Cross-reference the test timestamps with:
      • Exchange HttpProxy logs (Autodiscover, EAS)
      • IIS logs on CAS servers
      • Azure AD Sign-in logs (portal.azure.com)
    
    Look for patterns:
      • Do failures correlate with specific Exchange servers?
      • Are failures happening at specific times?
      • Is there a pattern in which endpoint (JSON vs XML) is used?
    
    ═══════════════════════════════════════════════════════════════════════════════

.NOTES
    Author: HMA Test Script (No Empty Bearer)
    Date: 2026-01-24
    
    Requirements:
    - Network access to login.microsoftonline.com and your Exchange endpoints
    - For ROPC mode: User must not have MFA enforced
    - For Device Code mode: User can have MFA enabled (you'll authenticate in browser)

.PARAMETER EmailAddress
    The email address of the mailbox to test.

.PARAMETER Credential
    PSCredential object. If not provided, you will be prompted. Not needed if using -UseDeviceCode.

.PARAMETER ExchangeServer
    The FQDN of your on-premises Exchange server (e.g., mail.contoso.com).
    If not provided, will attempt to discover via Autodiscover.

.PARAMETER UseDeviceCode
    Use Device Code flow for authentication. This SUPPORTS MFA!
    You will be given a code to enter at https://microsoft.com/devicelogin

.PARAMETER TenantId
    Your Azure AD tenant ID or domain (e.g., contoso.onmicrosoft.com or GUID).
    If not provided, will use 'common' endpoint.

.PARAMETER SkipCertificateCheck
    Skip SSL certificate validation (use for testing only).

.EXAMPLE
    .\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "user@contoso.com"
    # Basic test using ROPC (will prompt for password, no MFA support)

.EXAMPLE
    .\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "user@contoso.com" -UseDeviceCode
    # Test with MFA support - you'll get a code to enter at microsoft.com/devicelogin

.EXAMPLE
    .\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "user@contoso.com" -UseDeviceCode -Verbose
    # MFA test with full HTTP request/response details shown

.EXAMPLE
    .\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "user@contoso.com" -ExchangeServer "mail.contoso.com" -TenantId "contoso.onmicrosoft.com"
    # Specify Exchange server and tenant explicitly

.EXAMPLE
    .\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "user@contoso.com" -Verbose -OutputPath "C:\Logs\hma-test.log"
    # Save detailed diagnostic log to file for analysis

.EXAMPLE
    # DIAGNOSING INTERMITTENT ISSUES - Run multiple tests with logging
    1..5 | ForEach-Object {
        Write-Host "=== Test Run $_ ===" -ForegroundColor Cyan
        .\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "user@contoso.com" `
            -UseDeviceCode -Verbose -OutputPath "C:\Logs\HmaTest_$_.log"
        Start-Sleep -Seconds 60
    }

.EXAMPLE
    .\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "user@contoso.com" -Verbose

.EXAMPLE
    .\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "user@contoso.com" -UseDeviceCode
    # Uses Device Code flow - works with MFA! You'll get a code to enter at https://microsoft.com/devicelogin

.EXAMPLE
    $cred = Get-Credential
    .\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "user@contoso.com" -Credential $cred -OutputPath "C:\Logs\HmaTest.log"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$EmailAddress,
    
    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,
    
    [Parameter(Mandatory = $false)]
    [string]$ExchangeServer,
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId = "common",
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipCertificateCheck,
    
    [Parameter(Mandatory = $false)]
    [switch]$UseDeviceCode,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ""
)

#region HTTP Configuration
# Disable Expect: 100-continue header to prevent 417 errors with strict proxies/firewalls
[System.Net.ServicePointManager]::Expect100Continue = $false
# Force TLS 1.2 - Azure AD endpoints reject older TLS versions
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
#endregion

#region Configuration
# Well-known client IDs for Microsoft apps that support ROPC
$script:ClientIds = @{
    "OutlookMobile" = "27922004-5251-4030-b22d-91ecd9a37ea4"
    "OutlookDesktop" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    "ExchangePowerShell" = "fb78d390-0c51-40cd-8e17-fdbfab77341b"
}

# Resources/Scopes for different services
$script:Resources = @{
    "EAS" = "https://outlook.office365.com"
    "EWS" = "https://outlook.office365.com"
    "OnPremEAS" = $null  # Will be set based on ExchangeServer
    "OnPremAutodiscover" = $null
}

$script:TestResults = @{
    TokenAcquisition = $null
    AutodiscoverJson = $null
    AutodiscoverXml = $null
    ActiveSync = $null
    FolderSync = $null
    Errors = @()
}

$script:LogOutput = @()
#endregion

#region Helper Functions
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logLine = "[${timestamp}] [${Level}] $Message"
    $script:LogOutput += $logLine
    
    if ($VerbosePreference -eq 'Continue' -or $Level -eq "ERROR") {
        $color = switch ($Level) {
            "ERROR" { "Red" }
            "WARN" { "Yellow" }
            "DEBUG" { "DarkGray" }
            "RESPONSE" { "DarkCyan" }
            "REQUEST" { "DarkMagenta" }
            default { "Gray" }
        }
        Write-Host $logLine -ForegroundColor $color
    }
}

function Write-DetailedRequest {
    param(
        [string]$Method,
        [string]$Uri,
        [hashtable]$Headers,
        [string]$Body = ""
    )
    
    Write-Log "===== HTTP REQUEST =====" -Level "REQUEST"
    Write-Log "$Method $Uri" -Level "REQUEST"
    Write-Log "Headers:" -Level "REQUEST"
    foreach ($key in $Headers.Keys) {
        $value = $Headers[$key]
        # Mask authorization header value
        if ($key -eq "Authorization") {
            $value = $value.Substring(0, [Math]::Min(20, $value.Length)) + "..."
        }
        Write-Log "  $key : $value" -Level "REQUEST"
    }
    if ($Body) {
        Write-Log "Body: $Body" -Level "REQUEST"
    }
    Write-Log "========================" -Level "REQUEST"
}

function Write-DetailedResponse {
    param(
        [int]$StatusCode,
        [string]$StatusDescription,
        $Headers,
        [string]$Content = "",
        [int]$ContentLength = 0
    )
    
    Write-Log "===== HTTP RESPONSE =====" -Level "RESPONSE"
    Write-Log "Status: $StatusCode $StatusDescription" -Level "RESPONSE"
    Write-Log "Headers:" -Level "RESPONSE"
    
    if ($Headers) {
        foreach ($key in $Headers.Keys) {
            $value = $Headers[$key]
            Write-Log "  $key : $value" -Level "RESPONSE"
        }
    }
    
    if ($Content) {
        Write-Log "Content-Length: $ContentLength" -Level "RESPONSE"
        # Truncate very long responses
        if ($Content.Length -gt 2000) {
            Write-Log "Body (truncated): $($Content.Substring(0, 2000))..." -Level "RESPONSE"
        } else {
            Write-Log "Body: $Content" -Level "RESPONSE"
        }
    }
    Write-Log "=========================" -Level "RESPONSE"
}

function Write-DetailedError {
    param(
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [string]$Context = ""
    )
    
    Write-Log "===== ERROR DETAILS =====" -Level "ERROR"
    Write-Log "Context: $Context" -Level "ERROR"
    Write-Log "Exception Type: $($ErrorRecord.Exception.GetType().FullName)" -Level "ERROR"
    Write-Log "Message: $($ErrorRecord.Exception.Message)" -Level "ERROR"
    
    if ($ErrorRecord.Exception.Response) {
        $response = $ErrorRecord.Exception.Response
        Write-Log "HTTP Status: $([int]$response.StatusCode) $($response.StatusCode)" -Level "ERROR"
        
        # Get response headers
        Write-Log "Response Headers:" -Level "ERROR"
        try {
            foreach ($header in $response.Headers) {
                $values = $response.Headers.GetValues($header)
                Write-Log "  $header : $($values -join '; ')" -Level "ERROR"
            }
        } catch {
            # Silently continue if headers cannot be enumerated
            Write-Log "  [Unable to enumerate response headers]" -Level "DEBUG"
        }
        
        # Try to get response body
        try {
            $responseStream = $response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($responseStream)
            $responseBody = $reader.ReadToEnd()
            $reader.Close()
            $responseStream.Close()
            
            if ($responseBody) {
                Write-Log "Response Body: $responseBody" -Level "ERROR"
                
                # Try to parse as JSON for better formatting
                try {
                    $jsonBody = $responseBody | ConvertFrom-Json
                    if ($jsonBody.error) {
                        Write-Log "  Error Code: $($jsonBody.error)" -Level "ERROR"
                    }
                    if ($jsonBody.error_description) {
                        Write-Log "  Error Description: $($jsonBody.error_description)" -Level "ERROR"
                    }
                } catch {
                    # Response body is not JSON, already logged as raw text
                }
            }
        } catch {
            Write-Log "Could not read response body" -Level "ERROR"
        }
    }
    
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        Write-Log "Error Details: $($ErrorRecord.ErrorDetails.Message)" -Level "ERROR"
    }
    
    Write-Log "Stack Trace: $($ErrorRecord.ScriptStackTrace)" -Level "DEBUG"
    Write-Log "=========================" -Level "ERROR"
}

function Write-TestResult {
    # Status can be: Success, Warning, Error, Info
    param(
        [string]$TestName,
        [string]$Status,
        [string]$Message,
        [string]$Details = ""
    )
    
    $color = switch ($Status) {
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Info" { "Cyan" }
        default { "White" }
    }
    
    $symbol = switch ($Status) {
        "Success" { "[+]" }
        "Warning" { "[!]" }
        "Error" { "[-]" }
        "Info" { "[*]" }
        default { "[?]" }
    }
    
    Write-Host "$symbol $TestName : " -NoNewline
    Write-Host $Message -ForegroundColor $color
    Write-Log "$symbol $TestName : $Message" -Level $Status.ToUpper()
    
    if ($Details) {
        Write-Host "    $Details" -ForegroundColor Gray
    }
}

function Get-OAuthToken {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$Resource,
        [PSCredential]$Credential
    )
    
    Write-Host "`n=== Acquiring OAuth Token ===" -ForegroundColor Cyan
    Write-Host "Tenant: $TenantId" -ForegroundColor Gray
    Write-Host "Resource: $Resource" -ForegroundColor Gray
    Write-Host "Client ID: $ClientId" -ForegroundColor Gray
    
    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/token"
    
    $body = @{
        grant_type = "password"
        client_id = $ClientId
        resource = $Resource
        username = $Credential.UserName
        password = $Credential.GetNetworkCredential().Password
        scope = "openid"
    }
    
    # Log the request (without password)
    $logBody = $body.Clone()
    $logBody.password = "***REDACTED***"
    Write-Log "Token Request to: $tokenEndpoint" -Level "DEBUG"
    Write-Log "Request Body: $($logBody | ConvertTo-Json -Compress)" -Level "DEBUG"
    
    try {
        Write-Log "Sending token request..." -Level "DEBUG"
        $response = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        
        Write-TestResult -TestName "Token Acquisition" -Status "Success" -Message "Successfully acquired OAuth token" -Details "Token type: $($response.token_type), Expires in: $($response.expires_in) seconds"
        
        # Log token details (without the actual token)
        Write-Log "Token acquired successfully" -Level "DEBUG"
        Write-Log "  Token Type: $($response.token_type)" -Level "DEBUG"
        Write-Log "  Expires In: $($response.expires_in) seconds" -Level "DEBUG"
        Write-Log "  Resource: $($response.resource)" -Level "DEBUG"
        Write-Log "  Scope: $($response.scope)" -Level "DEBUG"
        
        # Decode and log JWT claims (header and payload, not signature)
        try {
            $tokenParts = $response.access_token.Split('.')
            if ($tokenParts.Count -ge 2) {
                # Decode payload (second part)
                $payload = $tokenParts[1]
                # Fix padding
                $padding = 4 - ($payload.Length % 4)
                if ($padding -lt 4) { $payload += '=' * $padding }
                $decodedPayload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload.Replace('-','+').Replace('_','/')))
                $claims = $decodedPayload | ConvertFrom-Json
                
                Write-Log "Token Claims:" -Level "DEBUG"
                Write-Log "  Audience (aud): $($claims.aud)" -Level "DEBUG"
                Write-Log "  Issuer (iss): $($claims.iss)" -Level "DEBUG"
                Write-Log "  UPN: $($claims.upn)" -Level "DEBUG"
                Write-Log "  App ID: $($claims.appid)" -Level "DEBUG"
                Write-Log "  Issued At: $(([DateTime]'1970-01-01').AddSeconds($claims.iat))" -Level "DEBUG"
                Write-Log "  Expires At: $(([DateTime]'1970-01-01').AddSeconds($claims.exp))" -Level "DEBUG"
            }
        }
        catch {
            Write-Log "Could not decode token claims: $($_.Exception.Message)" -Level "DEBUG"
        }
        
        return @{
            Success = $true
            AccessToken = $response.access_token
            TokenType = $response.token_type
            ExpiresIn = $response.expires_in
            Resource = $response.resource
        }
    }
    catch {
        Write-DetailedError -ErrorRecord $_ -Context "OAuth Token Acquisition"
        
        $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        $errorMessage = if ($errorDetails) { 
            "$($errorDetails.error): $($errorDetails.error_description)" 
        } else { 
            $_.Exception.Message 
        }
        
        Write-TestResult -TestName "Token Acquisition" -Status "Error" -Message "Failed to acquire token" -Details $errorMessage
        
        # Check for common issues
        if ($errorMessage -match "AADSTS50126") {
            Write-Host "    -> Invalid username or password" -ForegroundColor Yellow
            Write-Log "Error Analysis: Invalid credentials (AADSTS50126)" -Level "ERROR"
        }
        elseif ($errorMessage -match "AADSTS50076|AADSTS50079") {
            Write-Host "    -> MFA is required. ROPC flow does not support MFA." -ForegroundColor Yellow
            Write-Host "    -> Consider using a service account without MFA for testing." -ForegroundColor Yellow
            Write-Log "Error Analysis: MFA required - ROPC incompatible (AADSTS50076/50079)" -Level "ERROR"
        }
        elseif ($errorMessage -match "AADSTS7000218") {
            Write-Host "    -> ROPC flow is disabled for this tenant or app." -ForegroundColor Yellow
            Write-Host "    -> Enable 'Allow public client flows' in the app registration." -ForegroundColor Yellow
            Write-Log "Error Analysis: ROPC disabled (AADSTS7000218)" -Level "ERROR"
        }
        elseif ($errorMessage -match "AADSTS50034") {
            Write-Host "    -> User account not found. Check the username format." -ForegroundColor Yellow
            Write-Log "Error Analysis: User not found (AADSTS50034)" -Level "ERROR"
        }
        elseif ($errorMessage -match "AADSTS65001") {
            Write-Host "    -> The user or admin hasn't consented to use the application." -ForegroundColor Yellow
            Write-Log "Error Analysis: Consent required (AADSTS65001)" -Level "ERROR"
        }
        elseif ($errorMessage -match "AADSTS50105") {
            Write-Host "    -> User not assigned to the application." -ForegroundColor Yellow
            Write-Log "Error Analysis: User not assigned to app (AADSTS50105)" -Level "ERROR"
        }
        
        return @{
            Success = $false
            Error = $errorMessage
        }
    }
}

function Get-OAuthTokenDeviceCode {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$Resource
    )
    
    Write-Host "`n=== Acquiring OAuth Token via Device Code Flow (MFA Supported) ===" -ForegroundColor Cyan
    Write-Log "Starting Device Code Flow authentication" -Level "INFO"
    Write-Host "Tenant: $TenantId" -ForegroundColor Gray
    Write-Host "Resource: $Resource" -ForegroundColor Gray
    Write-Host "Client ID: $ClientId" -ForegroundColor Gray
    
    $deviceCodeEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/devicecode"
    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/token"
    
    # Step 1: Request device code
    $deviceCodeBody = @{
        client_id = $ClientId
        resource = $Resource
    }
    
    Write-Log "Requesting device code from: $deviceCodeEndpoint" -Level "DEBUG"
    
    try {
        $deviceCodeResponse = Invoke-RestMethod -Uri $deviceCodeEndpoint -Method POST -Body $deviceCodeBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        
        Write-Log "Device code received successfully" -Level "DEBUG"
        Write-Log "  Device Code: $($deviceCodeResponse.device_code.Substring(0, 20))..." -Level "DEBUG"
        Write-Log "  User Code: $($deviceCodeResponse.user_code)" -Level "DEBUG"
        Write-Log "  Verification URL: $($deviceCodeResponse.verification_url)" -Level "DEBUG"
        Write-Log "  Expires In: $($deviceCodeResponse.expires_in) seconds" -Level "DEBUG"
        Write-Log "  Polling Interval: $($deviceCodeResponse.interval) seconds" -Level "DEBUG"
        
        # Display instructions to user
        Write-Host "`n" -NoNewline
        Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
        Write-Host "║                     DEVICE CODE AUTHENTICATION                    ║" -ForegroundColor Yellow
        Write-Host "╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor Yellow
        Write-Host "║                                                                   ║" -ForegroundColor Yellow
        Write-Host "║  To authenticate, open a browser and go to:                       ║" -ForegroundColor Yellow
        Write-Host "║                                                                   ║" -ForegroundColor Yellow
        Write-Host "║      " -NoNewline -ForegroundColor Yellow
        Write-Host "https://microsoft.com/devicelogin" -NoNewline -ForegroundColor Cyan
        Write-Host "                          ║" -ForegroundColor Yellow
        Write-Host "║                                                                   ║" -ForegroundColor Yellow
        Write-Host "║  Then enter this code:                                            ║" -ForegroundColor Yellow
        Write-Host "║                                                                   ║" -ForegroundColor Yellow
        Write-Host "║                        " -NoNewline -ForegroundColor Yellow
        Write-Host "$($deviceCodeResponse.user_code)" -NoNewline -ForegroundColor Green
        Write-Host "                                 ║" -ForegroundColor Yellow
        Write-Host "║                                                                   ║" -ForegroundColor Yellow
        Write-Host "║  Complete the sign-in (including MFA if required).                ║" -ForegroundColor Yellow
        Write-Host "║  This script will continue automatically when done.               ║" -ForegroundColor Yellow
        Write-Host "║                                                                   ║" -ForegroundColor Yellow
        Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
        Write-Host "`n"
        
        # Copy to clipboard if possible
        try {
            $deviceCodeResponse.user_code | Set-Clipboard
            Write-Host "  (Code copied to clipboard)" -ForegroundColor DarkGray
        }
        catch {
            # Clipboard not available, that's fine
        }
        
        Write-Host "`nWaiting for authentication..." -ForegroundColor Gray
        
        # Step 2: Poll for token
        $pollInterval = [int]$deviceCodeResponse.interval
        if ($pollInterval -lt 5) { $pollInterval = 5 }  # Minimum 5 seconds
        
        $expiresAt = (Get-Date).AddSeconds([int]$deviceCodeResponse.expires_in)
        $tokenBody = @{
            grant_type = "urn:ietf:params:oauth:grant-type:device_code"
            client_id = $ClientId
            device_code = $deviceCodeResponse.device_code
        }
        
        $authenticated = $false
        $tokenResponse = $null
        
        while ((Get-Date) -lt $expiresAt -and -not $authenticated) {
            Start-Sleep -Seconds $pollInterval
            
            try {
                $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                $authenticated = $true
                Write-Host "`n  Authentication successful!" -ForegroundColor Green
                Write-Log "Device code authentication successful" -Level "INFO"
            }
            catch {
                $errorBody = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                
                if ($errorBody.error -eq "authorization_pending") {
                    # User hasn't completed auth yet, keep waiting
                    Write-Host "." -NoNewline -ForegroundColor Gray
                    Write-Log "Authorization pending, continuing to poll..." -Level "DEBUG"
                }
                elseif ($errorBody.error -eq "slow_down") {
                    # Need to slow down polling
                    $pollInterval += 5
                    Write-Log "Slowing down polling to $pollInterval seconds" -Level "DEBUG"
                }
                elseif ($errorBody.error -eq "expired_token") {
                    Write-Host "`n  Device code expired. Please try again." -ForegroundColor Red
                    Write-Log "Device code expired" -Level "ERROR"
                    return @{ Success = $false; Error = "Device code expired" }
                }
                elseif ($errorBody.error -eq "authorization_declined") {
                    Write-Host "`n  Authentication was declined by user." -ForegroundColor Red
                    Write-Log "Authentication declined by user" -Level "ERROR"
                    return @{ Success = $false; Error = "Authentication declined" }
                }
                else {
                    Write-DetailedError -ErrorRecord $_ -Context "Device Code Token Polling"
                    return @{ Success = $false; Error = $errorBody.error_description }
                }
            }
        }
        
        if (-not $authenticated) {
            Write-Host "`n  Timeout waiting for authentication." -ForegroundColor Red
            Write-Log "Device code flow timed out" -Level "ERROR"
            return @{ Success = $false; Error = "Authentication timeout" }
        }
        
        Write-TestResult -TestName "Token Acquisition (Device Code)" -Status "Success" -Message "Successfully acquired OAuth token via Device Code flow" -Details "Token type: $($tokenResponse.token_type), Expires in: $($tokenResponse.expires_in) seconds"
        
        # Log token details
        Write-Log "Token acquired via Device Code flow" -Level "DEBUG"
        Write-Log "  Token Type: $($tokenResponse.token_type)" -Level "DEBUG"
        Write-Log "  Expires In: $($tokenResponse.expires_in) seconds" -Level "DEBUG"
        Write-Log "  Resource: $($tokenResponse.resource)" -Level "DEBUG"
        
        # Decode and log JWT claims
        try {
            $tokenParts = $tokenResponse.access_token.Split('.')
            if ($tokenParts.Count -ge 2) {
                $payload = $tokenParts[1]
                $padding = 4 - ($payload.Length % 4)
                if ($padding -lt 4) { $payload += '=' * $padding }
                $decodedPayload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload.Replace('-','+').Replace('_','/')))
                $claims = $decodedPayload | ConvertFrom-Json
                
                Write-Log "Token Claims:" -Level "DEBUG"
                Write-Log "  Audience (aud): $($claims.aud)" -Level "DEBUG"
                Write-Log "  Issuer (iss): $($claims.iss)" -Level "DEBUG"
                Write-Log "  UPN: $($claims.upn)" -Level "DEBUG"
                Write-Log "  App ID: $($claims.appid)" -Level "DEBUG"
                if ($claims.amr) {
                    Write-Log "  Auth Methods (amr): $($claims.amr -join ', ')" -Level "DEBUG"
                }
            }
        }
        catch {
            Write-Log "Could not decode token claims: $($_.Exception.Message)" -Level "DEBUG"
        }
        
        return @{
            Success = $true
            AccessToken = $tokenResponse.access_token
            TokenType = $tokenResponse.token_type
            ExpiresIn = $tokenResponse.expires_in
            Resource = $tokenResponse.resource
            RefreshToken = $tokenResponse.refresh_token
        }
    }
    catch {
        Write-DetailedError -ErrorRecord $_ -Context "Device Code Request"
        
        $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        $errorMessage = if ($errorDetails) { 
            "$($errorDetails.error): $($errorDetails.error_description)" 
        } else { 
            $_.Exception.Message 
        }
        
        Write-TestResult -TestName "Token Acquisition (Device Code)" -Status "Error" -Message "Failed to initiate device code flow" -Details $errorMessage
        
        return @{
            Success = $false
            Error = $errorMessage
        }
    }
}

function Get-OAuthTokenForOnPrem {
    param(
        [string]$ExchangeServerFqdn,
        [PSCredential]$Credential,
        [string]$TenantId,
        [switch]$UseDeviceCode
    )
    
    Write-Host "`n=== Acquiring OAuth Token for On-Premises Exchange ===" -ForegroundColor Cyan
    
    if ($UseDeviceCode) {
        Write-Host "Using Device Code flow (MFA supported)" -ForegroundColor Green
        Write-Log "Authentication mode: Device Code Flow (MFA supported)" -Level "INFO"
    }
    else {
        Write-Host "Using ROPC flow (no MFA support)" -ForegroundColor Gray
        Write-Log "Authentication mode: ROPC Flow (no MFA)" -Level "INFO"
    }
    
    # For on-prem HMA, the resource is typically the on-prem Exchange server FQDN
    # But the token is still acquired from Azure AD
    
    # First try with the server FQDN as resource
    $resource = "https://$ExchangeServerFqdn"
    Write-Host "Attempting with resource: $resource" -ForegroundColor Gray
    
    if ($UseDeviceCode) {
        # Use Device Code flow (supports MFA)
        $result = Get-OAuthTokenDeviceCode -TenantId $TenantId -ClientId $script:ClientIds["OutlookMobile"] -Resource $resource
    }
    else {
        # Use ROPC flow (no MFA support)
        $result = Get-OAuthToken -TenantId $TenantId -ClientId $script:ClientIds["OutlookMobile"] -Resource $resource -Credential $Credential
    }
    
    if (-not $result.Success) {
        # Try with outlook.office365.com as resource (works for some HMA configs)
        Write-Host "`nRetrying with outlook.office365.com as resource..." -ForegroundColor Yellow
        $resource = "https://outlook.office365.com"
        
        if ($UseDeviceCode) {
            $result = Get-OAuthTokenDeviceCode -TenantId $TenantId -ClientId $script:ClientIds["OutlookMobile"] -Resource $resource
        }
        else {
            $result = Get-OAuthToken -TenantId $TenantId -ClientId $script:ClientIds["OutlookMobile"] -Resource $resource -Credential $Credential
        }
    }
    
    return $result
}

function Test-AutodiscoverJson {
    param(
        [string]$EmailAddress,
        [string]$AccessToken,
        [string]$ServerFqdn = ""
    )
    
    Write-Host "`n=== Testing Autodiscover JSON Endpoint ===" -ForegroundColor Cyan
    Write-Log "Starting Autodiscover JSON test for: $EmailAddress" -Level "INFO"
    
    $domain = $EmailAddress.Split('@')[1]
    
    # Build list of Autodiscover URLs to try
    $autodiscoverUrls = @()
    
    if ($ServerFqdn) {
        $autodiscoverUrls += "https://$ServerFqdn/autodiscover/autodiscover.json?Email=$EmailAddress`&Protocol=ActiveSync"
    }
    
    $autodiscoverUrls += @(
        "https://autodiscover.$domain/autodiscover/autodiscover.json?Email=$EmailAddress`&Protocol=ActiveSync",
        "https://$domain/autodiscover/autodiscover.json?Email=$EmailAddress`&Protocol=ActiveSync"
    )
    
    Write-Log "URLs to try: $($autodiscoverUrls -join ', ')" -Level "DEBUG"
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type" = "application/json"
        "User-Agent" = "TestHMA-NoEmptyBearer/1.0"
    }
    
    foreach ($url in $autodiscoverUrls) {
        Write-Host "Trying: $url" -ForegroundColor Gray
        Write-Log "Attempting Autodiscover at: $url" -Level "DEBUG"
        
        Write-DetailedRequest -Method "GET" -Uri $url -Headers $headers
        
        try {
            $invokeParams = @{
                Uri = $url
                Method = "GET"
                Headers = $headers
                ErrorAction = "Stop"
                UseBasicParsing = $true
            }
            
            if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -ge 6) {
                $invokeParams.SkipCertificateCheck = $true
            }
            
            $response = Invoke-WebRequest @invokeParams
            
            # Log detailed response
            Write-DetailedResponse -StatusCode $response.StatusCode -StatusDescription $response.StatusDescription -Headers $response.Headers -Content $response.Content -ContentLength $response.RawContentLength
            
            $content = $response.Content | ConvertFrom-Json
            
            Write-TestResult -TestName "Autodiscover JSON" -Status "Success" -Message "Got response from $url"
            Write-Host "    Protocol: $($content.Protocol)" -ForegroundColor Gray
            Write-Host "    URL: $($content.Url)" -ForegroundColor Gray
            
            Write-Log "Autodiscover Response Details:" -Level "DEBUG"
            Write-Log "  Protocol: $($content.Protocol)" -Level "DEBUG"
            Write-Log "  Url: $($content.Url)" -Level "DEBUG"
            if ($content.RedirectAddr) {
                Write-Log "  RedirectAddr: $($content.RedirectAddr)" -Level "DEBUG"
            }
            return @{
                Success = $true
                Url = $url
                Response = $content
                ActiveSyncUrl = $content.Url
            }
        }
        catch {
            Write-DetailedError -ErrorRecord $_ -Context "Autodiscover JSON: $url"
            
            $statusCode = $_.Exception.Response.StatusCode.value__
            Write-Host "    Failed: HTTP $statusCode - $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Log "Autodiscover failed for $url - HTTP $statusCode" -Level "WARN"
            
            if ($statusCode -eq 401) {
                # Try to get WWW-Authenticate header for debugging
                try {
                    $wwwAuth = $_.Exception.Response.Headers.GetValues("WWW-Authenticate")
                    if ($wwwAuth) {
                        Write-Host "    WWW-Authenticate: $($wwwAuth -join '; ')" -ForegroundColor Gray
                        Write-Log "WWW-Authenticate header: $($wwwAuth -join '; ')" -Level "DEBUG"
                        
                        # Parse Bearer challenge for more details
                        foreach ($challenge in $wwwAuth) {
                            if ($challenge -match "Bearer") {
                                Write-Log "Analyzing Bearer challenge:" -Level "DEBUG"
                                if ($challenge -match 'realm="(.+?)"') { Write-Log "  Realm: $($Matches[1])" -Level "DEBUG" }
                                if ($challenge -match 'client_id="(.+?)"') { Write-Log "  Expected Client ID: $($Matches[1])" -Level "DEBUG" }
                                if ($challenge -match 'trusted_issuers="(.+?)"') { Write-Log "  Trusted Issuers: $($Matches[1])" -Level "DEBUG" }
                                if ($challenge -match 'authorization_uri="(.+?)"') { Write-Log "  Authorization URI: $($Matches[1])" -Level "DEBUG" }
                                if ($challenge -match 'error="(.+?)"') { Write-Log "  Error: $($Matches[1])" -Level "DEBUG" }
                            }
                        }
                    }
                }
                catch {
                    # WWW-Authenticate header not available or not readable
                }
            }
            elseif ($statusCode -eq 302 -or $statusCode -eq 301) {
                try {
                    $location = $_.Exception.Response.Headers.GetValues("Location")
                    Write-Log "Redirect Location: $location" -Level "DEBUG"
                }
                catch {
                    # Location header not available
                }
            }
        }
    }
    
    Write-TestResult -TestName "Autodiscover JSON" -Status "Error" -Message "All Autodiscover JSON endpoints failed"
    Write-Log "All Autodiscover JSON endpoints failed" -Level "ERROR"
    return @{ Success = $false }
}

function Test-ActiveSyncOptions {
    param(
        [string]$ActiveSyncUrl,
        [string]$AccessToken
    )
    
    Write-Host "`n=== Testing ActiveSync OPTIONS ===" -ForegroundColor Cyan
    Write-Host "URL: $ActiveSyncUrl" -ForegroundColor Gray
    Write-Log "Starting ActiveSync OPTIONS test" -Level "INFO"
    Write-Log "URL: $ActiveSyncUrl" -Level "DEBUG"
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "User-Agent" = "TestHMA-NoEmptyBearer/1.0"
    }
    
    Write-DetailedRequest -Method "OPTIONS" -Uri $ActiveSyncUrl -Headers $headers
    
    try {
        $invokeParams = @{
            Uri = $ActiveSyncUrl
            Method = "OPTIONS"
            Headers = $headers
            ErrorAction = "Stop"
            UseBasicParsing = $true
        }
        
        if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -ge 6) {
            $invokeParams.SkipCertificateCheck = $true
        }
        
        $response = Invoke-WebRequest @invokeParams
        
        # Log detailed response
        Write-DetailedResponse -StatusCode $response.StatusCode -StatusDescription $response.StatusDescription -Headers $response.Headers -Content $response.Content -ContentLength $response.RawContentLength
        
        $msAsVersions = $response.Headers["MS-ASProtocolVersions"]
        $msAsCommands = $response.Headers["MS-ASProtocolCommands"]
        $msServerActiveSync = $response.Headers["MS-Server-ActiveSync"]
        
        Write-TestResult -TestName "ActiveSync OPTIONS" -Status "Success" -Message "ActiveSync endpoint responded successfully"
        Write-Host "    MS-ASProtocolVersions: $msAsVersions" -ForegroundColor Gray
        Write-Host "    Status Code: $($response.StatusCode)" -ForegroundColor Gray
        
        Write-Log "ActiveSync OPTIONS Response Details:" -Level "DEBUG"
        Write-Log "  Status Code: $($response.StatusCode)" -Level "DEBUG"
        Write-Log "  MS-Server-ActiveSync: $msServerActiveSync" -Level "DEBUG"
        Write-Log "  MS-ASProtocolVersions: $msAsVersions" -Level "DEBUG"
        Write-Log "  MS-ASProtocolCommands: $msAsCommands" -Level "DEBUG"
        
        # Log all X- headers which often contain diagnostic info
        foreach ($key in $response.Headers.Keys) {
            if ($key -match "^X-") {
                Write-Log "  $key : $($response.Headers[$key])" -Level "DEBUG"
            }
        }
        
        return @{
            Success = $true
            StatusCode = $response.StatusCode
            ProtocolVersions = $msAsVersions
            ProtocolCommands = $msAsCommands
            ServerVersion = $msServerActiveSync
            AllHeaders = $response.Headers
        }
    }
    catch {
        Write-DetailedError -ErrorRecord $_ -Context "ActiveSync OPTIONS"
        
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-TestResult -TestName "ActiveSync OPTIONS" -Status "Error" -Message "Failed with HTTP $statusCode" -Details $_.Exception.Message
        
        if ($statusCode -eq 401) {
            Write-Host "    -> Token may not be valid for this resource" -ForegroundColor Yellow
            Write-Host "    -> Check that OAuth is enabled on the ActiveSync virtual directory" -ForegroundColor Yellow
            Write-Log "401 Analysis: Token rejected - OAuth may not be enabled on ActiveSync VDir" -Level "ERROR"
            
            # Get WWW-Authenticate for analysis
            try {
                $wwwAuth = $_.Exception.Response.Headers.GetValues("WWW-Authenticate")
                if ($wwwAuth) {
                    Write-Log "WWW-Authenticate challenges:" -Level "DEBUG"
                    foreach ($challenge in $wwwAuth) {
                        Write-Log "  $challenge" -Level "DEBUG"
                    }
                }
            }
            catch {
                # WWW-Authenticate header not available
            }
        }
        elseif ($statusCode -eq 403) {
            Write-Host "    -> Access denied. Check ActiveSync mailbox policy or device access rules" -ForegroundColor Yellow
            Write-Log "403 Analysis: Access denied - check mailbox policy or CAR" -Level "ERROR"
        }
        elseif ($statusCode -eq 456) {
            Write-Host "    -> Device blocked by quarantine or block rule" -ForegroundColor Yellow
            Write-Log "456 Analysis: Device blocked by Exchange" -Level "ERROR"
        }
        
        return @{
            Success = $false
            StatusCode = $statusCode
            Error = $_.Exception.Message
        }
    }
}

function Test-ActiveSyncFolderSync {
    param(
        [string]$ActiveSyncUrl,
        [string]$AccessToken,
        [string]$EmailAddress
    )
    
    Write-Host "`n=== Testing ActiveSync FolderSync ===" -ForegroundColor Cyan
    Write-Log "Starting ActiveSync FolderSync test" -Level "INFO"
    
    # WBXML encoded FolderSync request with SyncKey of 0
    # This is a minimal FolderSync request
    $folderSyncWbxml = [byte[]]@(
        0x03, 0x01, 0x6A, 0x00,  # WBXML header
        0x00, 0x07,              # FolderHierarchy codepage
        0x56,                    # FolderSync tag
        0x52, 0x03, 0x30, 0x00, 0x01,  # SyncKey = "0"
        0x01                     # End FolderSync
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type" = "application/vnd.ms-sync.wbxml"
        "MS-ASProtocolVersion" = "14.1"
        "User-Agent" = "TestHMA-NoEmptyBearer/1.0"
        "X-MS-PolicyKey" = "0"
    }
    
    $easUrl = "$ActiveSyncUrl`?Cmd=FolderSync`&User=$([Uri]::EscapeDataString($EmailAddress))`&DeviceId=TestHMA123`&DeviceType=TestHMA"
    
    Write-Host "URL: $easUrl" -ForegroundColor Gray
    Write-Log "FolderSync URL: $easUrl" -Level "DEBUG"
    
    Write-DetailedRequest -Method "POST" -Uri $easUrl -Headers $headers -Body "[WBXML Binary Data - $($folderSyncWbxml.Length) bytes]"
    
    try {
        $invokeParams = @{
            Uri = $easUrl
            Method = "POST"
            Headers = $headers
            Body = $folderSyncWbxml
            ErrorAction = "Stop"
            UseBasicParsing = $true
        }
        
        if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -ge 6) {
            $invokeParams.SkipCertificateCheck = $true
        }
        
        $response = Invoke-WebRequest @invokeParams
        
        # Log response details
        Write-DetailedResponse -StatusCode $response.StatusCode -StatusDescription $response.StatusDescription -Headers $response.Headers -Content "[WBXML Binary Response]" -ContentLength $response.RawContentLength
        
        Write-TestResult -TestName "ActiveSync FolderSync" -Status "Success" -Message "FolderSync completed successfully"
        Write-Host "    Status Code: $($response.StatusCode)" -ForegroundColor Gray
        Write-Host "    Content Length: $($response.RawContentLength) bytes" -ForegroundColor Gray
        
        Write-Log "FolderSync succeeded" -Level "DEBUG"
        Write-Log "  Status Code: $($response.StatusCode)" -Level "DEBUG"
        Write-Log "  Content Length: $($response.RawContentLength) bytes" -Level "DEBUG"
        
        # Log diagnostic headers
        foreach ($key in $response.Headers.Keys) {
            if ($key -match "^X-|^MS-") {
                Write-Log "  $key : $($response.Headers[$key])" -Level "DEBUG"
            }
        }
        
        return @{
            Success = $true
            StatusCode = $response.StatusCode
            ResponseHeaders = $response.Headers
        }
    }
    catch {
        Write-DetailedError -ErrorRecord $_ -Context "ActiveSync FolderSync"
        
        $statusCode = $_.Exception.Response.StatusCode.value__
        
        if ($statusCode -eq 449) {
            # 449 = Retry after provisioning - this is actually a success for our test
            Write-TestResult -TestName "ActiveSync FolderSync" -Status "Warning" -Message "Received 449 - Device needs provisioning (this confirms OAuth is working)"
            Write-Log "FolderSync returned 449 - Device provisioning required (OAuth working)" -Level "WARN"
            return @{
                Success = $true
                StatusCode = 449
                NeedsProvisioning = $true
            }
        }
        
        Write-TestResult -TestName "ActiveSync FolderSync" -Status "Error" -Message "Failed with HTTP $statusCode" -Details $_.Exception.Message
        Write-Log "FolderSync failed with HTTP $statusCode" -Level "ERROR"
        
        if ($statusCode -eq 401) {
            Write-Log "401 on FolderSync - Token rejected at command level" -Level "ERROR"
        }
        elseif ($statusCode -eq 403) {
            Write-Log "403 on FolderSync - Permission denied" -Level "ERROR"
        }
        elseif ($statusCode -eq 503) {
            Write-Log "503 on FolderSync - Service unavailable, backend may be down" -Level "ERROR"
        }
        
        return @{
            Success = $false
            StatusCode = $statusCode
            Error = $_.Exception.Message
        }
    }
}

function Get-AutodiscoverServerFromDns {
    param([string]$Domain)
    
    Write-Host "`n=== Discovering Exchange Server ===" -ForegroundColor Cyan
    Write-Log "Starting DNS discovery for domain: $Domain" -Level "INFO"
    
    # Try to resolve autodiscover record
    $autodiscoverFqdn = "autodiscover.$Domain"
    
    try {
        $dns = Resolve-DnsName -Name $autodiscoverFqdn -Type A -ErrorAction Stop
        Write-Host "Found: $autodiscoverFqdn -> $($dns.IPAddress -join ', ')" -ForegroundColor Gray
        Write-Log "DNS A record found: $autodiscoverFqdn -> $($dns.IPAddress -join ', ')" -Level "DEBUG"
        return $autodiscoverFqdn
    }
    catch {
        Write-Host "Could not resolve $autodiscoverFqdn" -ForegroundColor Yellow
        Write-Log "DNS A record not found for $autodiscoverFqdn" -Level "DEBUG"
    }
    
    # Try SRV record
    try {
        $srv = Resolve-DnsName -Name "_autodiscover._tcp.$Domain" -Type SRV -ErrorAction Stop
        $target = $srv.NameTarget
        Write-Host "Found SRV: $target" -ForegroundColor Gray
        Write-Log "DNS SRV record found: $target" -Level "DEBUG"
        return $target
    }
    catch {
        Write-Host "Could not find Autodiscover SRV record" -ForegroundColor Yellow
    }
    
    return $null
}
#endregion

#region Main Script
Clear-Host
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  HMA/OAuth Test for Exchange ActiveSync" -ForegroundColor Cyan
Write-Host "  (No Empty Bearer Token Version)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Email: $EmailAddress" -ForegroundColor White
Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
if ($UseDeviceCode) {
    Write-Host "Auth Mode: Device Code Flow (MFA Supported)" -ForegroundColor Green
} else {
    Write-Host "Auth Mode: ROPC Flow (No MFA)" -ForegroundColor Gray
}
Write-Host ""

# Handle certificate validation for PowerShell 5.1
if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -lt 6) {
    Write-Host "Note: SkipCertificateCheck requires PowerShell 6+. Using certificate bypass." -ForegroundColor Yellow
    $certPolicyCode = @'
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
        return true;
    }
}
'@
    Add-Type -TypeDefinition $certPolicyCode
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

# Get credentials if not provided and not using device code flow
if (-not $UseDeviceCode -and -not $Credential) {
    Write-Host "Please enter credentials for $EmailAddress" -ForegroundColor Yellow
    $Credential = Get-Credential -UserName $EmailAddress -Message "Enter password for $EmailAddress"
    
    if (-not $Credential) {
        Write-Host "No credentials provided. Exiting." -ForegroundColor Red
        exit 1
    }
}

# Discover Exchange server if not provided
if (-not $ExchangeServer) {
    $domain = $EmailAddress.Split('@')[1]
    $ExchangeServer = Get-AutodiscoverServerFromDns -Domain $domain
    
    if (-not $ExchangeServer) {
        Write-Host "Could not discover Exchange server. Please provide -ExchangeServer parameter." -ForegroundColor Red
        exit 1
    }
}

Write-Host "`nExchange Server: $ExchangeServer" -ForegroundColor White

# Step 1: Acquire OAuth token
if ($UseDeviceCode) {
    $tokenResult = Get-OAuthTokenForOnPrem -ExchangeServerFqdn $ExchangeServer -TenantId $TenantId -UseDeviceCode
} else {
    $tokenResult = Get-OAuthTokenForOnPrem -ExchangeServerFqdn $ExchangeServer -Credential $Credential -TenantId $TenantId
}
$script:TestResults.TokenAcquisition = $tokenResult

if (-not $tokenResult.Success) {
    Write-Host "`n" -NoNewline
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "  TOKEN ACQUISITION FAILED - Cannot continue testing" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red

    $errorMsg = $tokenResult.Error
    $diagnosed = $false

    # 1. Invalid credentials
    if ($errorMsg -match "AADSTS50126") {
        Write-Host "  Cause: Invalid credentials (username or password)" -ForegroundColor Yellow
        $diagnosed = $true
    }
    # 2. MFA required
    elseif ($errorMsg -match "AADSTS50076|AADSTS50079") {
        Write-Host "  Cause: MFA is required for this account (ROPC does not support MFA)" -ForegroundColor Yellow
        Write-Host "  Action: Use -UseDeviceCode for MFA accounts." -ForegroundColor Yellow
        $diagnosed = $true
    }
    # 3. ROPC flow disabled
    elseif ($errorMsg -match "AADSTS7000218") {
        Write-Host "  Cause: ROPC flow is disabled in Azure AD for this app/tenant." -ForegroundColor Yellow
        Write-Host "  Action: Enable 'Allow public client flows' in the app registration." -ForegroundColor Yellow
        $diagnosed = $true
    }
    # 4. User not found
    elseif ($errorMsg -match "AADSTS50034") {
        Write-Host "  Cause: User not found in Azure AD." -ForegroundColor Yellow
        Write-Host "  Action: Check username and Azure AD sync status." -ForegroundColor Yellow
        $diagnosed = $true
    }
    # 5. Conditional Access policy blocking ROPC
    elseif ($errorMsg -match "AADSTS53003|AADSTS50158|AADSTS50020|AADSTS50105|AADSTS50196|AADSTS50128|AADSTS50173|AADSTS50144|AADSTS50155|AADSTS50132|AADSTS50133|AADSTS50169|AADSTS50171|AADSTS50187|AADSTS50194|AADSTS51009|AADSTS51011|AADSTS51012|AADSTS51013|AADSTS51014|AADSTS51015|AADSTS51016|AADSTS51017|AADSTS51018|AADSTS51019|AADSTS51020|AADSTS51021|AADSTS51022|AADSTS51023|AADSTS51024|AADSTS51025|AADSTS51026|AADSTS51027|AADSTS51028|AADSTS51029|AADSTS51030|AADSTS51031|AADSTS51032|AADSTS51033|AADSTS51034|AADSTS51035|AADSTS51036|AADSTS51037|AADSTS51038|AADSTS51039|AADSTS51040|AADSTS51041|AADSTS51042|AADSTS51043|AADSTS51044|AADSTS51045|AADSTS51046|AADSTS51047|AADSTS51048|AADSTS51049|AADSTS51050|AADSTS51051|AADSTS51052|AADSTS51053|AADSTS51054|AADSTS51055|AADSTS51056|AADSTS51057|AADSTS51058|AADSTS51059|AADSTS51060|AADSTS51061|AADSTS51062|AADSTS51063|AADSTS51064|AADSTS51065|AADSTS51066|AADSTS51067|AADSTS51068|AADSTS51069|AADSTS51070|AADSTS51071|AADSTS51072|AADSTS51073|AADSTS51074|AADSTS51075|AADSTS51076|AADSTS51077|AADSTS51078|AADSTS51079|AADSTS51080|AADSTS51081|AADSTS51082|AADSTS51083|AADSTS51084|AADSTS51085|AADSTS51086|AADSTS51087|AADSTS51088|AADSTS51089|AADSTS51090|AADSTS51091|AADSTS51092|AADSTS51093|AADSTS51094|AADSTS51095|AADSTS51096|AADSTS51097|AADSTS51098|AADSTS51099|AADSTS51100|AADSTS51101|AADSTS51102|AADSTS51103|AADSTS51104|AADSTS51105|AADSTS51106|AADSTS51107|AADSTS51108|AADSTS51109|AADSTS51110|AADSTS51111|AADSTS51112|AADSTS51113|AADSTS51114|AADSTS51115|AADSTS51116|AADSTS51117|AADSTS51118|AADSTS51119|AADSTS51120|AADSTS51121|AADSTS51122|AADSTS51123|AADSTS51124|AADSTS51125|AADSTS51126|AADSTS51127|AADSTS51128|AADSTS51129|AADSTS51130|AADSTS51131|AADSTS51132|AADSTS51133|AADSTS51134|AADSTS51135|AADSTS51136|AADSTS51137|AADSTS51138|AADSTS51139|AADSTS51140|AADSTS51141|AADSTS51142|AADSTS51143|AADSTS51144|AADSTS51145|AADSTS51146|AADSTS51147|AADSTS51148|AADSTS51149|AADSTS51150|AADSTS51151|AADSTS51152|AADSTS51153|AADSTS51154|AADSTS51155|AADSTS51156|AADSTS51157|AADSTS51158|AADSTS51159|AADSTS51160|AADSTS51161|AADSTS51162|AADSTS51163|AADSTS51164|AADSTS51165|AADSTS51166|AADSTS51167|AADSTS51168|AADSTS51169|AADSTS51170|AADSTS51171|AADSTS51172|AADSTS51173|AADSTS51174|AADSTS51175|AADSTS51176|AADSTS51177|AADSTS51178|AADSTS51179|AADSTS51180|AADSTS51181|AADSTS51182|AADSTS51183|AADSTS51184|AADSTS51185|AADSTS51186|AADSTS51187|AADSTS51188|AADSTS51189|AADSTS51190|AADSTS51191|AADSTS51192|AADSTS51193|AADSTS51194|AADSTS51195|AADSTS51196|AADSTS51197|AADSTS51198|AADSTS51199|AADSTS51200|AADSTS51201|AADSTS51202|AADSTS51203|AADSTS51204|AADSTS51205|AADSTS51206|AADSTS51207|AADSTS51208|AADSTS51209|AADSTS51210|AADSTS51211|AADSTS51212|AADSTS51213|AADSTS51214|AADSTS51215|AADSTS51216|AADSTS51217|AADSTS51218|AADSTS51219|AADSTS51220|AADSTS51221|AADSTS51222|AADSTS51223|AADSTS51224|AADSTS51225|AADSTS51226|AADSTS51227|AADSTS51228|AADSTS51229|AADSTS51230|AADSTS51231|AADSTS51232|AADSTS51233|AADSTS51234|AADSTS51235|AADSTS51236|AADSTS51237|AADSTS51238|AADSTS51239|AADSTS51240|AADSTS51241|AADSTS51242|AADSTS51243|AADSTS51244|AADSTS51245|AADSTS51246|AADSTS51247|AADSTS51248|AADSTS51249|AADSTS51250|AADSTS51251|AADSTS51252|AADSTS51253|AADSTS51254|AADSTS51255|AADSTS51256|AADSTS51257|AADSTS51258|AADSTS51259|AADSTS51260|AADSTS51261|AADSTS51262|AADSTS51263|AADSTS51264|AADSTS51265|AADSTS51266|AADSTS51267|AADSTS51268|AADSTS51269|AADSTS51270|AADSTS51271|AADSTS51272|AADSTS51273|AADSTS51274|AADSTS51275|AADSTS51276|AADSTS51277|AADSTS51278|AADSTS51279|AADSTS51280|AADSTS51281|AADSTS51282|AADSTS51283|AADSTS51284|AADSTS51285|AADSTS51286|AADSTS51287|AADSTS51288|AADSTS51289|AADSTS51290|AADSTS51291|AADSTS51292|AADSTS51293|AADSTS51294|AADSTS51295|AADSTS51296|AADSTS51297|AADSTS51298|AADSTS51299|AADSTS51300|AADSTS51301|AADSTS51302|AADSTS51303|AADSTS51304|AADSTS51305|AADSTS51306|AADSTS51307|AADSTS51308|AADSTS51309|AADSTS51310|AADSTS51311|AADSTS51312|AADSTS51313|AADSTS51314|AADSTS51315|AADSTS51316|AADSTS51317|AADSTS51318|AADSTS51319|AADSTS51320|AADSTS51321|AADSTS51322|AADSTS51323|AADSTS51324|AADSTS51325|AADSTS51326|AADSTS51327|AADSTS51328|AADSTS51329|AADSTS51330|AADSTS51331|AADSTS51332|AADSTS51333|AADSTS51334|AADSTS51335|AADSTS51336|AADSTS51337|AADSTS51338|AADSTS51339|AADSTS51340|AADSTS51341|AADSTS51342|AADSTS51343|AADSTS51344|AADSTS51345|AADSTS51346|AADSTS51347|AADSTS51348|AADSTS51349|AADSTS51350|AADSTS51351|AADSTS51352|AADSTS51353|AADSTS51354|AADSTS51355|AADSTS51356|AADSTS51357|AADSTS51358|AADSTS51359|AADSTS51360|AADSTS51361|AADSTS51362|AADSTS51363|AADSTS51364|AADSTS51365|AADSTS51366|AADSTS51367|AADSTS51368|AADSTS51369|AADSTS51370|AADSTS51371|AADSTS51372|AADSTS51373|AADSTS51374|AADSTS51375|AADSTS51376|AADSTS51377|AADSTS51378|AADSTS51379|AADSTS51380|AADSTS51381|AADSTS51382|AADSTS51383|AADSTS51384|AADSTS51385|AADSTS51386|AADSTS51387|AADSTS51388|AADSTS51389|AADSTS51390|AADSTS51391|AADSTS51392|AADSTS51393|AADSTS51394|AADSTS51395|AADSTS51396|AADSTS51397|AADSTS51398|AADSTS51399|AADSTS51400|AADSTS51401|AADSTS51402|AADSTS51403|AADSTS51404|AADSTS51405|AADSTS51406|AADSTS51407|AADSTS51408|AADSTS51409|AADSTS51410|AADSTS51411|AADSTS51412|AADSTS51413|AADSTS51414|AADSTS51415|AADSTS51416|AADSTS51417|AADSTS51418|AADSTS51419|AADSTS51420|AADSTS51421|AADSTS51422|AADSTS51423|AADSTS51424|AADSTS51425|AADSTS51426|AADSTS51427|AADSTS51428|AADSTS51429|AADSTS51430|AADSTS51431|AADSTS51432|AADSTS51433|AADSTS51434|AADSTS51435|AADSTS51436|AADSTS51437|AADSTS51438|AADSTS51439|AADSTS51440|AADSTS51441|AADSTS51442|AADSTS51443|AADSTS51444|AADSTS51445|AADSTS51446|AADSTS51447|AADSTS51448|AADSTS51449|AADSTS51450|AADSTS51451|AADSTS51452|AADSTS51453|AADSTS51454|AADSTS51455|AADSTS51456|AADSTS51457|AADSTS51458|AADSTS51459|AADSTS51460|AADSTS51461|AADSTS51462|AADSTS51463|AADSTS51464|AADSTS51465|AADSTS51466|AADSTS51467|AADSTS51468|AADSTS51469|AADSTS51470|AADSTS51471|AADSTS51472|AADSTS51473|AADSTS51474|AADSTS51475|AADSTS51476|AADSTS51477|AADSTS51478|AADSTS51479|AADSTS51480|AADSTS51481|AADSTS51482|AADSTS51483|AADSTS51484|AADSTS51485|AADSTS51486|AADSTS51487|AADSTS51488|AADSTS51489|AADSTS51490|AADSTS51491|AADSTS51492|AADSTS51493|AADSTS51494|AADSTS51495|AADSTS51496|AADSTS51497|AADSTS51498|AADSTS51499|AADSTS51500|AADSTS51501|AADSTS51502|AADSTS51503|AADSTS51504|AADSTS51505|AADSTS51506|AADSTS51507|AADSTS51508|AADSTS51509|AADSTS51510|AADSTS51511|AADSTS51512|AADSTS51513|AADSTS51514|AADSTS51515|AADSTS51516|AADSTS51517|AADSTS51518|AADSTS51519|AADSTS51520|AADSTS51521|AADSTS51522|AADSTS51523|AADSTS51524|AADSTS51525|AADSTS51526|AADSTS51527|AADSTS51528|AADSTS51529|AADSTS51530|AADSTS51531|AADSTS51532|AADSTS51533|AADSTS51534|AADSTS51535|AADSTS51536|AADSTS51537|AADSTS51538|AADSTS51539|AADSTS51540|AADSTS51541|AADSTS51542|AADSTS51543|AADSTS51544|AADSTS51545|AADSTS51546|AADSTS51547|AADSTS51548|AADSTS51549|AADSTS51550|AADSTS51551|AADSTS51552|AADSTS51553|AADSTS51554|AADSTS51555|AADSTS51556|AADSTS51557|AADSTS51558|AADSTS51559|AADSTS51560|AADSTS51561|AADSTS51562|AADSTS51563|AADSTS51564|AADSTS51565|AADSTS51566|AADSTS51567|AADSTS51568|AADSTS51569|AADSTS51570|AADSTS51571|AADSTS51572|AADSTS51573|AADSTS51574|AADSTS51575|AADSTS51576|AADSTS51577|AADSTS51578|AADSTS51579|AADSTS51580|AADSTS51581|AADSTS51582|AADSTS51583|AADSTS51584|AADSTS51585|AADSTS51586|AADSTS51587|AADSTS51588|AADSTS51589|AADSTS51590|AADSTS51591|AADSTS51592|AADSTS51593|AADSTS51594|AADSTS51595|AADSTS51596|AADSTS51597|AADSTS51598|AADSTS51599|AADSTS51600|AADSTS51601|AADSTS51602|AADSTS51603|AADSTS51604|AADSTS51605|AADSTS51606|AADSTS51607|AADSTS51608|AADSTS51609|AADSTS51610|AADSTS51611|AADSTS51612|AADSTS51613|AADSTS51614|AADSTS51615|AADSTS51616|AADSTS51617|AADSTS51618|AADSTS51619|AADSTS51620|AADSTS51621|AADSTS51622|AADSTS51623|AADSTS51624|AADSTS51625|AADSTS51626|AADSTS51627|AADSTS51628|AADSTS51629|AADSTS51630|AADSTS51631|AADSTS51632|AADSTS51633|AADSTS51634|AADSTS51635|AADSTS51636|AADSTS51637|AADSTS51638|AADSTS51639|AADSTS51640|AADSTS51641|AADSTS51642|AADSTS51643|AADSTS51644|AADSTS51645|AADSTS51646|AADSTS51647|AADSTS51648|AADSTS51649|AADSTS51650|AADSTS51651|AADSTS51652|AADSTS51653|AADSTS51654|AADSTS51655|AADSTS51656|AADSTS51657|AADSTS51658|AADSTS51659|AADSTS51660|AADSTS51661|AADSTS51662|AADSTS51663|AADSTS51664|AADSTS51665|AADSTS51666|AADSTS51667|AADSTS51668|AADSTS51669|AADSTS51670|AADSTS51671|AADSTS51672|AADSTS51673|AADSTS51674|AADSTS51675|AADSTS51676|AADSTS51677|AADSTS51678|AADSTS51679|AADSTS51680|AADSTS51681|AADSTS51682|AADSTS51683|AADSTS51684|AADSTS51685|AADSTS51686|AADSTS51687|AADSTS51688|AADSTS51689|AADSTS51690|AADSTS51691|AADSTS51692|AADSTS51693|AADSTS51694|AADSTS51695|AADSTS51696|AADSTS51697|AADSTS51698|AADSTS51699|AADSTS51700|AADSTS51701|AADSTS51702|AADSTS51703|AADSTS51704|AADSTS51705|AADSTS51706|AADSTS51707|AADSTS51708|AADSTS51709|AADSTS51710|AADSTS51711|AADSTS51712|AADSTS51713|AADSTS51714|AADSTS51715|AADSTS51716|AADSTS51717|AADSTS51718|AADSTS51719|AADSTS51720|AADSTS51721|AADSTS51722|AADSTS51723|AADSTS51724|AADSTS51725|AADSTS51726|AADSTS51727|AADSTS51728|AADSTS51729|AADSTS51730|AADSTS51731|AADSTS51732|AADSTS51733|AADSTS51734|AADSTS51735|AADSTS51736|AADSTS51737|AADSTS51738|AADSTS51739|AADSTS51740|AADSTS51741|AADSTS51742|AADSTS51743|AADSTS51744|AADSTS51745|AADSTS51746|AADSTS51747|AADSTS51748|AADSTS51749|AADSTS51750|AADSTS51751|AADSTS51752|AADSTS51753|AADSTS51754|AADSTS51755|AADSTS51756|AADSTS51757|AADSTS51758|AADSTS51759|AADSTS51760|AADSTS51761|AADSTS51762|AADSTS51763|AADSTS51764|AADSTS51765|AADSTS51766|AADSTS51767|AADSTS51768|AADSTS51769|AADSTS51770|AADSTS51771|AADSTS51772|AADSTS51773|AADSTS51774|AADSTS51775|AADSTS51776|AADSTS51777|AADSTS51778|AADSTS51779|AADSTS51780|AADSTS51781|AADSTS51782|AADSTS51783|AADSTS51784|AADSTS51785|AADSTS51786|AADSTS51787|AADSTS51788|AADSTS51789|AADSTS51790|AADSTS51791|AADSTS51792|AADSTS51793|AADSTS51794|AADSTS51795|AADSTS51796|AADSTS51797|AADSTS51798|AADSTS51799|AADSTS51800|AADSTS51801|AADSTS51802|AADSTS51803|AADSTS51804|AADSTS51805|AADSTS51806|AADSTS51807|AADSTS51808|AADSTS51809|AADSTS51810|AADSTS51811|AADSTS51812|AADSTS51813|AADSTS51814|AADSTS51815|AADSTS51816|AADSTS51817|AADSTS51818|AADSTS51819|AADSTS51820|AADSTS51821|AADSTS51822|AADSTS51823|AADSTS51824|AADSTS51825|AADSTS51826|AADSTS51827|AADSTS51828|AADSTS51829|AADSTS51830|AADSTS51831|AADSTS51832|AADSTS51833|AADSTS51834|AADSTS51835|AADSTS51836|AADSTS51837|AADSTS51838|AADSTS51839|AADSTS51840|AADSTS51841|AADSTS51842|AADSTS51843|AADSTS51844|AADSTS51845|AADSTS51846|AADSTS51847|AADSTS51848|AADSTS51849|AADSTS51850|AADSTS51851|AADSTS51852|AADSTS51853|AADSTS51854|AADSTS51855|AADSTS51856|AADSTS51857|AADSTS51858|AADSTS51859|AADSTS51860|AADSTS51861|AADSTS51862|AADSTS51863|AADSTS51864|AADSTS51865|AADSTS51866|AADSTS51867|AADSTS51868|AADSTS51869|AADSTS51870|AADSTS51871|AADSTS51872|AADSTS51873|AADSTS51874|AADSTS51875|AADSTS51876|AADSTS51877|AADSTS51878|AADSTS51879|AADSTS51880|AADSTS51881|AADSTS51882|AADSTS51883|AADSTS51884|AADSTS51885|AADSTS51886|AADSTS51887|AADSTS51888|AADSTS51889|AADSTS51890|AADSTS51891|AADSTS51892|AADSTS51893|AADSTS51894|AADSTS51895|AADSTS51896|AADSTS51897|AADSTS51898|AADSTS51899|AADSTS51900|AADSTS51901|AADSTS51902|AADSTS51903|AADSTS51904|AADSTS51905|AADSTS51906|AADSTS51907|AADSTS51908|AADSTS51909|AADSTS51910|AADSTS51911|AADSTS51912|AADSTS51913|AADSTS51914|AADSTS51915|AADSTS51916|AADSTS51917|AADSTS51918|AADSTS51919|AADSTS51920|AADSTS51921|AADSTS51922|AADSTS51923|AADSTS51924|AADSTS51925|AADSTS51926|AADSTS51927|AADSTS51928|AADSTS51929|AADSTS51930|AADSTS51931|AADSTS51932|AADSTS51933|AADSTS51934|AADSTS51935|AADSTS51936|AADSTS51937|AADSTS51938|AADSTS51939|AADSTS51940|AADSTS51941|AADSTS51942|AADSTS51943|AADSTS51944|AADSTS51945|AADSTS51946|AADSTS51947|AADSTS51948|AADSTS51949|AADSTS51950|AADSTS51951|AADSTS51952|AADSTS51953|AADSTS51954|AADSTS51955|AADSTS51956|AADSTS51957|AADSTS51958|AADSTS51959|AADSTS51960|AADSTS51961|AADSTS51962|AADSTS51963|AADSTS51964|AADSTS51965|AADSTS51966|AADSTS51967|AADSTS51968|AADSTS51969|AADSTS51970|AADSTS51971|AADSTS51972|AADSTS51973|AADSTS51974|AADSTS51975|AADSTS51976|AADSTS51977|AADSTS51978|AADSTS51979|AADSTS51980|AADSTS51981|AADSTS51982|AADSTS51983|AADSTS51984|AADSTS51985|AADSTS51986|AADSTS51987|AADSTS51988|AADSTS51989|AADSTS51990|AADSTS51991|AADSTS51992|AADSTS51993|AADSTS51994|AADSTS51995|AADSTS51996|AADSTS51997|AADSTS51998|AADSTS51999") {
        Write-Host "  Cause: Conditional Access policy or other Azure AD policy is blocking ROPC or this sign-in." -ForegroundColor Yellow
        Write-Host "  Action: Review Azure AD sign-in logs and Conditional Access policies." -ForegroundColor Yellow
        $diagnosed = $true
    }

    if (-not $diagnosed) {
        Write-Host "  Cause: Unknown. See error details above and Azure AD sign-in logs for more information." -ForegroundColor Yellow
    }
    exit 1
}

$accessToken = $tokenResult.AccessToken

# Step 2: Test Autodiscover JSON
$autodiscoverResult = Test-AutodiscoverJson -EmailAddress $EmailAddress -AccessToken $accessToken -ServerFqdn $ExchangeServer
$script:TestResults.AutodiscoverJson = $autodiscoverResult

# Step 3: Test ActiveSync
$activeSyncUrl = if ($autodiscoverResult.Success -and $autodiscoverResult.ActiveSyncUrl) {
    $autodiscoverResult.ActiveSyncUrl
} else {
    "https://$ExchangeServer/Microsoft-Server-ActiveSync"
}

$optionsResult = Test-ActiveSyncOptions -ActiveSyncUrl $activeSyncUrl -AccessToken $accessToken
$script:TestResults.ActiveSync = $optionsResult

if ($optionsResult.Success) {
    # Step 4: Try FolderSync to confirm full auth flow
    $folderSyncResult = Test-ActiveSyncFolderSync -ActiveSyncUrl $activeSyncUrl -AccessToken $accessToken -EmailAddress $EmailAddress
    $script:TestResults.FolderSync = $folderSyncResult
} else {
    $folderSyncResult = @{ Success = $false; Skipped = $true }
}

# Summary
Write-Host "`n" -NoNewline
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  TEST SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$allSuccess = $true

Write-Host "`n"
Write-Log "===== TEST SUMMARY =====" -Level "INFO"

if ($tokenResult.Success) {
    Write-Host '[PASS] ' -NoNewline -ForegroundColor Green
    Write-Host 'OAuth Token Acquisition'
    Write-Log '[PASS] OAuth Token Acquisition' -Level 'INFO'
} else {
    Write-Host '[FAIL] ' -NoNewline -ForegroundColor Red
    Write-Host 'OAuth Token Acquisition'
    Write-Log '[FAIL] OAuth Token Acquisition' -Level 'ERROR'
    $allSuccess = $false
}

if ($autodiscoverResult.Success) {
    Write-Host '[PASS] ' -NoNewline -ForegroundColor Green
    Write-Host "Autodiscover JSON ($($autodiscoverResult.Url))"
    $logMsg = '[PASS] Autodiscover JSON - ' + $autodiscoverResult.Url
    Write-Log $logMsg -Level "INFO"
} else {
    Write-Host '[FAIL] ' -NoNewline -ForegroundColor Red
    Write-Host 'Autodiscover JSON'
    Write-Log '[FAIL] Autodiscover JSON' -Level "ERROR"
    $allSuccess = $false
}

if ($optionsResult.Success) {
    Write-Host '[PASS] ' -NoNewline -ForegroundColor Green
    Write-Host 'ActiveSync OPTIONS'
    Write-Log '[PASS] ActiveSync OPTIONS' -Level 'INFO'
} else {
    Write-Host '[FAIL] ' -NoNewline -ForegroundColor Red
    Write-Host 'ActiveSync OPTIONS'
    Write-Log '[FAIL] ActiveSync OPTIONS' -Level 'ERROR'
    $allSuccess = $false
}

if ($folderSyncResult -and -not $folderSyncResult.Skipped) {
    if ($folderSyncResult.Success) {
        Write-Host '[PASS] ' -NoNewline -ForegroundColor Green
        Write-Host 'ActiveSync FolderSync'
        Write-Log '[PASS] ActiveSync FolderSync' -Level "INFO"
    } else {
        Write-Host '[WARN] ' -NoNewline -ForegroundColor Yellow
        Write-Host 'ActiveSync FolderSync (OPTIONS passed, FolderSync failed)'
        Write-Log '[WARN] ActiveSync FolderSync failed but OPTIONS succeeded' -Level "WARN"
    }
}

Write-Host "`n"
if ($allSuccess) {
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "  ALL TESTS PASSED - HMA is working correctly" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Log "OVERALL RESULT: ALL TESTS PASSED" -Level "INFO"
} else {
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "  SOME TESTS FAILED - Review output above for details" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Log "OVERALL RESULT: SOME TESTS FAILED" -Level "ERROR"
}

# Save log file
if ($OutputPath) {
    $logFile = $OutputPath
} else {
    $dateStr = Get-Date -Format "yyyyMMdd-HHmmss"
    $logFile = ".\HmaTest-$dateStr.log"
}

try {
    $script:LogOutput | Out-File -FilePath $logFile -Encoding UTF8
    Write-Host "`nDetailed log saved to: $logFile" -ForegroundColor Cyan
}
catch {
    Write-Host "`nFailed to save log file: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "`nTip: Run with -Verbose for detailed request/response output during execution.`n" -ForegroundColor Gray
#endregion

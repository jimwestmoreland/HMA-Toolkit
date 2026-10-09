<#
.SYNOPSIS
    Confirms whether a specific user can complete the Exchange Hybrid Modern Authentication path.

.DESCRIPTION
    This script validates the user-specific HMA sequence instead of only proving that
    Exchange ActiveSync is reachable. It checks Exchange configuration when run from
    Exchange Management Shell, acquires an OAuth token as the target user, calls
    Autodiscover JSON with a bearer token, then calls ActiveSync with the bearer token.

    A passing result confirms that the user can use HMA for ActiveSync. To prove that
    a particular already-enrolled device is currently using HMA, correlate the script
    timestamp with Microsoft Entra sign-in logs and Exchange HttpProxy/IIS logs.

.PARAMETER EmailAddress
    SMTP address of the mailbox to validate.

.PARAMETER ExchangeServer
    Public FQDN for the on-premises Exchange namespace, for example mail.contoso.com.
    If omitted, the script tries autodiscover.<domain> and <domain>.

.PARAMETER UseDeviceCode
    Uses OAuth device-code flow. This is recommended because it supports MFA and is
    closest to an interactive modern-auth sign-in.

.PARAMETER TenantId
    Tenant ID, tenant primary domain, or common. Use the tenant domain/GUID when possible.

.PARAMETER Credential
    Optional credential for ROPC/password flow. ROPC does not support MFA and is often
    blocked by Conditional Access. Prefer -UseDeviceCode.

.PARAMETER OutputPath
    Optional path for the full debug log.

.PARAMETER SkipCertificateCheck
    Bypasses TLS certificate validation for lab testing only.

.EXAMPLE
    .\Confirm-HmaUsageForUser.ps1 -EmailAddress user@contoso.com -ExchangeServer mail.contoso.com -TenantId contoso.onmicrosoft.com -UseDeviceCode -Verbose

.EXAMPLE
    .\Confirm-HmaUsageForUser.ps1 -EmailAddress user@contoso.com -ExchangeServer mail.contoso.com -OutputPath C:\Logs\hma-user-check.log -Verbose
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string]$EmailAddress,

    [Parameter(Mandatory = $false)]
    [string]$ExchangeServer,

    [Parameter(Mandatory = $false)]
    [string]$TenantId = "common",

    [Parameter(Mandatory = $false)]
    [switch]$UseDeviceCode,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$SkipCertificateCheck
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
[System.Net.ServicePointManager]::Expect100Continue = $false
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

$script:LogOutput = New-Object System.Collections.Generic.List[string]
$script:CheckResults = New-Object System.Collections.Generic.List[object]
$script:FlowEvents = New-Object System.Collections.Generic.List[string]
$script:ClientId = "27922004-5251-4030-b22d-91ecd9a37ea4" # Outlook Mobile

function Write-HmaLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet("INFO", "PASS", "WARN", "ERROR", "DEBUG", "REQUEST", "RESPONSE")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $line = "[${timestamp}] [${Level}] $Message"
    $script:LogOutput.Add($line) | Out-Null

    $show = $VerbosePreference -eq "Continue" -or $Level -in @("PASS", "WARN", "ERROR", "INFO")
    if ($show) {
        $color = switch ($Level) {
            "PASS" { "Green" }
            "WARN" { "Yellow" }
            "ERROR" { "Red" }
            "DEBUG" { "DarkGray" }
            "REQUEST" { "DarkMagenta" }
            "RESPONSE" { "DarkCyan" }
            default { "Gray" }
        }
        Write-Host $line -ForegroundColor $color
    }
}

function Add-HmaCheck {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [ValidateSet("Pass", "Warn", "Fail", "Info", "Skipped")]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$Detail
    )

    $script:CheckResults.Add([pscustomobject]@{
        Name = $Name
        Status = $Status
        Detail = $Detail
    }) | Out-Null

    $level = switch ($Status) {
        "Pass" { "PASS" }
        "Fail" { "ERROR" }
        "Warn" { "WARN" }
        default { "INFO" }
    }
    Write-HmaLog "$Name - $Status - $Detail" -Level $level
}

function Save-HmaLog {
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        return
    }

    $parent = Split-Path -Parent $OutputPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }
    $script:LogOutput | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    Write-Host "Full debug log saved to $OutputPath" -ForegroundColor Cyan
}

function Enable-HmaCertificateBypass {
    if (-not $SkipCertificateCheck) {
        return
    }

    if ($PSVersionTable.PSVersion.Major -ge 6) {
        return
    }

    $certPolicyCode = @'
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
        return true;
    }
}
'@
    Add-Type -TypeDefinition $certPolicyCode -ErrorAction SilentlyContinue
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    Write-HmaLog "TLS certificate validation bypass enabled for this process." -Level "WARN"
}

function ConvertFrom-HmaJwtPayload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )

    $parts = $AccessToken.Split(".")
    if ($parts.Count -lt 2) {
        throw "Access token is not a JWT with header and payload segments."
    }

    $payload = $parts[1].Replace("-", "+").Replace("_", "/")
    $padding = 4 - ($payload.Length % 4)
    if ($padding -lt 4) {
        $payload += "=" * $padding
    }

    $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
    return $json | ConvertFrom-Json
}

function Assert-HmaTokenResponse {
    param(
        [AllowNull()]
        [object]$Response,

        [Parameter(Mandatory = $true)]
        [string]$TokenEndpoint
    )

    $responseType = if ($null -eq $Response) { "null" } else { $Response.GetType().FullName }
    if ($Response -isnot [System.Collections.IDictionary] -and $Response -isnot [PSCustomObject]) {
        throw "Invalid OAuth token response from $TokenEndpoint (response type: $responseType). Expected a JSON object containing access_token, token_type, and expires_in."
    }

    if ($Response.error) {
        throw "OAuth token endpoint returned an error: $($Response.error): $($Response.error_description)"
    }

    $invalid = @()
    if ($Response.access_token -isnot [string] -or [string]::IsNullOrWhiteSpace($Response.access_token)) {
        $invalid += "access_token"
    }
    if ($Response.token_type -isnot [string] -or $Response.token_type -ine "Bearer") {
        $invalid += "token_type expected Bearer"
    }
    $expiresIn = 0L
    if (-not [long]::TryParse([string]$Response.expires_in, [ref]$expiresIn) -or $expiresIn -le 0) {
        $invalid += "expires_in expected positive seconds"
    }

    if ($invalid.Count -gt 0) {
        throw "Invalid OAuth token response from $TokenEndpoint (response type: $responseType). Missing or invalid fields: $($invalid -join ', '). Raw response omitted to protect credentials and tokens."
    }
}

function Get-HmaResponseHeader {
    param(
        [Parameter(Mandatory = $true)]
        $Headers,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    foreach ($key in $Headers.Keys) {
        if ($key -ieq $Name) {
            $value = $Headers[$key]
            if ($value -is [array]) {
                return ($value -join "; ")
            }
            return [string]$value
        }
    }
    return $null
}

function Write-HmaRequestLog {
    param(
        [string]$Method,
        [string]$Uri,
        [hashtable]$Headers,
        [string]$Body
    )

    Write-HmaLog "HTTP request: $Method $Uri" -Level "REQUEST"
    foreach ($key in $Headers.Keys) {
        $value = if ($key -ieq "Authorization") { "Bearer <redacted>" } else { [string]$Headers[$key] }
        Write-HmaLog "  ${key}: $value" -Level "REQUEST"
    }
    if ($Body) {
        Write-HmaLog "  Body: $Body" -Level "REQUEST"
    }
}

function Write-HmaResponseLog {
    param(
        [int]$StatusCode,
        [string]$StatusDescription,
        $Headers,
        [string]$Content
    )

    Write-HmaLog "HTTP response: $StatusCode $StatusDescription" -Level "RESPONSE"
    if ($Headers) {
        foreach ($key in $Headers.Keys) {
            Write-HmaLog "  ${key}: $($Headers[$key])" -Level "RESPONSE"
        }
    }
    if ($Content) {
        $body = if ($Content.Length -gt 2000) { $Content.Substring(0, 2000) + "..." } else { $Content }
        Write-HmaLog "  Body: $body" -Level "RESPONSE"
    }
}

function Invoke-HmaWebRequest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$Method,

        [hashtable]$Headers = @{},

        [string]$Body,

        [string]$ContentType
    )

    Write-HmaRequestLog -Method $Method -Uri $Uri -Headers $Headers -Body $Body

    $invokeParams = @{
        Uri = $Uri
        Method = $Method
        Headers = $Headers
        ErrorAction = "Stop"
        UseBasicParsing = $true
    }
    if ($Body) {
        $invokeParams.Body = $Body
    }
    if ($ContentType) {
        $invokeParams.ContentType = $ContentType
    }
    if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -ge 6) {
        $invokeParams.SkipCertificateCheck = $true
    }

    try {
        $response = Invoke-WebRequest @invokeParams
        Write-HmaResponseLog -StatusCode ([int]$response.StatusCode) -StatusDescription $response.StatusDescription -Headers $response.Headers -Content $response.Content
        return @{
            Success = $true
            StatusCode = [int]$response.StatusCode
            Headers = $response.Headers
            Content = $response.Content
            Raw = $response
        }
    }
    catch {
        $statusCode = $null
        $headers = $null
        $content = $null

        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            $headers = $_.Exception.Response.Headers
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                if ($stream) {
                    $reader = New-Object System.IO.StreamReader($stream)
                    $content = $reader.ReadToEnd()
                }
            }
            catch {
                Write-HmaLog "Could not read error response body: $($_.Exception.Message)" -Level "DEBUG"
            }
        }

        Write-HmaLog "HTTP request failed: $($_.Exception.Message)" -Level "ERROR"
        if ($statusCode) {
            Write-HmaResponseLog -StatusCode $statusCode -StatusDescription "Error" -Headers $headers -Content $content
        }

        return @{
            Success = $false
            StatusCode = $statusCode
            Headers = $headers
            Content = $content
            Error = $_.Exception.Message
        }
    }
}

function Get-HmaOAuthTokenPassword {
    param(
        [string]$Resource,
        [PSCredential]$CredentialToUse
    )

    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/token"
    $body = @{
        grant_type = "password"
        client_id = $script:ClientId
        resource = $Resource
        username = $CredentialToUse.UserName
        password = $CredentialToUse.GetNetworkCredential().Password
        scope = "openid"
    }

    Write-HmaLog "Requesting token by ROPC for resource $Resource. ROPC fails for MFA and is commonly blocked by Conditional Access." -Level "WARN"
    $response = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
    Assert-HmaTokenResponse -Response $response -TokenEndpoint $tokenEndpoint
    return $response
}

function Get-HmaOAuthTokenDeviceCode {
    param(
        [string]$Resource
    )

    $deviceCodeEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/devicecode"
    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/token"
    $deviceBody = @{
        client_id = $script:ClientId
        resource = $Resource
    }

    Write-HmaLog "Requesting device code for resource $Resource." -Level "INFO"
    $device = Invoke-RestMethod -Uri $deviceCodeEndpoint -Method POST -Body $deviceBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
    Write-Host ""
    Write-Host $device.message -ForegroundColor Cyan
    Write-Host ""

    $deadline = (Get-Date).AddSeconds([int]$device.expires_in)
    $interval = [Math]::Max([int]$device.interval, 5)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval
        $tokenBody = @{
            grant_type = "urn:ietf:params:oauth:grant-type:device_code"
            client_id = $script:ClientId
            code = $device.device_code
        }

        try {
            $token = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
            Assert-HmaTokenResponse -Response $token -TokenEndpoint $tokenEndpoint
            return $token
        }
        catch {
            $errorBody = $null
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                $errorBody = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
            }
            if ($errorBody -and $errorBody.error -eq "authorization_pending") {
                Write-HmaLog "Device authorization pending; polling again." -Level "DEBUG"
                continue
            }
            if ($errorBody -and $errorBody.error -eq "slow_down") {
                $interval += 5
                Write-HmaLog "Device endpoint asked polling to slow down; interval now $interval seconds." -Level "DEBUG"
                continue
            }
            $message = if ($errorBody) { "$($errorBody.error): $($errorBody.error_description)" } else { $_.Exception.Message }
            throw "Device-code token acquisition failed: $message"
        }
    }

    throw "Timed out waiting for device-code authentication."
}

function Get-HmaOAuthToken {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ResourcesToTry
    )

    foreach ($resource in $ResourcesToTry) {
        try {
            $token = if ($UseDeviceCode) {
                Get-HmaOAuthTokenDeviceCode -Resource $resource
            } else {
                if (-not $Credential) {
                    $Credential = Get-Credential -UserName $EmailAddress -Message "Enter password for $EmailAddress"
                }
                Get-HmaOAuthTokenPassword -Resource $resource -CredentialToUse $Credential
            }

            $claims = ConvertFrom-HmaJwtPayload -AccessToken $token.access_token
            Add-HmaCheck -Name "OAuth token acquisition" -Status "Pass" -Detail "Token issued for resource $resource; token_type=$($token.token_type); expires_in=$($token.expires_in)."
            Write-HmaLog "Token claims: aud=$($claims.aud); appid=$($claims.appid); upn=$($claims.upn); preferred_username=$($claims.preferred_username); amr=$($claims.amr -join ','); exp=$($claims.exp)" -Level "DEBUG"
            $script:FlowEvents.Add("User acquired a Bearer OAuth access token as Outlook Mobile client ID $script:ClientId for resource $resource.") | Out-Null
            return @{
                Success = $true
                AccessToken = $token.access_token
                Resource = $resource
                Claims = $claims
                Raw = $token
            }
        }
        catch {
            Add-HmaCheck -Name "OAuth token acquisition for $resource" -Status "Warn" -Detail $_.Exception.Message
        }
    }

    Add-HmaCheck -Name "OAuth token acquisition" -Status "Fail" -Detail "No attempted resource returned a valid Bearer token."
    return @{ Success = $false }
}

function Resolve-HmaExchangeServer {
    if ($ExchangeServer) {
        return $ExchangeServer.Trim().TrimEnd("/")
    }

    $domain = $EmailAddress.Split("@")[1]
    $candidates = @("autodiscover.$domain", $domain)
    foreach ($candidate in $candidates) {
        try {
            Resolve-DnsName -Name $candidate -Type A -ErrorAction Stop | Out-Null
            Add-HmaCheck -Name "Exchange namespace discovery" -Status "Info" -Detail "Using $candidate from DNS."
            return $candidate
        }
        catch {
            Write-HmaLog "Could not resolve ${candidate}: $($_.Exception.Message)" -Level "DEBUG"
        }
    }

    Add-HmaCheck -Name "Exchange namespace discovery" -Status "Fail" -Detail "Could not resolve autodiscover or root domain. Re-run with -ExchangeServer."
    return $null
}

function Test-HmaExchangeConfiguration {
    Write-HmaLog "Checking Exchange Management Shell configuration if cmdlets are available." -Level "INFO"

    if (-not (Get-Command Get-OrganizationConfig -ErrorAction SilentlyContinue)) {
        Add-HmaCheck -Name "Exchange configuration checks" -Status "Skipped" -Detail "Exchange cmdlets not available in this PowerShell session."
        return
    }

    $org = Get-OrganizationConfig
    if ($org.OAuth2ClientProfileEnabled -eq $true) {
        Add-HmaCheck -Name "Organization OAuth2ClientProfileEnabled" -Status "Pass" -Detail "OAuth2ClientProfileEnabled is True."
    } else {
        Add-HmaCheck -Name "Organization OAuth2ClientProfileEnabled" -Status "Fail" -Detail "OAuth2ClientProfileEnabled is False. HMA is disabled for Exchange clients."
    }

    $authServers = Get-AuthServer -ErrorAction Stop | Where-Object { $_.Name -like "*EvoSts*" -or $_.Type -eq "AzureAD" }
    if (-not $authServers) {
        Add-HmaCheck -Name "EvoSTS AuthServer" -Status "Fail" -Detail "No EvoSTS/AzureAD AuthServer found."
    } else {
        foreach ($authServer in $authServers) {
            $status = if ($authServer.Enabled -and $authServer.IsDefaultAuthorizationEndpoint) { "Pass" } elseif ($authServer.Enabled) { "Warn" } else { "Fail" }
            Add-HmaCheck -Name "EvoSTS AuthServer $($authServer.Name)" -Status $status -Detail "Enabled=$($authServer.Enabled); IsDefaultAuthorizationEndpoint=$($authServer.IsDefaultAuthorizationEndpoint); TokenIssuingEndpoint=$($authServer.TokenIssuingEndpoint)."
        }
    }

    $mailbox = Get-Mailbox -Identity $EmailAddress -ErrorAction Stop
    Add-HmaCheck -Name "Target mailbox" -Status "Info" -Detail "RecipientTypeDetails=$($mailbox.RecipientTypeDetails); Database=$($mailbox.Database); AuthenticationPolicy=$($mailbox.AuthenticationPolicy)."

    $casMailbox = Get-CASMailbox -Identity $EmailAddress -ErrorAction Stop
    if ($casMailbox.ActiveSyncEnabled -eq $true) {
        Add-HmaCheck -Name "User ActiveSync" -Status "Pass" -Detail "ActiveSyncEnabled=True for $EmailAddress."
    } else {
        Add-HmaCheck -Name "User ActiveSync" -Status "Fail" -Detail "ActiveSyncEnabled=False for $EmailAddress."
    }

    $policyName = $mailbox.AuthenticationPolicy
    if (-not $policyName -and $org.PSObject.Properties.Name -contains "DefaultAuthenticationPolicy") {
        $policyName = $org.DefaultAuthenticationPolicy
    }

    if ($policyName) {
        $policy = Get-AuthenticationPolicy -Identity $policyName -ErrorAction Stop
        if ($policy.BlockModernAuthActiveSync -eq $true) {
            Add-HmaCheck -Name "Authentication policy ActiveSync modern auth" -Status "Fail" -Detail "$policyName blocks Modern Auth for ActiveSync."
        } else {
            Add-HmaCheck -Name "Authentication policy ActiveSync modern auth" -Status "Pass" -Detail "$policyName does not block Modern Auth for ActiveSync."
        }
    } else {
        Add-HmaCheck -Name "Authentication policy ActiveSync modern auth" -Status "Info" -Detail "No user/default authentication policy found; Modern Auth is not blocked by policy."
    }

    $asVdirs = Get-ActiveSyncVirtualDirectory -ErrorAction Stop
    foreach ($vdir in $asVdirs) {
        $status = if ($vdir.PSObject.Properties.Name -contains "OAuthAuthentication" -and $vdir.OAuthAuthentication -eq $true) { "Pass" } else { "Warn" }
        Add-HmaCheck -Name "ActiveSync vDir OAuth $($vdir.Server)\$($vdir.Name)" -Status $status -Detail "OAuthAuthentication=$($vdir.OAuthAuthentication); InternalUrl=$($vdir.InternalUrl); ExternalUrl=$($vdir.ExternalUrl)."
    }

    $adVdirs = Get-AutodiscoverVirtualDirectory -ErrorAction Stop
    foreach ($vdir in $adVdirs) {
        $status = if ($vdir.PSObject.Properties.Name -contains "OAuthAuthentication" -and $vdir.OAuthAuthentication -eq $true) { "Pass" } else { "Warn" }
        Add-HmaCheck -Name "Autodiscover vDir OAuth $($vdir.Server)\$($vdir.Name)" -Status $status -Detail "OAuthAuthentication=$($vdir.OAuthAuthentication); InternalUrl=$($vdir.InternalUrl); ExternalUrl=$($vdir.ExternalUrl)."
    }
}

function Test-HmaAutodiscoverJson {
    param(
        [string]$ServerFqdn,
        [string]$AccessToken
    )

    $encodedEmail = [System.Uri]::EscapeDataString($EmailAddress)
    $domain = $EmailAddress.Split("@")[1]
    $urls = New-Object System.Collections.Generic.List[string]
    if ($ServerFqdn) {
        $urls.Add("https://$ServerFqdn/autodiscover/autodiscover.json?Email=$encodedEmail&Protocol=activesync")
    }
    $urls.Add("https://autodiscover.$domain/autodiscover/autodiscover.json?Email=$encodedEmail&Protocol=activesync")
    $urls.Add("https://$domain/autodiscover/autodiscover.json?Email=$encodedEmail&Protocol=activesync")

    $headers = @{
        Authorization = "Bearer $AccessToken"
        "User-Agent" = "Confirm-HmaUsageForUser/1.0"
        Accept = "application/json"
    }

    foreach ($url in ($urls | Select-Object -Unique)) {
        $response = Invoke-HmaWebRequest -Uri $url -Method "GET" -Headers $headers
        if ($response.Success) {
            try {
                $json = $response.Content | ConvertFrom-Json
            }
            catch {
                Add-HmaCheck -Name "Autodiscover JSON response" -Status "Warn" -Detail "Response from $url was HTTP $($response.StatusCode) but not valid JSON: $($_.Exception.Message)"
                continue
            }

            if ($json.Protocol -ieq "ActiveSync" -and $json.Url) {
                Add-HmaCheck -Name "Autodiscover JSON with Bearer token" -Status "Pass" -Detail "Returned ActiveSync URL $($json.Url)."
                $script:FlowEvents.Add("Autodiscover JSON accepted the Bearer token and returned ActiveSync endpoint $($json.Url).") | Out-Null
                return @{
                    Success = $true
                    ActiveSyncUrl = $json.Url
                    Url = $url
                    Response = $json
                }
            }

            Add-HmaCheck -Name "Autodiscover JSON with Bearer token" -Status "Warn" -Detail "HTTP $($response.StatusCode) from $url, but response did not include Protocol=ActiveSync and Url."
        } else {
            $wwwAuth = Get-HmaResponseHeader -Headers $response.Headers -Name "WWW-Authenticate"
            if ($wwwAuth -match "Bearer") {
                Add-HmaCheck -Name "Autodiscover Bearer challenge" -Status "Info" -Detail "$url returned Bearer challenge: $wwwAuth"
            } else {
                Add-HmaCheck -Name "Autodiscover JSON with Bearer token" -Status "Warn" -Detail "$url failed with HTTP $($response.StatusCode): $($response.Error)"
            }
        }
    }

    Add-HmaCheck -Name "Autodiscover JSON with Bearer token" -Status "Fail" -Detail "No Autodiscover JSON endpoint returned an ActiveSync URL for this user."
    return @{ Success = $false }
}

function Test-HmaActiveSyncOptions {
    param(
        [string]$ActiveSyncUrl,
        [string]$AccessToken
    )

    $headers = @{
        Authorization = "Bearer $AccessToken"
        "User-Agent" = "Confirm-HmaUsageForUser/1.0"
    }

    $response = Invoke-HmaWebRequest -Uri $ActiveSyncUrl -Method "OPTIONS" -Headers $headers
    if ($response.Success) {
        $protocolVersions = Get-HmaResponseHeader -Headers $response.Headers -Name "MS-ASProtocolVersions"
        $commands = Get-HmaResponseHeader -Headers $response.Headers -Name "MS-ASProtocolCommands"
        Add-HmaCheck -Name "ActiveSync OPTIONS with Bearer token" -Status "Pass" -Detail "HTTP $($response.StatusCode). MS-ASProtocolVersions=$protocolVersions; MS-ASProtocolCommands=$commands."
        $script:FlowEvents.Add("ActiveSync OPTIONS accepted the Bearer token and returned protocol versions: $protocolVersions.") | Out-Null
        return @{
            Success = $true
            StatusCode = $response.StatusCode
            Headers = $response.Headers
        }
    }

    $wwwAuth = Get-HmaResponseHeader -Headers $response.Headers -Name "WWW-Authenticate"
    if ($response.StatusCode -eq 401 -and $wwwAuth -match "Bearer") {
        Add-HmaCheck -Name "ActiveSync OPTIONS with Bearer token" -Status "Fail" -Detail "Token was rejected, but ActiveSync advertised Bearer. Check token audience, EvoSTS, SPNs, and vDir OAuth. WWW-Authenticate=$wwwAuth"
    } elseif ($response.StatusCode -eq 401) {
        Add-HmaCheck -Name "ActiveSync OPTIONS with Bearer token" -Status "Fail" -Detail "HTTP 401 without Bearer challenge. OAuth may not be enabled or a device in front of Exchange may be answering."
    } else {
        Add-HmaCheck -Name "ActiveSync OPTIONS with Bearer token" -Status "Fail" -Detail "HTTP $($response.StatusCode): $($response.Error)"
    }

    return @{ Success = $false; StatusCode = $response.StatusCode; Headers = $response.Headers }
}

function Test-HmaActiveSyncFolderSync {
    param(
        [string]$ActiveSyncUrl,
        [string]$AccessToken
    )

    $deviceId = "HMAValidate" + (Get-Date -Format "yyyyMMddHHmmss")
    $separator = if ($ActiveSyncUrl -match "\?") { "&" } else { "?" }
    $folderSyncUrl = "$ActiveSyncUrl${separator}Cmd=FolderSync&User=$([System.Uri]::EscapeDataString($EmailAddress))&DeviceId=$deviceId&DeviceType=HMAValidator"
    $body = '<?xml version="1.0" encoding="utf-8"?><FolderSync xmlns="FolderHierarchy:"><SyncKey>0</SyncKey></FolderSync>'
    $headers = @{
        Authorization = "Bearer $AccessToken"
        "User-Agent" = "Confirm-HmaUsageForUser/1.0"
        "Content-Type" = "application/vnd.ms-sync.wbxml"
        "MS-ASProtocolVersion" = "16.1"
    }

    $response = Invoke-HmaWebRequest -Uri $folderSyncUrl -Method "POST" -Headers $headers -Body $body -ContentType "application/vnd.ms-sync.wbxml"
    if ($response.Success) {
        Add-HmaCheck -Name "ActiveSync FolderSync with Bearer token" -Status "Pass" -Detail "HTTP $($response.StatusCode). Bearer token was accepted at command level."
        $script:FlowEvents.Add("ActiveSync FolderSync accepted the Bearer token at command level.") | Out-Null
        return @{ Success = $true; StatusCode = $response.StatusCode }
    }

    if ($response.StatusCode -eq 449) {
        Add-HmaCheck -Name "ActiveSync FolderSync with Bearer token" -Status "Pass" -Detail "HTTP 449 device provisioning required. This is expected for a synthetic device and confirms OAuth reached ActiveSync command processing."
        $script:FlowEvents.Add("ActiveSync FolderSync reached command processing and returned 449 provisioning required, which is expected for a synthetic device.") | Out-Null
        return @{ Success = $true; StatusCode = 449; NeedsProvisioning = $true }
    }

    if ($response.StatusCode -eq 401) {
        Add-HmaCheck -Name "ActiveSync FolderSync with Bearer token" -Status "Fail" -Detail "HTTP 401. Token was rejected at ActiveSync command level."
    } else {
        Add-HmaCheck -Name "ActiveSync FolderSync with Bearer token" -Status "Warn" -Detail "HTTP $($response.StatusCode): $($response.Error)"
    }

    return @{ Success = $false; StatusCode = $response.StatusCode }
}

function Write-HmaFinalSummary {
    param(
        [bool]$TokenSucceeded,
        [bool]$AutodiscoverSucceeded,
        [bool]$OptionsSucceeded,
        [bool]$FolderSyncSucceeded
    )

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  HMA USER VALIDATION SUMMARY" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $failedConfig = @($script:CheckResults | Where-Object { $_.Status -eq "Fail" -and $_.Name -notmatch "OAuth token acquisition for " })
    $result = if ($TokenSucceeded -and $AutodiscoverSucceeded -and $OptionsSucceeded -and $FolderSyncSucceeded -and $failedConfig.Count -eq 0) {
        "CONFIRMED: This user can complete the HMA ActiveSync sequence."
    } elseif ($TokenSucceeded -and $AutodiscoverSucceeded -and $OptionsSucceeded) {
        "PARTIAL CONFIRMATION: Token, Autodiscover, and ActiveSync OPTIONS worked, but FolderSync did not fully validate."
    } else {
        "NOT CONFIRMED: The HMA sequence did not complete for this user."
    }

    Write-Host $result -ForegroundColor $(if ($result -like "CONFIRMED*") { "Green" } elseif ($result -like "PARTIAL*") { "Yellow" } else { "Red" })
    Write-HmaLog $result -Level "INFO"

    Write-Host ""
    Write-Host "Observed working sequence:" -ForegroundColor White
    if ($script:FlowEvents.Count -gt 0) {
        $i = 1
        foreach ($event in $script:FlowEvents) {
            Write-Host "  $i. $event" -ForegroundColor Gray
            $i++
        }
    } else {
        Write-Host "  No successful HMA flow events were observed." -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "Important interpretation:" -ForegroundColor White
    Write-Host "  This script validates the user-specific HMA path by performing an OAuth/Bearer flow as the user." -ForegroundColor Gray
    Write-Host "  To prove a particular existing phone is currently using HMA, correlate this user's recent Entra sign-ins and Exchange HttpProxy/IIS ActiveSync logs around the device sync time." -ForegroundColor Gray
}

try {
    Enable-HmaCertificateBypass

    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Confirm HMA Usage For User" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "User: $EmailAddress" -ForegroundColor White
    Write-Host "Tenant: $TenantId" -ForegroundColor White
    Write-Host "Mode: $(if ($UseDeviceCode) { 'Device Code' } else { 'ROPC/password' })" -ForegroundColor White
    Write-Host ""

    Test-HmaExchangeConfiguration

    $resolvedServer = Resolve-HmaExchangeServer
    if (-not $resolvedServer) {
        Write-HmaFinalSummary -TokenSucceeded $false -AutodiscoverSucceeded $false -OptionsSucceeded $false -FolderSyncSucceeded $false
        Save-HmaLog
        exit 1
    }

    $resources = @(
        "https://$resolvedServer",
        "https://$resolvedServer/",
        "https://outlook.office365.com"
    ) | Select-Object -Unique

    $tokenResult = Get-HmaOAuthToken -ResourcesToTry $resources
    if (-not $tokenResult.Success) {
        Write-HmaFinalSummary -TokenSucceeded $false -AutodiscoverSucceeded $false -OptionsSucceeded $false -FolderSyncSucceeded $false
        Save-HmaLog
        exit 1
    }

    $autodiscover = Test-HmaAutodiscoverJson -ServerFqdn $resolvedServer -AccessToken $tokenResult.AccessToken
    if (-not $autodiscover.Success) {
        Write-HmaFinalSummary -TokenSucceeded $true -AutodiscoverSucceeded $false -OptionsSucceeded $false -FolderSyncSucceeded $false
        Save-HmaLog
        exit 1
    }

    $options = Test-HmaActiveSyncOptions -ActiveSyncUrl $autodiscover.ActiveSyncUrl -AccessToken $tokenResult.AccessToken
    if (-not $options.Success) {
        Write-HmaFinalSummary -TokenSucceeded $true -AutodiscoverSucceeded $true -OptionsSucceeded $false -FolderSyncSucceeded $false
        Save-HmaLog
        exit 1
    }

    $folderSync = Test-HmaActiveSyncFolderSync -ActiveSyncUrl $autodiscover.ActiveSyncUrl -AccessToken $tokenResult.AccessToken
    Write-HmaFinalSummary -TokenSucceeded $true -AutodiscoverSucceeded $true -OptionsSucceeded $true -FolderSyncSucceeded ([bool]$folderSync.Success)
    Save-HmaLog

    if ($folderSync.Success) {
        exit 0
    }
    exit 2
}
catch {
    Add-HmaCheck -Name "Unhandled script error" -Status "Fail" -Detail $_.Exception.Message
    Write-HmaFinalSummary -TokenSucceeded $false -AutodiscoverSucceeded $false -OptionsSucceeded $false -FolderSyncSucceeded $false
    Save-HmaLog
    exit 1
}

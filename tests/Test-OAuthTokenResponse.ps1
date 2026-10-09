# Load only the authentication functions, not the script's interactive main block.
$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-HmaEasNoEmptyBearer.ps1'
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    throw "Script parse errors: $($parseErrors.Message -join '; ')"
}
$functionNames = @('Assert-OAuthTokenResponse', 'Get-OAuthToken', 'Get-OAuthTokenDeviceCode', 'Get-OAuthTokenForOnPrem')
foreach ($name in $functionNames) {
    $functionAst = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if (-not $functionAst) { throw "Function not found: $name" }
    . ([scriptblock]::Create($functionAst.Extent.Text))
}

function Write-Host { param($Object, $ForegroundColor, [switch]$NoNewline) }
function Set-Clipboard { param([Parameter(ValueFromPipeline)]$Value) }
function Start-Sleep {
    param($Seconds)
    $script:Sleeps.Add($Seconds)
}
function Write-Log {
    param($Message, $Level)
    $script:Logs.Add("$Level : $Message")
}
function Write-DetailedError {
    param($ErrorRecord, $Context)
    Write-Log -Message "$Context : $($ErrorRecord.Exception.Message)" -Level 'ERROR'
}
function Write-TestResult {
    param($TestName, $Status, $Message, $Details)
    $script:Results.Add($Status)
    Write-Log -Message "$TestName : $Message : $Details" -Level $Status
}
function Invoke-RestMethod {
    param($Uri, $Method, $Body, $ContentType)
    $script:Requests.Add([PSCustomObject]@{ Uri = $Uri; Resource = $Body.resource })
    if ($Uri -like '*/devicecode') {
        return [PSCustomObject]@{
            device_code = 'offline-device-code-1234567890'
            user_code = 'OFFLINE'
            verification_url = 'https://microsoft.com/devicelogin'
            expires_in = 600
            interval = 5
        }
    }
    if ($script:Responses.Count -eq 0) { throw 'Unexpected token request' }
    $response = $script:Responses.Dequeue()
    if ($response -is [System.Management.Automation.ErrorRecord]) {
        throw $response
    }
    return $response
}
function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}
function Reset-Test {
    $script:Responses = New-Object System.Collections.Queue
    $script:Logs = New-Object 'System.Collections.Generic.List[string]'
    $script:Results = New-Object 'System.Collections.Generic.List[string]'
    $script:Sleeps = New-Object 'System.Collections.Generic.List[int]'
    $script:Requests = New-Object 'System.Collections.Generic.List[object]'
}
function New-OAuthError {
    param([string]$Code, [string]$Description)
    $record = New-Object System.Management.Automation.ErrorRecord(
        (New-Object System.Exception('HTTP token request failed')),
        'OfflineOAuthError',
        [System.Management.Automation.ErrorCategory]::InvalidOperation,
        $null
    )
    $record.ErrorDetails = New-Object System.Management.Automation.ErrorDetails(
        (@{ error = $Code; error_description = $Description } | ConvertTo-Json -Compress)
    )
    return $record
}

$credential = New-Object PSCredential('offline@example.invalid', (ConvertTo-SecureString 'offline-password' -AsPlainText -Force))
$parameters = @{ TenantId = 'offline-tenant'; ClientId = 'offline-client'; Resource = 'https://mail.example.invalid' }
$valid = [PSCustomObject]@{ access_token = 'offline-opaque-token'; token_type = 'Bearer'; expires_in = '3600' }
$cases = @(
    @{ Name = 'valid string expiry'; Response = $valid; Success = $true }
    @{ Name = 'valid numeric expiry'; Response = @{ access_token = 'offline-opaque-token'; token_type = 'bearer'; expires_in = 3600 }; Success = $true }
    @{ Name = 'null response'; Response = $null; Success = $false }
    @{ Name = 'HTML response'; Response = '<html>offline-secret-marker</html>'; Success = $false }
    @{ Name = 'empty object'; Response = [PSCustomObject]@{}; Success = $false }
    @{ Name = 'missing token'; Response = @{ token_type = 'Bearer'; expires_in = 3600 }; Success = $false }
    @{ Name = 'whitespace token'; Response = @{ access_token = ' '; token_type = 'Bearer'; expires_in = 3600 }; Success = $false }
    @{ Name = 'non-string token'; Response = @{ access_token = 123; token_type = 'Bearer'; expires_in = 3600 }; Success = $false }
    @{ Name = 'missing token type'; Response = @{ access_token = 'offline-secret-marker'; expires_in = 3600 }; Success = $false }
    @{ Name = 'wrong token type'; Response = @{ access_token = 'offline-secret-marker'; token_type = 'Basic'; expires_in = 3600 }; Success = $false }
    @{ Name = 'missing expiry'; Response = @{ access_token = 'offline-secret-marker'; token_type = 'Bearer' }; Success = $false }
    @{ Name = 'zero expiry'; Response = @{ access_token = 'offline-secret-marker'; token_type = 'Bearer'; expires_in = 0 }; Success = $false }
    @{ Name = 'negative expiry'; Response = @{ access_token = 'offline-secret-marker'; token_type = 'Bearer'; expires_in = -1 }; Success = $false }
    @{ Name = 'non-numeric expiry'; Response = @{ access_token = 'offline-secret-marker'; token_type = 'Bearer'; expires_in = 'invalid' }; Success = $false }
    @{ Name = 'OAuth error body'; Response = @{ error = 'invalid_grant'; error_description = 'Offline denial' }; Success = $false }
    @{ Name = 'HTTP OAuth error'; Response = (New-OAuthError 'invalid_grant' 'Offline denial'); Success = $false }
    @{ Name = 'transport error without details'; Response = (New-Object System.Management.Automation.ErrorRecord(
        (New-Object System.Exception('Offline transport failure')), 'OfflineTransport',
        [System.Management.Automation.ErrorCategory]::ConnectionError, $null
    )); Success = $false }
)
$passed = 0
foreach ($flow in @('ROPC', 'DeviceCode')) {
    foreach ($case in $cases) {
        Reset-Test
        $script:Responses.Enqueue($case.Response)
        $result = if ($flow -eq 'ROPC') {
            Get-OAuthToken @parameters -Credential $credential
        } else {
            Get-OAuthTokenDeviceCode @parameters
        }
        $label = "$flow / $($case.Name)"
        Assert-Test ($result.Success -eq $case.Success) "$label : wrong success status"
        if ($case.Success) {
            Assert-Test ($result.AccessToken -eq 'offline-opaque-token') "$label : token not preserved"
            Assert-Test ($script:Results.Contains('Success')) "$label : missing success report"
        } else {
            Assert-Test (-not [string]::IsNullOrWhiteSpace($result.Error)) "$label : missing error message"
            Assert-Test (-not $script:Results.Contains('Success')) "$label : false success report"
            Assert-Test ($script:Results.Contains('Error')) "$label : missing error report"
            Assert-Test (($script:Logs -join "`n") -notmatch 'Could not decode token claims') "$label : attempted token decoding"
            Assert-Test (($script:Logs -join "`n") -notmatch 'Authentication successful') "$label : false authentication success"
            Assert-Test ("$($result.Error)`n$($script:Logs -join "`n")" -notmatch 'offline-secret-marker') "$label : leaked response body"
            if ($case.Name -eq 'empty object') {
                Assert-Test ($result.Error -match 'access_token' -and $result.Error -match 'token_type' -and $result.Error -match 'expires_in') "$label : missing field diagnostics"
            }
            if ($case.Name -like '*OAuth error*') {
                Assert-Test ($result.Error -match 'invalid_grant.*Offline denial') "$label : lost OAuth error"
            }
            if ($case.Name -eq 'transport error without details') {
                Assert-Test ($result.Error -match 'Offline transport failure') "$label : lost exception message"
            }
        }
        $passed++
    }
}

Reset-Test
$script:Responses.Enqueue((New-OAuthError 'authorization_pending' 'Waiting'))
$script:Responses.Enqueue((New-OAuthError 'slow_down' 'Slow down'))
$script:Responses.Enqueue($valid)
$result = Get-OAuthTokenDeviceCode @parameters
Assert-Test ($result.Success) 'Device Code polling did not complete'
Assert-Test (($script:Sleeps -join ',') -eq '5,5,10') 'Device Code polling intervals changed'
$passed++

foreach ($flow in @('ROPC', 'DeviceCode')) {
    Reset-Test
    $script:ClientIds = @{ OutlookMobile = 'offline-client' }
    $script:Responses.Enqueue([PSCustomObject]@{})
    $script:Responses.Enqueue([PSCustomObject]@{})
    $result = Get-OAuthTokenForOnPrem -ExchangeServerFqdn 'mail.example.invalid' -TenantId 'offline-tenant' -Credential $credential -UseDeviceCode:($flow -eq 'DeviceCode')
    Assert-Test (-not $result.Success) "$flow : fallback accepted invalid tokens"
    Assert-Test (-not $script:Results.Contains('Success')) "$flow : fallback reported false success"
    $tokenRequests = @($script:Requests | Where-Object { $_.Uri -like '*/token' })
    Assert-Test ($tokenRequests.Count -eq 2) "$flow : resource fallback changed"
    $resourceRequests = if ($flow -eq 'DeviceCode') {
        @($script:Requests | Where-Object { $_.Uri -like '*/devicecode' })
    } else {
        $tokenRequests
    }
    Assert-Test ($resourceRequests[0].Resource -eq 'https://mail.example.invalid') "$flow : initial resource changed"
    Assert-Test ($resourceRequests[1].Resource -eq 'https://outlook.office365.com') "$flow : fallback resource changed"
    $passed++
}

Microsoft.PowerShell.Utility\Write-Host "PASS: $passed offline OAuth regression tests."

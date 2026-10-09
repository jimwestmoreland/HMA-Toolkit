<#
.SYNOPSIS
    Audits whether a specific user has evidence of Hybrid Modern Authentication usage.

.DESCRIPTION
    This script correlates Microsoft Entra sign-in logs with Exchange on-premises
    ActiveSync/HttpProxy/IIS logs for one user and time window.

    A strong HMA finding requires both:
      1. A successful Microsoft Entra modern-auth sign-in for the user to Exchange/Outlook.
      2. Matching Exchange on-premises ActiveSync traffic for the same user in the same window.

    ActiveSync server traffic without a matching Entra sign-in is flagged as possible
    legacy/basic ActiveSync. Entra sign-in evidence without server-side traffic is
    flagged as inconclusive.

    Microsoft Graph sign-in logs require AuditLog.Read.All. Exchange log parsing is
    local/read-only and supports W3C-style Exchange/IIS logs with #Fields headers.

.PARAMETER UserPrincipalName
    The user principal name to audit.

.PARAMETER StartTime
    Start of the audit window. Defaults to 24 hours before script start.

.PARAMETER EndTime
    End of the audit window. Defaults to script start time.

.PARAMETER ExchangeLogPath
    One or more Exchange log directories or files. Directories are searched recursively
    for likely ActiveSync/HttpProxy/IIS log files.

.PARAMETER SkipGraph
    Skip Microsoft Entra sign-in log lookup and only parse Exchange logs.

.PARAMETER SkipExchangeLogs
    Skip Exchange log parsing and only query Microsoft Entra sign-in logs.

.PARAMETER OutputPath
    Optional path for the full audit log.

.PARAMETER CsvOutputPath
    Optional path to export correlated evidence rows as CSV.

.EXAMPLE
    .\Get-HmaUsageAuditForUser.ps1 -UserPrincipalName user@contoso.com `
        -StartTime (Get-Date).AddHours(-8) `
        -ExchangeLogPath "C:\Program Files\Microsoft\Exchange Server\V15\Logging" `
        -Verbose

.EXAMPLE
    .\Get-HmaUsageAuditForUser.ps1 -UserPrincipalName user@contoso.com `
        -StartTime "2026-10-09T15:00:00Z" `
        -EndTime "2026-10-09T18:00:00Z" `
        -ExchangeLogPath "\\EX01\c$\Program Files\Microsoft\Exchange Server\V15\Logging\HttpProxy\Eas" `
        -CsvOutputPath C:\Logs\hma-audit-user.csv
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $false)]
    [datetime]$StartTime = (Get-Date).AddDays(-1),

    [Parameter(Mandatory = $false)]
    [datetime]$EndTime = (Get-Date),

    [Parameter(Mandatory = $false)]
    [string[]]$ExchangeLogPath = @(
        "C:\Program Files\Microsoft\Exchange Server\V15\Logging\HttpProxy\Eas",
        "C:\Program Files\Microsoft\Exchange Server\V15\Logging\HttpProxy\Autodiscover",
        "C:\inetpub\logs\LogFiles"
    ),

    [Parameter(Mandatory = $false)]
    [switch]$SkipGraph,

    [Parameter(Mandatory = $false)]
    [switch]$SkipExchangeLogs,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string]$CsvOutputPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

if ($EndTime -le $StartTime) {
    throw "EndTime must be later than StartTime."
}

$script:LogOutput = New-Object System.Collections.Generic.List[string]
$script:Evidence = New-Object System.Collections.Generic.List[object]

$script:KnownModernClientAppIds = @{
    "27922004-5251-4030-b22d-91ecd9a37ea4" = "Outlook Mobile"
    "d3590ed6-52b3-4102-aeff-aad2292ab01c" = "Microsoft Office / Outlook Desktop"
    "00000002-0000-0ff1-ce00-000000000000" = "Office 365 Exchange Online"
}

function Write-AuditLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet("INFO", "PASS", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $line = "[${timestamp}] [${Level}] $Message"
    $script:LogOutput.Add($line) | Out-Null

    if ($VerbosePreference -eq "Continue" -or $Level -in @("INFO", "PASS", "WARN", "ERROR")) {
        $color = switch ($Level) {
            "PASS" { "Green" }
            "WARN" { "Yellow" }
            "ERROR" { "Red" }
            "DEBUG" { "DarkGray" }
            default { "Gray" }
        }
        Write-Host $line -ForegroundColor $color
    }
}

function Save-AuditLog {
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        return
    }

    $parent = Split-Path -Parent $OutputPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }
    $script:LogOutput | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    Write-Host "Full audit log saved to $OutputPath" -ForegroundColor Cyan
}

function ConvertTo-GraphDateTime {
    param([datetime]$DateTime)
    return $DateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function ConvertTo-ODataStringLiteral {
    param([string]$Value)
    return $Value.Replace("'", "''")
}

function Invoke-GraphSignInRequest {
    param([string]$Uri)

    if (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue) {
        if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue) -or -not (Get-MgContext)) {
            if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
                throw "Microsoft.Graph PowerShell is present only partially. Install Microsoft.Graph or sign in with Azure CLI."
            }
            Write-AuditLog "Connecting to Microsoft Graph with AuditLog.Read.All and Directory.Read.All." -Level "INFO"
            Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All" -NoWelcome | Out-Null
        }
        return Invoke-MgGraphRequest -Method GET -Uri $Uri
    }

    if (Get-Command az -ErrorAction SilentlyContinue) {
        Write-AuditLog "Microsoft.Graph PowerShell not found. Trying Azure CLI token for Microsoft Graph." -Level "INFO"
        $tokenJson = az account get-access-token --resource-type ms-graph 2>$null | ConvertFrom-Json
        if (-not $tokenJson.accessToken) {
            throw "Azure CLI did not return a Microsoft Graph access token. Run az login and retry, or install Microsoft.Graph PowerShell."
        }
        return Invoke-RestMethod -Method GET -Uri $Uri -Headers @{ Authorization = "Bearer $($tokenJson.accessToken)" }
    }

    throw "No Graph client found. Install Microsoft.Graph PowerShell or sign in with Azure CLI."
}

function Get-EntraSignIns {
    if ($SkipGraph) {
        Write-AuditLog "Skipping Microsoft Entra sign-in lookup by request." -Level "WARN"
        return @()
    }

    $start = ConvertTo-GraphDateTime -DateTime $StartTime
    $end = ConvertTo-GraphDateTime -DateTime $EndTime
    $user = ConvertTo-ODataStringLiteral -Value $UserPrincipalName
    $filter = "userPrincipalName eq '$user' and createdDateTime ge $start and createdDateTime le $end"
    $encodedFilter = [System.Uri]::EscapeDataString($filter)
    $select = "id,createdDateTime,userPrincipalName,appDisplayName,appId,resourceDisplayName,resourceId,clientAppUsed,ipAddress,deviceDetail,location,status,conditionalAccessStatus"
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=100&`$filter=$encodedFilter&`$select=$select&`$orderby=createdDateTime desc"

    Write-AuditLog "Querying Microsoft Entra sign-in logs for $UserPrincipalName from $start to $end." -Level "INFO"
    $all = New-Object System.Collections.Generic.List[object]

    do {
        $result = Invoke-GraphSignInRequest -Uri $uri
        $values = @($result.value)
        foreach ($item in $values) {
            $all.Add($item) | Out-Null
        }
        $next = $null
        if ($result.PSObject.Properties.Name -contains "@odata.nextLink") {
            $next = $result.'@odata.nextLink'
        }
        $uri = $next
    } while ($uri)

    Write-AuditLog "Retrieved $($all.Count) Microsoft Entra sign-in records for the user." -Level "INFO"
    return @($all)
}

function Test-IsLikelyModernExchangeSignIn {
    param([object]$SignIn)

    $appId = [string]$SignIn.appId
    $app = [string]$SignIn.appDisplayName
    $resource = [string]$SignIn.resourceDisplayName
    $clientApp = [string]$SignIn.clientAppUsed
    $statusCode = if ($SignIn.status -and $SignIn.status.PSObject.Properties.Name -contains "errorCode") { [int]$SignIn.status.errorCode } else { -1 }

    if ($statusCode -ne 0) {
        return $false
    }

    $isExchangeResource = $resource -match "Exchange|Office 365 Exchange|Office 365"
    $isOutlookApp = $app -match "Outlook|Office|Exchange" -or $script:KnownModernClientAppIds.ContainsKey($appId)
    $isLegacyClientLabel = $clientApp -match "Exchange ActiveSync|Other clients|POP|IMAP|SMTP"

    return ($isExchangeResource -and $isOutlookApp -and -not $isLegacyClientLabel)
}

function Convert-SignInToEvidence {
    param([object]$SignIn)

    $statusCode = if ($SignIn.status -and $SignIn.status.PSObject.Properties.Name -contains "errorCode") { [int]$SignIn.status.errorCode } else { $null }
    $failureReason = if ($SignIn.status -and $SignIn.status.PSObject.Properties.Name -contains "failureReason") { [string]$SignIn.status.failureReason } else { "" }
    $device = if ($SignIn.deviceDetail) { "$($SignIn.deviceDetail.operatingSystem) $($SignIn.deviceDetail.browser) $($SignIn.deviceDetail.deviceId)" } else { "" }

    return [pscustomobject]@{
        Source = "EntraSignIn"
        Time = ([datetime]$SignIn.createdDateTime).ToUniversalTime()
        User = $SignIn.userPrincipalName
        Verdict = if (Test-IsLikelyModernExchangeSignIn -SignIn $SignIn) { "ModernAuthExchangeSignIn" } elseif ($statusCode -eq 0) { "OtherSuccessfulSignIn" } else { "FailedSignIn" }
        AppDisplayName = $SignIn.appDisplayName
        AppId = $SignIn.appId
        ResourceDisplayName = $SignIn.resourceDisplayName
        ClientAppUsed = $SignIn.clientAppUsed
        IpAddress = $SignIn.ipAddress
        Device = $device
        StatusCode = $statusCode
        FailureReason = $failureReason
        ConditionalAccessStatus = $SignIn.conditionalAccessStatus
        LogFile = ""
        RawSummary = "app=$($SignIn.appDisplayName); resource=$($SignIn.resourceDisplayName); clientApp=$($SignIn.clientAppUsed); ip=$($SignIn.ipAddress)"
    }
}

function Get-ExchangeLogFiles {
    if ($SkipExchangeLogs) {
        Write-AuditLog "Skipping Exchange log parsing by request." -Level "WARN"
        return @()
    }

    $files = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    foreach ($path in $ExchangeLogPath) {
        if (-not (Test-Path -LiteralPath $path)) {
            Write-AuditLog "Exchange log path not found: $path" -Level "WARN"
            continue
        }

        $item = Get-Item -LiteralPath $path
        if ($item.PSIsContainer) {
            $candidates = Get-ChildItem -LiteralPath $item.FullName -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Extension -in @(".log", ".txt") -and
                    ($_.Name -match "Eas|ActiveSync|W3SVC|u_ex|HttpProxy|Autodiscover")
                }
            foreach ($candidate in $candidates) {
                if ($candidate.LastWriteTime -ge $StartTime.AddDays(-1) -and $candidate.LastWriteTime -le $EndTime.AddDays(1)) {
                    $files.Add($candidate) | Out-Null
                }
            }
        } else {
            $files.Add($item) | Out-Null
        }
    }

    $unique = $files | Sort-Object FullName -Unique
    Write-AuditLog "Selected $(@($unique).Count) Exchange/IIS log files for parsing." -Level "INFO"
    return @($unique)
}

function Convert-LogDateTime {
    param(
        [hashtable]$Row,
        [datetime]$FileDateHint
    )

    $date = if ($Row.ContainsKey("date")) { $Row["date"] } else { "" }
    $time = if ($Row.ContainsKey("time")) { $Row["time"] } else { "" }
    if ($date -and $time) {
        return ([datetime]::SpecifyKind([datetime]::Parse("$date $time"), [DateTimeKind]::Utc))
    }

    if ($Row.ContainsKey("DateTime")) {
        return [datetime]$Row["DateTime"]
    }

    return $FileDateHint.ToUniversalTime()
}

function Read-W3CLogRows {
    param([System.IO.FileInfo]$File)

    $fields = $null
    $lineNumber = 0
    foreach ($line in [System.IO.File]::ReadLines($File.FullName)) {
        $lineNumber++
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        if ($line.StartsWith("#Fields:", [System.StringComparison]::OrdinalIgnoreCase)) {
            $fields = $line.Substring(8).Trim().Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)
            continue
        }
        if ($line.StartsWith("#")) {
            continue
        }
        if (-not $fields) {
            continue
        }

        $values = $line.Split(" ")
        $row = @{}
        for ($i = 0; $i -lt $fields.Count; $i++) {
            $row[$fields[$i]] = if ($i -lt $values.Count) { $values[$i] } else { "" }
        }
        $row["_LineNumber"] = $lineNumber
        $row["_Raw"] = $line
        [pscustomobject]$row
    }
}

function Test-RowMatchesUser {
    param(
        [hashtable]$Row,
        [string]$RawLine
    )

    $needles = @(
        $UserPrincipalName,
        [System.Uri]::EscapeDataString($UserPrincipalName),
        $UserPrincipalName.Replace("@", "%40"),
        $UserPrincipalName.Split("@")[0]
    ) | Select-Object -Unique

    foreach ($needle in $needles) {
        if ($RawLine -like "*$needle*") {
            return $true
        }
    }
    return $false
}

function Convert-ExchangeRowToEvidence {
    param(
        [hashtable]$Row,
        [System.IO.FileInfo]$File
    )

    $raw = [string]$Row["_Raw"]
    $time = Convert-LogDateTime -Row $Row -FileDateHint $File.LastWriteTime
    $uri = if ($Row.ContainsKey("cs-uri-stem")) { $Row["cs-uri-stem"] } elseif ($Row.ContainsKey("UrlStem")) { $Row["UrlStem"] } else { "" }
    $query = if ($Row.ContainsKey("cs-uri-query")) { $Row["cs-uri-query"] } elseif ($Row.ContainsKey("UrlQuery")) { $Row["UrlQuery"] } else { "" }
    $status = if ($Row.ContainsKey("sc-status")) { $Row["sc-status"] } elseif ($Row.ContainsKey("HttpStatus")) { $Row["HttpStatus"] } else { "" }
    $userAgent = if ($Row.ContainsKey("cs(User-Agent)")) { $Row["cs(User-Agent)"] } elseif ($Row.ContainsKey("UserAgent")) { $Row["UserAgent"] } else { "" }
    $authType = if ($Row.ContainsKey("cs-username")) { $Row["cs-username"] } else { "" }
    $clientIp = if ($Row.ContainsKey("c-ip")) { $Row["c-ip"] } elseif ($Row.ContainsKey("ClientIpAddress")) { $Row["ClientIpAddress"] } else { "" }

    $isActiveSync = $raw -match "Microsoft-Server-ActiveSync|ActiveSync|/EAS|HttpProxy\\Eas"
    $mentionsBearer = $raw -match "Bearer|OAuth|authorization_uri|OAuthClaims|OAuthAuthentication"
    $mentionsBasic = $raw -match "Basic|Negotiate|NTLM"

    $verdict = if ($isActiveSync -and $mentionsBearer) {
        "ActiveSyncOAuthEvidence"
    } elseif ($isActiveSync -and $mentionsBasic) {
        "ActiveSyncLegacyAuthEvidence"
    } elseif ($isActiveSync) {
        "ActiveSyncTraffic"
    } else {
        "RelatedExchangeLog"
    }

    return [pscustomobject]@{
        Source = "ExchangeLog"
        Time = $time.ToUniversalTime()
        User = $UserPrincipalName
        Verdict = $verdict
        AppDisplayName = ""
        AppId = ""
        ResourceDisplayName = ""
        ClientAppUsed = $userAgent
        IpAddress = $clientIp
        Device = ""
        StatusCode = $status
        FailureReason = ""
        ConditionalAccessStatus = ""
        LogFile = $File.FullName
        RawSummary = "uri=$uri; query=$query; cs-username=$authType; rawLine=$($Row['_LineNumber'])"
    }
}

function Get-ExchangeLogEvidence {
    $files = Get-ExchangeLogFiles
    if (@($files).Count -eq 0) {
        return @()
    }

    $evidence = New-Object System.Collections.Generic.List[object]
    foreach ($file in $files) {
        Write-AuditLog "Parsing $($file.FullName)" -Level "DEBUG"
        try {
            foreach ($rowObject in Read-W3CLogRows -File $file) {
                $row = @{}
                foreach ($property in $rowObject.PSObject.Properties) {
                    $row[$property.Name] = [string]$property.Value
                }

                $raw = [string]$row["_Raw"]
                if (-not (Test-RowMatchesUser -Row $row -RawLine $raw)) {
                    continue
                }

                $time = Convert-LogDateTime -Row $row -FileDateHint $file.LastWriteTime
                if ($time -lt $StartTime.ToUniversalTime() -or $time -gt $EndTime.ToUniversalTime()) {
                    continue
                }

                $evidence.Add((Convert-ExchangeRowToEvidence -Row $row -File $file)) | Out-Null
            }
        }
        catch {
            Write-AuditLog "Failed parsing $($file.FullName): $($_.Exception.Message)" -Level "WARN"
        }
    }

    Write-AuditLog "Found $($evidence.Count) Exchange log evidence rows for the user in the window." -Level "INFO"
    return @($evidence)
}

function Get-CorrelationVerdict {
    param([object[]]$EvidenceRows)

    $modernSignIns = @($EvidenceRows | Where-Object { $_.Source -eq "EntraSignIn" -and $_.Verdict -eq "ModernAuthExchangeSignIn" })
    $exchangeTraffic = @($EvidenceRows | Where-Object { $_.Source -eq "ExchangeLog" -and $_.Verdict -match "ActiveSync" })
    $exchangeOAuth = @($EvidenceRows | Where-Object { $_.Source -eq "ExchangeLog" -and $_.Verdict -eq "ActiveSyncOAuthEvidence" })
    $exchangeLegacy = @($EvidenceRows | Where-Object { $_.Source -eq "ExchangeLog" -and $_.Verdict -eq "ActiveSyncLegacyAuthEvidence" })

    if ($modernSignIns.Count -gt 0 -and ($exchangeTraffic.Count -gt 0 -or $SkipExchangeLogs)) {
        return @{
            Verdict = "CONFIRMED_OR_STRONG"
            Message = "User has successful Entra modern-auth Exchange/Outlook sign-in evidence and matching ActiveSync server traffic in the audit window."
            ModernSignIns = $modernSignIns.Count
            ExchangeTraffic = $exchangeTraffic.Count
            ExchangeOAuth = $exchangeOAuth.Count
            ExchangeLegacy = $exchangeLegacy.Count
        }
    }

    if ($modernSignIns.Count -gt 0) {
        return @{
            Verdict = "INCONCLUSIVE_MODERN_SIGNIN_ONLY"
            Message = "User has successful Entra modern-auth Exchange/Outlook sign-in evidence, but no matching Exchange ActiveSync server log rows were found or provided."
            ModernSignIns = $modernSignIns.Count
            ExchangeTraffic = $exchangeTraffic.Count
            ExchangeOAuth = $exchangeOAuth.Count
            ExchangeLegacy = $exchangeLegacy.Count
        }
    }

    if ($exchangeTraffic.Count -gt 0) {
        return @{
            Verdict = "LEGACY_OR_UNCONFIRMED"
            Message = "Exchange ActiveSync traffic exists for the user, but no successful Entra modern-auth Exchange/Outlook sign-in was found in the window. This is suspicious for legacy/basic ActiveSync or missing Entra audit data."
            ModernSignIns = $modernSignIns.Count
            ExchangeTraffic = $exchangeTraffic.Count
            ExchangeOAuth = $exchangeOAuth.Count
            ExchangeLegacy = $exchangeLegacy.Count
        }
    }

    return @{
        Verdict = "NO_EVIDENCE"
        Message = "No Entra modern-auth Exchange/Outlook sign-in evidence and no Exchange ActiveSync server traffic were found for the user in the window."
        ModernSignIns = 0
        ExchangeTraffic = 0
        ExchangeOAuth = 0
        ExchangeLegacy = 0
    }
}

try {
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  HMA Usage Audit For User" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "User: $UserPrincipalName" -ForegroundColor White
    Write-Host "Window: $($StartTime.ToUniversalTime().ToString('u')) to $($EndTime.ToUniversalTime().ToString('u'))" -ForegroundColor White
    Write-Host ""

    $signIns = Get-EntraSignIns
    foreach ($signIn in $signIns) {
        $script:Evidence.Add((Convert-SignInToEvidence -SignIn $signIn)) | Out-Null
    }

    $exchangeRows = Get-ExchangeLogEvidence
    foreach ($row in $exchangeRows) {
        $script:Evidence.Add($row) | Out-Null
    }

    $orderedEvidence = @($script:Evidence | Sort-Object Time)
    $correlation = Get-CorrelationVerdict -EvidenceRows $orderedEvidence

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  AUDIT VERDICT" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $verdictColor = switch ($correlation.Verdict) {
        "CONFIRMED_OR_STRONG" { "Green" }
        "INCONCLUSIVE_MODERN_SIGNIN_ONLY" { "Yellow" }
        "LEGACY_OR_UNCONFIRMED" { "Yellow" }
        default { "Red" }
    }
    Write-Host "$($correlation.Verdict): $($correlation.Message)" -ForegroundColor $verdictColor
    Write-Host ""
    Write-Host "Counts:" -ForegroundColor White
    Write-Host "  Modern Entra Exchange/Outlook sign-ins: $($correlation.ModernSignIns)" -ForegroundColor Gray
    Write-Host "  Exchange ActiveSync traffic rows:       $($correlation.ExchangeTraffic)" -ForegroundColor Gray
    Write-Host "  Exchange OAuth/Bearer evidence rows:   $($correlation.ExchangeOAuth)" -ForegroundColor Gray
    Write-Host "  Exchange legacy/basic evidence rows:   $($correlation.ExchangeLegacy)" -ForegroundColor Gray

    if ($orderedEvidence.Count -gt 0) {
        Write-Host ""
        Write-Host "Evidence timeline:" -ForegroundColor White
        $orderedEvidence |
            Select-Object Time, Source, Verdict, AppDisplayName, ResourceDisplayName, ClientAppUsed, IpAddress, StatusCode, RawSummary |
            Format-Table -AutoSize
    }

    if ($CsvOutputPath) {
        $parent = Split-Path -Parent $CsvOutputPath
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -Path $parent -ItemType Directory -Force | Out-Null
        }
        $orderedEvidence | Export-Csv -LiteralPath $CsvOutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "Evidence CSV saved to $CsvOutputPath" -ForegroundColor Cyan
    }

    Save-AuditLog

    if ($correlation.Verdict -eq "CONFIRMED_OR_STRONG") {
        exit 0
    }
    if ($correlation.Verdict -like "INCONCLUSIVE*" -or $correlation.Verdict -eq "LEGACY_OR_UNCONFIRMED") {
        exit 2
    }
    exit 1
}
catch {
    Write-AuditLog "Audit failed: $($_.Exception.Message)" -Level "ERROR"
    Save-AuditLog
    exit 1
}

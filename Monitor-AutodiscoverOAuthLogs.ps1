<#
# VERSION: 2026-01-28 UTC
.SYNOPSIS
    Monitors Exchange HttpProxy logs and OAuth event logs to diagnose intermittent HMA failures.
    Reads directly from server log files - no external HTTP requests required.
    
.DESCRIPTION
    This script helps diagnose the correlation between OAuth metadata failures and
    Autodiscover behavior by reading server-side logs:
    - HttpProxy Autodiscover logs for all autodiscover.json requests
    - Windows Event logs for OAuth errors
    - Correlates timestamps to identify patterns
    
.PARAMETER ExchangeServers
    Array of Exchange server names to monitor.
    If not specified, will auto-detect from Get-ExchangeServer.

.PARAMETER UserEmail
    Filter logs to a specific user's email address. Highly recommended.

.PARAMETER HoursBack
    How many hours of logs to analyze. Default is 1 hour.

.PARAMETER TailMode
    If specified, continuously monitors logs in real-time (like tail -f).
    Otherwise, does a one-time analysis of existing logs.

.PARAMETER RefreshIntervalSeconds
    In TailMode, how often to check for new log entries. Default is 10 seconds.

.PARAMETER OutputPath
    Path to save the analysis report.

.EXAMPLE
    .\Monitor-AutodiscoverOAuthLogs.ps1 -UserEmail "user@contoso.com" -HoursBack 2
    
.EXAMPLE
    .\Monitor-AutodiscoverOAuthLogs.ps1 -UserEmail "user@contoso.com" -TailMode -RefreshIntervalSeconds 5

.NOTES
    Run from Exchange Management Shell or a machine with UNC access to Exchange servers.
    Requires admin share access (\\server\C$) to Exchange servers.
#>

param(
    [Parameter(Mandatory = $false)]
    [string[]]$ExchangeServers,
    
    [Parameter(Mandatory = $true)]
    [string]$UserEmail,
    
    [Parameter(Mandatory = $false)]
    [int]$HoursBack = 1,
    
    [Parameter(Mandatory = $false)]
    [switch]$TailMode,
    
    [Parameter(Mandatory = $false)]
    [int]$RefreshIntervalSeconds = 10,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\AutodiscoverOAuth-LogAnalysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
)

#region Initialization
$script:LogEntries = @()
$script:AutodiscoverRequests = @()
$script:OAuthEvents = @()
$script:LastReadPositions = @{}
$script:StartTime = Get-Date
$script:AnalysisStartTime = (Get-Date).AddHours(-$HoursBack)

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "JSON", "XML", "EVENT", "CORRELATION")]
        [string]$Level = "INFO",
        [string]$Source = "Monitor"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logLine = "[$timestamp] [$Level] [$Source] $Message"
    
    $color = switch ($Level) {
        "INFO" { "White" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        "JSON" { "Green" }
        "XML" { "Magenta" }
        "EVENT" { "Cyan" }
        "CORRELATION" { "White" }
    }
    Write-Host $logLine -ForegroundColor $color
    $script:LogEntries += $logLine
}

function Write-Section {
    param([string]$Title)
    $separator = "=" * 70
    Write-Host ""
    Write-Host $separator -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $separator -ForegroundColor Cyan
    Write-Host ""
    $script:LogEntries += ""
    $script:LogEntries += $separator
    $script:LogEntries += "  $Title"
    $script:LogEntries += $separator
    $script:LogEntries += ""
}
#endregion

#region Auto-detect Exchange Servers
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  AUTODISCOVER & OAUTH LOG ANALYZER" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

if (-not $ExchangeServers -or $ExchangeServers.Count -eq 0) {
    Write-Host "Auto-detecting Exchange servers..." -ForegroundColor Yellow
    try {
        $exServers = Get-ExchangeServer -ErrorAction SilentlyContinue | 
            Where-Object { $_.ServerRole -match "Mailbox" -and $_.ServerRole -notmatch "Edge" } |
            Select-Object -ExpandProperty Name
        
        if ($exServers) {
            $ExchangeServers = $exServers
            Write-Host "  Found: $($ExchangeServers -join ', ')" -ForegroundColor Green
        }
    } catch {
        Write-Host "  Could not auto-detect. Using local server." -ForegroundColor Yellow
        $ExchangeServers = @($env:COMPUTERNAME)
    }
}

Write-Host ""
Write-Host "Configuration:" -ForegroundColor White
Write-Host "  User Filter: $UserEmail" -ForegroundColor Gray
Write-Host "  Time Range: $($script:AnalysisStartTime.ToString('yyyy-MM-dd HH:mm:ss')) to now" -ForegroundColor Gray
Write-Host "  Exchange Servers: $($ExchangeServers -join ', ')" -ForegroundColor Gray
Write-Host "  Mode: $(if ($TailMode) { 'Continuous tail (Ctrl+C to stop)' } else { 'One-time analysis' })" -ForegroundColor Gray
Write-Host "  Output: $OutputPath" -ForegroundColor Gray
Write-Host ""
#endregion

#region Log Parsing Functions
function ConvertFrom-HttpProxyLogLine {
    param(
        [string]$LogLine,
        [string]$ServerName
    )
    
    # Skip headers
    if ($LogLine -match "^#" -or $LogLine -match "^DateTime" -or [string]::IsNullOrWhiteSpace($LogLine)) {
        return $null
    }
    
    # Split by comma (CSV format)
    $fields = $LogLine -split ","
    
    if ($fields.Count -lt 20) { return $null }
    
    # Key fields from HttpProxy logs:
    # 0=DateTime, 8=UrlHost, 9=UrlStem, 11=AuthenticationType, 12=IsAuthenticated
    # 15=AnchorMailbox, 16=UserAgent, 19=HttpStatus, 22=Method
    
    try {
        $entry = [PSCustomObject]@{
            Server = $ServerName
            DateTime = $fields[0]
            UrlStem = $fields[9]
            AuthType = $fields[11]
            IsAuthenticated = $fields[12]
            AnchorMailbox = $fields[15]
            UserAgent = $fields[16]
            HttpStatus = $fields[19]
            Method = $fields[22]
            GenericInfo = if ($fields.Count -gt 67) { $fields[67] } else { "" }
            RawLine = $LogLine
        }
        return $entry
    } catch {
        return $null
    }
}

function Get-AutodiscoverLogs {
    param(
        [string]$Server,
        [datetime]$Since,
        [string]$FilterEmail
    )
    
    $results = @()
    $logPath = "\\$Server\C$\Program Files\Microsoft\Exchange Server\V15\Logging\HttpProxy\Autodiscover"
    
    if (-not (Test-Path $logPath -ErrorAction SilentlyContinue)) {
        Write-Log -Message "Cannot access Autodiscover logs on $Server" -Level "WARNING" -Source $Server
        return $results
    }
    
    # Get recent log files
    $logFiles = Get-ChildItem -Path $logPath -Filter "*.log" -ErrorAction SilentlyContinue | 
        Where-Object { $_.LastWriteTime -ge $Since } |
        Sort-Object LastWriteTime -Descending
    
    foreach ($logFile in $logFiles) {
        try {
            $content = Get-Content $logFile.FullName -ErrorAction SilentlyContinue
            
            foreach ($line in $content) {
                # Filter for our user
                if ($FilterEmail -and $line -notmatch [regex]::Escape($FilterEmail)) { continue }
                
                # Filter for autodiscover.json or autodiscover.xml
                if ($line -notmatch "autodiscover\.(json|xml)") { continue }
                
                $entry = ConvertFrom-HttpProxyLogLine -LogLine $line -ServerName $Server
                if ($entry) {
                    # Parse timestamp and filter by time
                    try {
                        $entryTime = [DateTime]::Parse($entry.DateTime)
                        if ($entryTime -ge $Since) {
                            $results += $entry
                        }
                    } catch {
                        # If we can't parse time, include it anyway
                        $results += $entry
                    }
                }
            }
        } catch {
            Write-Log -Message "Error reading $($logFile.Name): $_" -Level "WARNING" -Source $Server
        }
    }
    
    return $results
}

function Get-OAuthEventLogs {
    param(
        [string]$Server,
        [datetime]$Since
    )
    
    $results = @()
    
    try {
        $events = Get-WinEvent -ComputerName $Server -FilterHashtable @{
            LogName = 'Application'
            ProviderName = 'MSExchange OAuth'
            StartTime = $Since
        } -MaxEvents 200 -ErrorAction SilentlyContinue
        
        foreach ($evt in $events) {
            $results += [PSCustomObject]@{
                Server = $Server
                DateTime = $evt.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                EventId = $evt.Id
                Level = $evt.LevelDisplayName
                Message = $evt.Message
                IsMetadataError = ($evt.Message -match "metadata|connection was closed|WebException")
            }
        }
    } catch {
        Write-Log -Message "Could not read OAuth events from $Server`: $_" -Level "WARNING" -Source $Server
    }
    
    return $results
}
#endregion

#region Analysis Functions
function Invoke-AutodiscoverPatternAnalysis {
    param(
        [array]$Requests
    )
    
    if ($Requests.Count -eq 0) {
        Write-Log -Message "No autodiscover requests found for user" -Level "WARNING" -Source "Analysis"
        return
    }
    
    Write-Section -Title "AUTODISCOVER REQUEST ANALYSIS"
    
    # Group by URL type
    $jsonRequests = $Requests | Where-Object { $_.UrlStem -match "\.json" }
    $xmlRequests = $Requests | Where-Object { $_.UrlStem -match "\.xml" }
    
    Write-Log -Message "Total requests found: $($Requests.Count)" -Level "INFO" -Source "Analysis"
    Write-Log -Message "  JSON endpoint requests: $($jsonRequests.Count)" -Level "JSON" -Source "Analysis"
    Write-Log -Message "  XML endpoint requests: $($xmlRequests.Count)" -Level "XML" -Source "Analysis"
    
    # Analyze JSON requests
    if ($jsonRequests.Count -gt 0) {
        Write-Host ""
        Write-Log -Message "--- JSON Requests (Modern Auth path) ---" -Level "INFO" -Source "Analysis"
        
        $jsonV1 = $jsonRequests | Where-Object { $_.UrlStem -match "/v1\.0/" }
        $jsonInitial = $jsonRequests | Where-Object { $_.UrlStem -notmatch "/v1\.0/" }
        
        Write-Log -Message "  Initial autodiscover.json: $($jsonInitial.Count)" -Level "INFO" -Source "Analysis"
        Write-Log -Message "  V1.0 autodiscover.json: $($jsonV1.Count)" -Level "INFO" -Source "Analysis"
        
        # Show successful vs failed
        $json200 = $jsonRequests | Where-Object { $_.HttpStatus -eq "200" }
        $jsonFailed = $jsonRequests | Where-Object { $_.HttpStatus -ne "200" }
        
        Write-Log -Message "  HTTP 200 (success): $($json200.Count)" -Level "JSON" -Source "Analysis"
        if ($jsonFailed.Count -gt 0) {
            Write-Log -Message "  HTTP non-200 (failed): $($jsonFailed.Count)" -Level "ERROR" -Source "Analysis"
            foreach ($fail in $jsonFailed | Select-Object -First 5) {
                Write-Log -Message "    $($fail.DateTime) - HTTP $($fail.HttpStatus) - $($fail.UrlStem)" -Level "ERROR" -Source "Analysis"
            }
        }
    }
    
    # Analyze XML requests (fallback behavior)
    if ($xmlRequests.Count -gt 0) {
        Write-Host ""
        Write-Log -Message "--- XML Requests (Legacy Auth fallback) ---" -Level "WARNING" -Source "Analysis"
        
        foreach ($xml in $xmlRequests) {
            $anchorInfo = if ($xml.AnchorMailbox) { "AnchorMailbox=$($xml.AnchorMailbox)" } else { "NO AnchorMailbox" }
            Write-Log -Message "$($xml.DateTime) | $($xml.Server) | HTTP $($xml.HttpStatus) | $($xml.Method) | $anchorInfo" -Level "XML" -Source "Analysis"
        }
        
        # Check for the problematic pattern: XML request with no AnchorMailbox and 401
        $problemXml = $xmlRequests | Where-Object { 
            $_.HttpStatus -eq "401" -and 
            ([string]::IsNullOrWhiteSpace($_.AnchorMailbox) -or $_.AnchorMailbox -eq "")
        }
        
        if ($problemXml.Count -gt 0) {
            Write-Host ""
            Write-Log -Message "*** PROBLEM PATTERN DETECTED: $($problemXml.Count) XML requests with 401 and no AnchorMailbox ***" -Level "ERROR" -Source "Analysis"
            Write-Log -Message "This indicates the client is falling back to legacy auth and failing" -Level "ERROR" -Source "Analysis"
        }
    }
    
    # Timeline analysis - look for JSON followed by XML (fallback pattern)
    Write-Host ""
    Write-Log -Message "--- Request Sequence Analysis ---" -Level "INFO" -Source "Analysis"
    
    $sortedRequests = $Requests | Sort-Object DateTime
    
    for ($i = 0; $i -lt $sortedRequests.Count - 1; $i++) {
        $current = $sortedRequests[$i]
        $next = $sortedRequests[$i + 1]
        
        # Check for JSON followed by XML within 10 seconds (fallback)
        if ($current.UrlStem -match "\.json" -and $next.UrlStem -match "\.xml") {
            try {
                $timeDiff = ([DateTime]::Parse($next.DateTime) - [DateTime]::Parse($current.DateTime)).TotalSeconds
                if ($timeDiff -lt 10) {
                    Write-Log -Message "FALLBACK DETECTED at $($current.DateTime):" -Level "CORRELATION" -Source "Analysis"
                    Write-Log -Message "  1. JSON: $($current.UrlStem) -> HTTP $($current.HttpStatus)" -Level "JSON" -Source "Analysis"
                    Write-Log -Message "  2. XML:  $($next.UrlStem) -> HTTP $($next.HttpStatus) (after $([math]::Round($timeDiff, 2))s)" -Level "XML" -Source "Analysis"
                }
            } catch { }
        }
    }
}

function Compare-EventTimestamps {
    param(
        [array]$AutodiscoverRequests,
        [array]$OAuthEvents
    )
    
    if ($OAuthEvents.Count -eq 0) {
        Write-Log -Message "No OAuth events found in the time range" -Level "INFO" -Source "Correlation"
        return
    }
    
    Write-Section -Title "OAUTH EVENT CORRELATION"
    
    # Show OAuth errors
    $oauthErrors = $OAuthEvents | Where-Object { $_.Level -match "Error|Warning" -or $_.IsMetadataError }
    
    Write-Log -Message "Total OAuth events: $($OAuthEvents.Count)" -Level "INFO" -Source "Correlation"
    Write-Log -Message "OAuth errors/warnings: $($oauthErrors.Count)" -Level "EVENT" -Source "Correlation"
    
    # Show metadata errors specifically
    $metadataErrors = $OAuthEvents | Where-Object { $_.IsMetadataError }
    if ($metadataErrors.Count -gt 0) {
        Write-Host ""
        Write-Log -Message "*** METADATA RETRIEVAL ERRORS: $($metadataErrors.Count) ***" -Level "ERROR" -Source "Correlation"
        foreach ($err in $metadataErrors) {
            $shortMsg = if ($err.Message.Length -gt 150) { $err.Message.Substring(0, 150) + "..." } else { $err.Message }
            Write-Log -Message "$($err.DateTime) | $($err.Server) | Event $($err.EventId) | $shortMsg" -Level "EVENT" -Source "Correlation"
        }
    }
    
    # Correlate OAuth errors with XML fallback
    $xmlFallbacks = $AutodiscoverRequests | Where-Object { $_.UrlStem -match "\.xml" }
    
    if ($metadataErrors.Count -gt 0 -and $xmlFallbacks.Count -gt 0) {
        Write-Host ""
        Write-Log -Message "--- TIME CORRELATION: OAuth Errors vs XML Fallbacks ---" -Level "INFO" -Source "Correlation"
        
        foreach ($oauthErr in $metadataErrors) {
            try {
                $oauthTime = [DateTime]::Parse($oauthErr.DateTime)
                
                # Find XML requests within 60 seconds of this OAuth error
                foreach ($xml in $xmlFallbacks) {
                    try {
                        $xmlTime = [DateTime]::Parse($xml.DateTime)
                        $timeDiff = [Math]::Abs(($xmlTime - $oauthTime).TotalSeconds)
                        
                        if ($timeDiff -lt 60) {
                            Write-Log -Message "*** CORRELATION FOUND ***" -Level "CORRELATION" -Source "Correlation"
                            Write-Log -Message "  OAuth Error: $($oauthErr.DateTime) on $($oauthErr.Server)" -Level "EVENT" -Source "Correlation"
                            Write-Log -Message "  XML Fallback: $($xml.DateTime) on $($xml.Server) (within $([math]::Round($timeDiff, 1))s)" -Level "XML" -Source "Correlation"
                            Write-Log -Message "  This suggests OAuth failure is causing legacy auth fallback!" -Level "ERROR" -Source "Correlation"
                        }
                    } catch { }
                }
            } catch { }
        }
    }
}
#endregion

#region Main Execution
function Invoke-Analysis {
    Write-Section -Title "COLLECTING LOGS FROM EXCHANGE SERVERS"
    
    $allAutodiscoverRequests = @()
    $allOAuthEvents = @()
    
    foreach ($server in $ExchangeServers) {
        Write-Host "Processing $server..." -ForegroundColor Yellow
        
        # Get Autodiscover logs
        $adrLogs = Get-AutodiscoverLogs -Server $server -Since $script:AnalysisStartTime -FilterEmail $UserEmail
        Write-Log -Message "Found $($adrLogs.Count) autodiscover requests" -Level "INFO" -Source $server
        $allAutodiscoverRequests += $adrLogs
        
        # Get OAuth events
        $oauthLogs = Get-OAuthEventLogs -Server $server -Since $script:AnalysisStartTime
        Write-Log -Message "Found $($oauthLogs.Count) OAuth events" -Level "INFO" -Source $server
        $allOAuthEvents += $oauthLogs
    }
    
    # Store for reporting
    $script:AutodiscoverRequests = $allAutodiscoverRequests
    $script:OAuthEvents = $allOAuthEvents
    
    # Run analysis
    Invoke-AutodiscoverPatternAnalysis -Requests $allAutodiscoverRequests
    Compare-EventTimestamps -AutodiscoverRequests $allAutodiscoverRequests -OAuthEvents $allOAuthEvents
}

# Run initial analysis
Invoke-Analysis

# If TailMode, keep monitoring
if ($TailMode) {
    Write-Section -Title "CONTINUOUS MONITORING (Ctrl+C to stop)"
    
    $lastCheck = Get-Date
    
    try {
        while ($true) {
            Start-Sleep -Seconds $RefreshIntervalSeconds
            
            $newRequests = @()
            $newEvents = @()
            
            foreach ($server in $ExchangeServers) {
                $adr = Get-AutodiscoverLogs -Server $server -Since $lastCheck -FilterEmail $UserEmail
                $oauth = Get-OAuthEventLogs -Server $server -Since $lastCheck
                
                $newRequests += $adr
                $newEvents += $oauth
            }
            
            # Report new entries
            foreach ($req in $newRequests) {
                $level = if ($req.UrlStem -match "\.xml") { "XML" } else { "JSON" }
                Write-Log -Message "$($req.Server) | $($req.Method) $($req.UrlStem) -> HTTP $($req.HttpStatus)" -Level $level -Source "Live"
            }
            
            foreach ($evt in $newEvents) {
                $shortMsg = if ($evt.Message.Length -gt 100) { $evt.Message.Substring(0, 100) + "..." } else { $evt.Message }
                Write-Log -Message "$($evt.Server) | Event $($evt.EventId) | $shortMsg" -Level "EVENT" -Source "Live"
            }
            
            $lastCheck = Get-Date
        }
    } catch {
        # Ctrl+C pressed
    }
}
#endregion

#region Save Report and Key Findings

# Calculate all metrics for findings
$jsonRequests = $script:AutodiscoverRequests | Where-Object { $_.UrlStem -match "\.json" }
$xmlRequests = $script:AutodiscoverRequests | Where-Object { $_.UrlStem -match "\.xml" }
$jsonCount = $jsonRequests.Count
$xmlCount = $xmlRequests.Count
$jsonV1Count = ($jsonRequests | Where-Object { $_.UrlStem -match "/v1\.0/" }).Count
$metadataErrors = $script:OAuthEvents | Where-Object { $_.IsMetadataError }
$metadataErrorCount = $metadataErrors.Count

# Problem XML requests (401 with no AnchorMailbox)
$problemXmlRequests = $xmlRequests | Where-Object { 
    $_.HttpStatus -eq "401" -and 
    ([string]::IsNullOrWhiteSpace($_.AnchorMailbox) -or $_.AnchorMailbox -eq "")
}
$problemXmlCount = $problemXmlRequests.Count

# Count fallback patterns (JSON followed by XML within 10 seconds)
$fallbackCount = 0
$sortedRequests = $script:AutodiscoverRequests | Sort-Object DateTime
for ($i = 0; $i -lt $sortedRequests.Count - 1; $i++) {
    $current = $sortedRequests[$i]
    $next = $sortedRequests[$i + 1]
    if ($current.UrlStem -match "\.json" -and $next.UrlStem -match "\.xml") {
        try {
            $timeDiff = ([DateTime]::Parse($next.DateTime) - [DateTime]::Parse($current.DateTime)).TotalSeconds
            if ($timeDiff -lt 10) { $fallbackCount++ }
        } catch { }
    }
}

# Count correlations (OAuth error within 60s of XML fallback)
$correlationCount = 0
foreach ($oauthErr in $metadataErrors) {
    try {
        $oauthTime = [DateTime]::Parse($oauthErr.DateTime)
        foreach ($xml in $xmlRequests) {
            try {
                $xmlTime = [DateTime]::Parse($xml.DateTime)
                $timeDiff = [Math]::Abs(($xmlTime - $oauthTime).TotalSeconds)
                if ($timeDiff -lt 60) { $correlationCount++; break }
            } catch { }
        }
    } catch { }
}

# Determine correlation confidence
$correlationConfidence = "NONE"
if ($correlationCount -gt 0 -and $metadataErrorCount -gt 0) {
    $correlationRatio = $correlationCount / $metadataErrorCount
    if ($correlationRatio -ge 0.8) { $correlationConfidence = "STRONG" }
    elseif ($correlationRatio -ge 0.5) { $correlationConfidence = "MODERATE" }
    elseif ($correlationRatio -gt 0) { $correlationConfidence = "WEAK" }
}

Write-Section -Title "KEY FINDINGS"

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor White
Write-Host "║                         ANALYSIS RESULTS                         ║" -ForegroundColor White
Write-Host "╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor White

# Finding 1: XML Fallback Detected?
$xmlFallbackDetected = $xmlCount -gt 0
$finding1Color = if ($xmlFallbackDetected) { "Red" } else { "Green" }
$finding1Status = if ($xmlFallbackDetected) { "YES - $xmlCount XML request(s)" } else { "NO" }
Write-Host "║  [1] Legacy XML Fallback Detected?     " -NoNewline -ForegroundColor White
Write-Host "$($finding1Status.PadRight(26))" -NoNewline -ForegroundColor $finding1Color
Write-Host "║" -ForegroundColor White

# Finding 2: Problem Pattern (401 + no AnchorMailbox)?
$problemPatternDetected = $problemXmlCount -gt 0
$finding2Color = if ($problemPatternDetected) { "Red" } else { "Green" }
$finding2Status = if ($problemPatternDetected) { "YES - $problemXmlCount occurrence(s)" } else { "NO" }
Write-Host "║  [2] 401 Error + No AnchorMailbox?     " -NoNewline -ForegroundColor White
Write-Host "$($finding2Status.PadRight(26))" -NoNewline -ForegroundColor $finding2Color
Write-Host "║" -ForegroundColor White

# Finding 3: OAuth Metadata Errors?
$oauthErrorsDetected = $metadataErrorCount -gt 0
$finding3Color = if ($oauthErrorsDetected) { "Red" } else { "Green" }
$finding3Status = if ($oauthErrorsDetected) { "YES - $metadataErrorCount error(s)" } else { "NO" }
Write-Host "║  [3] OAuth Metadata Retrieval Errors?  " -NoNewline -ForegroundColor White
Write-Host "$($finding3Status.PadRight(26))" -NoNewline -ForegroundColor $finding3Color
Write-Host "║" -ForegroundColor White

# Finding 4: JSON->XML Fallback Sequences?
$fallbackSequenceDetected = $fallbackCount -gt 0
$finding4Color = if ($fallbackSequenceDetected) { "Yellow" } else { "Green" }
$finding4Status = if ($fallbackSequenceDetected) { "YES - $fallbackCount sequence(s)" } else { "NO" }
Write-Host "║  [4] JSON->XML Fallback Sequences?     " -NoNewline -ForegroundColor White
Write-Host "$($finding4Status.PadRight(26))" -NoNewline -ForegroundColor $finding4Color
Write-Host "║" -ForegroundColor White

# Finding 5: Correlation Confidence
$finding5Color = switch ($correlationConfidence) {
    "STRONG" { "Red" }
    "MODERATE" { "Yellow" }
    "WEAK" { "Yellow" }
    default { "Green" }
}
$finding5Status = "$correlationConfidence ($correlationCount correlation(s))"
Write-Host "║  [5] OAuth Error <-> XML Correlation?  " -NoNewline -ForegroundColor White
Write-Host "$($finding5Status.PadRight(26))" -NoNewline -ForegroundColor $finding5Color
Write-Host "║" -ForegroundColor White

Write-Host "╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor White
Write-Host "║                           STATISTICS                             ║" -ForegroundColor White
Write-Host "╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor White
Write-Host "║  Total Autodiscover Requests:  $($script:AutodiscoverRequests.Count.ToString().PadRight(35))║" -ForegroundColor Gray
Write-Host "║    - JSON endpoint (Modern Auth):  $($jsonCount.ToString().PadRight(31))║" -ForegroundColor Green
Write-Host "║    - JSON v1.0 (full OAuth flow):  $($jsonV1Count.ToString().PadRight(31))║" -ForegroundColor Green
Write-Host "║    - XML endpoint (Legacy Auth):   $($xmlCount.ToString().PadRight(31))║" -ForegroundColor $(if ($xmlCount -gt 0) { "Red" } else { "Gray" })
Write-Host "║  Total OAuth Events:  $($script:OAuthEvents.Count.ToString().PadRight(44))║" -ForegroundColor Gray
Write-Host "║    - Metadata retrieval errors:  $($metadataErrorCount.ToString().PadRight(33))║" -ForegroundColor $(if ($metadataErrorCount -gt 0) { "Red" } else { "Gray" })
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor White

# Add to log entries
$script:LogEntries += ""
$script:LogEntries += "======================================================================"
$script:LogEntries += "KEY FINDINGS"
$script:LogEntries += "======================================================================"
$script:LogEntries += ""
$script:LogEntries += "[1] Legacy XML Fallback Detected?      $finding1Status"
$script:LogEntries += "[2] 401 Error + No AnchorMailbox?      $finding2Status"
$script:LogEntries += "[3] OAuth Metadata Retrieval Errors?   $finding3Status"
$script:LogEntries += "[4] JSON->XML Fallback Sequences?      $finding4Status"
$script:LogEntries += "[5] OAuth Error <-> XML Correlation?   $finding5Status"
$script:LogEntries += ""
$script:LogEntries += "STATISTICS:"
$script:LogEntries += "  Total Autodiscover Requests: $($script:AutodiscoverRequests.Count)"
$script:LogEntries += "    - JSON endpoint (Modern Auth): $jsonCount"
$script:LogEntries += "    - JSON v1.0 (full OAuth flow): $jsonV1Count"
$script:LogEntries += "    - XML endpoint (Legacy Auth): $xmlCount"
$script:LogEntries += "  Total OAuth Events: $($script:OAuthEvents.Count)"
$script:LogEntries += "    - Metadata retrieval errors: $metadataErrorCount"

# Recommendations based on findings
Write-Host ""
Write-Section -Title "RECOMMENDATIONS"

$hasIssues = $xmlFallbackDetected -or $oauthErrorsDetected -or $problemPatternDetected

if (-not $hasIssues) {
    Write-Host "  [OK] No issues detected in the analyzed time period." -ForegroundColor Green
    Write-Host "  If intermittent failures are occurring, try:" -ForegroundColor Gray
    Write-Host "    - Increasing -HoursBack to capture more data" -ForegroundColor Gray
    Write-Host "    - Running in -TailMode during active failure reproduction" -ForegroundColor Gray
    $script:LogEntries += "[OK] No issues detected in the analyzed time period."
} else {
    $recommendationNum = 1
    
    if ($correlationConfidence -eq "STRONG" -or $correlationConfidence -eq "MODERATE") {
        Write-Host "  [$recommendationNum] CRITICAL: OAuth metadata errors correlate with XML fallbacks" -ForegroundColor Red
        Write-Host "      The OAuth metadata retrieval failures appear to be causing" -ForegroundColor White
        Write-Host "      the client to fall back to legacy XML autodiscover." -ForegroundColor White
        Write-Host ""
        Write-Host "      ACTION: Check connectivity to the OAuth metadata URL:" -ForegroundColor Yellow
        Write-Host "      - Identify the URL from Get-PartnerApplication | FL AuthMetadataUrl" -ForegroundColor Gray
        Write-Host "      - Test connectivity: Invoke-WebRequest -Uri <URL> -UseBasicParsing" -ForegroundColor Gray
        Write-Host "      - Check for proxy/firewall blocking or SSL inspection" -ForegroundColor Gray
        $script:LogEntries += "[$recommendationNum] CRITICAL: OAuth metadata errors correlate with XML fallbacks"
        $script:LogEntries += "    ACTION: Check connectivity to OAuth metadata URL"
        $recommendationNum++
        Write-Host ""
    }
    
    if ($oauthErrorsDetected) {
        Write-Host "  [$recommendationNum] OAuth Metadata Retrieval Errors Detected" -ForegroundColor Red
        Write-Host "      Exchange is failing to retrieve OAuth metadata from partner applications." -ForegroundColor White
        Write-Host ""
        Write-Host "      ACTIONS:" -ForegroundColor Yellow
        Write-Host "      - Check network connectivity from affected servers to metadata URLs" -ForegroundColor Gray
        Write-Host "      - Verify no proxy/firewall is blocking or inspecting SSL traffic" -ForegroundColor Gray
        Write-Host "      - Review Get-PartnerApplication for the failing metadata URL" -ForegroundColor Gray
        Write-Host "      - Check if the Lync/SfB server (if applicable) is accessible" -ForegroundColor Gray
        $script:LogEntries += "[$recommendationNum] OAuth Metadata Retrieval Errors Detected"
        $script:LogEntries += "    ACTION: Check network connectivity to metadata URLs"
        $recommendationNum++
        Write-Host ""
    }
    
    if ($problemPatternDetected) {
        Write-Host "  [$recommendationNum] Client Failing with 401 on Legacy XML Endpoint" -ForegroundColor Red
        Write-Host "      The client is falling back to legacy autodiscover.xml and failing" -ForegroundColor White
        Write-Host "      because the server (correctly) requires authentication." -ForegroundColor White
        Write-Host ""
        Write-Host "      ROOT CAUSE: The client is not receiving proper Modern Auth guidance" -ForegroundColor Yellow
        Write-Host "      from the initial autodiscover.json response, causing legacy fallback." -ForegroundColor Yellow
        $script:LogEntries += "[$recommendationNum] Client Failing with 401 on Legacy XML Endpoint"
        $script:LogEntries += "    ROOT CAUSE: Client not receiving Modern Auth guidance"
        $recommendationNum++
        Write-Host ""
    }
    
    if ($fallbackSequenceDetected -and -not $oauthErrorsDetected) {
        Write-Host "  [$recommendationNum] JSON->XML Fallback Without OAuth Errors" -ForegroundColor Yellow
        Write-Host "      Clients are falling back to XML but no OAuth errors were logged." -ForegroundColor White
        Write-Host ""
        Write-Host "      POSSIBLE CAUSES:" -ForegroundColor Yellow
        Write-Host "      - The autodiscover.json response content may be incorrect" -ForegroundColor Gray
        Write-Host "      - A proxy may be modifying the autodiscover.json response" -ForegroundColor Gray
        Write-Host "      - Client-side caching of stale autodiscover data" -ForegroundColor Gray
        Write-Host ""
        Write-Host "      ACTION: Capture and compare autodiscover.json responses from" -ForegroundColor Gray
        Write-Host "      different servers to check for inconsistencies." -ForegroundColor Gray
        $script:LogEntries += "[$recommendationNum] JSON->XML Fallback Without OAuth Errors"
        $script:LogEntries += "    ACTION: Compare autodiscover.json responses across servers"
        $recommendationNum++
        Write-Host ""
    }
    
    if ($xmlFallbackDetected -and $jsonV1Count -eq 0) {
        Write-Host "  [$recommendationNum] No v1.0 JSON Requests Observed" -ForegroundColor Yellow
        Write-Host "      Clients are never reaching the v1.0 autodiscover endpoint." -ForegroundColor White
        Write-Host "      The initial autodiscover.json response may not be directing" -ForegroundColor White
        Write-Host "      clients to the v1.0 endpoint for OAuth authentication." -ForegroundColor White
        Write-Host ""
        Write-Host "      ACTION: Verify the autodiscover.json response contains proper" -ForegroundColor Gray
        Write-Host "      OAuth endpoint information." -ForegroundColor Gray
        $script:LogEntries += "[$recommendationNum] No v1.0 JSON Requests Observed"
        $script:LogEntries += "    ACTION: Verify autodiscover.json contains OAuth endpoints"
        $recommendationNum++
        Write-Host ""
    }
}

# Save to file
Write-Host ""
try {
    $script:LogEntries | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Report saved to: $OutputPath" -ForegroundColor Green
} catch {
    Write-Host "Failed to save report: $_" -ForegroundColor Red
}
#endregion

# VERSION: 2026-02-05 UTC
<#
.SYNOPSIS
    Diagnose Auth Server configuration issues for Exchange HMA.

.DESCRIPTION
    This script analyzes Auth Server configuration to identify:
    - Empty certificate caches (no thumbprint stored)
    - Deprecated ACS (Azure Access Control Service) endpoints
    - Unreachable custom/partner Auth Server endpoints
    - Misconfigured or disabled Auth Servers
    
    Use this script when Stale-OAuth-Remediation.ps1 shows:
    - "NO CACHE - No certificate currently cached"
    - ACS endpoint returning 0 thumbprints
    - Connection errors to custom metadata endpoints

.PARAMETER TestConnectivity
    Test connectivity to all Auth Server metadata endpoints.

.PARAMETER ShowRecommendations
    Display recommendations for fixing identified issues.

.PARAMETER ExportReport
    Export findings to a text file.

.EXAMPLE
    .\Diagnose-AuthServerIssues.ps1
    # Basic analysis of all Auth Servers

.EXAMPLE
    .\Diagnose-AuthServerIssues.ps1 -TestConnectivity -ShowRecommendations
    # Full analysis with connectivity tests and recommendations

.NOTES
    Author: HMA Troubleshooting Toolkit
    Date: 2026-02-05
    
    Run from Exchange Management Shell.
#>

param(
    [switch]$TestConnectivity,
    [switch]$ShowRecommendations,
    [switch]$ExportReport,
    [string]$OutputPath = ".\AuthServer-Diagnosis-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
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

function Test-AuthServerEndpoint {
    param(
        [string]$Url,
        [int]$TimeoutSeconds = 15
    )
    
    $result = @{
        Url = $Url
        Reachable = $false
        StatusCode = $null
        SSLIssuer = $null
        CertificatesFound = 0
        Error = $null
        IsDeprecated = $false
        ResponseTime = $null
    }
    
    # Check for deprecated ACS endpoints
    if ($Url -match "accounts\.accesscontrol\.windows\.net") {
        $result.IsDeprecated = $true
    }
    
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        
        # First check TLS certificate
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.Method = "GET"
        $request.Timeout = $TimeoutSeconds * 1000
        $request.AllowAutoRedirect = $true
        
        try {
            $response = $request.GetResponse()
            $result.StatusCode = [int]$response.StatusCode
            $result.Reachable = $true
            
            # Get SSL certificate info
            $cert = $request.ServicePoint.Certificate
            if ($cert) {
                $result.SSLIssuer = $cert.Issuer
            }
            
            # Read response to count certificates
            $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
            $content = $reader.ReadToEnd()
            $reader.Close()
            $response.Close()
            
            # Count certificates in response
            if ($Url -match "\.xml$|federationmetadata") {
                # XML format - count X509Certificate elements
                $certMatches = [regex]::Matches($content, "<X509Certificate>")
                $result.CertificatesFound = $certMatches.Count
            }
            else {
                # JSON format - count x5c arrays
                $certMatches = [regex]::Matches($content, '"x5c"\s*:\s*\[')
                $result.CertificatesFound = $certMatches.Count
            }
        }
        catch [System.Net.WebException] {
            $result.Error = $_.Exception.Message
            if ($_.Exception.Response) {
                $result.StatusCode = [int]$_.Exception.Response.StatusCode
            }
            
            # Still try to get SSL info even on error
            $cert = $request.ServicePoint.Certificate
            if ($cert) {
                $result.SSLIssuer = $cert.Issuer
            }
        }
        
        $stopwatch.Stop()
        $result.ResponseTime = $stopwatch.ElapsedMilliseconds
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

function Get-AuthServerAnalysis {
    param([object]$AuthServer)
    
    $analysis = @{
        Name = $AuthServer.Name
        Type = $AuthServer.Type
        Enabled = $AuthServer.Enabled
        IsDefault = $AuthServer.IsDefaultAuthorizationEndpoint
        MetadataUrl = $AuthServer.AuthMetadataUrl
        HasCachedCert = $false
        CachedThumbprint = $null
        Issues = @()
        Recommendations = @()
        Severity = "OK"
    }
    
    # Check for cached certificate
    if ($AuthServer.CurrentCertificateThumbprint) {
        $analysis.HasCachedCert = $true
        $analysis.CachedThumbprint = $AuthServer.CurrentCertificateThumbprint
    }
    else {
        $analysis.Issues += "No certificate cached (CurrentCertificateThumbprint is empty)"
        $analysis.Recommendations += "Run: Set-AuthServer -Identity '$($AuthServer.Name)' -RefreshAuthMetadata"
        $analysis.Severity = "Warning"
    }
    
    # Check for deprecated ACS
    if ($AuthServer.AuthMetadataUrl -match "accounts\.accesscontrol\.windows\.net") {
        $analysis.Issues += "Uses deprecated Azure Access Control Service (ACS)"
        $analysis.Recommendations += "ACS was retired in 2018. Consider disabling if not required."
        $analysis.Recommendations += "Modern HMA should use evoSTS (login.windows.net) as primary."
        if ($analysis.Severity -ne "Error") { $analysis.Severity = "Warning" }
    }
    
    # Check for custom/internal endpoints
    if ($AuthServer.AuthMetadataUrl -notmatch "login\.windows\.net|accounts\.accesscontrol\.windows\.net|login\.microsoftonline\.com") {
        $analysis.Issues += "Custom/partner Auth Server endpoint detected"
        $analysis.Recommendations += "Verify this endpoint is reachable from all Exchange servers"
        $analysis.Recommendations += "Check if this partner application is still in use"
    }
    
    # Check if disabled
    if (-not $AuthServer.Enabled) {
        $analysis.Issues += "Auth Server is DISABLED"
        $analysis.Severity = "Warning"
    }
    
    # Check IsDefaultAuthorizationEndpoint for evoSTS
    if ($AuthServer.Type -eq "AzureAD" -and -not $AuthServer.IsDefaultAuthorizationEndpoint) {
        $analysis.Issues += "AzureAD Auth Server is not set as default endpoint"
        $analysis.Recommendations += "Set-AuthServer -Identity '$($AuthServer.Name)' -IsDefaultAuthorizationEndpoint `$true"
        if ($analysis.Severity -ne "Error") { $analysis.Severity = "Warning" }
    }
    
    return $analysis
}

#endregion Functions

#region Main

Write-Banner "AUTH SERVER DIAGNOSTIC ANALYSIS"

# Check for Exchange Management Shell
try {
    $null = Get-Command Get-AuthServer -ErrorAction Stop
}
catch {
    Write-Status "This script must be run from Exchange Management Shell!" -Type Error
    exit 1
}

# Get all Auth Servers
Write-Section "Auth Server Configuration"

try {
    $authServers = Get-AuthServer -ErrorAction Stop
}
catch {
    Write-Status "Failed to get Auth Servers: $($_.Exception.Message)" -Type Error
    exit 1
}

if (-not $authServers) {
    Write-Status "No Auth Servers configured!" -Type Error
    exit 1
}

Write-Status "Found $($authServers.Count) Auth Server(s)" -Type Info
Write-Host ""

$allAnalysis = @()
$report = @()
$report += "AUTH SERVER DIAGNOSTIC REPORT"
$report += "=============================="
$report += "Generated: $(Get-Date)"
$report += ""

foreach ($authServer in $authServers) {
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Auth Server: " -NoNewline
    Write-Host "$($authServer.Name)" -ForegroundColor Cyan
    Write-Host "    Type:                 $($authServer.Type)"
    Write-Host "    Enabled:              " -NoNewline
    if ($authServer.Enabled) {
        Write-Host "Yes" -ForegroundColor Green
    } else {
        Write-Host "No" -ForegroundColor Red
    }
    Write-Host "    IsDefaultEndpoint:    $($authServer.IsDefaultAuthorizationEndpoint)"
    Write-Host "    Metadata URL:         $($authServer.AuthMetadataUrl)"
    Write-Host "    Cached Thumbprint:    " -NoNewline
    if ($authServer.CurrentCertificateThumbprint) {
        Write-Host "$($authServer.CurrentCertificateThumbprint)" -ForegroundColor Green
    } else {
        Write-Host "(NONE)" -ForegroundColor Red
    }
    
    # Analyze this Auth Server
    $analysis = Get-AuthServerAnalysis -AuthServer $authServer
    $allAnalysis += $analysis
    
    # Show issues
    if ($analysis.Issues.Count -gt 0) {
        Write-Host ""
        Write-Host "    Issues Found:" -ForegroundColor Yellow
        foreach ($issue in $analysis.Issues) {
            Write-Host "      [!] $issue" -ForegroundColor Yellow
        }
    }
    
    # Test connectivity if requested
    if ($TestConnectivity -and $authServer.AuthMetadataUrl) {
        Write-Host ""
        Write-Host "    Connectivity Test:" -ForegroundColor Cyan
        $connTest = Test-AuthServerEndpoint -Url $authServer.AuthMetadataUrl
        $analysis.ConnectivityTest = $connTest
        
        if ($connTest.Reachable) {
            Write-Host "      Status:       " -NoNewline
            Write-Host "REACHABLE ($($connTest.ResponseTime)ms)" -ForegroundColor Green
            Write-Host "      Certs Found:  " -NoNewline
            if ($connTest.CertificatesFound -gt 0) {
                Write-Host "$($connTest.CertificatesFound)" -ForegroundColor Green
            } else {
                Write-Host "0 (PROBLEM!)" -ForegroundColor Red
                $analysis.Issues += "Metadata endpoint returned 0 certificates"
                $analysis.Severity = "Error"
            }
            
            # Check SSL issuer
            if ($connTest.SSLIssuer) {
                $isMicrosoft = $connTest.SSLIssuer -match "Microsoft|DigiCert|Baltimore"
                Write-Host "      SSL Issuer:   " -NoNewline
                if ($isMicrosoft) {
                    Write-Host "OK (Microsoft CA)" -ForegroundColor Green
                } else {
                    Write-Host "$($connTest.SSLIssuer)" -ForegroundColor Red
                    $analysis.Issues += "Non-Microsoft SSL certificate detected (possible SSL inspection)"
                }
            }
        }
        else {
            Write-Host "      Status:       " -NoNewline
            Write-Host "FAILED" -ForegroundColor Red
            Write-Host "      Error:        $($connTest.Error)" -ForegroundColor Red
            $analysis.Issues += "Cannot reach metadata endpoint: $($connTest.Error)"
            $analysis.Severity = "Error"
        }
        
        if ($connTest.IsDeprecated) {
            Write-Host "      Notice:       " -NoNewline
            Write-Host "DEPRECATED SERVICE (ACS retired 2018)" -ForegroundColor Yellow
        }
    }
    
    Write-Host ""
    
    # Add to report
    $report += "AUTH SERVER: $($authServer.Name)"
    $report += "  Type: $($authServer.Type)"
    $report += "  Enabled: $($authServer.Enabled)"
    $report += "  URL: $($authServer.AuthMetadataUrl)"
    $report += "  Cached Cert: $(if ($authServer.CurrentCertificateThumbprint) { $authServer.CurrentCertificateThumbprint } else { 'NONE' })"
    $report += "  Severity: $($analysis.Severity)"
    if ($analysis.Issues.Count -gt 0) {
        $report += "  Issues:"
        foreach ($issue in $analysis.Issues) {
            $report += "    - $issue"
        }
    }
    $report += ""
}

# Summary
Write-Section "Summary"

$errorCount = ($allAnalysis | Where-Object { $_.Severity -eq "Error" }).Count
$warningCount = ($allAnalysis | Where-Object { $_.Severity -eq "Warning" }).Count
$okCount = ($allAnalysis | Where-Object { $_.Severity -eq "OK" }).Count

Write-Host ""
Write-Host "  Total Auth Servers:    $($allAnalysis.Count)"
Write-Host "  Status OK:             " -NoNewline
Write-Host "$okCount" -ForegroundColor Green
Write-Host "  Warnings:              " -NoNewline
if ($warningCount -gt 0) { Write-Host "$warningCount" -ForegroundColor Yellow } else { Write-Host "0" -ForegroundColor Gray }
Write-Host "  Errors:                " -NoNewline
if ($errorCount -gt 0) { Write-Host "$errorCount" -ForegroundColor Red } else { Write-Host "0" -ForegroundColor Gray }
Write-Host ""

# Check for common configurations
$hasEvoSts = $allAnalysis | Where-Object { $_.Type -eq "AzureAD" -and $_.MetadataUrl -match "login\.windows\.net" }
$hasAcs = $allAnalysis | Where-Object { $_.MetadataUrl -match "accounts\.accesscontrol\.windows\.net" }
$hasCustom = $allAnalysis | Where-Object { $_.MetadataUrl -notmatch "login\.windows\.net|accounts\.accesscontrol\.windows\.net|login\.microsoftonline\.com" }

if ($hasEvoSts) {
    $evoStatus = $hasEvoSts | Select-Object -First 1
    Write-Host "  evoSTS (Modern OAuth):     " -NoNewline
    if ($evoStatus.HasCachedCert) {
        Write-Host "CONFIGURED" -ForegroundColor Green
    } else {
        Write-Host "NO CACHE" -ForegroundColor Yellow
    }
}

if ($hasAcs) {
    Write-Host "  ACS (Legacy/Deprecated):   " -NoNewline
    Write-Host "PRESENT" -ForegroundColor Yellow
}

if ($hasCustom) {
    Write-Host "  Custom/Partner Servers:    " -NoNewline
    Write-Host "$($hasCustom.Count) found" -ForegroundColor Cyan
}

Write-Host ""

# Recommendations
if ($ShowRecommendations) {
    Write-Section "Recommendations"
    Write-Host ""
    
    $recCount = 0
    
    # No cached certs
    $noCachServers = $allAnalysis | Where-Object { -not $_.HasCachedCert }
    if ($noCachServers.Count -gt 0) {
        $recCount++
        Write-Host "  $recCount. REFRESH METADATA FOR EMPTY CACHE" -ForegroundColor Cyan
        Write-Host "     The following Auth Servers have no cached certificates:" -ForegroundColor White
        foreach ($srv in $noCachServers) {
            Write-Host "       - $($srv.Name)" -ForegroundColor Gray
        }
        Write-Host ""
        Write-Host "     Run these commands:" -ForegroundColor Yellow
        foreach ($srv in $noCachServers) {
            Write-Host "       Set-AuthServer -Identity '$($srv.Name)' -RefreshAuthMetadata" -ForegroundColor Gray
        }
        Write-Host ""
    }
    
    # Deprecated ACS
    if ($hasAcs) {
        $recCount++
        Write-Host "  $recCount. EVALUATE DEPRECATED ACS AUTH SERVER" -ForegroundColor Cyan
        Write-Host "     Azure Access Control Service (ACS) was retired in November 2018." -ForegroundColor White
        Write-Host "     Modern HMA uses evoSTS (login.windows.net) for OAuth." -ForegroundColor White
        Write-Host ""
        Write-Host "     Options:" -ForegroundColor Yellow
        Write-Host "       a) If not needed: Disable the ACS Auth Server" -ForegroundColor Gray
        Write-Host "          Set-AuthServer -Identity 'ACS - ...' -Enabled `$false" -ForegroundColor Gray
        Write-Host "       b) If needed for legacy apps: Keep but monitor for issues" -ForegroundColor Gray
        Write-Host ""
    }
    
    # Unreachable endpoints
    $unreachable = $allAnalysis | Where-Object { $_.ConnectivityTest -and -not $_.ConnectivityTest.Reachable }
    if ($unreachable.Count -gt 0) {
        $recCount++
        Write-Host "  $recCount. FIX UNREACHABLE METADATA ENDPOINTS" -ForegroundColor Red
        Write-Host "     The following endpoints cannot be reached:" -ForegroundColor White
        foreach ($srv in $unreachable) {
            Write-Host "       - $($srv.Name): $($srv.MetadataUrl)" -ForegroundColor Gray
            Write-Host "         Error: $($srv.ConnectivityTest.Error)" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "     Actions:" -ForegroundColor Yellow
        Write-Host "       - Verify DNS resolution for the endpoint" -ForegroundColor Gray
        Write-Host "       - Check firewall rules allow HTTPS (443) outbound" -ForegroundColor Gray
        Write-Host "       - Verify the partner application is running" -ForegroundColor Gray
        Write-Host "       - If no longer needed, disable the Auth Server" -ForegroundColor Gray
        Write-Host ""
    }
    
    # Zero certificates from endpoint
    $zeroCerts = $allAnalysis | Where-Object { $_.ConnectivityTest -and $_.ConnectivityTest.Reachable -and $_.ConnectivityTest.CertificatesFound -eq 0 }
    if ($zeroCerts.Count -gt 0) {
        $recCount++
        Write-Host "  $recCount. INVESTIGATE ENDPOINTS RETURNING NO CERTIFICATES" -ForegroundColor Red
        Write-Host "     The following endpoints are reachable but return no signing certificates:" -ForegroundColor White
        foreach ($srv in $zeroCerts) {
            Write-Host "       - $($srv.Name): $($srv.MetadataUrl)" -ForegroundColor Gray
        }
        Write-Host ""
        Write-Host "     This typically means:" -ForegroundColor Yellow
        Write-Host "       - The service is deprecated (ACS)" -ForegroundColor Gray
        Write-Host "       - The endpoint is misconfigured" -ForegroundColor Gray
        Write-Host "       - The partner application is not returning proper metadata" -ForegroundColor Gray
        Write-Host ""
    }
    
    # evoSTS not default
    $evoNotDefault = $allAnalysis | Where-Object { $_.Type -eq "AzureAD" -and -not $_.IsDefault }
    if ($evoNotDefault.Count -gt 0) {
        $recCount++
        Write-Host "  $recCount. SET EVOSTS AS DEFAULT AUTHORIZATION ENDPOINT" -ForegroundColor Cyan
        Write-Host "     For modern HMA, evoSTS should be the default:" -ForegroundColor White
        foreach ($srv in $evoNotDefault) {
            Write-Host "       Set-AuthServer -Identity '$($srv.Name)' -IsDefaultAuthorizationEndpoint `$true" -ForegroundColor Gray
        }
        Write-Host ""
    }
    
    if ($recCount -eq 0) {
        Write-Host "  No recommendations - all Auth Servers appear healthy." -ForegroundColor Green
        Write-Host ""
    }
}

# Export report
if ($ExportReport) {
    $report += ""
    $report += "SUMMARY"
    $report += "======="
    $report += "Total: $($allAnalysis.Count), OK: $okCount, Warnings: $warningCount, Errors: $errorCount"
    
    $report | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Report saved to: $OutputPath" -ForegroundColor Green
    Write-Host ""
}

Write-Host "Diagnosis complete." -ForegroundColor Cyan
Write-Host ""

#endregion Main

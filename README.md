# HMA Troubleshooting Toolkit

PowerShell scripts for diagnosing Hybrid Modern Authentication (HMA) issues with Exchange On-Premises and Outlook mobile clients.

## Problem Addressed

Intermittent authentication failures on mobile Outlook clients when connecting to on-premises Exchange mailboxes with Hybrid Modern Authentication configured.

## Scripts Included

| Script | Purpose | When to Use |
|--------|---------|-------------|
| `Get-HMADiagnostics.ps1` | Comprehensive HMA configuration collection from all Exchange servers | **Step 1** - Start here for full diagnostics |
| `Test-HmaEasNoEmptyBearer.ps1` | Tests OAuth flow without sending empty bearer tokens | **Step 2** - Validate OAuth authentication works |
| `Check-AuthPolicyBlocking.ps1` | Quick check for Authentication Policies blocking Modern Auth | **Quick Check** - Faster than full diagnostics |
| `Detect-ProxyAndSSLIssues.ps1` | Comprehensive proxy interference and SSL inspection detection | **Step 3** - When OAuth issues persist |
| `Stale-OAuth-Remediation.ps1` | Diagnose and fix stale OAuth certificate cache issues | **Step 4** - When "different certificate" errors detected |
| `Diagnose-AuthServerIssues.ps1` | Analyze Auth Server configuration (deprecated ACS, custom endpoints) | **Step 5** - When Auth Servers have empty caches or unreachable endpoints |

---

## About Test-HmaEasNoEmptyBearer.ps1

This script is an alternative to the Microsoft-published [Test-OAuthConnectivity](https://learn.microsoft.com/en-us/exchange/troubleshoot/administration/test-oauth-authentication-is-failing) cmdlet and the community [Test-HmaEas.ps1](https://github.com/mikepfeiffer/Test-HmaEas) script.

### Why a Different Approach?

| Original Approach | This Script's Approach |
|-------------------|------------------------|
| Sends an **empty bearer token** to trigger a 401 response | Acquires a **real OAuth token** from Azure AD first |
| Parses the `WWW-Authenticate` header to discover OAuth endpoints | Uses known Azure AD endpoints directly |
| Fails if the environment blocks empty bearer tokens | Works in restricted environments |
| No MFA support | **Supports MFA** via `-UseDeviceCode` switch |

### When to Use This Script

- Your environment **blocks empty bearer token requests** (security policy)
- The Remote Connectivity Analyzer test fails with connection reset errors
- `Test-OAuthConnectivity` or `Test-HmaEas.ps1` fail unexpectedly
- The user account has **MFA enabled** (use `-UseDeviceCode`)
- You need to test with a **federated (ADFS) domain** (use `-UseDeviceCode`)

### Related Resources

- [Microsoft Docs: Configure OAuth for Exchange Hybrid](https://learn.microsoft.com/en-us/exchange/configure-oauth-authentication-between-exchange-and-exchange-online-organizations-exchange-2013-help)
- [Microsoft Docs: Test-OAuthConnectivity](https://learn.microsoft.com/en-us/powershell/module/exchange/test-oauthconnectivity)
- [Test-HmaEas.ps1 (Original)](https://github.com/mikepfeiffer/Test-HmaEas) - Mike Pfeiffer's original HMA test script

---

## Troubleshooting Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         HMA TROUBLESHOOTING WORKFLOW                        │
└─────────────────────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────┐
    │  STEP 1: Run Get-HMADiagnostics.ps1  │
    │  (Collects full configuration)       │
    └──────────────────┬───────────────────┘
                       │
                       ▼
           ┌───────────────────────┐
           │  Issues Found?        │
           └───────────┬───────────┘
                       │
          ┌────────────┴────────────┐
          │                         │
          ▼                         ▼
    ┌──────────┐             ┌──────────────┐
    │   YES    │             │      NO      │
    └────┬─────┘             └──────┬───────┘
         │                          │
         ▼                          ▼
    Fix reported              ┌──────────────────────────────────────┐
    issues first              │  STEP 2: Run Test-HmaEasNoEmptyBearer│
                              │  (Validate OAuth flow works)         │
                              └──────────────────┬───────────────────┘
                                                 │
                                                 ▼
                                    ┌────────────────────────┐
                                    │  OAuth Test Passes?    │
                                    └───────────┬────────────┘
                                                │
                               ┌────────────────┴────────────────┐
                               │                                 │
                               ▼                                 ▼
                         ┌──────────┐                     ┌──────────────┐
                         │   YES    │                     │      NO      │
                         └────┬─────┘                     └──────┬───────┘
                              │                                  │
                              ▼                                  ▼
                    Issue is likely              ┌───────────────────────────────────────┐
                    client-side or               │  STEP 3: Run Detect-ProxyAndSSLIssues │
                    network path                 │  (Check for proxy/SSL interference)   │
                                                 └──────────────────┬────────────────────┘
                                                                    │
                                                                    ▼
                                                 ┌──────────────────────────────────────────┐
                                                 │  "Different certificate" errors found?   │
                                                 └──────────────────┬───────────────────────┘
                                                                    │
                                                   ┌────────────────┴────────────────┐
                                                   │                                 │
                                                   ▼                                 ▼
                                             ┌──────────┐                     ┌──────────────┐
                                             │   YES    │                     │      NO      │
                                             └────┬─────┘                     └──────┬───────┘
                                                  │                                  │
                                                  ▼                                  ▼
                                    ┌────────────────────────────────────┐    Other proxy/SSL
                                    │  STEP 4: Stale-OAuth-Remediation   │    issues detected -
                                    │  (Diagnose cache vs SSL inspection)│    work with network
                                    └────────────────────────────────────┘    team
```

### Quick Policy Check (Optional Shortcut)

If you suspect **Authentication Policies** are the issue and don't want to run the full diagnostics:

```powershell
.\Check-AuthPolicyBlocking.ps1 -UserEmail "user@contoso.com"
```

This runs much faster than `Get-HMADiagnostics.ps1` and focuses specifically on policies that block Modern Authentication.

---

## Step-by-Step Usage

### Step 1: Gather Full Diagnostics

```powershell
# Run from Exchange Management Shell
.\Get-HMADiagnostics.ps1 -TestMailbox "user@contoso.com"
```

**What it checks:**
- OAuth configuration on all Exchange servers
- Virtual directory authentication settings
- Certificate configuration and trust
- Authentication policies that may block Modern Auth
- MFA detection for the test user

**Review the output for:**
- `[CRITICAL]` - Must fix immediately
- `[WARNING]` - May cause issues
- `[INFO]` - Informational

### Step 2: Test OAuth Authentication

Based on the MFA detection from Step 1:

```powershell
# If NO MFA detected:
.\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "user@contoso.com" -Verbose

# If MFA IS detected:
.\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "user@contoso.com" -UseDeviceCode -Verbose
```

**What it validates:**
- Token acquisition from Azure AD
- Token acceptance by Exchange on-premises
- ActiveSync connectivity with OAuth

### Step 3: Check for Proxy Interference

If OAuth tests fail or issues persist despite correct configuration:

```powershell
# Auto-detect and scan ALL Exchange servers
.\Detect-ProxyAndSSLIssues.ps1

# Scan specific servers
.\Detect-ProxyAndSSLIssues.ps1 -ExchangeServers "EX01","EX02"

# Check last 48 hours for a specific user
.\Detect-ProxyAndSSLIssues.ps1 -HoursBack 48 -UserEmail "user@contoso.com"

# Scan specific servers
.\Detect-ProxyAndSSLIssues.ps1 -ExchangeServers "EX01","EX02"

# Skip live SSL certificate checks (log analysis only)
.\Detect-ProxyAndSSLIssues.ps1 -IncludeSSLCheck:$false

# Include Azure AD sign-in log analysis (requires Graph connection)
Connect-MgGraph -Scopes "AuditLog.Read.All"
.\Detect-ProxyAndSSLIssues.ps1 -IncludeAzureAD
```

**What it detects:**
- SSL/TLS inspection (certificate chain analysis to Azure AD)
- Empty/stripped Authorization headers (Bearer token removed)
- Certificate validation errors in OAuth and CAPI2 logs
- Connection resets and timeouts
- High 401 error rates
- NTLM/Basic fallback patterns (OAuth failing silently)
- Known proxy IP patterns and headers
- Azure AD sign-in failures (optional)

**Performance Tips:**
- Use `-IncludeSSLCheck:$false` for faster scans (skips live certificate checks)

### Step 4: Diagnose Certificate Cache Issues

If Step 3 detects "different certificate(s) have been found" errors (Event 2008), run the remediation script:

```powershell
# Quick status table - per-server connectivity summary (fast check)
.\Stale-OAuth-Remediation.ps1 -QuickStatus

# Quick mode - just check if cache is stale (for restricted environments)
.\Stale-OAuth-Remediation.ps1 -CacheCheckOnly

# Full mode - auto-detect servers, test connectivity, diagnose root cause
.\Stale-OAuth-Remediation.ps1

# Diagnose only without making changes
.\Stale-OAuth-Remediation.ps1 -DiagnoseOnly

# Test from local server only (skip remote server testing)
.\Stale-OAuth-Remediation.ps1 -LocalOnly
```

**-QuickStatus output example:**
```
  SERVER             CONNECT      SSL STATUS   CACHE        NOTES
  ------             -------      ----------   -----        -----
  YOUREXCH01         OK           Clean        CURRENT      
  YOUREXCH02         OK           INTERCEPT    N/A*         Corporate Proxy CA
  YOUREXCH03         UNREACH      N/A          N/A          Cannot reach server

  Servers: 3 total | 1 OK | 2 issues | Cache: CURRENT | SSL Intercept: 1
```

**What it checks:**
- Compares cached certificate thumbprints vs live Azure AD certificates
- Tests Azure AD connectivity from each Exchange server
- Detects SSL inspection by examining TLS certificate issuers
- Generates per-server diagnostic report

**Possible outcomes:**

| Finding | Meaning | Action |
|---------|---------|--------|
| Cache STALE, No SSL inspection | Microsoft rotated certs, Exchange didn't update | Refresh metadata (script will prompt) |
| Cache CURRENT, SSL inspection detected | Proxy intercepting OAuth traffic | Work with network team to bypass SSL inspection |
| Cache STALE, SSL inspection detected | Can't refresh because proxy blocks it | Fix SSL inspection FIRST, then refresh |
| Cache CURRENT, No SSL inspection | Intermittent SSL inspection | Investigate time-based routing or run during failure window |

---

## Quick Reference Commands

```powershell
# === FULL DIAGNOSTIC RUN ===
.\Get-HMADiagnostics.ps1 -TestMailbox "user@contoso.com"

# === QUICK POLICY CHECK ===
.\Check-AuthPolicyBlocking.ps1 -UserEmail "user@contoso.com"

# === TEST OAUTH (no MFA) ===
.\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "user@contoso.com" -Verbose

# === TEST OAUTH (with MFA) ===
.\Test-HmaEasNoEmptyBearer.ps1 -EmailAddress "user@contoso.com" -UseDeviceCode -Verbose

# === PROXY AND SSL INSPECTION CHECK ===
.\Detect-ProxyAndSSLIssues.ps1 -HoursBack 24

# === QUICK SERVER STATUS TABLE ===
.\Stale-OAuth-Remediation.ps1 -QuickStatus

# === CERTIFICATE CACHE CHECK (quick mode) ===
.\Stale-OAuth-Remediation.ps1 -CacheCheckOnly

# === CERTIFICATE CACHE REMEDIATION (full mode) ===
.\Stale-OAuth-Remediation.ps1
```

---

## Enhanced MFA Detection (Optional)

For better MFA detection, connect to Azure AD before running diagnostics:

```powershell
# Install MSOnline module (one-time)
Install-Module MSOnline -Force

# Connect to Azure AD
Connect-MsolService

# Now run diagnostics - will query user's MFA status automatically
.\Get-HMADiagnostics.ps1 -TestMailbox "user@contoso.com"
```

---

## Script Details

### Get-HMADiagnostics.ps1
- Auto-discovers all Exchange CAS servers
- Collects OAuth, virtual directory, and certificate configuration
- Automated misconfiguration detection (Critical/Warning/Info)
- Remote data collection from all servers
- Includes Authentication Policy analysis (same as Check-AuthPolicyBlocking.ps1)
- **MFA Detection:**
  - Scans OAuth logs for MFA error codes (AADSTS50076, AADSTS50079, etc.)
  - Queries Azure AD for user's MFA methods and enforcement status (if connected)
  - Provides confidence level: Confirmed, High, or Unknown
  - Smart recommendation for Standard vs Device Code mode

### Check-AuthPolicyBlocking.ps1
- Quick focused check for Authentication Policies only
- Identifies policies that block Modern Auth for:
  - ActiveSync
  - Autodiscover
  - MAPI
  - EWS
  - OWA
- Can check a specific user's assigned policy
- Much faster than full diagnostics when you only need policy info

### Test-HmaEasNoEmptyBearer.ps1
- Works in environments that block empty bearer token requests
- Supports MFA via Device Code flow (`-UseDeviceCode`)
- Detailed HTTP request/response logging
- JWT token decoding and claim analysis
- Error code analysis with recommendations

### Detect-ProxyAndSSLIssues.ps1
- **Comprehensive proxy and SSL inspection detection**
- **Auto-detects all Exchange servers** in the organization
- **Generates 2 output files:**
  - Summary Report (`ProxySSL-Analysis-[timestamp].txt`) - Findings and recommendations
  - Full Transcript (`ProxySSL-Analysis-[timestamp]-Transcript.txt`) - Complete verbose output for root cause analysis
- **Live SSL certificate chain verification** to Azure AD endpoints
- Scans HttpProxy logs (EAS, Autodiscover, MAPI, EWS)
- Scans IIS logs for error patterns
- Queries Windows Event Logs remotely (Schannel, OAuth, CAPI2)
- Detects empty/stripped Authorization headers
- Analyzes authentication fallback patterns (NTLM/Basic instead of OAuth)
- Optional Azure AD sign-in log analysis
- Groups findings by server and pattern type
- Provides evidence strength scoring (Strong/Moderate/Weak)
- Pre-validates server connectivity before scanning

### Stale-OAuth-Remediation.ps1
- **Diagnoses and remediates "different certificate(s) have been found" errors**
- **Three modes:**
  - Quick Status (`-QuickStatus`) - Per-server connectivity table only, no detailed analysis
  - Quick (`-CacheCheckOnly`) - Cache vs Azure AD comparison for restricted environments
  - Full - Complete diagnostics with connectivity tests and remediation prompts
- Compares Exchange cached certificate thumbprints vs live Azure AD certificates
- Auto-detects all Exchange servers in the organization
- Tests Azure AD metadata endpoint connectivity from each server
- Detects SSL inspection by examining TLS certificate issuers (non-Microsoft CAs)
- Generates per-server diagnostic report with columns: SERVER, CONNECT, SSL STATUS, CACHE, NOTES
- **Smart remediation logic:**
  - If cache is stale and no SSL inspection → Prompts to refresh metadata
  - If cache is current → Identifies SSL inspection as root cause, skips remediation
  - If SSL inspection detected → Blocks remediation, advises network team action
- Supports manual remediation steps with copy-paste commands
- `-DiagnoseOnly` mode for analysis without changes
- `-LocalOnly` mode when remote testing is blocked

### Diagnose-AuthServerIssues.ps1
- **Analyzes Auth Server configuration to identify problematic endpoints**
- Detects Auth Servers with empty certificate caches (no thumbprint stored)
- Identifies deprecated ACS (Azure Access Control Service) endpoints (retired 2018)
- Finds custom/partner Auth Server endpoints that may be unreachable
- `-TestConnectivity` tests each metadata endpoint for reachability and certificate count
- `-ShowRecommendations` provides actionable remediation steps
- `-ExportReport` saves findings to a text file
- Useful when Stale-OAuth-Remediation shows:
  - "NO CACHE - No certificate currently cached"
  - ACS endpoint returning 0 thumbprints
  - Connection errors to custom metadata endpoints

---

## Requirements

| Script | Requirements |
|--------|-------------|
| Get-HMADiagnostics.ps1 | Exchange Management Shell, Admin rights on Exchange servers |
| Check-AuthPolicyBlocking.ps1 | Exchange Management Shell |
| Test-HmaEasNoEmptyBearer.ps1 | PowerShell 5.1+, Network access to Azure AD |
| Detect-ProxyAndSSLIssues.ps1 | Exchange Management Shell, Admin share access to servers, WinRM access |
| Stale-OAuth-Remediation.ps1 | Exchange Management Shell, WinRM access (full mode), Network access to Azure AD |
| Diagnose-AuthServerIssues.ps1 | Exchange Management Shell, Network access to Azure AD |

---

## License

MIT License - Feel free to use and modify.

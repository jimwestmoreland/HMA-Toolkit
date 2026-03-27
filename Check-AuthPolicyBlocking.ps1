<#
.SYNOPSIS
    Quick check for Authentication Policies blocking Modern Authentication.
    
.DESCRIPTION
    Scans all Exchange Authentication Policies to identify any that block
    Modern Authentication for various protocols (ActiveSync, Autodiscover, etc.)
    
    Run this in Exchange Management Shell to quickly identify if authentication
    policies are causing OAuth/Modern Auth failures.

.PARAMETER UserEmail
    Optional. Check a specific user's authentication policy assignment.

.EXAMPLE
    .\Check-AuthPolicyBlocking.ps1
    # List all policies that block modern auth
    
.EXAMPLE
    .\Check-AuthPolicyBlocking.ps1 -UserEmail "user@contoso.com"
    # Check if a specific user has a blocking policy

.NOTES
    Author: HMA Troubleshooting Toolkit
    Date: 2026-01-26
    Requires: Exchange Management Shell
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$UserEmail
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Authentication Policy Blocking Check" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Get all authentication policies
try {
    $policies = Get-AuthenticationPolicy
} catch {
    Write-Host "[ERROR] Failed to retrieve authentication policies. Are you in Exchange Management Shell?" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}

if (-not $policies) {
    Write-Host "[OK] No custom authentication policies found. Modern Auth is allowed by default.`n" -ForegroundColor Green
} else {
    Write-Host "Found $($policies.Count) Authentication Policy(ies):`n" -ForegroundColor White
    
    $blockingPolicies = @()
    
    foreach ($policy in $policies) {
        Write-Host "Policy: $($policy.Name)" -ForegroundColor Yellow
        Write-Host "  ----------------------------------------"
        
        $hasBlocking = $false
        $blockingProtocols = @()
        
        # Check each BlockModernAuth setting
        $blockSettings = @(
            @{ Name = "ActiveSync"; Value = $policy.BlockModernAuthActiveSync },
            @{ Name = "Autodiscover"; Value = $policy.BlockModernAuthAutodiscover },
            @{ Name = "IMAP"; Value = $policy.BlockModernAuthImap },
            @{ Name = "MAPI"; Value = $policy.BlockModernAuthMapi },
            @{ Name = "OfflineAddressBook"; Value = $policy.BlockModernAuthOfflineAddressBook },
            @{ Name = "POP"; Value = $policy.BlockModernAuthPop },
            @{ Name = "RPC"; Value = $policy.BlockModernAuthRpc },
            @{ Name = "WebServices"; Value = $policy.BlockModernAuthWebServices }
        )
        
        foreach ($setting in $blockSettings) {
            if ($setting.Value -eq $true) {
                Write-Host "  [BLOCKED] BlockModernAuth$($setting.Name): True" -ForegroundColor Red
                $hasBlocking = $true
                $blockingProtocols += $setting.Name
            } else {
                Write-Host "  [OK]      BlockModernAuth$($setting.Name): False" -ForegroundColor Green
            }
        }
        
        if ($hasBlocking) {
            $blockingPolicies += [PSCustomObject]@{
                PolicyName = $policy.Name
                BlockingProtocols = $blockingProtocols -join ", "
            }
        }
        
        Write-Host ""
    }
    
    # Summary
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    if ($blockingPolicies.Count -gt 0) {
        Write-Host "[WARNING] $($blockingPolicies.Count) policy(ies) BLOCK Modern Authentication:`n" -ForegroundColor Red
        foreach ($bp in $blockingPolicies) {
            Write-Host "  - $($bp.PolicyName)" -ForegroundColor Red
            Write-Host "    Blocks: $($bp.BlockingProtocols)" -ForegroundColor Yellow
        }
        Write-Host ""
    } else {
        Write-Host "[OK] No policies are blocking Modern Authentication.`n" -ForegroundColor Green
    }
}

# Check organization default policy
Write-Host "----------------------------------------" -ForegroundColor Gray
Write-Host "Organization Default Policy:" -ForegroundColor White
try {
    $orgConfig = Get-OrganizationConfig | Select-Object DefaultAuthenticationPolicy
    if ($orgConfig.DefaultAuthenticationPolicy) {
        Write-Host "  Default Policy: $($orgConfig.DefaultAuthenticationPolicy)" -ForegroundColor Yellow
        $defaultPolicy = Get-AuthenticationPolicy -Identity $orgConfig.DefaultAuthenticationPolicy -ErrorAction SilentlyContinue
        if ($defaultPolicy.BlockModernAuthActiveSync -eq $true) {
            Write-Host "  [CRITICAL] Default policy BLOCKS Modern Auth for ActiveSync!" -ForegroundColor Red
        }
    } else {
        Write-Host "  [OK] No organization default policy set." -ForegroundColor Green
    }
} catch {
    Write-Host "  [ERROR] Could not check organization config." -ForegroundColor Red
}
Write-Host ""

# Check specific user if provided
if ($UserEmail) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  User Policy Check: $UserEmail" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    try {
        $mailbox = Get-Mailbox -Identity $UserEmail -ErrorAction Stop
        
        if ($mailbox.AuthenticationPolicy) {
            Write-Host "Assigned Policy: $($mailbox.AuthenticationPolicy)" -ForegroundColor Yellow
            
            $userPolicy = Get-AuthenticationPolicy -Identity $mailbox.AuthenticationPolicy -ErrorAction SilentlyContinue
            if ($userPolicy) {
                if ($userPolicy.BlockModernAuthActiveSync -eq $true) {
                    Write-Host "`n[CRITICAL] This user's policy BLOCKS Modern Auth for ActiveSync!" -ForegroundColor Red
                    Write-Host "`nTo fix, run one of:" -ForegroundColor White
                    Write-Host "  # Remove user from policy:" -ForegroundColor Gray
                    Write-Host "  Set-Mailbox '$UserEmail' -AuthenticationPolicy `$null" -ForegroundColor Cyan
                    Write-Host "`n  # Or modify the policy:" -ForegroundColor Gray
                    Write-Host "  Set-AuthenticationPolicy '$($mailbox.AuthenticationPolicy)' -BlockModernAuthActiveSync `$false" -ForegroundColor Cyan
                } else {
                    Write-Host "`n[OK] User's policy allows Modern Auth for ActiveSync." -ForegroundColor Green
                }
            }
        } else {
            Write-Host "No explicit policy assigned." -ForegroundColor White
            
            # Check if org default applies
            $orgConfig = Get-OrganizationConfig | Select-Object DefaultAuthenticationPolicy
            if ($orgConfig.DefaultAuthenticationPolicy) {
                Write-Host "Using organization default: $($orgConfig.DefaultAuthenticationPolicy)" -ForegroundColor Yellow
            } else {
                Write-Host "[OK] No policy assigned - Modern Auth is allowed." -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "[ERROR] Could not find mailbox: $UserEmail" -ForegroundColor Red
        Write-Host "Error: $_" -ForegroundColor Red
    }
    Write-Host ""
}

# List users with blocking policies
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Users with Blocking Policies" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if ($blockingPolicies.Count -gt 0) {
    foreach ($bp in $blockingPolicies) {
        Write-Host "Policy: $($bp.PolicyName)" -ForegroundColor Yellow
        try {
            $usersWithPolicy = Get-Mailbox -ResultSize Unlimited | Where-Object { $_.AuthenticationPolicy -eq $bp.PolicyName }
            if ($usersWithPolicy) {
                Write-Host "  Users assigned ($($usersWithPolicy.Count)):" -ForegroundColor White
                $usersWithPolicy | Select-Object -First 10 | ForEach-Object {
                    Write-Host "    - $($_.PrimarySmtpAddress)" -ForegroundColor Gray
                }
                if ($usersWithPolicy.Count -gt 10) {
                    Write-Host "    ... and $($usersWithPolicy.Count - 10) more" -ForegroundColor Gray
                }
            } else {
                Write-Host "  No users currently assigned to this policy." -ForegroundColor Green
            }
        } catch {
            Write-Host "  [ERROR] Could not enumerate users." -ForegroundColor Red
        }
        Write-Host ""
    }
} else {
    Write-Host "[OK] No blocking policies exist - no users affected.`n" -ForegroundColor Green
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Check Complete" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

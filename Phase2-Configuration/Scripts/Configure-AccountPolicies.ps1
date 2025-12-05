# Script: Configure-AccountPolicies.ps1
# Purpose: Configure Windows Server 2025 account policies (password, lockout, Kerberos)
# Framework Alignment: CIS Benchmarks 1.1.x, 1.2.x, 1.3.x
# Requires: Administrator privileges, secedit.exe or Group Policy

<#
.SYNOPSIS
    Configures account policies including password policy, account lockout, and Kerberos settings.

.DESCRIPTION
    This script applies CIS Benchmark and Microsoft Security Baseline recommended settings for:
    - Password Policy (length, complexity, history, age)
    - Account Lockout Policy (threshold, duration, reset)
    - Kerberos Policy (ticket lifetimes, clock skew)

.NOTES
    - These settings are typically applied via Group Policy at the domain level
    - Local policy changes may be overridden by domain GPO
    - Test in lab environment before production deployment
    - CIS References: 1.1.1-1.1.6, 1.2.1-1.2.3, 1.3.1-1.3.5

.EXAMPLE
    .\Configure-AccountPolicies.ps1
#>

[CmdletBinding()]
param(
    [switch]$WhatIf
)

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'  # Continue on errors to attempt all operations

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Account Policies Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running on domain controller (account policies should be set at domain level)
$isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -eq 4 -or (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -eq 5
if ($isDC) {
    Write-Warning "This appears to be a domain controller. Account policies should be configured at the domain level via Group Policy."
    Write-Warning "Local policy changes may not apply or may be overridden by domain GPO."
}

# Create temporary INF file for secedit
$infPath = "$env:TEMP\AccountPolicies.inf"
$sdbPath = "$env:TEMP\AccountPolicies.sdb"

try {
    # Build INF content
    $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature=`"`$CHICAGO`$`"
Revision=1
[System Access]
; Password Policy - CIS 1.1.1-1.1.6
MinimumPasswordAge = 1
MaximumPasswordAge = 60
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
ClearTextPassword = 0
; Store passwords using reversible encryption = 0 (Disabled) - CIS 1.1.6

; Account Lockout Policy - CIS 1.2.1-1.2.3
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 15
; LockoutDuration = -1 means account locked until admin unlocks

; Kerberos Policy - CIS 1.3.1-1.3.5
MaxTicketAge = 10
MaxRenewAge = 7
MaxServiceAge = 600
MaxClockSkew = 5
TicketValidateClient = 1
"@

    Write-Host "Creating security policy INF file..." -ForegroundColor Yellow
    $infContent | Out-File -FilePath $infPath -Encoding ASCII -Force

    if ($WhatIf) {
        Write-Host "[WHATIF] Would apply account policies:" -ForegroundColor Green
        Write-Host "  Password Policy:" -ForegroundColor Green
        Write-Host "    Minimum length: 14 characters" -ForegroundColor Green
        Write-Host "    Complexity: Enabled" -ForegroundColor Green
        Write-Host "    History: 24 passwords" -ForegroundColor Green
        Write-Host "    Max age: 60 days" -ForegroundColor Green
        Write-Host "    Min age: 1 day" -ForegroundColor Green
        Write-Host "    Reversible encryption: Disabled" -ForegroundColor Green
        Write-Host "  Account Lockout:" -ForegroundColor Green
        Write-Host "    Threshold: 5 attempts" -ForegroundColor Green
        Write-Host "    Duration: 15 minutes" -ForegroundColor Green
        Write-Host "    Reset: 15 minutes" -ForegroundColor Green
        Write-Host "  Kerberos:" -ForegroundColor Green
        Write-Host "    Max ticket age: 10 hours" -ForegroundColor Green
        Write-Host "    Max service ticket: 600 minutes" -ForegroundColor Green
        Write-Host "    Max clock skew: 5 minutes" -ForegroundColor Green
    } else {
        Write-Host "Applying account policies..." -ForegroundColor Yellow
        
        # Import policy using secedit
        $seceditArgs = @(
            "/configure",
            "/db", $sdbPath,
            "/cfg", $infPath,
            "/quiet"
        )
        
        $result = Start-Process -FilePath "secedit.exe" -ArgumentList $seceditArgs -Wait -PassThru -NoNewWindow
        
        if ($result.ExitCode -eq 0) {
            Write-Host "Account policies applied successfully." -ForegroundColor Green
        } else {
            Write-Warning "Failed to apply account policies. Exit code: $($result.ExitCode)"
            Write-Host "This may be due to domain GPO overriding local policy." -ForegroundColor Yellow
        }
        
        # Verify settings (if not overridden by domain GPO)
        Write-Host "`nVerifying password policy..." -ForegroundColor Yellow
        $netAccounts = net accounts
        Write-Host $netAccounts
        
        Write-Host "`nNote: Domain GPO may override local policy settings." -ForegroundColor Yellow
        Write-Host "Verify settings with: gpresult /h report.html" -ForegroundColor Yellow
    }
} catch {
    Write-Warning "Error configuring account policies: $_"
    Write-Host "Some account policy settings may not have been applied. Review errors above." -ForegroundColor Yellow
} finally {
    # Cleanup
    if (Test-Path $infPath) { Remove-Item $infPath -Force -ErrorAction SilentlyContinue }
    if (Test-Path $sdbPath) { Remove-Item $sdbPath -Force -ErrorAction SilentlyContinue }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Account Policies Configuration Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan


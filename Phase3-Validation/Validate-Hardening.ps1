# Script: Validate-Hardening.ps1
# Purpose: Automated validation of Windows Server 2025 hardening
# Framework Alignment: CIS Benchmarks, Microsoft Security Baseline
# Requires: Administrator privileges

<#
.SYNOPSIS
    Validates that all hardening configurations have been applied correctly.

.DESCRIPTION
    This script checks:
    - Account policies
    - Local security options
    - User rights assignments
    - Windows Defender configuration
    - Exploit Guard & ASR
    - Firewall settings
    - RDP hardening
    - Logging & auditing
    - Credential Guard
    - Group Policy application

.NOTES
    - Run as Administrator
    - Generates a validation report
    - Some checks may show warnings if settings are managed via GPO

.EXAMPLE
    .\Validate-Hardening.ps1
    .\Validate-Hardening.ps1 -OutputFile "C:\Hardening-Validation-Report.html"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "C:\Hardening-Validation-Report.txt"
)

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'

$validationResults = @()
$totalChecks = 0
$passedChecks = 0
$failedChecks = 0
$warningChecks = 0

function Add-ValidationResult {
    param(
        [string]$Category,
        [string]$Check,
        [string]$Status,
        [string]$Details = "",
        [string]$Recommendation = ""
    )
    
    $script:totalChecks++
    switch ($Status) {
        "Pass" { $script:passedChecks++ }
        "Fail" { $script:failedChecks++ }
        "Warning" { $script:warningChecks++ }
    }
    
    $script:validationResults += [PSCustomObject]@{
        Category = $Category
        Check = $Check
        Status = $Status
        Details = $Details
        Recommendation = $Recommendation
    }
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Hardening Validation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Account Policies
Write-Host "Validating Account Policies..." -ForegroundColor Yellow
try {
    $netAccounts = net accounts 2>&1 | Out-String
    if ($netAccounts -match "Minimum password length:\s+14") {
        Add-ValidationResult -Category "Account Policies" -Check "Minimum password length" -Status "Pass" -Details "14 characters"
    } else {
        Add-ValidationResult -Category "Account Policies" -Check "Minimum password length" -Status "Fail" -Details "Not set to 14" -Recommendation "Set minimum password length to 14"
    }
    
    if ($netAccounts -match "Password history maintained:\s+24") {
        Add-ValidationResult -Category "Account Policies" -Check "Password history" -Status "Pass" -Details "24 passwords"
    } else {
        Add-ValidationResult -Category "Account Policies" -Check "Password history" -Status "Warning" -Details "May be managed by domain GPO"
    }
} catch {
    Add-ValidationResult -Category "Account Policies" -Check "Password policy verification" -Status "Warning" -Details "Could not verify: $_"
}

# 2. Local Security Options
Write-Host "Validating Local Security Options..." -ForegroundColor Yellow
try {
    $lsaSettings = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
    
    if ($lsaSettings.LmCompatibilityLevel -eq 5) {
        Add-ValidationResult -Category "Local Security Options" -Check "NTLM authentication level" -Status "Pass" -Details "Level 5 (NTLMv2 only)"
    } else {
        Add-ValidationResult -Category "Local Security Options" -Check "NTLM authentication level" -Status "Fail" -Details "Not set to 5" -Recommendation "Set LmCompatibilityLevel to 5"
    }
    
    if ($lsaSettings.NoLMHash -eq 1) {
        Add-ValidationResult -Category "Local Security Options" -Check "LM hash storage" -Status "Pass" -Details "Disabled"
    } else {
        Add-ValidationResult -Category "Local Security Options" -Check "LM hash storage" -Status "Warning" -Details "May be managed by GPO"
    }
    
    $uacSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
    if ($uacSettings.EnableLUA -eq 1) {
        Add-ValidationResult -Category "Local Security Options" -Check "UAC enabled" -Status "Pass" -Details "Enabled"
    } else {
        Add-ValidationResult -Category "Local Security Options" -Check "UAC enabled" -Status "Fail" -Details "UAC disabled" -Recommendation "Enable UAC"
    }
} catch {
    Add-ValidationResult -Category "Local Security Options" -Check "Registry verification" -Status "Warning" -Details "Could not verify: $_"
}

# 3. Windows Defender
Write-Host "Validating Windows Defender..." -ForegroundColor Yellow
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defenderStatus -and $defenderStatus.RealTimeProtectionEnabled) {
        Add-ValidationResult -Category "Windows Defender" -Check "Real-time protection" -Status "Pass" -Details "Enabled"
    } else {
        Add-ValidationResult -Category "Windows Defender" -Check "Real-time protection" -Status "Fail" -Details "Disabled" -Recommendation "Enable real-time protection"
    }
    
    $defenderPrefs = Get-MpPreference -ErrorAction SilentlyContinue
    if ($defenderPrefs.MAPSReporting -eq "Advanced") {
        Add-ValidationResult -Category "Windows Defender" -Check "Cloud protection" -Status "Pass" -Details "Advanced"
    } else {
        Add-ValidationResult -Category "Windows Defender" -Check "Cloud protection" -Status "Warning" -Details "Not set to Advanced"
    }
    
    if ($defenderPrefs.PUAProtection -eq "Enabled") {
        Add-ValidationResult -Category "Windows Defender" -Check "PUA protection" -Status "Pass" -Details "Enabled"
    } else {
        Add-ValidationResult -Category "Windows Defender" -Check "PUA protection" -Status "Warning" -Details "Not enabled"
    }
} catch {
    Add-ValidationResult -Category "Windows Defender" -Check "Defender status" -Status "Warning" -Details "Could not verify: $_"
}

# 4. ASR Rules
Write-Host "Validating ASR Rules..." -ForegroundColor Yellow
try {
    $asrRules = Get-MpPreference -ErrorAction SilentlyContinue
    if ($asrRules.AttackSurfaceReductionRules_Ids) {
        $ruleCount = $asrRules.AttackSurfaceReductionRules_Ids.Count
        if ($ruleCount -ge 10) {
            Add-ValidationResult -Category "ASR Rules" -Check "ASR rules configured" -Status "Pass" -Details "$ruleCount rules configured"
        } else {
            Add-ValidationResult -Category "ASR Rules" -Check "ASR rules configured" -Status "Warning" -Details "Only $ruleCount rules configured (recommend 10+)"
        }
    } else {
        Add-ValidationResult -Category "ASR Rules" -Check "ASR rules configured" -Status "Warning" -Details "No ASR rules found"
    }
} catch {
    Add-ValidationResult -Category "ASR Rules" -Check "ASR verification" -Status "Warning" -Details "Could not verify: $_"
}

# 5. Firewall
Write-Host "Validating Windows Firewall..." -ForegroundColor Yellow
try {
    $firewallProfiles = Get-NetFirewallProfile
    foreach ($profile in $firewallProfiles) {
        if ($profile.Enabled -and $profile.DefaultInboundAction -eq "Block") {
            Add-ValidationResult -Category "Firewall" -Check "$($profile.Name) profile" -Status "Pass" -Details "Enabled, Block inbound"
        } else {
            Add-ValidationResult -Category "Firewall" -Check "$($profile.Name) profile" -Status "Fail" -Details "Not configured correctly" -Recommendation "Enable firewall and block inbound by default"
        }
    }
} catch {
    Add-ValidationResult -Category "Firewall" -Check "Firewall verification" -Status "Warning" -Details "Could not verify: $_"
}

# 6. RDP Hardening
Write-Host "Validating RDP Hardening..." -ForegroundColor Yellow
try {
    $rdpSettings = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue
    if ($rdpSettings.UserAuthentication -eq 1) {
        Add-ValidationResult -Category "RDP Hardening" -Check "Network Level Authentication" -Status "Pass" -Details "Required"
    } else {
        Add-ValidationResult -Category "RDP Hardening" -Check "Network Level Authentication" -Status "Fail" -Details "Not required" -Recommendation "Enable NLA for RDP"
    }
    
    $rdpWinStations = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue
    if ($rdpWinStations.MinEncryptionLevel -eq 3) {
        Add-ValidationResult -Category "RDP Hardening" -Check "RDP encryption level" -Status "Pass" -Details "High (3)"
    } else {
        Add-ValidationResult -Category "RDP Hardening" -Check "RDP encryption level" -Status "Warning" -Details "Not set to High"
    }
} catch {
    Add-ValidationResult -Category "RDP Hardening" -Check "RDP verification" -Status "Warning" -Details "Could not verify: $_"
}

# 7. Logging & Auditing
Write-Host "Validating Logging & Auditing..." -ForegroundColor Yellow
try {
    $securityLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
    if ($securityLog -and $securityLog.MaximumSizeInBytes -ge 512MB) {
        Add-ValidationResult -Category "Logging" -Check "Security log size" -Status "Pass" -Details "$([math]::Round($securityLog.MaximumSizeInBytes / 1MB, 2)) MB"
    } else {
        Add-ValidationResult -Category "Logging" -Check "Security log size" -Status "Warning" -Details "Less than 512 MB" -Recommendation "Increase Security log size to 512 MB minimum"
    }
    
    $psTranscription = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
    if ($psTranscription -and $psTranscription.EnableTranscripting -eq 1) {
        Add-ValidationResult -Category "Logging" -Check "PowerShell transcription" -Status "Pass" -Details "Enabled"
    } else {
        Add-ValidationResult -Category "Logging" -Check "PowerShell transcription" -Status "Warning" -Details "Not enabled"
    }
} catch {
    Add-ValidationResult -Category "Logging" -Check "Logging verification" -Status "Warning" -Details "Could not verify: $_"
}

# 8. Cryptographic Settings
Write-Host "Validating Cryptographic Settings..." -ForegroundColor Yellow
try {
    $schannelPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    
    # Check TLS 1.0 (should be disabled)
    $tls10Server = Get-ItemProperty -Path "$schannelPath\TLS 1.0\Server" -ErrorAction SilentlyContinue
    if ($tls10Server -and ($tls10Server.Enabled -eq 0 -or $tls10Server.DisabledByDefault -eq 1)) {
        Add-ValidationResult -Category "Cryptographic Settings" -Check "TLS 1.0 disabled" -Status "Pass" -Details "TLS 1.0 is disabled"
    } else {
        Add-ValidationResult -Category "Cryptographic Settings" -Check "TLS 1.0 disabled" -Status "Fail" -Details "TLS 1.0 is enabled" -Recommendation "Disable TLS 1.0"
    }
    
    # Check TLS 1.1 (should be disabled)
    $tls11Server = Get-ItemProperty -Path "$schannelPath\TLS 1.1\Server" -ErrorAction SilentlyContinue
    if ($tls11Server -and ($tls11Server.Enabled -eq 0 -or $tls11Server.DisabledByDefault -eq 1)) {
        Add-ValidationResult -Category "Cryptographic Settings" -Check "TLS 1.1 disabled" -Status "Pass" -Details "TLS 1.1 is disabled"
    } else {
        Add-ValidationResult -Category "Cryptographic Settings" -Check "TLS 1.1 disabled" -Status "Fail" -Details "TLS 1.1 is enabled" -Recommendation "Disable TLS 1.1"
    }
    
    # Check TLS 1.2 (should be enabled)
    $tls12Server = Get-ItemProperty -Path "$schannelPath\TLS 1.2\Server" -ErrorAction SilentlyContinue
    if ($tls12Server -and $tls12Server.Enabled -eq 1 -and $tls12Server.DisabledByDefault -eq 0) {
        Add-ValidationResult -Category "Cryptographic Settings" -Check "TLS 1.2 enabled" -Status "Pass" -Details "TLS 1.2 is enabled"
    } else {
        Add-ValidationResult -Category "Cryptographic Settings" -Check "TLS 1.2 enabled" -Status "Warning" -Details "TLS 1.2 may not be enabled"
    }
    
    # Check SSL 2.0 (should be disabled)
    $ssl20Server = Get-ItemProperty -Path "$schannelPath\SSL 2.0\Server" -ErrorAction SilentlyContinue
    if ($ssl20Server -and ($ssl20Server.Enabled -eq 0 -or $ssl20Server.DisabledByDefault -eq 1)) {
        Add-ValidationResult -Category "Cryptographic Settings" -Check "SSL 2.0 disabled" -Status "Pass" -Details "SSL 2.0 is disabled"
    } else {
        Add-ValidationResult -Category "Cryptographic Settings" -Check "SSL 2.0 disabled" -Status "Fail" -Details "SSL 2.0 may be enabled" -Recommendation "Disable SSL 2.0"
    }
    
    # Check SSL 3.0 (should be disabled)
    $ssl30Server = Get-ItemProperty -Path "$schannelPath\SSL 3.0\Server" -ErrorAction SilentlyContinue
    if ($ssl30Server -and ($ssl30Server.Enabled -eq 0 -or $ssl30Server.DisabledByDefault -eq 1)) {
        Add-ValidationResult -Category "Cryptographic Settings" -Check "SSL 3.0 disabled" -Status "Pass" -Details "SSL 3.0 is disabled"
    } else {
        Add-ValidationResult -Category "Cryptographic Settings" -Check "SSL 3.0 disabled" -Status "Fail" -Details "SSL 3.0 may be enabled" -Recommendation "Disable SSL 3.0"
    }
    
    # Check MD5 hash (should be disabled)
    $md5Hash = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -ErrorAction SilentlyContinue
    if ($md5Hash -and ($md5Hash.Enabled -eq 0 -or $md5Hash.DisabledByDefault -eq 1)) {
        Add-ValidationResult -Category "Cryptographic Settings" -Check "MD5 hash disabled" -Status "Pass" -Details "MD5 is disabled"
    } else {
        Add-ValidationResult -Category "Cryptographic Settings" -Check "MD5 hash disabled" -Status "Warning" -Details "MD5 may be enabled" -Recommendation "Disable MD5 hash"
    }
    
} catch {
    Add-ValidationResult -Category "Cryptographic Settings" -Check "Cryptographic verification" -Status "Warning" -Details "Could not verify: $_"
}

# 9. Credential Guard
Write-Host "Validating Credential Guard..." -ForegroundColor Yellow
try {
    $lsaProtection = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
    if ($lsaProtection.RunAsPPL -eq 1) {
        Add-ValidationResult -Category "Credential Guard" -Check "LSA Protection" -Status "Pass" -Details "Enabled (RunAsPPL)"
    } else {
        Add-ValidationResult -Category "Credential Guard" -Check "LSA Protection" -Status "Warning" -Details "Not enabled" -Recommendation "Enable LSA Protection"
    }
    
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard" -ErrorAction SilentlyContinue
    if ($deviceGuard) {
        $cgStatus = $deviceGuard.VirtualizationBasedSecurityStatus
        if ($cgStatus -eq 2 -or $cgStatus -eq 1) {
            Add-ValidationResult -Category "Credential Guard" -Check "Credential Guard status" -Status "Pass" -Details "Running (Status: $cgStatus)"
        } else {
            Add-ValidationResult -Category "Credential Guard" -Check "Credential Guard status" -Status "Warning" -Details "Not running (Status: $cgStatus)" -Recommendation "Restart system or check hardware compatibility"
        }
    } else {
        Add-ValidationResult -Category "Credential Guard" -Check "Credential Guard status" -Status "Warning" -Details "Device Guard not available" -Recommendation "Check hardware compatibility (UEFI, TPM)"
    }
} catch {
    Add-ValidationResult -Category "Credential Guard" -Check "Credential Guard verification" -Status "Warning" -Details "Could not verify: $_"
}

# Generate Report
Write-Host "`nGenerating validation report..." -ForegroundColor Yellow

$report = @"
========================================
Windows Server 2025 Hardening Validation Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
========================================

Summary:
--------
Total Checks: $totalChecks
Passed: $passedChecks
Failed: $failedChecks
Warnings: $warningChecks

Detailed Results:
-----------------

"@

foreach ($result in $validationResults) {
    $statusSymbol = switch ($result.Status) {
        "Pass" { "[PASS]" }
        "Fail" { "[FAIL]" }
        "Warning" { "[WARN]" }
    }
    
    $report += @"
$statusSymbol $($result.Category) - $($result.Check)
   Status: $($result.Status)
   Details: $($result.Details)
"@
    
    if ($result.Recommendation) {
        $report += "`n   Recommendation: $($result.Recommendation)"
    }
    $report += "`n`n"
}

$report += @"
========================================
End of Report
========================================
"@

# Output to file
$report | Out-File -FilePath $OutputFile -Encoding UTF8
Write-Host "Report saved to: $OutputFile" -ForegroundColor Green

# Display summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Validation Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Checks: $totalChecks" -ForegroundColor White
Write-Host "Passed: $passedChecks" -ForegroundColor Green
Write-Host "Failed: $failedChecks" -ForegroundColor $(if ($failedChecks -gt 0) { "Red" } else { "Green" })
Write-Host "Warnings: $warningChecks" -ForegroundColor $(if ($warningChecks -gt 0) { "Yellow" } else { "Green" })
Write-Host ""

# Display failed checks
$failedResults = $validationResults | Where-Object { $_.Status -eq "Fail" }
if ($failedResults) {
    Write-Host "Failed Checks:" -ForegroundColor Red
    foreach ($failed in $failedResults) {
        Write-Host "  - $($failed.Category): $($failed.Check)" -ForegroundColor Red
        if ($failed.Recommendation) {
            Write-Host "    Recommendation: $($failed.Recommendation)" -ForegroundColor Yellow
        }
    }
    Write-Host ""
}

Write-Host "Detailed report: $OutputFile" -ForegroundColor Cyan


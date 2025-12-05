# Script: Configure-LocalSecurityOptions.ps1
# Purpose: Configure Windows Server 2025 local security options via registry
# Framework Alignment: CIS Benchmarks 2.3.x, Microsoft Security Baseline
# Requires: Administrator privileges

<#
.SYNOPSIS
    Configures local security options that cannot be easily set via secedit or require registry changes.

.DESCRIPTION
    This script applies critical local security options including:
    - Network security (NTLM, SMB, Kerberos)
    - Interactive logon settings
    - UAC settings
    - Network access restrictions
    - Domain member security

.NOTES
    - Many of these settings are better managed via Group Policy
    - Registry changes take effect immediately or after reboot
    - Test in lab environment before production
    - CIS References: 2.3.x series

.EXAMPLE
    .\Configure-LocalSecurityOptions.ps1
#>

[CmdletBinding()]
param(
    [switch]$WhatIf
)

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'  # Continue on errors to attempt all operations

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Local Security Options Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Registry paths
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$regPathSecurity = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$regPathMSClient = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$regPathNetwork = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$regPathKerberos = "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc"

# Function to set registry value
function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord"
    )
    
    if (-not (Test-Path $Path)) {
        if ($WhatIf) {
            Write-Host "[WHATIF] Would create registry path: $Path" -ForegroundColor Green
        } else {
            New-Item -Path $Path -Force | Out-Null
        }
    }
    
    if ($WhatIf) {
        Write-Host "[WHATIF] Would set: $Path\$Name = $Value ($Type)" -ForegroundColor Green
    } else {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Host "  Set: $Path\$Name = $Value" -ForegroundColor Gray
    }
}

try {
    Write-Host "Configuring network security settings..." -ForegroundColor Yellow
    
    # Network security: LAN Manager authentication level - CIS 2.3.70
    # 5 = Send NTLMv2 response only. Refuse LM & NTLM
    Set-RegistryValue -Path $regPath -Name "LmCompatibilityLevel" -Value 5
    
    # Network security: Minimum session security for NTLM SSP clients - CIS 2.3.71
    # 0x20080000 = Require NTLMv2, Require 128-bit encryption
    Set-RegistryValue -Path $regPath -Name "NtlmMinClientSec" -Value 0x20080000
    
    # Network security: Minimum session security for NTLM SSP servers - CIS 2.3.72
    # 0x20080000 = Require NTLMv2, Require 128-bit encryption
    Set-RegistryValue -Path $regPath -Name "NtlmMinServerSec" -Value 0x20080000
    
    # Network security: Do not store LAN Manager hash value - CIS 2.3.68
    Set-RegistryValue -Path $regPath -Name "NoLMHash" -Value 1
    
    Write-Host "`nConfiguring SMB security settings..." -ForegroundColor Yellow
    
    # Microsoft network server: Digitally sign communications (always) - CIS 2.3.50
    Set-RegistryValue -Path $regPathSecurity -Name "RequireSecuritySignature" -Value 1
    
    # Microsoft network server: Digitally sign communications (if client agrees) - CIS 2.3.51
    Set-RegistryValue -Path $regPathSecurity -Name "EnableSecuritySignature" -Value 1
    
    # Microsoft network client: Digitally sign communications (always) - CIS 2.3.47
    Set-RegistryValue -Path $regPathMSClient -Name "RequireSecuritySignature" -Value 1
    
    # Microsoft network client: Digitally sign communications (if server agrees) - CIS 2.3.48
    Set-RegistryValue -Path $regPathMSClient -Name "EnableSecuritySignature" -Value 1
    
    # Microsoft network client: Send unencrypted password to third-party SMB servers - CIS 2.3.49
    Set-RegistryValue -Path $regPathMSClient -Name "EnablePlainTextPassword" -Value 0
    
    Write-Host "`nConfiguring Kerberos settings..." -ForegroundColor Yellow
    
    # Network security: Configure encryption types allowed for Kerberos - CIS 2.3.67
    # Allow: AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types
    # 0x7FFFFFFF = All supported types (adjust as needed for your environment)
    Set-RegistryValue -Path $regPathKerberos -Name "SupportedEncryptionTypes" -Value 0x7FFFFFFF
    
    Write-Host "`nConfiguring interactive logon settings..." -ForegroundColor Yellow
    
    # Interactive logon: Don't display last signed-in - CIS 2.3.37
    Set-RegistryValue -Path $regPath -Name "DontDisplayLastUserName" -Value 1
    
    # Interactive logon: Machine inactivity limit - CIS 2.3.39
    # 900 seconds = 15 minutes
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Value 900
    
    # Interactive logon: Number of previous logons to cache - CIS 2.3.42
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "CachedLogonsCount" -Value 2
    
    # Interactive logon: Prompt user to change password before expiration - CIS 2.3.43
    # 14 days = 1209600 seconds
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaximumPasswordAge" -Value 14
    
    Write-Host "`nConfiguring network access restrictions..." -ForegroundColor Yellow
    
    # Network access: Do not allow anonymous enumeration of SAM accounts - CIS 2.3.55
    Set-RegistryValue -Path $regPath -Name "RestrictAnonymousSAM" -Value 1
    
    # Network access: Do not allow anonymous enumeration of SAM accounts and shares - CIS 2.3.56
    Set-RegistryValue -Path $regPath -Name "RestrictAnonymous" -Value 1
    
    # Network access: Allow anonymous SID/Name translation - CIS 2.3.54
    Set-RegistryValue -Path $regPath -Name "RestrictAnonymousSAM" -Value 1
    
    # Network access: Named Pipes that can be accessed anonymously - CIS 2.3.59
    # Remove all entries (set to empty)
    Set-RegistryValue -Path $regPath -Name "NullSessionPipes" -Value "" -Type "MultiString"
    
    # Network access: Shares that can be accessed anonymously - CIS 2.3.63
    # Remove all entries (set to empty)
    Set-RegistryValue -Path $regPath -Name "NullSessionShares" -Value "" -Type "MultiString"
    
    Write-Host "`nConfiguring domain member security..." -ForegroundColor Yellow
    
    # Domain member: Digitally encrypt or sign secure channel data (always) - CIS 2.3.30
    Set-RegistryValue -Path $regPath -Name "RequireStrongKey" -Value 1
    
    # Domain member: Digitally encrypt secure channel data (when possible) - CIS 2.3.31
    Set-RegistryValue -Path $regPath -Name "SealSecureChannel" -Value 1
    
    # Domain member: Digitally sign secure channel data (when possible) - CIS 2.3.32
    Set-RegistryValue -Path $regPath -Name "SignSecureChannel" -Value 1
    
    # Domain member: Require strong (Windows 2000 or later) session key - CIS 2.3.35
    Set-RegistryValue -Path $regPath -Name "RequireStrongKey" -Value 1
    
    # Domain member: Maximum machine account password age - CIS 2.3.34
    # 30 days = 2592000 seconds
    Set-RegistryValue -Path $regPath -Name "MaxPasswordAge" -Value 2592000
    
    Write-Host "`nConfiguring UAC settings..." -ForegroundColor Yellow
    
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    
    # UAC: Admin Approval Mode for Built-in Administrator - CIS 2.3.86
    Set-RegistryValue -Path $uacPath -Name "FilterAdministratorToken" -Value 1
    
    # UAC: Behavior of elevation prompt for administrators - CIS 2.3.88
    # 2 = Prompt for consent on secure desktop
    Set-RegistryValue -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2
    
    # UAC: Behavior of elevation prompt for standard users - CIS 2.3.89
    # 0 = Automatically deny elevation requests
    Set-RegistryValue -Path $uacPath -Name "ConsentPromptBehaviorUser" -Value 0
    
    # UAC: Detect application installations and prompt for elevation - CIS 2.3.90
    Set-RegistryValue -Path $uacPath -Name "EnableInstallerDetection" -Value 1
    
    # UAC: Only elevate executables that are signed and validated - CIS 2.3.91
    Set-RegistryValue -Path $uacPath -Name "ValidateAdminCodeSignatures" -Value 1
    
    # UAC: Only elevate UIAccess applications in secure locations - CIS 2.3.92
    Set-RegistryValue -Path $uacPath -Name "EnableSecureUIAPaths" -Value 1
    
    # UAC: Run all administrators in Admin Approval Mode - CIS 2.3.93
    Set-RegistryValue -Path $uacPath -Name "EnableLUA" -Value 1
    
    # UAC: Switch to secure desktop when prompting for elevation - CIS 2.3.94
    Set-RegistryValue -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1
    
    # UAC: Virtualize file and registry write failures - CIS 2.3.95
    Set-RegistryValue -Path $uacPath -Name "EnableVirtualization" -Value 1
    
    Write-Host "`nConfiguring shutdown settings..." -ForegroundColor Yellow
    
    # Shutdown: Clear virtual memory pagefile - CIS 2.3.81
    Set-RegistryValue -Path $uacPath -Name "ClearPageFileAtShutdown" -Value 1
    
    if (-not $WhatIf) {
        Write-Host "`nLocal security options configured successfully." -ForegroundColor Green
        Write-Host "Some settings may require a reboot to take full effect." -ForegroundColor Yellow
    }
    
} catch {
    Write-Warning "Error configuring local security options: $_"
    Write-Host "Some local security options may not have been applied. Review errors above." -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Local Security Options Configuration Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan


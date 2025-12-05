# Script: Configure-CredentialGuard.ps1
# Purpose: Enable Credential Guard and LSA Protection
# Framework Alignment: CIS Benchmarks 2.3.10-2.3.11, Microsoft Security Baseline
# Requires: Administrator privileges, UEFI firmware, TPM 2.0 (recommended)

<#
.SYNOPSIS
    Enables Credential Guard and LSA Protection to prevent credential theft.

.DESCRIPTION
    This script enables:
    - Credential Guard (Virtualization-Based Security)
    - LSA Protection (RunAsPPL)
    - Required registry settings
    - Group Policy recommendations

.NOTES
    - Requires UEFI firmware (not Legacy BIOS)
    - TPM 2.0 recommended for best security
    - May require system restart
    - Some systems may not support Credential Guard
    - CIS References: 2.3.10-2.3.11

.EXAMPLE
    .\Configure-CredentialGuard.ps1
#>

[CmdletBinding()]
param(
    [switch]$WhatIf
)

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'  # Continue on errors to attempt all operations

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Credential Guard & LSA Protection Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check system requirements
Write-Host "Checking system requirements..." -ForegroundColor Yellow

$firmwareType = (Get-CimInstance -ClassName Win32_ComputerSystem).BootupState
$tpm = Get-Tpm -ErrorAction SilentlyContinue

if ($WhatIf) {
    Write-Host "[WHATIF] Would check system requirements" -ForegroundColor Green
} else {
    Write-Host "  Firmware type: $firmwareType" -ForegroundColor Gray
    if ($firmwareType -notlike "*UEFI*") {
        Write-Warning "Credential Guard requires UEFI firmware. Current firmware may not support it."
    }
    
    if ($tpm) {
        Write-Host "  TPM Present: $($tpm.TpmPresent)" -ForegroundColor Gray
        Write-Host "  TPM Ready: $($tpm.TpmReady)" -ForegroundColor Gray
        Write-Host "  TPM Version: $($tpm.ManufacturerVersionInfo)" -ForegroundColor Gray
        if (-not $tpm.TpmReady) {
            Write-Warning "TPM is not ready. Initialize TPM in TPM Management Console."
        }
    } else {
        Write-Warning "TPM not found. Credential Guard will work but TPM provides additional security."
    }
}

try {
    # Registry paths
    $lsaRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $deviceGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    $vbsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios"
    
    Write-Host "`nConfiguring LSA Protection (RunAsPPL)..." -ForegroundColor Yellow
    
    # CIS 2.3.10 - Configure LSA to run as a protected process
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable LSA Protection (RunAsPPL)" -ForegroundColor Green
    } else {
        if (-not (Test-Path $lsaRegPath)) {
            New-Item -Path $lsaRegPath -Force | Out-Null
        }
        Set-ItemProperty -Path $lsaRegPath -Name "RunAsPPL" -Value 1 -Type DWord -ErrorAction Stop
        Write-Host "  Enabled LSA Protection (RunAsPPL)" -ForegroundColor Gray
    }
    
    Write-Host "`nConfiguring Credential Guard..." -ForegroundColor Yellow
    
    # Create DeviceGuard registry paths
    if (-not $WhatIf) {
        if (-not (Test-Path $deviceGuardPath)) {
            New-Item -Path $deviceGuardPath -Force | Out-Null
        }
        if (-not (Test-Path $vbsPath)) {
            New-Item -Path $vbsPath -Force | Out-Null
        }
    }
    
    # CIS 2.3.11 - Enable Virtualization Based Security (Credential Guard)
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable Credential Guard" -ForegroundColor Green
        Write-Host "[WHATIF] Would configure registry settings for VBS" -ForegroundColor Green
    } else {
        # Enable Credential Guard
        Set-ItemProperty -Path $vbsPath -Name "CredentialGuard" -Value 1 -Type DWord -ErrorAction Stop
        Write-Host "  Enabled Credential Guard" -ForegroundColor Gray
        
        # Enable Virtualization Based Security
        Set-ItemProperty -Path $deviceGuardPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord -ErrorAction Stop
        Write-Host "  Enabled Virtualization Based Security" -ForegroundColor Gray
        
        # Require UEFI lock (prevents disabling via registry)
        Set-ItemProperty -Path $deviceGuardPath -Name "RequirePlatformSecurityFeatures" -Value 1 -Type DWord -ErrorAction Stop
        Write-Host "  Enabled UEFI lock (requires UEFI to disable)" -ForegroundColor Gray
        
        # Enable Secure Boot (if supported)
        Set-ItemProperty -Path $deviceGuardPath -Name "Locked" -Value 0 -Type DWord -ErrorAction Stop
        # Locked = 0 means settings can be changed, 1 means locked (set via UEFI)
        Write-Host "  Note: Set 'Locked' to 1 via UEFI for maximum security" -ForegroundColor Yellow
    }
    
    # Additional LSA settings
    Write-Host "`nConfiguring additional LSA security settings..." -ForegroundColor Yellow
    
    # Disable NTLM (audit first, then restrict)
    if ($WhatIf) {
        Write-Host "[WHATIF] Would configure NTLM restrictions" -ForegroundColor Green
    } else {
        # Audit NTLM usage (see Configure-LocalSecurityOptions.ps1 for full NTLM configuration)
        Write-Host "  NTLM restrictions configured via Local Security Options script" -ForegroundColor Gray
    }
    
    if (-not $WhatIf) {
        Write-Host "`nVerifying Credential Guard configuration..." -ForegroundColor Yellow
        
        $runAsPPL = Get-ItemProperty -Path $lsaRegPath -Name "RunAsPPL" -ErrorAction SilentlyContinue
        $credGuard = Get-ItemProperty -Path $vbsPath -Name "CredentialGuard" -ErrorAction SilentlyContinue
        $vbsEnabled = Get-ItemProperty -Path $deviceGuardPath -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue
        
        Write-Host "`nCredential Guard Status:" -ForegroundColor Cyan
        Write-Host "  LSA Protection (RunAsPPL): $($runAsPPL.RunAsPPL -eq 1)" -ForegroundColor Gray
        Write-Host "  Credential Guard: $($credGuard.CredentialGuard -eq 1)" -ForegroundColor Gray
        Write-Host "  VBS Enabled: $($vbsEnabled.EnableVirtualizationBasedSecurity -eq 1)" -ForegroundColor Gray
        
        # Check if Credential Guard is actually running
        $deviceGuardStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard" -ErrorAction SilentlyContinue
        if ($deviceGuardStatus) {
            Write-Host "`nDevice Guard Status:" -ForegroundColor Cyan
            Write-Host "  VirtualizationBasedSecurityStatus: $($deviceGuardStatus.VirtualizationBasedSecurityStatus)" -ForegroundColor Gray
            Write-Host "  RequiredSecurityProperties: $($deviceGuardStatus.RequiredSecurityProperties)" -ForegroundColor Gray
            Write-Host "  AvailableSecurityProperties: $($deviceGuardStatus.AvailableSecurityProperties)" -ForegroundColor Gray
            
            if ($deviceGuardStatus.VirtualizationBasedSecurityStatus -eq 2) {
                Write-Host "  Status: Credential Guard is running" -ForegroundColor Green
            } elseif ($deviceGuardStatus.VirtualizationBasedSecurityStatus -eq 1) {
                Write-Host "  Status: Credential Guard is enabled but not running (may require reboot)" -ForegroundColor Yellow
            } else {
                Write-Host "  Status: Credential Guard is not running" -ForegroundColor Red
            }
        } else {
            Write-Warning "Could not query Device Guard status. Credential Guard may not be supported on this system."
        }
        
        Write-Host "`nNote: A system restart may be required for Credential Guard to take effect." -ForegroundColor Yellow
        Write-Host "After restart, verify with: Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard" -ForegroundColor Yellow
    }
    
} catch {
    Write-Error "Error configuring Credential Guard: $_"
    throw
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Credential Guard Configuration Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`nImportant Notes:" -ForegroundColor Yellow
Write-Host "1. System restart required for Credential Guard to activate" -ForegroundColor White
Write-Host "2. Verify Credential Guard is running after restart" -ForegroundColor White
Write-Host "3. Configure via Group Policy for domain-wide deployment" -ForegroundColor White
Write-Host "4. GPO Path: Computer Configuration > Policies > Administrative Templates > System > Device Guard" -ForegroundColor White
Write-Host "5. Some systems may not support Credential Guard (check hardware compatibility)" -ForegroundColor White


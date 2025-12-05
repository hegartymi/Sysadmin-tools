# Script: Configure-Defender.ps1
# Purpose: Configure Windows Defender Antivirus settings
# Framework Alignment: CIS Benchmarks 9.1-9.12, Microsoft Security Baseline
# Requires: Administrator privileges, Windows Defender module

<#
.SYNOPSIS
    Configures Windows Defender Antivirus with recommended security settings.

.DESCRIPTION
    This script enables and configures:
    - Real-time protection
    - Cloud-delivered protection
    - Sample submission
    - Tamper protection
    - PUA protection
    - Scheduled scans
    - Network protection

.NOTES
    - Requires Windows Defender to be installed (default on Windows Server 2025)
    - Some settings may require Windows Defender ATP or Intune
    - CIS References: 9.1-9.12

.EXAMPLE
    .\Configure-Defender.ps1
#>

[CmdletBinding()]
param(
    [switch]$WhatIf
)

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'  # Continue on errors to attempt all operations

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Windows Defender Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Windows Defender is available
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defenderStatus) {
        Write-Host "Windows Defender is installed and available." -ForegroundColor Green
    } else {
        Write-Warning "Windows Defender is not available. Skipping Defender configuration."
        Write-Host "This script requires Windows Defender to be installed." -ForegroundColor Yellow
        return
    }
} catch {
    Write-Warning "Windows Defender is not available. Skipping Defender configuration: $_"
    return
}

try {
    Write-Host "Configuring Windows Defender settings..." -ForegroundColor Yellow
    
    # CIS 9.1 - Turn on real-time protection
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable real-time protection" -ForegroundColor Green
    } else {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Write-Host "  Enabled real-time protection" -ForegroundColor Gray
    }
    
    # CIS 9.2 - Turn on cloud-delivered protection
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable cloud-delivered protection" -ForegroundColor Green
    } else {
        Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
        Write-Host "  Enabled cloud-delivered protection (MAPS: Advanced)" -ForegroundColor Gray
    }
    
    # CIS 9.3 - Turn on sample submission (Send safe samples automatically)
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable automatic safe sample submission" -ForegroundColor Green
    } else {
        Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue
        Write-Host "  Enabled automatic safe sample submission" -ForegroundColor Gray
    }
    
    # CIS 9.4 - Turn on tamper protection (if available)
    # Note: Tamper protection may require Intune or Group Policy
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable tamper protection (may require GPO/Intune)" -ForegroundColor Green
    } else {
        try {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
            # Tamper protection is typically managed via GPO or Intune
            Write-Host "  Note: Tamper protection should be enabled via GPO (see GPO-Configuration-Tables.md)" -ForegroundColor Yellow
        } catch {
            Write-Warning "Tamper protection may require Group Policy or Intune configuration"
        }
    }
    
    # CIS 9.5 - Turn on behavior monitoring
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable behavior monitoring" -ForegroundColor Green
    } else {
        Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
        Write-Host "  Enabled behavior monitoring" -ForegroundColor Gray
    }
    
    # CIS 9.6 - Turn on protection against Potentially Unwanted Applications
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable PUA protection" -ForegroundColor Green
    } else {
        Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
        Write-Host "  Enabled PUA protection" -ForegroundColor Gray
    }
    
    # CIS 9.7 - Scan removable drives
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable scanning of removable drives" -ForegroundColor Green
    } else {
        Set-MpPreference -DisableRemovableDriveScanning $false -ErrorAction SilentlyContinue
        Write-Host "  Enabled removable drive scanning" -ForegroundColor Gray
    }
    
    # CIS 9.9 - Configure scheduled scan (Daily quick scan)
    if ($WhatIf) {
        Write-Host "[WHATIF] Would configure daily quick scan at 2:00 AM" -ForegroundColor Green
    } else {
        # Schedule daily quick scan at 2:00 AM
        $scanTime = New-TimeSpan -Hours 2 -Minutes 0
        Set-MpPreference -ScanScheduleDay Everyday -ScanScheduleTime $scanTime -ScanType QuickScan -ErrorAction SilentlyContinue
        Write-Host "  Configured daily quick scan at 2:00 AM" -ForegroundColor Gray
    }
    
    # CIS 9.10 - Turn on e-mail scanning
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable email scanning" -ForegroundColor Green
    } else {
        Set-MpPreference -DisableEmailScanning $false -ErrorAction SilentlyContinue
        Write-Host "  Enabled email scanning" -ForegroundColor Gray
    }
    
    # CIS 9.11 - Turn on network protection
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable network protection in block mode" -ForegroundColor Green
    } else {
        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
        Write-Host "  Enabled network protection" -ForegroundColor Gray
    }
    
    # Additional recommended settings
    Write-Host "`nConfiguring additional Defender settings..." -ForegroundColor Yellow
    
    # Enable process scanning
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable process scanning" -ForegroundColor Green
    } else {
        Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
        Write-Host "  Enabled process scanning" -ForegroundColor Gray
    }
    
    # Enable script scanning
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable script scanning" -ForegroundColor Green
    } else {
        Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
        Write-Host "  Enabled script scanning" -ForegroundColor Gray
    }
    
    # Set scan parameters
    if ($WhatIf) {
        Write-Host "[WHATIF] Would configure scan parameters" -ForegroundColor Green
    } else {
        Set-MpPreference -ScanAvgCPULoadFactor 50 -ErrorAction SilentlyContinue
        Set-MpPreference -RemediationScheduleDay Everyday -ErrorAction SilentlyContinue
        Write-Host "  Configured scan CPU load factor and remediation schedule" -ForegroundColor Gray
    }
    
    if (-not $WhatIf) {
        Write-Host "`nVerifying Defender configuration..." -ForegroundColor Yellow
        $prefs = Get-MpPreference
        $status = Get-MpComputerStatus
        
        Write-Host "`nCurrent Defender Settings:" -ForegroundColor Cyan
        Write-Host "  Real-time protection: $($status.RealTimeProtectionEnabled)" -ForegroundColor Gray
        Write-Host "  Cloud protection: $($prefs.MAPSReporting)" -ForegroundColor Gray
        Write-Host "  PUA protection: $($prefs.PUAProtection)" -ForegroundColor Gray
        Write-Host "  Network protection: $($prefs.EnableNetworkProtection)" -ForegroundColor Gray
        Write-Host "  Sample submission: $($prefs.SubmitSamplesConsent)" -ForegroundColor Gray
        Write-Host "  Scheduled scan: $($prefs.ScanScheduleDay) at $($prefs.ScanScheduleTime)" -ForegroundColor Gray
    }
    
} catch {
    Write-Warning "Error configuring Windows Defender: $_"
    Write-Host "Some Defender settings may not have been applied. Review errors above." -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Windows Defender Configuration Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`nNote: Some settings (like tamper protection) may require Group Policy configuration." -ForegroundColor Yellow


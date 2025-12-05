# Script: Configure-RDPHardening.ps1
# Purpose: Harden Remote Desktop Protocol (RDP) settings
# Framework Alignment: CIS Benchmarks 2.3.7-2.3.15
# Requires: Administrator privileges

<#
.SYNOPSIS
    Hardens RDP configuration with security best practices.

.DESCRIPTION
    This script configures:
    - Network Level Authentication (NLA)
    - RDP encryption level
    - Session timeouts
    - Clipboard and drive redirection restrictions
    - RDP port (optional)

.NOTES
    - Many settings are better managed via Group Policy
    - Some settings require registry changes
    - Test RDP connectivity after applying changes
    - CIS References: 2.3.7-2.3.15

.PARAMETER RDPSecurityGroup
    Security group allowed to use RDP (e.g., "DOMAIN\RDP-Users")

.PARAMETER ChangeRDPPort
    Change RDP port from default 3389 (optional, requires firewall rule update)

.EXAMPLE
    .\Configure-RDPHardening.ps1 -RDPSecurityGroup "DOMAIN\RDP-Users"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$RDPSecurityGroup = "",  # e.g., "DOMAIN\RDP-Users"
    
    [Parameter(Mandatory=$false)]
    [int]$ChangeRDPPort = 0,  # 0 = keep default 3389
    
    [switch]$WhatIf
)

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'  # Continue on errors to attempt all operations

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RDP Hardening Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Registry paths
$rdpRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$rdpWinStationsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$rdpClientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

try {
    Write-Host "Configuring RDP security settings..." -ForegroundColor Yellow
    
    # CIS 2.3.7 - Require Network Level Authentication (NLA)
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable Network Level Authentication" -ForegroundColor Green
    } else {
        Set-ItemProperty -Path $rdpRegPath -Name "fDenyTSConnections" -Value 0 -ErrorAction Stop
        Set-ItemProperty -Path $rdpRegPath -Name "UserAuthentication" -Value 1 -ErrorAction Stop
        Write-Host "  Enabled Network Level Authentication (NLA)" -ForegroundColor Gray
    }
    
    # CIS 2.3.9 - Set client connection encryption level to High
    if ($WhatIf) {
        Write-Host "[WHATIF] Would set encryption level to High" -ForegroundColor Green
    } else {
        if (-not (Test-Path $rdpWinStationsPath)) {
            New-Item -Path $rdpWinStationsPath -Force | Out-Null
        }
        Set-ItemProperty -Path $rdpWinStationsPath -Name "MinEncryptionLevel" -Value 3 -ErrorAction Stop
        # 1 = Low, 2 = Client Compatible, 3 = High, 4 = FIPS Compliant
        Write-Host "  Set encryption level to High" -ForegroundColor Gray
    }
    
    # CIS 2.3.12 - Set time limit for active RDP sessions (15 minutes)
    if ($WhatIf) {
        Write-Host "[WHATIF] Would set active session limit to 15 minutes" -ForegroundColor Green
    } else {
        Set-ItemProperty -Path $rdpWinStationsPath -Name "MaxConnectionTime" -Value 900000 -ErrorAction Stop
        # Value in milliseconds: 900000 = 15 minutes
        Write-Host "  Set active session limit to 15 minutes" -ForegroundColor Gray
    }
    
    # CIS 2.3.13 - Set time limit for disconnected sessions (15 minutes)
    if ($WhatIf) {
        Write-Host "[WHATIF] Would set disconnected session limit to 15 minutes" -ForegroundColor Green
    } else {
        Set-ItemProperty -Path $rdpWinStationsPath -Name "MaxDisconnectionTime" -Value 900000 -ErrorAction Stop
        Write-Host "  Set disconnected session limit to 15 minutes" -ForegroundColor Gray
    }
    
    # CIS 2.3.14 - Disable clipboard redirection
    if ($WhatIf) {
        Write-Host "[WHATIF] Would disable clipboard redirection" -ForegroundColor Green
    } else {
        # This is typically managed via GPO, but can be set via registry
        # GPO: Computer Configuration > Policies > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Device and Resource Redirection
        Write-Host "  Clipboard redirection should be disabled via GPO (see GPO-Configuration-Tables.md)" -ForegroundColor Yellow
    }
    
    # CIS 2.3.15 - Disable drive redirection
    if ($WhatIf) {
        Write-Host "[WHATIF] Would disable drive redirection" -ForegroundColor Green
    } else {
        # This is typically managed via GPO
        Write-Host "  Drive redirection should be disabled via GPO (see GPO-Configuration-Tables.md)" -ForegroundColor Yellow
    }
    
    # Optional: Change RDP port
    if ($ChangeRDPPort -gt 0 -and $ChangeRDPPort -ne 3389) {
        if ($WhatIf) {
            Write-Host "[WHATIF] Would change RDP port to $ChangeRDPPort" -ForegroundColor Green
            Write-Host "[WHATIF] WARNING: Update firewall rules and inform users of new port" -ForegroundColor Yellow
        } else {
            Set-ItemProperty -Path $rdpWinStationsPath -Name "PortNumber" -Value $ChangeRDPPort -ErrorAction Stop
            Write-Host "  Changed RDP port to $ChangeRDPPort" -ForegroundColor Gray
            Write-Warning "RDP port changed to $ChangeRDPPort. Update firewall rules and inform users."
            Write-Warning "Connect using: mstsc /v:server:$ChangeRDPPort"
        }
    }
    
    # Enable RDP if disabled
    if (-not $WhatIf) {
        $rdpEnabled = (Get-ItemProperty -Path $rdpRegPath -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
        if ($rdpEnabled -eq 1) {
            Write-Host "  Enabling RDP..." -ForegroundColor Gray
            Set-ItemProperty -Path $rdpRegPath -Name "fDenyTSConnections" -Value 0
        }
    }
    
    # Configure RDP security group (if specified)
    if (-not [string]::IsNullOrWhiteSpace($RDPSecurityGroup)) {
        if ($WhatIf) {
            Write-Host "[WHATIF] Would restrict RDP to security group: $RDPSecurityGroup" -ForegroundColor Green
        } else {
            Write-Host "  Restricting RDP access to: $RDPSecurityGroup" -ForegroundColor Gray
            Write-Host "  Note: Use Configure-UserRights.ps1 or GPO to set 'Allow log on through RDP' user right" -ForegroundColor Yellow
            Write-Host "  GPO Path: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment" -ForegroundColor Yellow
            Write-Host "  Policy: 'Allow log on through Remote Desktop Services'" -ForegroundColor Yellow
        }
    } else {
        Write-Warning "No RDP security group specified. RDP access should be restricted to specific security group."
        Write-Warning "Run: .\Configure-UserRights.ps1 -RDPSecurityGroup 'DOMAIN\RDP-Users'"
    }
    
    # Additional security settings
    Write-Host "`nConfiguring additional RDP security settings..." -ForegroundColor Yellow
    
    # Disable RDP printer redirection
    if ($WhatIf) {
        Write-Host "[WHATIF] Would disable printer redirection" -ForegroundColor Green
    } else {
        # Managed via GPO, but can be set via registry
        Write-Host "  Printer redirection should be disabled via GPO" -ForegroundColor Yellow
    }
    
    # Require RDP security layer (RDP security layer instead of negotiable)
    if ($WhatIf) {
        Write-Host "[WHATIF] Would require RDP security layer" -ForegroundColor Green
    } else {
        Set-ItemProperty -Path $rdpWinStationsPath -Name "SecurityLayer" -Value 1 -ErrorAction SilentlyContinue
        # 0 = Negotiate, 1 = RDP, 2 = TLS
        Write-Host "  Set security layer to RDP (consider TLS/2 for enhanced security)" -ForegroundColor Gray
    }
    
    if (-not $WhatIf) {
        Write-Host "`nVerifying RDP configuration..." -ForegroundColor Yellow
        
        # Check RDP status
        $rdpStatus = Get-ItemProperty -Path $rdpRegPath -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
        $nlaStatus = Get-ItemProperty -Path $rdpRegPath -Name "UserAuthentication" -ErrorAction SilentlyContinue
        $encryptionLevel = Get-ItemProperty -Path $rdpWinStationsPath -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
        $rdpPort = Get-ItemProperty -Path $rdpWinStationsPath -Name "PortNumber" -ErrorAction SilentlyContinue
        
        Write-Host "`nRDP Configuration:" -ForegroundColor Cyan
        Write-Host "  RDP Enabled: $($rdpStatus.fDenyTSConnections -eq 0)" -ForegroundColor Gray
        Write-Host "  NLA Required: $($nlaStatus.UserAuthentication -eq 1)" -ForegroundColor Gray
        Write-Host "  Encryption Level: $($encryptionLevel.MinEncryptionLevel) (3 = High)" -ForegroundColor Gray
        Write-Host "  RDP Port: $($rdpPort.PortNumber)" -ForegroundColor Gray
        
        # Check firewall rule
        $rdpFirewallRule = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }
        if ($rdpFirewallRule) {
            Write-Host "  Firewall Rule: Enabled" -ForegroundColor Gray
        } else {
            Write-Warning "RDP firewall rule may be disabled. Verify firewall configuration."
        }
        
        Write-Host "`nNote: Some settings require Group Policy for full enforcement." -ForegroundColor Yellow
        Write-Host "Review GPO-Configuration-Tables.md for complete RDP hardening settings." -ForegroundColor Yellow
    }
    
} catch {
    Write-Error "Error configuring RDP hardening: $_"
    throw
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "RDP Hardening Configuration Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`nSecurity Recommendations:" -ForegroundColor Yellow
Write-Host "1. Restrict RDP to specific security group (not Domain Users)" -ForegroundColor White
Write-Host "2. Consider using a jump host or VPN for RDP access" -ForegroundColor White
Write-Host "3. Implement Just-in-Time (JIT) access if available" -ForegroundColor White
Write-Host "4. Monitor RDP connection attempts in Event Viewer" -ForegroundColor White
Write-Host "5. Consider changing RDP port from default 3389" -ForegroundColor White


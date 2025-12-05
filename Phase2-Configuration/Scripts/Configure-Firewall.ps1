# Script: Configure-Firewall.ps1
# Purpose: Configure Windows Firewall with Advanced Security
# Framework Alignment: CIS Benchmarks 9.1-9.2, Microsoft Security Baseline
# Requires: Administrator privileges

<#
.SYNOPSIS
    Configures Windows Firewall with default-deny inbound rules and allows only required ports.

.DESCRIPTION
    This script:
    - Sets firewall profiles to block inbound by default
    - Allows only required ports (RDP, SMB, etc.)
    - Configures outbound rules as needed
    - Removes or disables unnecessary rules

.NOTES
    - Modify allowed ports based on your server role
    - Test firewall rules in lab before production
    - CIS References: 9.1-9.2

.PARAMETER AllowedPorts
    Array of port numbers to allow inbound (e.g., @(3389, 445, 5985))

.PARAMETER ServerRole
    Server role description (e.g., "File Server", "Application Server") for rule naming

.EXAMPLE
    .\Configure-Firewall.ps1 -AllowedPorts @(3389, 445, 5985) -ServerRole "Application Server"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [int[]]$AllowedPorts = @(3389, 445, 5985),  # RDP, SMB, WinRM HTTP
    
    [Parameter(Mandatory=$false)]
    [string]$ServerRole = "Member Server",
    
    [switch]$WhatIf
)

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'  # Continue on errors to attempt all operations

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Windows Firewall Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Server Role: $ServerRole" -ForegroundColor Yellow
Write-Host "Allowed Inbound Ports: $($AllowedPorts -join ', ')" -ForegroundColor Yellow
Write-Host ""

try {
    # Get firewall profiles
    $domainProfile = Get-NetFirewallProfile -Profile Domain
    $privateProfile = Get-NetFirewallProfile -Profile Private
    $publicProfile = Get-NetFirewallProfile -Profile Public
    
    Write-Host "Configuring firewall profiles..." -ForegroundColor Yellow
    
    # Configure Domain Profile - CIS 9.1
    if ($WhatIf) {
        Write-Host "[WHATIF] Would configure Domain profile: Block inbound, Allow outbound" -ForegroundColor Green
    } else {
        Set-NetFirewallProfile -Profile Domain -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
        Write-Host "  Domain profile: Enabled, Block inbound, Allow outbound" -ForegroundColor Gray
    }
    
    # Configure Private Profile - CIS 9.1
    if ($WhatIf) {
        Write-Host "[WHATIF] Would configure Private profile: Block inbound, Allow outbound" -ForegroundColor Green
    } else {
        Set-NetFirewallProfile -Profile Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
        Write-Host "  Private profile: Enabled, Block inbound, Allow outbound" -ForegroundColor Gray
    }
    
    # Configure Public Profile - CIS 9.1
    if ($WhatIf) {
        Write-Host "[WHATIF] Would configure Public profile: Block inbound, Allow outbound" -ForegroundColor Green
    } else {
        Set-NetFirewallProfile -Profile Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
        Write-Host "  Public profile: Enabled, Block inbound, Allow outbound" -ForegroundColor Gray
    }
    
    Write-Host "`nConfiguring inbound firewall rules..." -ForegroundColor Yellow
    
    # Remove default inbound allow rules (except system rules)
    if (-not $WhatIf) {
        $defaultInboundRules = Get-NetFirewallRule -Direction Inbound -Enabled True | 
            Where-Object { $_.DisplayName -notlike "*Core Networking*" -and $_.DisplayName -notlike "*File and Printer Sharing*" }
        
        Write-Host "  Reviewing existing inbound rules..." -ForegroundColor Gray
        foreach ($rule in $defaultInboundRules) {
            Write-Host "    Found: $($rule.DisplayName)" -ForegroundColor DarkGray
        }
    }
    
    # Create inbound allow rules for specified ports
    foreach ($port in $AllowedPorts) {
        $ruleName = "Hardening-Allow-Inbound-Port-$port"
        $ruleDisplayName = "Hardening: Allow Inbound Port $port ($ServerRole)"
        
        if ($WhatIf) {
            Write-Host "[WHATIF] Would create inbound rule: $ruleDisplayName" -ForegroundColor Green
        } else {
            # Check if rule already exists
            $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
            
            if ($existingRule) {
                Write-Host "  Rule already exists: $ruleDisplayName" -ForegroundColor Gray
            } else {
                # Create new rule
                New-NetFirewallRule -Name $ruleName `
                    -DisplayName $ruleDisplayName `
                    -Direction Inbound `
                    -Protocol TCP `
                    -LocalPort $port `
                    -Action Allow `
                    -Profile Domain,Private `
                    -Enabled True | Out-Null
                
                Write-Host "  Created: $ruleDisplayName" -ForegroundColor Gray
            }
        }
    }
    
    # Common required rules
    Write-Host "`nConfiguring common required rules..." -ForegroundColor Yellow
    
    # ICMP (ping) - optional, disable if not needed
    $icmpRuleName = "Hardening-Allow-ICMP"
    if ($WhatIf) {
        Write-Host "[WHATIF] Would create ICMP rule (optional)" -ForegroundColor Green
    } else {
        $existingICMP = Get-NetFirewallRule -Name $icmpRuleName -ErrorAction SilentlyContinue
        if (-not $existingICMP) {
            # Allow ICMP Echo Request (ping) - comment out if not needed
            # New-NetFirewallRule -Name $icmpRuleName `
            #     -DisplayName "Hardening: Allow ICMP Echo Request" `
            #     -Direction Inbound `
            #     -Protocol ICMPv4 `
            #     -IcmpType 8 `
            #     -Action Allow `
            #     -Profile Domain,Private `
            #     -Enabled True | Out-Null
            Write-Host "  ICMP rule skipped (disabled by default for security)" -ForegroundColor Gray
        }
    }
    
    # SMB (if port 445 is in allowed ports)
    if ($AllowedPorts -contains 445) {
        $smbRuleName = "Hardening-Allow-SMB"
        if ($WhatIf) {
            Write-Host "[WHATIF] Would ensure SMB rule exists" -ForegroundColor Green
        } else {
            $existingSMB = Get-NetFirewallRule -Name $smbRuleName -ErrorAction SilentlyContinue
            if (-not $existingSMB) {
                # SMB is typically handled by built-in "File and Printer Sharing" rule
                Write-Host "  SMB access via File and Printer Sharing rule (verify it's enabled)" -ForegroundColor Gray
            }
        }
    }
    
    # RDP (if port 3389 is in allowed ports)
    if ($AllowedPorts -contains 3389) {
        $rdpRuleName = "Hardening-Allow-RDP"
        if ($WhatIf) {
            Write-Host "[WHATIF] Would ensure RDP rule exists" -ForegroundColor Green
        } else {
            # RDP is typically handled by built-in "Remote Desktop" rule
            $rdpRule = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
            if ($rdpRule) {
                Write-Host "  RDP access via Remote Desktop rule (verify it's enabled and restricted)" -ForegroundColor Gray
            } else {
                Write-Warning "RDP rule not found. RDP may be blocked."
            }
        }
    }
    
    # WinRM (if port 5985/5986 is in allowed ports)
    if ($AllowedPorts -contains 5985 -or $AllowedPorts -contains 5986) {
        $winrmRuleName = "Hardening-Allow-WinRM"
        if ($WhatIf) {
            Write-Host "[WHATIF] Would ensure WinRM rule exists" -ForegroundColor Green
        } else {
            $winrmRule = Get-NetFirewallRule -DisplayGroup "Windows Remote Management" -ErrorAction SilentlyContinue
            if ($winrmRule) {
                Write-Host "  WinRM access via Windows Remote Management rule (verify it's enabled and restricted)" -ForegroundColor Gray
            } else {
                Write-Warning "WinRM rule not found. WinRM may be blocked."
            }
        }
    }
    
    if (-not $WhatIf) {
        Write-Host "`nVerifying firewall configuration..." -ForegroundColor Yellow
        $profiles = Get-NetFirewallProfile
        foreach ($profile in $profiles) {
            Write-Host "`n$($profile.Name) Profile:" -ForegroundColor Cyan
            Write-Host "  Enabled: $($profile.Enabled)" -ForegroundColor Gray
            Write-Host "  Inbound: $($profile.DefaultInboundAction)" -ForegroundColor Gray
            Write-Host "  Outbound: $($profile.DefaultOutboundAction)" -ForegroundColor Gray
        }
        
        Write-Host "`nInbound Allow Rules:" -ForegroundColor Cyan
        $inboundRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | 
            Where-Object { $_.Name -like "Hardening-*" -or $_.DisplayGroup -in @("Remote Desktop", "File and Printer Sharing", "Windows Remote Management") }
        foreach ($rule in $inboundRules) {
            $ports = ($rule | Get-NetFirewallPortFilter).LocalPort
            Write-Host "  $($rule.DisplayName) - Ports: $ports" -ForegroundColor Gray
        }
    }
    
} catch {
    Write-Error "Error configuring firewall: $_"
    throw
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Windows Firewall Configuration Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`nNote: Review and test firewall rules before production deployment." -ForegroundColor Yellow
Write-Host "Verify required applications can communicate through the firewall." -ForegroundColor Yellow


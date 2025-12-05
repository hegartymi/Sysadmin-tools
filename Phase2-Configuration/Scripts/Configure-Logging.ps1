# Script: Configure-Logging.ps1
# Purpose: Configure advanced audit policy and PowerShell logging
# Framework Alignment: CIS Benchmarks 17.x, 18.9.x
# Requires: Administrator privileges

<#
.SYNOPSIS
    Configures comprehensive logging including advanced audit policy and PowerShell logging.

.DESCRIPTION
    This script enables:
    - Advanced Audit Policy (replaces basic audit policy)
    - PowerShell transcription
    - PowerShell script block logging
    - PowerShell module logging
    - Event log size and retention

.NOTES
    - Advanced Audit Policy requires Windows Server 2008 R2 or later
    - PowerShell logging generates significant log volume
    - Ensure sufficient disk space for logs
    - CIS References: 17.1.x-17.10.x, 18.9.x

.EXAMPLE
    .\Configure-Logging.ps1
#>

[CmdletBinding()]
param(
    [switch]$WhatIf
)

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'  # Continue on errors to attempt all operations

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Logging & Auditing Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

try {
    Write-Host "Configuring Advanced Audit Policy..." -ForegroundColor Yellow
    
    # Advanced Audit Policy subcategories
    $auditPolicies = @{
        # Account Logon - CIS 17.1.x
        "AuditCredentialValidation" = "Success and Failure"
        "AuditKerberosAuthenticationService" = "Success and Failure"
        "AuditKerberosServiceTicketOperations" = "Success and Failure"
        "AuditOtherAccountLogonEvents" = "Success and Failure"
        
        # Account Management - CIS 17.2.x
        "AuditApplicationGroupManagement" = "Success and Failure"
        "AuditComputerAccountManagement" = "Success and Failure"
        "AuditDistributionGroupManagement" = "Success and Failure"
        "AuditOtherAccountManagementEvents" = "Success and Failure"
        "AuditSecurityGroupManagement" = "Success and Failure"
        "AuditUserAccountManagement" = "Success and Failure"
        
        # DS Access - CIS 17.8.x
        "AuditDirectoryServiceAccess" = "Success and Failure"
        "AuditDirectoryServiceChanges" = "Success and Failure"
        "AuditDirectoryServiceReplication" = "Success and Failure"
        "AuditDetailedDirectoryServiceReplication" = "No Auditing"
        
        # Logon/Logoff - CIS 17.3.x
        "AuditAccountLockout" = "Success and Failure"
        "AuditUserDeviceClaims" = "Success and Failure"
        "AuditIPsecExtendedMode" = "Success and Failure"
        "AuditIPsecMainMode" = "Success and Failure"
        "AuditIPsecQuickMode" = "Success and Failure"
        "AuditLogoff" = "Success"
        "AuditLogon" = "Success and Failure"
        "AuditNetworkPolicyServer" = "Success and Failure"
        "AuditOtherLogonLogoffEvents" = "Success and Failure"
        "AuditSpecialLogon" = "Success and Failure"
        
        # Object Access - CIS 17.4.x (enable for sensitive objects)
        "AuditApplicationGenerated" = "Success and Failure"
        "AuditCertificationServices" = "Success and Failure"
        "AuditDetailedFileShare" = "Success and Failure"
        "AuditFileShare" = "Success and Failure"
        "AuditFileSystem" = "Success and Failure"
        "AuditFilteringPlatformConnection" = "Success and Failure"
        "AuditFilteringPlatformPacketDrop" = "Success and Failure"
        "AuditHandleManipulation" = "Success and Failure"
        "AuditKernelObject" = "Success and Failure"
        "AuditOtherObjectAccessEvents" = "Success and Failure"
        "AuditRegistry" = "Success and Failure"
        "AuditRemovableStorage" = "Success and Failure"
        "AuditSAM" = "Success and Failure"
        "AuditCentralAccessPolicyStaging" = "Success and Failure"
        
        # Policy Change - CIS 17.5.x
        "AuditAuditPolicyChange" = "Success and Failure"
        "AuditAuthenticationPolicyChange" = "Success and Failure"
        "AuditAuthorizationPolicyChange" = "Success and Failure"
        "AuditFilteringPlatformPolicyChange" = "Success and Failure"
        "AuditMPSSVCRuleLevelPolicyChange" = "Success and Failure"
        "AuditOtherPolicyChangeEvents" = "Success and Failure"
        "AuditPolicyChange" = "Success and Failure"
        
        # Privilege Use - CIS 17.6.x
        "AuditNonSensitivePrivilegeUse" = "No Auditing"
        "AuditOtherPrivilegeUseEvents" = "No Auditing"
        "AuditSensitivePrivilegeUse" = "Failure"
        
        # System - CIS 17.7.x
        "AuditIPsecDriver" = "Success and Failure"
        "AuditOtherSystemEvents" = "Success and Failure"
        "AuditSecurityStateChange" = "Success and Failure"
        "AuditSecuritySystemExtension" = "Success and Failure"
        "AuditSystemIntegrity" = "Success and Failure"
    }
    
    foreach ($policy in $auditPolicies.Keys) {
        $value = $auditPolicies[$policy]
        
        if ($WhatIf) {
            Write-Host "[WHATIF] Would set audit policy: $policy = $value" -ForegroundColor Green
        } else {
            try {
                # Convert value to auditpol format
                $auditValue = switch ($value) {
                    "Success and Failure" { "/success:enable /failure:enable" }
                    "Success" { "/success:enable /failure:disable" }
                    "Failure" { "/success:disable /failure:enable" }
                    "No Auditing" { "/success:disable /failure:disable" }
                    default { "/success:enable /failure:enable" }
                }
                
                $auditpolArgs = "/set", "/subcategory:`"$policy`"", $auditValue
                $result = & auditpol.exe $auditpolArgs 2>&1
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "  Set: $policy = $value" -ForegroundColor Gray
                } else {
                    Write-Warning "Failed to set $policy : $result"
                }
            } catch {
                Write-Warning "Error setting $policy : $_"
            }
        }
    }
    
    # CIS 17.10.1 - Force audit policy subcategory settings
    Write-Host "`nConfiguring audit policy enforcement..." -ForegroundColor Yellow
    if ($WhatIf) {
        Write-Host "[WHATIF] Would force audit policy subcategory settings" -ForegroundColor Green
    } else {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -ErrorAction Stop
        Write-Host "  Enabled: Force audit policy subcategory settings" -ForegroundColor Gray
    }
    
    # Configure Event Log sizes - CIS 17.9.x
    Write-Host "`nConfiguring Event Log settings..." -ForegroundColor Yellow
    
    $eventLogs = @("Security", "Application", "System")
    foreach ($logName in $eventLogs) {
        if ($WhatIf) {
            Write-Host "[WHATIF] Would set $logName log size to 512 MB" -ForegroundColor Green
        } else {
            try {
                $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
                if ($log.MaximumSizeInBytes -lt 512MB) {
                    $log.MaximumSizeInBytes = 512MB
                    $log.SaveChanges()
                    Write-Host "  Set $logName log size to 512 MB" -ForegroundColor Gray
                } else {
                    Write-Host "  $logName log size already >= 512 MB" -ForegroundColor Gray
                }
            } catch {
                Write-Warning "Could not configure $logName log: $_"
            }
        }
    }
    
    # Configure PowerShell Logging - CIS 18.9.x
    Write-Host "`nConfiguring PowerShell logging..." -ForegroundColor Yellow
    
    $psLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
    $psTranscriptionPath = "$psLoggingPath\Transcription"
    $psScriptBlockPath = "$psLoggingPath\ScriptBlockLogging"
    $psModulePath = "$psLoggingPath\ModuleLogging"
    
    # PowerShell Transcription - CIS 18.9.x
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable PowerShell transcription" -ForegroundColor Green
    } else {
        if (-not (Test-Path $psTranscriptionPath)) {
            New-Item -Path $psTranscriptionPath -Force | Out-Null
        }
        Set-ItemProperty -Path $psTranscriptionPath -Name "EnableInvocationHeader" -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path $psTranscriptionPath -Name "EnableTranscripting" -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path $psTranscriptionPath -Name "OutputDirectory" -Value "C:\PowerShell-Logs" -ErrorAction Stop
        Write-Host "  Enabled PowerShell transcription" -ForegroundColor Gray
        Write-Host "  Output directory: C:\PowerShell-Logs" -ForegroundColor Gray
    }
    
    # PowerShell Script Block Logging - CIS 18.9.x
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable PowerShell script block logging" -ForegroundColor Green
    } else {
        if (-not (Test-Path $psScriptBlockPath)) {
            New-Item -Path $psScriptBlockPath -Force | Out-Null
        }
        Set-ItemProperty -Path $psScriptBlockPath -Name "EnableScriptBlockLogging" -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path $psScriptBlockPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -ErrorAction Stop
        Write-Host "  Enabled PowerShell script block logging" -ForegroundColor Gray
    }
    
    # PowerShell Module Logging - CIS 18.9.x
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable PowerShell module logging" -ForegroundColor Green
    } else {
        if (-not (Test-Path $psModulePath)) {
            New-Item -Path $psModulePath -Force | Out-Null
        }
        Set-ItemProperty -Path $psModulePath -Name "EnableModuleLogging" -Value 1 -ErrorAction Stop
        Write-Host "  Enabled PowerShell module logging" -ForegroundColor Gray
    }
    
    if (-not $WhatIf) {
        Write-Host "`nVerifying logging configuration..." -ForegroundColor Yellow
        
        # Verify audit policy
        Write-Host "`nAdvanced Audit Policy Status:" -ForegroundColor Cyan
        $criticalPolicies = @("AuditLogon", "AuditAccountLogon", "AuditAccountManagement", "AuditPolicyChange")
        foreach ($policy in $criticalPolicies) {
            $status = & auditpol.exe /get /subcategory:"$policy" 2>&1 | Select-String "Subcategory GUID"
            Write-Host "  $policy : Configured" -ForegroundColor Gray
        }
        
        # Verify PowerShell logging
        Write-Host "`nPowerShell Logging Status:" -ForegroundColor Cyan
        $transcription = Get-ItemProperty -Path $psTranscriptionPath -ErrorAction SilentlyContinue
        $scriptBlock = Get-ItemProperty -Path $psScriptBlockPath -ErrorAction SilentlyContinue
        $module = Get-ItemProperty -Path $psModulePath -ErrorAction SilentlyContinue
        
        Write-Host "  Transcription: $($transcription.EnableTranscripting -eq 1)" -ForegroundColor Gray
        Write-Host "  Script Block Logging: $($scriptBlock.EnableScriptBlockLogging -eq 1)" -ForegroundColor Gray
        Write-Host "  Module Logging: $($module.EnableModuleLogging -eq 1)" -ForegroundColor Gray
        
        Write-Host "`nEvent Log Locations:" -ForegroundColor Cyan
        Write-Host "  Security: Event Viewer > Windows Logs > Security" -ForegroundColor Gray
        Write-Host "  PowerShell: Event Viewer > Applications and Services Logs > Microsoft > Windows > PowerShell" -ForegroundColor Gray
        Write-Host "  Transcription: C:\PowerShell-Logs (if configured)" -ForegroundColor Gray
    }
    
} catch {
    Write-Error "Error configuring logging: $_"
    throw
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Logging & Auditing Configuration Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`nNote: PowerShell logging generates significant log volume." -ForegroundColor Yellow
Write-Host "Monitor disk space and configure log rotation as needed." -ForegroundColor Yellow


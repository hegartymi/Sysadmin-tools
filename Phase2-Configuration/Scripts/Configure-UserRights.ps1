# Script: Configure-UserRights.ps1
# Purpose: Configure Windows Server 2025 user rights assignments
# Framework Alignment: CIS Benchmarks 2.2.x
# Requires: Administrator privileges, secedit.exe

<#
.SYNOPSIS
    Configures user rights assignments according to CIS Benchmarks.

.DESCRIPTION
    This script applies recommended user rights assignments including:
    - Network access restrictions
    - Logon rights
    - System privileges
    - Backup and restore rights

.NOTES
    - These settings are typically managed via Group Policy
    - Local policy changes may be overridden by domain GPO
    - Test in lab environment before production
    - CIS References: 2.2.1-2.2.42

.EXAMPLE
    .\Configure-UserRights.ps1 -RDPSecurityGroup "DOMAIN\RDP-Users"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$RDPSecurityGroup = "",  # e.g., "DOMAIN\RDP-Users" - if empty, will use Administrators only
    
    [switch]$WhatIf
)

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'  # Continue on errors to attempt all operations

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "User Rights Assignment Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Create temporary INF file for secedit
$infPath = "$env:TEMP\UserRights.inf"
$sdbPath = "$env:TEMP\UserRights.sdb"

# Default RDP group - if not specified, use Administrators only
if ([string]::IsNullOrWhiteSpace($RDPSecurityGroup)) {
    $RDPSecurityGroup = "*S-1-5-32-544"  # Administrators SID
    Write-Warning "No RDP security group specified. Using Administrators only."
    Write-Warning "For production, specify a dedicated security group: -RDPSecurityGroup 'DOMAIN\RDP-Users'"
} else {
    Write-Host "RDP access will be restricted to: $RDPSecurityGroup" -ForegroundColor Yellow
}

try {
    # Build INF content for user rights
    $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature=`"`$CHICAGO`$`"
Revision=1
[Privilege Rights]
; CIS 2.2.1 - Access Credential Manager as a trusted caller
SeTrustedCredManAccessPrivilege = 

; CIS 2.2.2 - Access this computer from the network
; Remove Domain Users if possible, keep only Authenticated Users or specific groups
SeNetworkLogonRight = *S-1-5-11

; CIS 2.2.3 - Act as part of the operating system
SeTcbPrivilege = 

; CIS 2.2.4 - Add workstations to domain
SeMachineAccountPrivilege = *S-1-5-32-544

; CIS 2.2.5 - Allow log on locally
SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-551

; CIS 2.2.6 - Allow log on through RDP (Critical!)
SeRemoteInteractiveLogonRight = $RDPSecurityGroup

; CIS 2.2.7 - Back up files and directories
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551

; CIS 2.2.8 - Change the system time
SeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19

; CIS 2.2.9 - Change the time zone
SeTimeZonePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-32-545

; CIS 2.2.10 - Create a pagefile
SeCreatePagefilePrivilege = *S-1-5-32-544

; CIS 2.2.11 - Create a token object
SeCreateTokenPrivilege = 

; CIS 2.2.12 - Create global objects
SeCreateGlobalPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6

; CIS 2.2.13 - Create permanent shared objects
SeCreatePermanentPrivilege = 

; CIS 2.2.14 - Create symbolic links
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544

; CIS 2.2.15 - Debug programs
SeDebugPrivilege = *S-1-5-32-544

; CIS 2.2.16 - Deny access to this computer from the network
SeDenyNetworkLogonRight = *S-1-5-32-501,*S-1-5-32-546

; CIS 2.2.17 - Deny log on as a batch job
SeDenyBatchLogonRight = *S-1-5-32-501

; CIS 2.2.18 - Deny log on as a service
SeDenyServiceLogonRight = *S-1-5-32-501

; CIS 2.2.19 - Deny log on locally
SeDenyInteractiveLogonRight = *S-1-5-32-501

; CIS 2.2.20 - Deny log on through RDP
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-501,*S-1-5-32-546

; CIS 2.2.21 - Enable computer and user accounts to be trusted for delegation
SeEnableDelegationPrivilege = 

; CIS 2.2.22 - Force shutdown from a remote system
SeRemoteShutdownPrivilege = *S-1-5-32-544

; CIS 2.2.23 - Generate security audits
SeAuditPrivilege = *S-1-5-19,*S-1-5-20

; CIS 2.2.24 - Impersonate a client after authentication
SeImpersonatePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6

; CIS 2.2.25 - Increase a process working set
SeIncreaseWorkingSetPrivilege = *S-1-5-32-545

; CIS 2.2.26 - Increase scheduling priority
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544

; CIS 2.2.27 - Load and unload device drivers
SeLoadDriverPrivilege = *S-1-5-32-544

; CIS 2.2.28 - Lock pages in memory
SeLockMemoryPrivilege = 

; CIS 2.2.29 - Log on as a batch job
SeBatchLogonRight = *S-1-5-32-544,*S-1-5-32-551

; CIS 2.2.30 - Log on as a service
SeServiceLogonRight = *S-1-5-20,*S-1-5-6

; CIS 2.2.31 - Manage auditing and security log
SeSecurityPrivilege = *S-1-5-32-544

; CIS 2.2.32 - Modify an object label
SeRelabelPrivilege = 

; CIS 2.2.33 - Modify firmware environment values
SeSystemEnvironmentPrivilege = *S-1-5-32-544

; CIS 2.2.34 - Perform volume maintenance tasks
SeManageVolumePrivilege = *S-1-5-32-544

; CIS 2.2.35 - Profile single process
SeProfileSingleProcessPrivilege = *S-1-5-32-544

; CIS 2.2.36 - Profile system performance
SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-0

; CIS 2.2.37 - Remove computer from docking station
SeUndockPrivilege = *S-1-5-32-544,*S-1-5-32-545

; CIS 2.2.38 - Replace a process level token
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20

; CIS 2.2.39 - Restore files and directories
SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551

; CIS 2.2.40 - Shut down the system
SeShutdownPrivilege = *S-1-5-32-544

; CIS 2.2.41 - Synchronize directory service data
SeSyncAgentPrivilege = 

; CIS 2.2.42 - Take ownership of files or other objects
SeTakeOwnershipPrivilege = *S-1-5-32-544
"@

    Write-Host "Creating user rights INF file..." -ForegroundColor Yellow
    $infContent | Out-File -FilePath $infPath -Encoding ASCII -Force

    if ($WhatIf) {
        Write-Host "[WHATIF] Would apply user rights assignments:" -ForegroundColor Green
        Write-Host "  RDP access restricted to: $RDPSecurityGroup" -ForegroundColor Green
        Write-Host "  Network access: Authenticated Users only" -ForegroundColor Green
        Write-Host "  Local logon: Administrators, Backup Operators" -ForegroundColor Green
        Write-Host "  Guest account: Denied all logon types" -ForegroundColor Green
    } else {
        Write-Host "Applying user rights assignments..." -ForegroundColor Yellow
        
        # Import policy using secedit
        $seceditArgs = @(
            "/configure",
            "/db", $sdbPath,
            "/cfg", $infPath,
            "/quiet"
        )
        
        $result = Start-Process -FilePath "secedit.exe" -ArgumentList $seceditArgs -Wait -PassThru -NoNewWindow
        
        if ($result.ExitCode -eq 0) {
            Write-Host "User rights assignments applied successfully." -ForegroundColor Green
        } else {
            Write-Error "Failed to apply user rights assignments. Exit code: $($result.ExitCode)"
        }
        
        Write-Host "`nVerifying RDP access rights..." -ForegroundColor Yellow
        $rdpRights = (Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue)
        if ($rdpRights) {
            Write-Host "Current RDP Users group members:" -ForegroundColor Yellow
            $rdpRights | ForEach-Object { Write-Host "  $($_.Name)" -ForegroundColor Gray }
        }
        
        Write-Host "`nNote: Domain GPO may override local policy settings." -ForegroundColor Yellow
        Write-Host "Verify settings with: gpresult /h report.html" -ForegroundColor Yellow
    }
} catch {
    Write-Error "Error configuring user rights: $_"
    throw
} finally {
    # Cleanup
    if (Test-Path $infPath) { Remove-Item $infPath -Force -ErrorAction SilentlyContinue }
    if (Test-Path $sdbPath) { Remove-Item $sdbPath -Force -ErrorAction SilentlyContinue }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "User Rights Assignment Configuration Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan


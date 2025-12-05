# Script: Start-Hardening.ps1
# Purpose: Simple sequential execution of all hardening scripts
# Usage: .\Start-Hardening.ps1

<#
.SYNOPSIS
    Runs all hardening configuration scripts sequentially with progress indicators.

.DESCRIPTION
    This script executes each hardening script one after another, showing clear
    progress and pausing between phases for review.

.PARAMETER RDPSecurityGroup
    Security group allowed to use RDP (e.g., "DOMAIN\RDP-Users")

.PARAMETER AllowedPorts
    Array of ports to allow through firewall (default: RDP, SMB, WinRM)

.PARAMETER ASRMode
    ASR rule mode: Warn (Audit) or Block (default: Warn)

.PARAMETER SkipPause
    Skip pause prompts between scripts (for automated execution)

.PARAMETER WhatIf
    Preview changes without applying them

.EXAMPLE
    .\Start-Hardening.ps1
    
.EXAMPLE
    .\Start-Hardening.ps1 -RDPSecurityGroup "DOMAIN\RDP-Users" -SkipPause
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$RDPSecurityGroup = "",
    
    [Parameter(Mandatory=$false)]
    [int[]]$AllowedPorts = @(3389, 445, 5985),
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Warn", "Block", "Audit")]
    [string]$ASRMode = "Warn",
    
    [switch]$SkipPause,
    
    [switch]$WhatIf
)

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'  # Continue on errors to attempt all operations

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptsPath = Join-Path $scriptDir "Phase2-Configuration\Scripts"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Windows Server 2025 Hardening" -ForegroundColor Cyan
Write-Host "Sequential Execution Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($WhatIf) {
    Write-Host "WHATIF MODE: No changes will be made" -ForegroundColor Green
    Write-Host ""
}

# Verify we're running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator. Right-click and select 'Run as Administrator'."
    exit 1
}

# Define script execution order
$scripts = @(
    @{
        Name = "Account Policies"
        Script = "Configure-AccountPolicies.ps1"
        Params = @{}
    },
    @{
        Name = "Local Security Options"
        Script = "Configure-LocalSecurityOptions.ps1"
        Params = @{}
    },
    @{
        Name = "Cryptographic Settings"
        Script = "Configure-CryptographicSettings.ps1"
        Params = @{}
    },
    @{
        Name = "User Rights Assignments"
        Script = "Configure-UserRights.ps1"
        Params = if ($RDPSecurityGroup) { @{RDPSecurityGroup = $RDPSecurityGroup} } else { @{} }
    },
    @{
        Name = "Windows Defender"
        Script = "Configure-Defender.ps1"
        Params = @{}
    },
    @{
        Name = "Exploit Guard & ASR"
        Script = "Configure-ExploitGuard.ps1"
        Params = @{ASRMode = $ASRMode}
    },
    @{
        Name = "Windows Firewall"
        Script = "Configure-Firewall.ps1"
        Params = @{AllowedPorts = $AllowedPorts}
    },
    @{
        Name = "RDP Hardening"
        Script = "Configure-RDPHardening.ps1"
        Params = if ($RDPSecurityGroup) { @{RDPSecurityGroup = $RDPSecurityGroup} } else { @{} }
    },
    @{
        Name = "Logging & Auditing"
        Script = "Configure-Logging.ps1"
        Params = @{}
    },
    @{
        Name = "Credential Guard & LSA Protection"
        Script = "Configure-CredentialGuard.ps1"
        Params = @{}
    }
)

$totalScripts = $scripts.Count
$currentScript = 0
$failedScripts = @()
$startTime = Get-Date

Write-Host "Starting hardening process..." -ForegroundColor Yellow
Write-Host "Total scripts to run: $totalScripts" -ForegroundColor Yellow
Write-Host ""

foreach ($scriptInfo in $scripts) {
    $currentScript++
    $scriptPath = Join-Path $scriptsPath $scriptInfo.Script
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "[$currentScript/$totalScripts] $($scriptInfo.Name)" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Script: $($scriptInfo.Script)" -ForegroundColor Gray
    Write-Host ""
    
    # Check if script exists
    if (-not (Test-Path $scriptPath)) {
        Write-Warning "Script not found: $scriptPath"
        $failedScripts += $scriptInfo.Name
        continue
    }
    
    try {
        # Build parameter hashtable
        $params = $scriptInfo.Params.Clone()
        if ($WhatIf) {
            $params.WhatIf = $true
        }
        
        # Execute script with error handling
        $scriptError = $null
        try {
            & $scriptPath @params 2>&1 | ForEach-Object {
                if ($_ -is [System.Management.Automation.ErrorRecord]) {
                    Write-Host $_ -ForegroundColor Red
                    $scriptError = $_
                } else {
                    Write-Host $_
                }
            }
        } catch {
            Write-Warning "Error executing $($scriptInfo.Name): $_"
            $scriptError = $_
        }
        
        # Check for errors but continue anyway
        if ($scriptError -or ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne $null)) {
            Write-Warning "[$currentScript/$totalScripts] $($scriptInfo.Name) - COMPLETED WITH ERRORS" -ForegroundColor Yellow
            $failedScripts += $scriptInfo.Name
        } else {
            Write-Host ""
            Write-Host "[$currentScript/$totalScripts] $($scriptInfo.Name) - COMPLETED" -ForegroundColor Green
        }
        
    } catch {
        Write-Warning "Error executing $($scriptInfo.Name): $_"
        Write-Host "Continuing with next script..." -ForegroundColor Yellow
        $failedScripts += $scriptInfo.Name
    }
    
    # Pause between scripts (unless SkipPause is specified)
    if (-not $SkipPause -and $currentScript -lt $totalScripts) {
        Write-Host ""
        Write-Host "Press any key to continue to next script, or Ctrl+C to cancel..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Write-Host ""
    }
}

$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Hardening Process Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Duration: $([math]::Round($duration.TotalMinutes, 2)) minutes" -ForegroundColor Green
Write-Host "Scripts executed: $currentScript/$totalScripts" -ForegroundColor Green

if ($failedScripts.Count -gt 0) {
    Write-Host ""
    Write-Host "Failed scripts:" -ForegroundColor Red
    foreach ($failed in $failedScripts) {
        Write-Host "  - $failed" -ForegroundColor Red
    }
} else {
    Write-Host "All scripts completed successfully!" -ForegroundColor Green
}

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Review any warnings or errors above" -ForegroundColor White
Write-Host "2. Apply Group Policy settings (see GPO-Configuration-Tables.md)" -ForegroundColor White
Write-Host "3. Run validation: .\Phase3-Validation\Validate-Hardening.ps1" -ForegroundColor White
Write-Host "4. Restart server if required (Credential Guard)" -ForegroundColor White
Write-Host ""


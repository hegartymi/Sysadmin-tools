# Script: Enable-ServerHardening.ps1
# Purpose: Main orchestration script for Windows Server 2025 hardening
# Framework Alignment: CIS Benchmarks, Microsoft Security Baseline, ASD Essential Eight
# Requires: Administrator privileges

<#
.SYNOPSIS
    Orchestrates the complete Windows Server 2025 hardening process.

.DESCRIPTION
    This script runs all hardening configuration scripts in the correct order:
    1. Account Policies
    2. Local Security Options
    3. User Rights Assignments
    4. Windows Defender
    5. Exploit Guard & ASR
    6. Firewall
    7. RDP Hardening
    8. Logging & Auditing
    9. Credential Guard
    10. WDAC (optional)

.NOTES
    - Run this script as Administrator
    - Test in lab environment before production
    - Some settings may require system restart
    - Review each script's output for warnings

.PARAMETER SkipWDAC
    Skip WDAC configuration (WDAC requires careful planning)

.PARAMETER RDPSecurityGroup
    Security group allowed to use RDP (e.g., "DOMAIN\RDP-Users")

.PARAMETER AllowedPorts
    Array of ports to allow through firewall (default: RDP, SMB, WinRM)

.PARAMETER ASRMode
    ASR rule mode: Warn (Audit) or Block (default: Warn)

.PARAMETER WhatIf
    Show what would be done without making changes

.EXAMPLE
    .\Enable-ServerHardening.ps1 -RDPSecurityGroup "DOMAIN\RDP-Users"
    
.EXAMPLE
    .\Enable-ServerHardening.ps1 -WhatIf  # Preview changes
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipWDAC,
    
    [Parameter(Mandatory=$false)]
    [string]$RDPSecurityGroup = "",
    
    [Parameter(Mandatory=$false)]
    [int[]]$AllowedPorts = @(3389, 445, 5985),  # RDP, SMB, WinRM HTTP
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Warn", "Block", "Audit")]
    [string]$ASRMode = "Warn",
    
    [switch]$WhatIf
)

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'  # Continue on errors to attempt all operations

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Windows Server 2025 Hardening" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script will configure comprehensive security hardening." -ForegroundColor Yellow
Write-Host "Framework: CIS Benchmarks, Microsoft Security Baseline, ASD Essential Eight" -ForegroundColor Yellow
Write-Host ""

if ($WhatIf) {
    Write-Host "WHATIF MODE: No changes will be made" -ForegroundColor Green
    Write-Host ""
}

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptsPath = $scriptDir

# Verify all required scripts exist
$requiredScripts = @(
    "Configure-AccountPolicies.ps1",
    "Configure-LocalSecurityOptions.ps1",
    "Configure-CryptographicSettings.ps1",
    "Configure-UserRights.ps1",
    "Configure-Defender.ps1",
    "Configure-ExploitGuard.ps1",
    "Configure-Firewall.ps1",
    "Configure-RDPHardening.ps1",
    "Configure-Logging.ps1",
    "Configure-CredentialGuard.ps1"
)

Write-Host "Verifying required scripts..." -ForegroundColor Yellow
foreach ($script in $requiredScripts) {
    $scriptPath = Join-Path $scriptsPath $script
    if (-not (Test-Path $scriptPath)) {
        Write-Error "Required script not found: $scriptPath"
        exit 1
    }
}
Write-Host "All required scripts found." -ForegroundColor Green
Write-Host ""

# Confirmation prompt (unless WhatIf)
if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Windows Server 2025", "Apply security hardening")) {
    Write-Host "Hardening cancelled by user." -ForegroundColor Yellow
    exit 0
}

$startTime = Get-Date
Write-Host "Starting hardening process at $startTime" -ForegroundColor Cyan
Write-Host ""

$failedPhases = @()

# Helper function to execute a phase with error handling
function Invoke-HardeningPhase {
    param(
        [string]$PhaseName,
        [string]$ScriptPath,
        [hashtable]$Parameters = @{}
    )
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host $PhaseName -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    try {
        & $ScriptPath @Parameters 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                Write-Host $_ -ForegroundColor Red
            } else {
                Write-Host $_
            }
        }
        Write-Host ""
        Write-Host "$PhaseName - COMPLETED" -ForegroundColor Green
        Write-Host ""
    } catch {
        Write-Warning "$PhaseName - FAILED: $_"
        Write-Host "Continuing with next phase..." -ForegroundColor Yellow
        Write-Host ""
        $script:failedPhases += $PhaseName
    }
}

try {
    # Phase 1: Account Policies
    Invoke-HardeningPhase -PhaseName "Phase 1: Account Policies" `
        -ScriptPath "$scriptsPath\Configure-AccountPolicies.ps1" `
        -Parameters @{WhatIf = $WhatIf}
    
    # Phase 2: Local Security Options
    Invoke-HardeningPhase -PhaseName "Phase 2: Local Security Options" `
        -ScriptPath "$scriptsPath\Configure-LocalSecurityOptions.ps1" `
        -Parameters @{WhatIf = $WhatIf}
    
    # Phase 2.5: Cryptographic Settings
    Invoke-HardeningPhase -PhaseName "Phase 2.5: Cryptographic Settings" `
        -ScriptPath "$scriptsPath\Configure-CryptographicSettings.ps1" `
        -Parameters @{WhatIf = $WhatIf}
    
    # Phase 3: User Rights Assignments
    $userRightsParams = if ([string]::IsNullOrWhiteSpace($RDPSecurityGroup)) {
        @{WhatIf = $WhatIf}
    } else {
        @{RDPSecurityGroup = $RDPSecurityGroup; WhatIf = $WhatIf}
    }
    Invoke-HardeningPhase -PhaseName "Phase 3: User Rights Assignments" `
        -ScriptPath "$scriptsPath\Configure-UserRights.ps1" `
        -Parameters $userRightsParams
    
    # Phase 4: Windows Defender
    Invoke-HardeningPhase -PhaseName "Phase 4: Windows Defender" `
        -ScriptPath "$scriptsPath\Configure-Defender.ps1" `
        -Parameters @{WhatIf = $WhatIf}
    
    # Phase 5: Exploit Guard & ASR
    Invoke-HardeningPhase -PhaseName "Phase 5: Exploit Guard & ASR" `
        -ScriptPath "$scriptsPath\Configure-ExploitGuard.ps1" `
        -Parameters @{ASRMode = $ASRMode; WhatIf = $WhatIf}
    
    # Phase 6: Firewall
    Invoke-HardeningPhase -PhaseName "Phase 6: Windows Firewall" `
        -ScriptPath "$scriptsPath\Configure-Firewall.ps1" `
        -Parameters @{AllowedPorts = $AllowedPorts; WhatIf = $WhatIf}
    
    # Phase 7: RDP Hardening
    $rdpParams = if ([string]::IsNullOrWhiteSpace($RDPSecurityGroup)) {
        @{WhatIf = $WhatIf}
    } else {
        @{RDPSecurityGroup = $RDPSecurityGroup; WhatIf = $WhatIf}
    }
    Invoke-HardeningPhase -PhaseName "Phase 7: RDP Hardening" `
        -ScriptPath "$scriptsPath\Configure-RDPHardening.ps1" `
        -Parameters $rdpParams
    
    # Phase 8: Logging & Auditing
    Invoke-HardeningPhase -PhaseName "Phase 8: Logging & Auditing" `
        -ScriptPath "$scriptsPath\Configure-Logging.ps1" `
        -Parameters @{WhatIf = $WhatIf}
    
    # Phase 9: Credential Guard
    Invoke-HardeningPhase -PhaseName "Phase 9: Credential Guard & LSA Protection" `
        -ScriptPath "$scriptsPath\Configure-CredentialGuard.ps1" `
        -Parameters @{WhatIf = $WhatIf}
    
    Write-Host ""
    
    # Phase 10: WDAC (Optional)
    if (-not $SkipWDAC) {
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Phase 10: Windows Defender Application Control (WDAC)" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Note: WDAC requires careful planning. Skipping automatic configuration." -ForegroundColor Yellow
        Write-Host "Run Configure-WDAC.ps1 manually after reviewing requirements." -ForegroundColor Yellow
        Write-Host ""
    } else {
        Write-Host "Skipping WDAC configuration (as requested)." -ForegroundColor Yellow
        Write-Host ""
    }
    
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Hardening Process Complete" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Duration: $([math]::Round($duration.TotalMinutes, 2)) minutes" -ForegroundColor Green
    Write-Host ""
    
    if ($failedPhases.Count -gt 0) {
        Write-Host "Phases completed with errors:" -ForegroundColor Yellow
        foreach ($phase in $failedPhases) {
            Write-Host "  - $phase" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "Note: Some phases may have completed partially. Review errors above." -ForegroundColor Yellow
    } else {
        Write-Host "All phases completed successfully!" -ForegroundColor Green
    }
    
    Write-Host ""
    if (-not $WhatIf) {
        Write-Host "Next Steps:" -ForegroundColor Yellow
        Write-Host "1. Review all script outputs for warnings and errors" -ForegroundColor White
        Write-Host "2. Apply Group Policy settings (see GPO-Configuration-Tables.md)" -ForegroundColor White
        Write-Host "3. Restart the server for Credential Guard to activate" -ForegroundColor White
        Write-Host "4. Run validation script: .\Validate-Hardening.ps1" -ForegroundColor White
        Write-Host "5. Monitor ASR and WDAC logs for 30 days before enforcing" -ForegroundColor White
        Write-Host "6. Test all applications and services for compatibility" -ForegroundColor White
        Write-Host ""
        Write-Host "Important:" -ForegroundColor Red
        Write-Host "- Some settings require system restart" -ForegroundColor White
        Write-Host "- Verify RDP access before closing current session" -ForegroundColor White
        Write-Host "- Review firewall rules to ensure required services are accessible" -ForegroundColor White
        if ($failedPhases.Count -gt 0) {
            Write-Host "- Re-run failed phases individually if needed" -ForegroundColor White
        }
    }
    
} catch {
    Write-Warning "Unexpected error during hardening process: $_"
    Write-Host "`nHardening process completed with errors. Review output above." -ForegroundColor Yellow
    Write-Host "Some phases may have completed successfully." -ForegroundColor Yellow
}


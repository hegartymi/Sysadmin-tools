# Phase 3: Validation Checklist

## Overview

This checklist provides commands and procedures to verify that all hardening configurations have been applied correctly. Use this after running the hardening scripts and applying Group Policy settings.

---

## 1. Account Policies

### Verification Commands

```powershell
# View password policy
net accounts

# Expected values:
# - Minimum password length: 14
# - Password history: 24
# - Maximum password age: 60 days
# - Minimum password age: 1 day
# - Lockout threshold: 5
# - Lockout duration: 15 minutes
```

### GPO Verification

```powershell
# Generate GPO report
gpresult /h report.html

# Check applied GPOs
gpresult /r
```

**What to Look For:**
- Password policy matches Phase 1 recommendations
- Account lockout policy is configured
- Kerberos policy settings applied

---

## 2. Local Security Options

### Verification Commands

```powershell
# Check NTLM settings
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object LmCompatibilityLevel, NtlmMinClientSec, NtlmMinServerSec, NoLMHash

# Expected:
# - LmCompatibilityLevel: 5 (NTLMv2 only)
# - NtlmMinClientSec: 0x20080000
# - NtlmMinServerSec: 0x20080000
# - NoLMHash: 1

# Check SMB settings
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" | Select-Object RequireSecuritySignature, EnableSecuritySignature

# Expected:
# - RequireSecuritySignature: 1
# - EnableSecuritySignature: 1

# Check UAC settings
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object EnableLUA, ConsentPromptBehaviorAdmin, ConsentPromptBehaviorUser

# Expected:
# - EnableLUA: 1
# - ConsentPromptBehaviorAdmin: 2
# - ConsentPromptBehaviorUser: 0
```

**What to Look For:**
- All registry values match expected settings
- No conflicting GPO settings

---

## 3. User Rights Assignments

### Verification Commands

```powershell
# Check RDP access rights
whoami /priv

# View user rights (requires secedit export or GPO report)
secedit /export /cfg userrights.txt
Get-Content userrights.txt | Select-String "SeRemoteInteractiveLogonRight"

# Check via GPO
gpresult /h report.html
# Look for: "Allow log on through Remote Desktop Services"
```

**What to Look For:**
- RDP access restricted to specific security group (not Domain Users)
- Guest account denied all logon types
- Network access restricted appropriately

---

## 4. Windows Defender

### Verification Commands

```powershell
# Check Defender status
Get-MpComputerStatus

# Check Defender preferences
Get-MpPreference | Select-Object DisableRealtimeMonitoring, MAPSReporting, PUAProtection, EnableNetworkProtection, SubmitSamplesConsent

# Expected:
# - DisableRealtimeMonitoring: False
# - MAPSReporting: Advanced
# - PUAProtection: Enabled
# - EnableNetworkProtection: Enabled
# - SubmitSamplesConsent: SendSafeSamplesAutomatically

# Check Defender exclusions (should be minimal)
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

**What to Look For:**
- Real-time protection enabled
- Cloud protection enabled
- PUA protection enabled
- Network protection enabled
- Minimal or no exclusions

---

## 5. Exploit Guard & ASR

### Verification Commands

```powershell
# Check ASR rules
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions

# Check Network Protection
Get-MpPreference | Select-Object EnableNetworkProtection

# Check ASR events (should see events if rules are working)
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -FilterXPath "*[System[(EventID=1121 or EventID=1122)]]" -MaxEvents 10
```

**What to Look For:**
- ASR rules configured (12 rules recommended)
- Rules in Warn/Audit mode initially
- Network Protection enabled
- ASR events appearing in Event Viewer

**Event Viewer Location:**
- `Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational`
- Event ID 1121: ASR rule triggered (blocked)
- Event ID 1122: ASR rule triggered (audited)

---

## 6. Windows Firewall

### Verification Commands

```powershell
# Check firewall profiles
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# Expected:
# - All profiles: Enabled = True
# - DefaultInboundAction: Block
# - DefaultOutboundAction: Allow

# Check inbound allow rules
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | 
    Where-Object { $_.Name -like "Hardening-*" -or $_.DisplayGroup -in @("Remote Desktop", "File and Printer Sharing") } |
    Select-Object DisplayName, DisplayGroup, Enabled

# Check for unnecessary rules
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | 
    Where-Object { $_.Name -notlike "Hardening-*" -and $_.DisplayGroup -notin @("Remote Desktop", "File and Printer Sharing", "Windows Remote Management", "Core Networking") }
```

**What to Look For:**
- All profiles block inbound by default
- Only required ports are allowed
- No unnecessary inbound rules

---

## 7. RDP Hardening

### Verification Commands

```powershell
# Check RDP registry settings
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" | 
    Select-Object fDenyTSConnections, UserAuthentication

# Expected:
# - fDenyTSConnections: 0 (RDP enabled)
# - UserAuthentication: 1 (NLA required)

# Check RDP encryption level
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" | 
    Select-Object MinEncryptionLevel, PortNumber

# Expected:
# - MinEncryptionLevel: 3 (High)
# - PortNumber: 3389 (or custom port)

# Check RDP firewall rule
Get-NetFirewallRule -DisplayGroup "Remote Desktop" | 
    Where-Object { $_.Enabled -eq $true } | 
    Select-Object DisplayName, Enabled, Direction

# Test RDP connection (from another machine)
# mstsc /v:servername
```

**What to Look For:**
- NLA required
- High encryption level
- RDP restricted to specific security group
- Firewall rule enabled and restricted

---

## 8. Logging & Auditing

### Verification Commands

```powershell
# Check Advanced Audit Policy
auditpol /get /category:* | Select-String "Logon|Account|Policy|System"

# Check specific subcategories
auditpol /get /subcategory:"Logon"

# Check Event Log sizes
Get-WinEvent -ListLog Security, Application, System | 
    Select-Object LogName, MaximumSizeInBytes, RecordCount

# Expected:
# - Security log: >= 512 MB
# - Application log: >= 512 MB
# - System log: >= 512 MB

# Check PowerShell logging
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue

# Check for audit events
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624 or EventID=4625)]]" -MaxEvents 5
```

**What to Look For:**
- Advanced Audit Policy enabled (not basic)
- Logon events (4624, 4625) appearing
- PowerShell logging enabled
- Event logs sized appropriately

**Event Viewer Locations:**
- Security log: `Windows Logs > Security`
- PowerShell: `Applications and Services Logs > Microsoft > Windows > PowerShell`

---

## 9. Credential Guard

### Verification Commands

```powershell
# Check LSA Protection
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object RunAsPPL

# Expected: RunAsPPL = 1

# Check Credential Guard status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard" -ErrorAction SilentlyContinue |
    Select-Object VirtualizationBasedSecurityStatus, RequiredSecurityProperties, AvailableSecurityProperties

# Status values:
# - 0 = Not running
# - 1 = Running with lock (UEFI lock enabled)
# - 2 = Running without lock

# Check VBS registry
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ErrorAction SilentlyContinue |
    Select-Object EnableVirtualizationBasedSecurity

# Expected: EnableVirtualizationBasedSecurity = 1
```

**What to Look For:**
- LSA Protection (RunAsPPL) enabled
- Credential Guard status = 2 (running) or 1 (running with lock)
- VBS enabled in registry
- System may require restart for Credential Guard to activate

---

## 10. WDAC (if configured)

### Verification Commands

```powershell
# Check WDAC policy status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard" -ErrorAction SilentlyContinue |
    Select-Object CodeIntegrityPolicyEnforcementStatus

# Check WDAC events
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 10 -ErrorAction SilentlyContinue

# Event IDs:
# - 3076: Blocked application
# - 3077: Allowed application
```

**What to Look For:**
- WDAC policy deployed (if configured)
- Code Integrity events appearing
- Applications allowed/blocked as expected

**Event Viewer Location:**
- `Applications and Services Logs > Microsoft > Windows > Code Integrity > Operational`

---

## 11. Group Policy Verification

### Verification Commands

```powershell
# Generate comprehensive GPO report
gpresult /h gpo-report.html /f

# Check applied GPOs
gpresult /r

# Check GPO processing
gpresult /scope Computer /v

# Force GPO refresh
gpupdate /force
```

**What to Look For:**
- All expected GPOs are applied
- No GPO conflicts
- Settings match GPO-Configuration-Tables.md

---

## 12. System Health Checks

### Verification Commands

```powershell
# Check Windows Update status
Get-WindowsUpdateLog

# Check for pending reboots
(Get-ComputerInfo).WindowsPendingReboot

# Check system integrity
sfc /verifyonly

# Check disk space (logs require space)
Get-PSDrive C | Select-Object Used, Free

# Check service status
Get-Service | Where-Object { $_.Status -ne "Running" -and $_.StartType -eq "Automatic" } | 
    Select-Object Name, Status, StartType
```

**What to Look For:**
- System is up to date
- No pending reboots (or reboot if required)
- System files intact
- Sufficient disk space for logs
- Critical services running

---

## Automated Validation Script

Run the automated validation script:

```powershell
.\Validate-Hardening.ps1
```

This script performs all checks above and generates a comprehensive report.

---

## Common Issues & Troubleshooting

### Issue: GPO settings not applying

**Solution:**
1. Run `gpupdate /force`
2. Check GPO link order and inheritance
3. Verify GPO permissions
4. Check for conflicting local policies

### Issue: Credential Guard not running

**Solution:**
1. Verify UEFI firmware (not Legacy BIOS)
2. Check TPM status
3. Restart system
4. Verify hardware compatibility

### Issue: ASR rules blocking legitimate applications

**Solution:**
1. Review ASR events in Event Viewer
2. Add exceptions: `Add-MpPreference -ExclusionPath "C:\Path\To\App"`
3. Consider switching rule to Warn mode temporarily

### Issue: Firewall blocking required services

**Solution:**
1. Review firewall rules: `Get-NetFirewallRule`
2. Add required ports: `New-NetFirewallRule`
3. Test connectivity after changes

---

## Next Steps

After validation:

1. **Document exceptions**: Record any settings that couldn't be applied and why
2. **Monitor logs**: Review ASR, WDAC, and security logs for 30 days
3. **Switch to enforcement**: After audit period, switch ASR/WDAC to Block/Enforced mode
4. **Regular reviews**: Schedule quarterly security reviews
5. **Update baselines**: Keep security baselines current with OS updates

---

## References

- CIS Benchmarks: https://www.cisecurity.org/benchmark/microsoft_windows_server
- Microsoft Security Baseline: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/
- ASD Essential Eight: https://www.cyber.gov.au/acsc/view-all-content/essential-eight


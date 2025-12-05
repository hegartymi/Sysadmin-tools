# Deployment Guide: Windows Server 2025 Hardening

## Overview

This guide provides a step-by-step approach for safely deploying security hardening to Windows Server 2025 in an enterprise environment. Follow this guide to minimize risk and ensure successful deployment.

---

## Pre-Deployment Checklist

### 1. Environment Assessment

- [ ] Document current server configuration
- [ ] Identify server role and required services
- [ ] List all applications running on the server
- [ ] Document network requirements (ports, protocols)
- [ ] Identify users/groups that require access
- [ ] Review current security baseline
- [ ] Check for pending Windows Updates

### 2. Backup & Recovery

- [ ] Create system state backup
- [ ] Create full system backup
- [ ] Document recovery procedures
- [ ] Test backup restoration (in lab)
- [ ] Create system restore point
- [ ] Document rollback procedures

### 3. Lab Testing

- [ ] Deploy hardening in lab environment first
- [ ] Test all applications and services
- [ ] Verify RDP access after hardening
- [ ] Test firewall rules
- [ ] Review ASR/WDAC audit logs
- [ ] Document any issues or exceptions

### 4. Communication

- [ ] Notify stakeholders of planned changes
- [ ] Schedule maintenance window (if needed)
- [ ] Prepare rollback plan
- [ ] Document expected downtime (if any)

---

## Deployment Phases

### Phase A: Critical Security (Immediate)

**Objective**: Apply essential security settings with minimal risk.

**Steps**:

1. **Account Policies**
   ```powershell
   .\Configure-AccountPolicies.ps1
   ```
   - Verify: `net accounts`
   - Risk: Low (domain GPO may override)

2. **Windows Defender**
   ```powershell
   .\Configure-Defender.ps1
   ```
   - Verify: `Get-MpComputerStatus`
   - Risk: Low

3. **Firewall (Basic)**
   ```powershell
   .\Configure-Firewall.ps1 -AllowedPorts @(3389, 445, 5985)
   ```
   - Verify: Test required services
   - Risk: Medium (may block required services)

4. **RDP Hardening**
   ```powershell
   .\Configure-RDPHardening.ps1 -RDPSecurityGroup "DOMAIN\RDP-Users"
   ```
   - Verify: Test RDP connection
   - Risk: Medium (may lock out administrators)

**Rollback**: Revert firewall rules, restore RDP settings via registry

---

### Phase B: High Priority (Within 1 Week)

**Objective**: Apply additional security controls after Phase A validation.

**Steps**:

1. **Local Security Options**
   ```powershell
   .\Configure-LocalSecurityOptions.ps1
   ```
   - Verify: Check registry settings
   - Risk: Low-Medium (may impact legacy apps)

2. **User Rights Assignments**
   ```powershell
   .\Configure-UserRights.ps1 -RDPSecurityGroup "DOMAIN\RDP-Users"
   ```
   - Verify: Test user access
   - Risk: Medium (may restrict legitimate access)

3. **Exploit Guard & ASR (Audit Mode)**
   ```powershell
   .\Configure-ExploitGuard.ps1 -ASRMode Warn
   ```
   - Verify: Check ASR events in Event Viewer
   - Risk: Low (Audit mode only)

4. **Advanced Audit Policy**
   ```powershell
   .\Configure-Logging.ps1
   ```
   - Verify: Check Event Viewer for events
   - Risk: Low (logging only)

**Rollback**: Disable ASR rules, revert audit policy

---

### Phase C: Enhanced Security (Within 1 Month)

**Objective**: Apply advanced security features after monitoring Phase B.

**Steps**:

1. **Credential Guard**
   ```powershell
   .\Configure-CredentialGuard.ps1
   ```
   - Verify: Check Device Guard status after restart
   - Risk: Medium (requires restart, hardware compatibility)

2. **ASR Enforcement** (After 30-day audit)
   ```powershell
   .\Configure-ExploitGuard.ps1 -ASRMode Block
   ```
   - Verify: Review ASR audit logs first
   - Risk: Medium (may block legitimate apps)

3. **WDAC** (Optional, after careful planning)
   ```powershell
   .\Configure-WDAC.ps1 -PolicyMode Audit -LOBPaths @("C:\MyApp")
   ```
   - Verify: Monitor Code Integrity events
   - Risk: High (may block legitimate applications)

**Rollback**: Disable Credential Guard, revert ASR to Warn, remove WDAC policy

---

## Deployment Procedure

### Step 1: Pre-Deployment

1. **Review server role and requirements**
   - Document required ports
   - List required applications
   - Identify user access requirements

2. **Create backup**
   ```powershell
   # System state backup
   wbadmin start systemstatebackup -backuptarget:\\backup-server\backups
   
   # System restore point
   Checkpoint-Computer -Description "Pre-Hardening" -RestorePointType "MODIFY_SETTINGS"
   ```

3. **Test in lab** (if available)
   - Deploy to lab server
   - Test all functionality
   - Document issues

### Step 2: Deployment

1. **Run hardening script**
   ```powershell
   # Preview changes
   .\Enable-ServerHardening.ps1 -WhatIf
   
   # Apply hardening
   .\Enable-ServerHardening.ps1 -RDPSecurityGroup "DOMAIN\RDP-Users" -ASRMode Warn
   ```

2. **Apply Group Policy settings**
   - Import GPO settings from `GPO-Configuration-Tables.md`
   - Link GPO to server OU
   - Run `gpupdate /force`

3. **Restart server** (if required)
   - Credential Guard requires restart
   - Some registry changes require restart

### Step 3: Post-Deployment Validation

1. **Run validation script**
   ```powershell
   .\Validate-Hardening.ps1
   ```

2. **Manual verification**
   - Test RDP access
   - Test required applications
   - Verify firewall rules
   - Check Event Viewer for errors

3. **Monitor logs**
   - Review ASR events (if in Audit mode)
   - Check security logs
   - Monitor PowerShell logs

### Step 4: Ongoing Management

1. **Monitor ASR/WDAC logs** (30 days)
   - Review blocked/allowed events
   - Add exceptions for legitimate apps
   - Document any issues

2. **Switch to enforcement** (after audit period)
   ```powershell
   .\Configure-ExploitGuard.ps1 -ASRMode Block
   ```

3. **Regular reviews**
   - Quarterly security assessments
   - Update baselines with OS updates
   - Review and update exceptions

---

## Risk Management

### Settings That May Break Functionality

| Setting | Risk Level | Potential Impact | Mitigation |
|---------|-----------|------------------|------------|
| ASR Rules | Medium | May block legitimate apps | Start in Audit mode, review logs |
| WDAC | High | May block unsigned apps | Start in Audit mode, add exceptions |
| Firewall | Medium | May block required services | Test firewall rules, add exceptions |
| RDP Restrictions | Medium | May lock out administrators | Use dedicated security group |
| SMB Signing Required | Low-Medium | May break legacy systems | Test with legacy systems first |
| NTLM Restrictions | Low-Medium | May impact legacy auth | Audit NTLM usage first |

### Exception Management

**Document exceptions** in a risk register:

```
Exception ID: EX-001
Setting: ASR Rule - Block Office macros
Reason: Legacy application requires macros
Risk Acceptance: Approved by [Name], Date: [Date]
Mitigation: Application isolated to specific server
Review Date: [Date]
```

### Rollback Procedures

**Quick Rollback** (for critical issues):

1. **Firewall**: Remove custom rules
   ```powershell
   Remove-NetFirewallRule -Name "Hardening-*"
   ```

2. **ASR**: Disable ASR rules
   ```powershell
   Set-MpPreference -AttackSurfaceReductionRules_Ids @() -AttackSurfaceReductionRules_Actions @()
   ```

3. **RDP**: Restore RDP settings
   ```powershell
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "UserAuthentication" -Value 0
   ```

**Full Rollback** (restore from backup):
- Restore system state backup
- Restore system restore point
- Revert GPO changes

---

## Monitoring & Maintenance

### Daily Monitoring (First Week)

- [ ] Review Event Viewer for errors
- [ ] Check ASR events (if in Audit mode)
- [ ] Verify critical services running
- [ ] Monitor disk space (logs)

### Weekly Monitoring (First Month)

- [ ] Review security logs
- [ ] Analyze ASR/WDAC audit logs
- [ ] Review firewall logs
- [ ] Check for blocked legitimate applications

### Monthly Reviews

- [ ] Review exception register
- [ ] Update security baselines
- [ ] Review and update GPOs
- [ ] Assess ASR/WDAC for enforcement

### Quarterly Assessments

- [ ] Full security assessment
- [ ] Review and update hardening scripts
- [ ] Update documentation
- [ ] Test disaster recovery procedures

---

## Troubleshooting

### Issue: RDP Access Lost

**Symptoms**: Cannot connect via RDP after hardening

**Solution**:
1. Check RDP firewall rule: `Get-NetFirewallRule -DisplayGroup "Remote Desktop"`
2. Verify user rights: `gpresult /r`
3. Check RDP service: `Get-Service TermService`
4. Use local console access if available
5. Rollback RDP settings if needed

### Issue: Application Blocked by ASR

**Symptoms**: Application fails to run, ASR event in Event Viewer

**Solution**:
1. Review ASR event (Event ID 1121, 1122)
2. Add exception: `Add-MpPreference -ExclusionPath "C:\Path\To\App"`
3. Consider switching rule to Warn mode temporarily
4. Document exception in risk register

### Issue: Firewall Blocking Required Service

**Symptoms**: Service cannot communicate, connection timeouts

**Solution**:
1. Review firewall rules: `Get-NetFirewallRule`
2. Check blocked connections: `Get-NetFirewallConnectionProfile`
3. Add required port: `New-NetFirewallRule -Name "Allow-Port-X" -Protocol TCP -LocalPort X -Action Allow`
4. Test connectivity

### Issue: Credential Guard Not Running

**Symptoms**: Device Guard status shows 0 (not running)

**Solution**:
1. Verify UEFI firmware (not Legacy BIOS)
2. Check TPM status: `Get-Tpm`
3. Verify registry settings
4. Restart system
5. Check hardware compatibility

---

## Success Criteria

Hardening is considered successful when:

- [ ] All validation checks pass (or acceptable warnings)
- [ ] All required services are accessible
- [ ] RDP access works for authorized users
- [ ] Applications function correctly
- [ ] No critical errors in Event Viewer
- [ ] ASR/WDAC audit logs show expected activity
- [ ] Security logs are being generated
- [ ] Firewall rules allow required traffic
- [ ] Credential Guard is running (if supported)

---

## Documentation Requirements

Maintain the following documentation:

1. **Hardening Configuration Log**
   - Date of deployment
   - Scripts executed
   - GPOs applied
   - Exceptions made

2. **Exception Register**
   - Settings that couldn't be applied
   - Reason for exception
   - Risk acceptance
   - Review dates

3. **Validation Reports**
   - Pre-deployment baseline
   - Post-deployment validation
   - Ongoing validation results

4. **Change Log**
   - Updates to hardening scripts
   - GPO modifications
   - Exception additions/removals

---

## References

- **CIS Benchmarks**: https://www.cisecurity.org/benchmark/microsoft_windows_server
- **Microsoft Security Baseline**: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/
- **ASD Essential Eight**: https://www.cyber.gov.au/acsc/view-all-content/essential-eight
- **Windows Defender ASR**: https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction
- **WDAC**: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control

---

## Support & Escalation

If issues arise during deployment:

1. **Check documentation**: Review this guide and validation checklist
2. **Review logs**: Event Viewer, PowerShell logs, ASR logs
3. **Test rollback**: Verify rollback procedures work
4. **Escalate**: Contact security team or Microsoft support if needed

---

**Last Updated**: [Date]  
**Version**: 1.0  
**Author**: Windows Security Engineering Team


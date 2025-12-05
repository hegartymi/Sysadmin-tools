# Phase 1: Windows Server 2025 Hardening Plan & Checklist

## Environment Understanding

**Target System**: Windows Server 2025 (GUI), domain-joined to `lauriston.int`  
**Role**: Member server hosting line-of-business applications  
**Management**: Group Policy + Intune (where applicable)  
**Security Frameworks**: Microsoft Baselines, CIS Benchmarks, ASD Essential Eight Level 2

---

## 1. OS & Baseline Configuration

### Objective
Establish secure baseline configuration, remove unnecessary components, and configure system-level security settings.

### Key Settings

| Category | Policy/Setting | Recommended Value | Framework Alignment |
|----------|---------------|-------------------|---------------------|
| **Services** | Disable unnecessary services | Disable: Fax, Remote Registry, SNMP (if unused), Telnet | CIS 2.2.x, MS Baseline |
| **Windows Features** | Remove unused roles/features | Remove: IIS (if unused), Print Server (if unused), SMB 1.0 | CIS 2.3.x |
| **System Updates** | Configure Windows Update | Automatic updates enabled, restart required | CIS 2.1, ASD E8 Maturity Level 2 |
| **Time Synchronization** | Configure W32Time | Sync with domain time source | CIS 2.4 |
| **UAC** | User Account Control | Enabled, require admin approval | CIS 2.3.17, MS Baseline |
| **PowerShell** | PowerShell execution policy | Restricted (managed via GPO) | CIS 18.9.x |

### Rationale
- Minimize attack surface by removing unused components
- Ensure timely patching (ASD E8 requirement)
- Prevent unauthorized privilege escalation via UAC
- Control script execution to prevent malicious PowerShell usage

---

## 2. Identity & Authentication

### Objective
Enforce strong authentication, protect credentials, and implement account security policies.

### Key Settings

| Category | Policy/Setting | Recommended Value | Framework Alignment |
|----------|---------------|-------------------|---------------------|
| **Password Policy** | Minimum password length | 14 characters | CIS 1.1.1, MS Baseline |
| **Password Policy** | Password complexity | Enabled | CIS 1.1.2 |
| **Password Policy** | Password history | Remember 24 passwords | CIS 1.1.3 |
| **Password Policy** | Maximum password age | 60 days | CIS 1.1.4 |
| **Password Policy** | Minimum password age | 1 day | CIS 1.1.5 |
| **Account Lockout** | Lockout threshold | 5 invalid attempts | CIS 1.2.1 |
| **Account Lockout** | Lockout duration | 15 minutes | CIS 1.2.2 |
| **Account Lockout** | Reset lockout counter | 15 minutes | CIS 1.2.3 |
| **Kerberos** | Maximum ticket age | 10 hours | CIS 1.3.1 |
| **Kerberos** | Maximum service ticket age | 600 minutes | CIS 1.3.2 |
| **Kerberos** | Maximum tolerance for clock skew | 5 minutes | CIS 1.3.3 |
| **LSA Protection** | RunAsPPL | Enabled (1) | CIS 2.3.10, MS Baseline |
| **Credential Guard** | Enable Virtualization Based Security | Enabled with UEFI lock | CIS 2.3.11, MS Baseline |
| **NTLM** | Restrict NTLM | Audit NTLM usage | CIS 1.4.x |

### Rationale
- Strong passwords reduce brute-force risk (ASD E8)
- Account lockout prevents credential stuffing
- Kerberos hardening prevents ticket replay attacks
- Credential Guard and LSA Protection prevent credential theft (ASD E8 Maturity Level 2)

---

## 3. RDP & Remote Management

### Objective
Secure remote access, enforce strong authentication, and limit exposure.

### Key Settings

| Category | Policy/Setting | Recommended Value | Framework Alignment |
|----------|---------------|-------------------|---------------------|
| **RDP** | Network Level Authentication | Enabled (required) | CIS 2.3.7, MS Baseline |
| **RDP** | Restrict RDP users | Specific security group only (not Domain Users) | CIS 2.3.8 |
| **RDP** | Set client connection encryption level | High | CIS 2.3.9 |
| **RDP** | Idle session limit | 15 minutes | CIS 2.3.12 |
| **RDP** | Disconnect on idle | Enabled | CIS 2.3.13 |
| **RDP** | Clipboard redirection | Disabled | CIS 2.3.14 |
| **RDP** | Drive redirection | Disabled | CIS 2.3.15 |
| **RDP** | Port | Change from 3389 (if possible) or restrict via firewall | Best practice |
| **WinRM** | Basic authentication | Disabled | CIS 18.9.x |
| **WinRM** | Unencrypted traffic | Disabled | CIS 18.9.x |
| **WinRM** | Kerberos authentication | Required | CIS 18.9.x |
| **PowerShell Remoting** | Enable-PSRemoting | Restricted to specific groups | CIS 18.9.x |

### Rationale
- NLA prevents pre-authentication attacks
- Restricting users limits lateral movement
- Disabling clipboard/drive redirection prevents data exfiltration
- Encrypted remoting prevents credential interception

### Additional Recommendations
- **Jump Host**: Use a dedicated RDP jump server with MFA
- **Just-in-Time (JIT)**: Consider Azure Arc JIT or similar for time-limited access
- **VPN**: Require VPN before RDP access from internet

---

## 4. Defender, Exploit Guard & ASR

### Objective
Enable comprehensive endpoint protection, exploit mitigation, and attack surface reduction.

### Key Settings

| Category | Policy/Setting | Recommended Value | Framework Alignment |
|----------|---------------|-------------------|---------------------|
| **Defender** | Real-time protection | Enabled | CIS 9.1, ASD E8 |
| **Defender** | Cloud-delivered protection | Enabled | CIS 9.2, MS Baseline |
| **Defender** | Automatic sample submission | Enabled (safe) | CIS 9.3 |
| **Defender** | Tamper protection | Enabled | CIS 9.4, MS Baseline |
| **Defender** | PUA protection | Enabled | CIS 9.5 |
| **Defender** | Scan removable drives | Enabled | CIS 9.6 |
| **Defender** | Scheduled scan | Daily quick scan | CIS 9.7 |
| **Exploit Guard** | Control Flow Guard (CFG) | Enabled | MS Baseline |
| **Exploit Guard** | Data Execution Prevention (DEP) | Enabled | MS Baseline |
| **ASR Rules** | Block Office macros | Warn (audit first) → Block | MS Baseline, ASD E8 |
| **ASR Rules** | Block executable content from email | Warn (audit first) → Block | MS Baseline |
| **ASR Rules** | Block JavaScript/VBScript from email | Warn (audit first) → Block | MS Baseline |
| **ASR Rules** | Block Office child processes | Warn (audit first) → Block | MS Baseline |
| **ASR Rules** | Block process creations from PSExec/WMI | Block | MS Baseline |
| **ASR Rules** | Block untrusted unsigned processes | Warn (audit first) → Block | MS Baseline |
| **SmartScreen** | Configure Windows Defender SmartScreen | Enabled | CIS 18.9.x |

### ASR Rule GUIDs (for reference)
- Block Office macros: `92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B`
- Block executable content from email: `BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550`
- Block JavaScript/VBScript from email: `D3E037E1-3EB8-4C12-9814-7B0F0C0F4E50`
- Block Office child processes: `D4F940AB-401B-4EFC-AADC-AD5F3C50688A`
- Block process creations from PSExec/WMI: `D1E49A11-9217-47CD-93B9-53328B74A957`
- Block untrusted unsigned processes: `B2B3F03D-6A65-4F7B-9A0C-3EBE1C1C3B3C`

### Rationale
- Real-time protection detects and blocks threats (ASD E8)
- ASR rules prevent common attack vectors (ASD E8 Maturity Level 2)
- Exploit Guard mitigates memory-based attacks
- Start ASR in Warn mode to assess impact before blocking

---

## 5. Cryptographic Settings

### Objective
Disable weak cryptographic protocols, ciphers, hashes, and key exchange algorithms to prevent cryptographic attacks.

### Key Settings

| Category | Policy/Setting | Recommended Value | Framework Alignment |
|----------|---------------|-------------------|---------------------|
| **SSL/TLS Protocols** | SSL 2.0 | Disabled | CIS, MS Baseline, NIST |
| **SSL/TLS Protocols** | SSL 3.0 | Disabled | CIS, MS Baseline, NIST |
| **SSL/TLS Protocols** | TLS 1.0 | Disabled | CIS, MS Baseline, NIST |
| **SSL/TLS Protocols** | TLS 1.1 | Disabled | CIS, MS Baseline, NIST |
| **SSL/TLS Protocols** | TLS 1.2 | Enabled | CIS, MS Baseline, NIST |
| **SSL/TLS Protocols** | TLS 1.3 | Enabled (if available) | NIST, Best Practice |
| **Cipher Suites** | RC4 ciphers | Disabled | CIS, MS Baseline |
| **Cipher Suites** | DES ciphers | Disabled | CIS, MS Baseline |
| **Cipher Suites** | NULL ciphers | Disabled | CIS, MS Baseline |
| **Cipher Suites** | AES 128/256 | Enabled | CIS, MS Baseline |
| **Hashing Algorithms** | MD5 | Disabled | CIS, MS Baseline, NIST |
| **Hashing Algorithms** | SHA1 | Disabled (or audit first) | CIS, MS Baseline, NIST |
| **Key Exchange** | Weak algorithms | Disabled | CIS, MS Baseline |
| **Key Exchange** | ECDH | Enabled | Best Practice |
| **.NET Framework** | Strong cryptography | Enabled | MS Baseline |

### Rationale
- Weak protocols (SSL 2.0/3.0, TLS 1.0/1.1) are vulnerable to attacks (POODLE, BEAST, etc.)
- Weak ciphers (RC4, DES) can be broken with modern computing power
- MD5 and SHA1 are cryptographically broken
- Enforcing TLS 1.2+ ensures modern, secure communications
- Prevents downgrade attacks and man-in-the-middle attacks

### Implementation Notes
- Some legacy applications may break when weak protocols are disabled
- Test applications after applying changes
- Consider disabling SHA1 only after verifying application compatibility
- System restart may be required for some settings

---

## 6. Firewall & Network Services

### Objective
Implement network segmentation, block unnecessary ports, and allow only required traffic.

### Key Settings

| Category | Policy/Setting | Recommended Value | Framework Alignment |
|----------|---------------|-------------------|---------------------|
| **Firewall** | Domain profile | Default: Block inbound, Allow outbound | CIS 9.1, MS Baseline |
| **Firewall** | Private profile | Default: Block inbound, Allow outbound | CIS 9.1 |
| **Firewall** | Public profile | Default: Block inbound, Allow outbound | CIS 9.1 |
| **Firewall** | Inbound rules | Allow only required ports (RDP, SMB, etc.) | CIS 9.2 |
| **Firewall** | Outbound rules | Monitor and restrict as needed | Best practice |
| **SMB** | SMB 1.0 | Disabled | CIS 2.3.1, MS Baseline |
| **SMB** | SMB signing | Required | CIS 2.3.2 |
| **SMB** | SMB encryption | Enabled (if supported) | CIS 2.3.3 |
| **LLMNR** | Link-Local Multicast Name Resolution | Disabled | CIS 2.3.4 |
| **NetBIOS** | NetBIOS over TCP/IP | Disabled (if not required) | CIS 2.3.5 |
| **ICMP** | ICMP redirects | Disabled | CIS 2.3.6 |

### Rationale
- Default-deny firewall reduces attack surface
- SMB hardening prevents SMB-based attacks (e.g., EternalBlue)
- Disabling LLMNR/NetBIOS prevents name resolution poisoning
- Network segmentation limits lateral movement

---

## 7. Application Control (WDAC / App Control)

### Objective
Implement application whitelisting to prevent unauthorized software execution.

### Key Settings

| Category | Policy/Setting | Recommended Value | Framework Alignment |
|----------|---------------|-------------------|---------------------|
| **WDAC** | Policy mode | Audit mode initially, then Enforced | CIS 18.9.x, ASD E8 |
| **WDAC** | Policy scope | Allow Microsoft-signed + line-of-business paths | Best practice |
| **WDAC** | Script enforcement | Enabled | CIS 18.9.x |
| **WDAC** | Policy refresh | Automatic | Best practice |

### Rationale
- Application control prevents execution of unauthorized software (ASD E8 Maturity Level 2)
- Start in Audit mode to identify legitimate applications before blocking
- Microsoft-signed baseline provides security without breaking Windows functionality

### Implementation Approach
1. Create base policy allowing Microsoft-signed executables
2. Add line-of-business application paths
3. Deploy in Audit mode
4. Monitor logs for 30 days
5. Tune policy based on audit logs
6. Switch to Enforced mode

---

## 8. Logging & Auditing

### Objective
Enable comprehensive logging for security monitoring, forensics, and SIEM integration.

### Key Settings

| Category | Policy/Setting | Recommended Value | Framework Alignment |
|----------|---------------|-------------------|---------------------|
| **Advanced Audit** | Account Logon | Success and Failure | CIS 17.1.x, MS Baseline |
| **Advanced Audit** | Account Management | Success and Failure | CIS 17.2.x |
| **Advanced Audit** | Logon/Logoff | Success and Failure | CIS 17.3.x |
| **Advanced Audit** | Object Access | Success and Failure (for sensitive objects) | CIS 17.4.x |
| **Advanced Audit** | Policy Change | Success and Failure | CIS 17.5.x |
| **Advanced Audit** | Privilege Use | Failure | CIS 17.6.x |
| **Advanced Audit** | System Events | Success and Failure | CIS 17.7.x |
| **Advanced Audit** | DS Access | Success and Failure | CIS 17.8.x |
| **PowerShell** | Transcription | Enabled | CIS 18.9.x |
| **PowerShell** | Script block logging | Enabled | CIS 18.9.x |
| **PowerShell** | Module logging | Enabled | CIS 18.9.x |
| **Event Log** | Security log size | 512 MB minimum | CIS 17.9.x |
| **Event Log** | Retention | Overwrite as needed (or archive) | CIS 17.9.x |
| **Defender** | Logging | Enabled, forward to SIEM | Best practice |

### Rationale
- Comprehensive auditing enables threat detection and forensics
- PowerShell logging detects malicious script execution
- SIEM integration provides centralized security monitoring
- Event log sizing ensures sufficient retention

---

## 9. Backup & Recovery Considerations

### Objective
Ensure system can be recovered securely after compromise or failure.

### Key Settings

| Category | Policy/Setting | Recommended Value | Framework Alignment |
|----------|---------------|-------------------|---------------------|
| **Backup** | System state backup | Daily | Best practice |
| **Backup** | Backup encryption | Enabled | CIS 3.1.x |
| **Backup** | Offline backup storage | Maintain offline backups | Best practice |
| **Recovery** | System restore points | Enabled | Best practice |
| **Recovery** | Recovery documentation | Document recovery procedures | Best practice |
| **BitLocker** | Drive encryption | Enabled (if applicable) | CIS 2.3.16, ASD E8 |

### Rationale
- Regular backups enable quick recovery from ransomware or system failure
- Encrypted backups protect sensitive data
- Offline backups prevent backup tampering
- BitLocker protects data at rest (ASD E8)

---

## Implementation Priority

### Phase A: Critical (Immediate)
1. Account policies (password, lockout)
2. Windows Defender (real-time protection)
3. Firewall (default-deny inbound)
4. RDP hardening (NLA, restricted users)
5. Basic audit policy

### Phase B: High (Within 1 week)
1. Cryptographic settings (disable weak protocols/ciphers)
2. Credential Guard / LSA Protection
3. Exploit Guard / ASR (Audit mode)
4. Advanced audit policy
5. PowerShell logging
6. SMB hardening

### Phase C: Medium (Within 1 month)
1. WDAC (Audit mode)
2. ASR enforcement (after audit review)
3. Network service hardening (LLMNR, NetBIOS)
4. BitLocker (if applicable)

### Phase D: Ongoing
1. Monitor ASR/WDAC audit logs
2. Tune policies based on logs
3. Review and update exceptions
4. Regular security assessments

---

## Risk Considerations

### Settings That May Break Functionality
- **ASR rules**: May block legitimate business applications (start in Audit)
- **WDAC**: May block unsigned line-of-business apps (requires policy tuning)
- **SMB signing required**: May break legacy systems
- **NTLM restrictions**: May impact legacy authentication

### Mitigation
1. Test all changes in lab environment first
2. Deploy ASR/WDAC in Audit mode for 30 days
3. Document exceptions and risk acceptance
4. Maintain rollback procedures
5. Communicate changes to application owners

---

## Next Steps

Proceed to **Phase 2** for:
- Detailed GPO configuration tables
- PowerShell implementation scripts
- WDAC policy templates


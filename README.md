# Windows Server 2025 Hardening Package

## Overview

This package provides comprehensive security hardening for Windows Server 2025 in enterprise, AD-joined environments. It aligns with:

- Microsoft Security Baselines for Windows Server 2025
- CIS Benchmarks for Windows Server (latest)
- Australian ASD Essential Eight Level 2 (where applicable)

## Environment Assumptions

- **OS**: Windows Server 2025, GUI, fully patched
- **Role**: Domain-joined member server hosting line-of-business applications
- **Domain**: Joined to Active Directory (lauriston.int), managed by Group Policy + possibly Intune
- **Access**: Local admin and domain admin available as needed

## Package Structure

```
windows server hardener/
├── README.md                          # This file
├── Phase1-Hardening-Plan.md          # Comprehensive hardening plan & checklist
├── Phase2-Configuration/
│   ├── GPO-Configuration-Tables.md   # Group Policy settings reference
│   ├── Scripts/
│   │   ├── Enable-ServerHardening.ps1          # Main orchestration script
│   │   ├── Configure-AccountPolicies.ps1       # Account policies
│   │   ├── Configure-LocalSecurityOptions.ps1 # Local security options
│   │   ├── Configure-UserRights.ps1            # User rights assignments
│   │   ├── Configure-Defender.ps1              # Windows Defender configuration
│   │   ├── Configure-ExploitGuard.ps1          # Exploit Guard & ASR
│   │   ├── Configure-Firewall.ps1             # Windows Firewall rules
│   │   ├── Configure-RDPHardening.ps1          # RDP security settings
│   │   ├── Configure-Logging.ps1               # Advanced audit & PowerShell logging
│   │   ├── Configure-CredentialGuard.ps1       # Credential Guard & LSA protection
│   │   └── Configure-WDAC.ps1                  # Application control (WDAC)
│   └── Templates/
│       └── WDAC-Policy-Template.xml            # Sample WDAC policy
└── Phase3-Validation/
    ├── Validation-Checklist.md                 # Verification procedures
    ├── Validate-Hardening.ps1                  # Automated validation script
    └── Deployment-Guide.md                    # Rollout strategy & risk management

```

## Hardening Functions & Operations

This package performs comprehensive security hardening across multiple categories:

### 1. Account Policies (`Configure-AccountPolicies.ps1`)
- **Password Policy**:
  - Minimum password length: 14 characters
  - Password complexity: Enabled
  - Password history: 24 passwords remembered
  - Maximum password age: 60 days
  - Minimum password age: 1 day
  - Disable reversible encryption storage
- **Account Lockout Policy**:
  - Lockout threshold: 5 invalid attempts
  - Lockout duration: 15 minutes
  - Reset lockout counter: 15 minutes
- **Kerberos Policy**:
  - Maximum ticket age: 10 hours
  - Maximum service ticket age: 600 minutes
  - Maximum clock skew tolerance: 5 minutes
  - Enforce user logon restrictions

### 2. Local Security Options (`Configure-LocalSecurityOptions.ps1`)
- **Network Security**:
  - LAN Manager authentication level: NTLMv2 only
  - Minimum NTLM session security (client/server): Require NTLMv2, 128-bit encryption
  - Disable LM hash storage
  - Configure Kerberos encryption types
- **SMB Security**:
  - Require SMB signing (always)
  - Enable SMB signing (if client/server agrees)
  - Disable unencrypted password transmission
- **Interactive Logon**:
  - Don't display last signed-in username
  - Machine inactivity limit: 15 minutes
  - Cached logons: 2
  - Prompt for password change: 14 days before expiration
- **Network Access**:
  - Disable anonymous SID/Name translation
  - Disable anonymous SAM account enumeration
  - Disable anonymous share enumeration
  - Remove anonymous named pipes and shares
  - Restrict remote registry access
- **UAC Settings**:
  - Enable UAC for all administrators
  - Require admin approval mode
  - Require secure desktop for elevation
  - Require signed executables for elevation
- **Domain Member Security**:
  - Require strong session keys
  - Digitally sign/encrypt secure channel data
  - Machine account password age: 30 days

### 3. Cryptographic Settings (`Configure-CryptographicSettings.ps1`)
- **Disable Weak SSL/TLS Protocols**:
  - SSL 2.0 (disabled)
  - SSL 3.0 (disabled)
  - TLS 1.0 (disabled)
  - TLS 1.1 (disabled)
- **Enable Strong Protocols**:
  - TLS 1.2 (enabled)
  - TLS 1.3 (enabled, if available)
- **Disable Weak Cipher Suites**:
  - DES 56/56
  - NULL ciphers
  - RC2 (all variants)
  - RC4 (all variants)
  - Triple DES 168
- **Enable Strong Cipher Suites**:
  - AES 128/128
  - AES 256/256
- **Disable Weak Hashing Algorithms**:
  - MD5 (disabled)
  - SHA1 (optional, with warning)
- **Key Exchange Algorithms**:
  - Enable ECDH (Elliptic Curve Diffie-Hellman)
  - Review weak algorithms
- **.NET Framework**:
  - Enable strong cryptography for .NET Framework (32-bit and 64-bit)

### 4. User Rights Assignments (`Configure-UserRights.ps1`)
- **Network Access**:
  - Restrict network access to Authenticated Users
  - Deny network access to Guest and Local accounts
- **Logon Rights**:
  - Restrict local logon to Administrators and Backup Operators
  - Restrict RDP access to specific security group (not Domain Users)
  - Deny logon rights to Guest account
- **System Privileges**:
  - Restrict debug programs to Administrators
  - Restrict load/unload device drivers to Administrators
  - Restrict system shutdown to Administrators
  - Restrict backup/restore to Administrators and Backup Operators
- **Security Settings**:
  - Deny access to credential manager
  - Restrict act as operating system
  - Restrict create token objects

### 5. Windows Defender (`Configure-Defender.ps1`)
- **Real-time Protection**:
  - Enable real-time protection
  - Enable behavior monitoring
  - Enable process scanning
  - Enable script scanning
- **Cloud Protection**:
  - Enable cloud-delivered protection (MAPS: Advanced)
  - Enable automatic safe sample submission
- **Protection Features**:
  - Enable PUA (Potentially Unwanted Applications) protection
  - Enable network protection
  - Configure tamper protection (via GPO)
- **Scanning Configuration**:
  - Enable removable drive scanning
  - Enable email scanning
  - Configure daily quick scan (2:00 AM)
  - Configure scan CPU load factor
- **Remediation**:
  - Configure remediation schedule
  - Enable quarantine cleanup

### 6. Exploit Guard & ASR (`Configure-ExploitGuard.ps1`)
- **Attack Surface Reduction (ASR) Rules** (12 rules, configurable mode):
  - Block executable content from email client and webmail
  - Block Office applications from creating child processes
  - Block Office applications from creating executable content
  - Block Office applications from injecting code into other processes
  - Block JavaScript or VBScript from launching downloaded executable content
  - Block execution of potentially obfuscated scripts
  - Block Office macro code from the Internet
  - Block executable files unless they meet prevalence/age/trusted list criteria
  - Block untrusted and unsigned processes from USB
  - Block Adobe Reader from creating child processes
  - Block persistence through WMI event subscription
  - Block process creations from PSExec and WMI commands
- **Network Protection**:
  - Enable network protection in block mode
- **Exploit Protection**:
  - Enable Control Flow Guard (CFG)
  - Enable Data Execution Prevention (DEP)
  - Configure via Group Policy

### 7. Windows Firewall (`Configure-Firewall.ps1`)
- **Firewall Profiles**:
  - Enable firewall on all profiles (Domain, Private, Public)
  - Block inbound connections by default
  - Allow outbound connections by default
- **Inbound Rules**:
  - Create custom allow rules for required ports only
  - Default: RDP (3389), SMB (445), WinRM (5985)
  - Configurable based on server role
- **Rule Management**:
  - Review and remove unnecessary inbound rules
  - Maintain system rules (Core Networking, File and Printer Sharing)

### 8. RDP Hardening (`Configure-RDPHardening.ps1`)
- **Authentication**:
  - Require Network Level Authentication (NLA)
  - Enable RDP (if disabled)
- **Encryption**:
  - Set encryption level to High
  - Require RDP security layer
- **Session Management**:
  - Active session limit: 15 minutes
  - Disconnected session limit: 15 minutes
- **Redirection Restrictions** (via GPO):
  - Disable clipboard redirection
  - Disable drive redirection
  - Disable printer redirection
- **Port Configuration**:
  - Optional: Change RDP port from default 3389
- **Access Control**:
  - Restrict RDP to specific security group (not Domain Users)

### 9. Logging & Auditing (`Configure-Logging.ps1`)
- **Advanced Audit Policy**:
  - Account Logon: Success and Failure
  - Account Management: Success and Failure
  - Directory Service Access: Success and Failure
  - Logon/Logoff: Success and Failure
  - Object Access: Success and Failure (for sensitive objects)
  - Policy Change: Success and Failure
  - Privilege Use: Failure
  - System Events: Success and Failure
- **Event Log Configuration**:
  - Security log size: 512 MB minimum
  - Application log size: 512 MB minimum
  - System log size: 512 MB minimum
- **PowerShell Logging**:
  - Enable PowerShell transcription
  - Enable script block logging
  - Enable script block invocation logging
  - Enable module logging
  - Configure transcription output directory
- **Audit Policy Enforcement**:
  - Force audit policy subcategory settings (override basic audit policy)

### 10. Credential Guard & LSA Protection (`Configure-CredentialGuard.ps1`)
- **LSA Protection**:
  - Enable RunAsPPL (Protected Process Light)
  - Prevent LSA credential theft
- **Credential Guard**:
  - Enable Virtualization Based Security (VBS)
  - Enable Credential Guard
  - Configure UEFI lock (requires UEFI to disable)
  - Require platform security features
- **System Requirements Check**:
  - Verify UEFI firmware (not Legacy BIOS)
  - Check TPM status and readiness
  - Validate hardware compatibility

### 11. Windows Defender Application Control (WDAC) (`Configure-WDAC.ps1`)
- **Policy Creation**:
  - Create base policy allowing Microsoft-signed applications
  - Add line-of-business application paths
  - Configure policy in Audit mode (initial deployment)
- **Policy Deployment**:
  - Convert XML policy to binary format
  - Deploy policy via Code Integrity
  - Monitor Code Integrity events
- **Policy Management**:
  - Start in Audit mode for 30 days
  - Review audit logs
  - Switch to Enforced mode after validation

## Quick Start

1. **Review Phase 1** (`Phase1-Hardening-Plan.md`) to understand the hardening approach
2. **Review GPO tables** (`Phase2-Configuration/GPO-Configuration-Tables.md`) for Group Policy settings
3. **Run hardening scripts** (as Administrator):
   
   **Option A - Simple Sequential Script (Recommended):**
   ```powershell
   .\Start-Hardening.ps1 -RDPSecurityGroup "DOMAIN\RDP-Users"
   ```
   Or double-click `Start-Hardening.bat` (runs as Administrator)
   
   **Option B - Full Orchestration Script:**
   ```powershell
   .\Phase2-Configuration\Scripts\Enable-ServerHardening.ps1 -RDPSecurityGroup "DOMAIN\RDP-Users"
   ```
   
4. **Validate** using `Phase3-Validation\Validate-Hardening.ps1`
5. **Apply GPO settings** via Group Policy Management Console

## Important Notes

- **Test in lab first**: Some settings may impact application functionality
- **ASR rules**: Start in Audit mode before enforcing
- **WDAC**: Begin in Audit mode and monitor logs
- **Backup**: Ensure system restore points or backups before applying changes
- **Document exceptions**: Maintain a risk register for any settings that cannot be applied

## Framework Alignment

Each configuration includes references to:
- **CIS**: CIS Benchmark control IDs
- **MS Baseline**: Microsoft Security Baseline references
- **ASD E8**: Australian Signals Directorate Essential Eight mappings


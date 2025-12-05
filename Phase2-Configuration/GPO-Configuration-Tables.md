# Phase 2: Group Policy Configuration Tables

## Overview

This document provides detailed Group Policy settings for Windows Server 2025 hardening. Apply these settings via Group Policy Management Console (GPMC) or import into your existing GPO structure.

**GPO Path Convention**: All paths are relative to `Computer Configuration → Policies` unless otherwise specified.

---

## Table 1: Account Policies

### Password Policy

| Policy Path | Policy Name | Recommended Value | CIS Reference | Notes |
|-------------|-------------|------------------|---------------|-------|
| `Windows Settings → Security Settings → Account Policies → Password Policy` | Enforce password history | 24 passwords remembered | CIS 1.1.3 | Prevents password reuse |
| `Windows Settings → Security Settings → Account Policies → Password Policy` | Maximum password age | 60 days | CIS 1.1.4 | Balance security vs. usability |
| `Windows Settings → Security Settings → Account Policies → Password Policy` | Minimum password age | 1 day | CIS 1.1.5 | Prevents immediate password change |
| `Windows Settings → Security Settings → Account Policies → Password Policy` | Minimum password length | 14 characters | CIS 1.1.1 | Stronger than default (7) |
| `Windows Settings → Security Settings → Account Policies → Password Policy` | Password must meet complexity requirements | Enabled | CIS 1.1.2 | Requires uppercase, lowercase, number, special char |
| `Windows Settings → Security Settings → Account Policies → Password Policy` | Store passwords using reversible encryption | Disabled | CIS 1.1.6 | Critical: Never enable |

### Account Lockout Policy

| Policy Path | Policy Name | Recommended Value | CIS Reference | Notes |
|-------------|-------------|------------------|---------------|-------|
| `Windows Settings → Security Settings → Account Policies → Account Lockout Policy` | Account lockout duration | 15 minutes | CIS 1.2.2 | Prevents brute force |
| `Windows Settings → Security Settings → Account Policies → Account Lockout Policy` | Account lockout threshold | 5 invalid logon attempts | CIS 1.2.1 | Balance security vs. lockout risk |
| `Windows Settings → Security Settings → Account Policies → Account Lockout Policy` | Reset account lockout counter after | 15 minutes | CIS 1.2.3 | Must be ≤ lockout duration |

### Kerberos Policy

| Policy Path | Policy Name | Recommended Value | CIS Reference | Notes |
|-------------|-------------|------------------|---------------|-------|
| `Windows Settings → Security Settings → Account Policies → Kerberos Policy` | Enforce user logon restrictions | Enabled | CIS 1.3.4 | Validates user rights |
| `Windows Settings → Security Settings → Account Policies → Kerberos Policy` | Maximum lifetime for service ticket | 600 minutes | CIS 1.3.2 | 10 hours |
| `Windows Settings → Security Settings → Account Policies → Kerberos Policy` | Maximum lifetime for user ticket | 10 hours | CIS 1.3.1 | Default is acceptable |
| `Windows Settings → Security Settings → Account Policies → Kerberos Policy` | Maximum lifetime for user ticket renewal | 7 days | CIS 1.3.5 | Default is acceptable |
| `Windows Settings → Security Settings → Account Policies → Kerberos Policy` | Maximum tolerance for computer clock synchronization | 5 minutes | CIS 1.3.3 | Prevents replay attacks |

---

## Table 2: Local Policies - Audit Policy

| Policy Path | Policy Name | Recommended Value | CIS Reference | Notes |
|-------------|-------------|------------------|---------------|-------|
| `Windows Settings → Security Settings → Local Policies → Audit Policy` | Audit account logon events | Success and Failure | CIS 17.1.1 | Track authentication |
| `Windows Settings → Security Settings → Local Policies → Audit Policy` | Audit account management | Success and Failure | CIS 17.2.1 | Track account changes |
| `Windows Settings → Security Settings → Local Policies → Audit Policy` | Audit directory service access | Success and Failure | CIS 17.8.1 | AD object access |
| `Windows Settings → Security Settings → Local Policies → Audit Policy` | Audit logon events | Success and Failure | CIS 17.3.1 | Track logons |
| `Windows Settings → Security Settings → Local Policies → Audit Policy` | Audit object access | Success and Failure | CIS 17.4.1 | Enable for sensitive files |
| `Windows Settings → Security Settings → Local Policies → Audit Policy` | Audit policy change | Success and Failure | CIS 17.5.1 | Track policy changes |
| `Windows Settings → Security Settings → Local Policies → Audit Policy` | Audit privilege use | Failure | CIS 17.6.1 | Track privilege abuse |
| `Windows Settings → Security Settings → Local Policies → Audit Policy` | Audit process tracking | No auditing | - | Optional, high volume |
| `Windows Settings → Security Settings → Local Policies → Audit Policy` | Audit system events | Success and Failure | CIS 17.7.1 | Track system changes |

---

## Table 3: Local Policies - User Rights Assignment

| Policy Path | Policy Name | Recommended Value | CIS Reference | Notes |
|-------------|-------------|------------------|---------------|-------|
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Access Credential Manager as a trusted caller | No one | CIS 2.2.1 | Prevent credential access |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Access this computer from the network | Authenticated Users, Domain Users (remove if possible) | CIS 2.2.2 | Restrict network access |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Act as part of the operating system | No one | CIS 2.2.3 | High privilege |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Add workstations to domain | Domain Admins | CIS 2.2.4 | Prevent unauthorized joins |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Allow log on locally | Administrators, Backup Operators (if needed) | CIS 2.2.5 | Restrict local logon |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Allow log on through RDP | Specific security group (NOT Domain Users) | CIS 2.2.6 | Critical for RDP security |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Back up files and directories | Administrators, Backup Operators | CIS 2.2.7 | Restrict backup access |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Change the system time | Administrators, LOCAL SERVICE | CIS 2.2.8 | Prevent time manipulation |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Change the time zone | Administrators, LOCAL SERVICE, Users | CIS 2.2.9 | Less critical |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Create a pagefile | Administrators | CIS 2.2.10 | System setting |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Create a token object | No one | CIS 2.2.11 | Prevent token manipulation |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Create global objects | Administrators, LOCAL SERVICE, NETWORK SERVICE, Service | CIS 2.2.12 | System requirement |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Create permanent shared objects | No one | CIS 2.2.13 | Prevent shared object abuse |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Create symbolic links | Administrators (if needed) | CIS 2.2.14 | Restrict symlink creation |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Debug programs | Administrators | CIS 2.2.15 | Restrict debugging |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Deny access to this computer from the network | Guest, Local account | CIS 2.2.16 | Explicit deny |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Deny log on as a batch job | Guest | CIS 2.2.17 | Explicit deny |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Deny log on as a service | Guest | CIS 2.2.18 | Explicit deny |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Deny log on locally | Guest | CIS 2.2.19 | Explicit deny |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Deny log on through RDP | Guest, Local account (if not needed) | CIS 2.2.20 | Explicit deny |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Enable computer and user accounts to be trusted for delegation | No one | CIS 2.2.21 | Prevent delegation abuse |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Force shutdown from a remote system | Administrators | CIS 2.2.22 | Restrict remote shutdown |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Generate security audits | LOCAL SERVICE, NETWORK SERVICE | CIS 2.2.23 | System requirement |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Impersonate a client after authentication | Administrators, LOCAL SERVICE, NETWORK SERVICE, Service | CIS 2.2.24 | System requirement |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Increase a process working set | Users | CIS 2.2.25 | System requirement |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Increase scheduling priority | Administrators | CIS 2.2.26 | Restrict priority changes |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Load and unload device drivers | Administrators | CIS 2.2.27 | Restrict driver loading |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Lock pages in memory | No one | CIS 2.2.28 | Prevent memory locking |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Log on as a batch job | Administrators, Backup Operators (if needed) | CIS 2.2.29 | Restrict batch jobs |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Log on as a service | NETWORK SERVICE, Service | CIS 2.2.30 | System requirement |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Manage auditing and security log | Administrators | CIS 2.2.31 | Restrict audit management |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Modify an object label | No one | CIS 2.2.32 | Prevent label modification |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Modify firmware environment values | Administrators | CIS 2.2.33 | Restrict firmware changes |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Perform volume maintenance tasks | Administrators | CIS 2.2.34 | Restrict volume operations |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Profile single process | Administrators | CIS 2.2.35 | Restrict profiling |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Profile system performance | Administrators, NT SERVICE\WdiServiceHost | CIS 2.2.36 | System requirement |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Remove computer from docking station | Administrators, Users | CIS 2.2.37 | Less critical |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Replace a process level token | LOCAL SERVICE, NETWORK SERVICE | CIS 2.2.38 | System requirement |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Restore files and directories | Administrators, Backup Operators | CIS 2.2.39 | Restrict restore access |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Shut down the system | Administrators | CIS 2.2.40 | Restrict shutdown |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Synchronize directory service data | No one | CIS 2.2.41 | Prevent DS sync abuse |
| `Windows Settings → Security Settings → Local Policies → User Rights Assignment` | Take ownership of files or other objects | Administrators | CIS 2.2.42 | Restrict ownership changes |

---

## Table 4: Local Policies - Security Options

| Policy Path | Policy Name | Recommended Value | CIS Reference | Notes |
|-------------|-------------|------------------|---------------|-------|
| `Windows Settings → Security Settings → Local Policies → Security Options` | Accounts: Block Microsoft accounts | Users can't add or log on with Microsoft accounts | CIS 2.3.18 | Prevent personal accounts |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Accounts: Guest account status | Disabled | CIS 2.3.19 | Disable guest account |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Accounts: Limit local account use of blank passwords to console logon only | Enabled | CIS 2.3.20 | Prevent blank password network logon |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Accounts: Rename administrator account | Rename to non-standard name | CIS 2.3.21 | Obscure admin account |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Accounts: Rename guest account | Rename to non-standard name | CIS 2.3.22 | Obscure guest account |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Audit: Force audit policy subcategory settings | Enabled | CIS 17.10.1 | Use Advanced Audit Policy |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Audit: Shut down system immediately if unable to log security audits | Disabled (or Enabled with caution) | CIS 17.10.2 | Risk: May cause DoS |
| `Windows Settings → Security Settings → Local Policies → Security Options` | DCOM: Machine Launch Restrictions in Security Descriptor | Configured | CIS 2.3.23 | Restrict DCOM |
| `Windows Settings → Security Settings → Local Policies → Security Options` | DCOM: Machine Access Restrictions in Security Descriptor | Configured | CIS 2.3.24 | Restrict DCOM |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Devices: Allow undock without having to log on | Disabled | CIS 2.3.25 | Prevent unauthorized undock |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Devices: Allowed to format and eject removable media | Administrators | CIS 2.3.26 | Restrict media operations |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Devices: Prevent users from installing printer drivers | Enabled | CIS 2.3.27 | Restrict driver installation |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Devices: Restrict CD-ROM access to locally logged-on user only | Enabled | CIS 2.3.28 | Restrict CD-ROM access |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Devices: Restrict floppy access to locally logged-on user only | Enabled | CIS 2.3.29 | Restrict floppy access |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Domain member: Digitally encrypt or sign secure channel data (always) | Enabled | CIS 2.3.30 | Secure domain communication |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Domain member: Digitally encrypt secure channel data (when possible) | Enabled | CIS 2.3.31 | Secure domain communication |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Domain member: Digitally sign secure channel data (when possible) | Enabled | CIS 2.3.32 | Secure domain communication |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Domain member: Disable machine account password changes | Disabled | CIS 2.3.33 | Allow password changes |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Domain member: Maximum machine account password age | 30 days | CIS 2.3.34 | Regular password rotation |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Domain member: Require strong (Windows 2000 or later) session key | Enabled | CIS 2.3.35 | Strong session keys |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Interactive logon: Display user information when session is locked | User display name only | CIS 2.3.36 | Don't show username |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Interactive logon: Don't display last signed-in | Enabled | CIS 2.3.37 | Don't reveal last user |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Interactive logon: Don't display username at sign-in | Enabled | CIS 2.3.38 | Don't reveal username |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Interactive logon: Machine inactivity limit | 900 seconds (15 minutes) | CIS 2.3.39 | Auto-lock after inactivity |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Interactive logon: Machine inactivity limit | Enabled | CIS 2.3.39 | Enable auto-lock |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Interactive logon: Message text for users attempting to log on | Configure warning message | CIS 2.3.40 | Legal/security notice |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Interactive logon: Message title for users attempting to log on | Configure warning title | CIS 2.3.41 | Legal/security notice |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Interactive logon: Number of previous logons to cache | 2 logons | CIS 2.3.42 | Limit cached credentials |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Interactive logon: Prompt user to change password before expiration | 14 days | CIS 2.3.43 | Advance warning |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Interactive logon: Require Domain Controller authentication to unlock workstation | Enabled | CIS 2.3.44 | Require DC for unlock |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Interactive logon: Require smart card | Disabled (unless MFA required) | CIS 2.3.45 | Optional for servers |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Interactive logon: Smart card removal behavior | Lock workstation | CIS 2.3.46 | Lock on card removal |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Microsoft network client: Digitally sign communications (always) | Enabled | CIS 2.3.47 | Require SMB signing |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Microsoft network client: Digitally sign communications (if server agrees) | Enabled | CIS 2.3.48 | Prefer SMB signing |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Microsoft network client: Send unencrypted password to third-party SMB servers | Disabled | CIS 2.3.49 | Prevent plaintext passwords |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Microsoft network server: Digitally sign communications (always) | Enabled | CIS 2.3.50 | Require SMB signing |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Microsoft network server: Digitally sign communications (if client agrees) | Enabled | CIS 2.3.51 | Prefer SMB signing |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Microsoft network server: Disconnect clients when logon hours expire | Enabled | CIS 2.3.52 | Enforce logon hours |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Microsoft network server: Server SPN target name validation level | Accept if provided by client | CIS 2.3.53 | Validate SPN |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network access: Allow anonymous SID/Name translation | Disabled | CIS 2.3.54 | Prevent SID enumeration |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network access: Do not allow anonymous enumeration of SAM accounts | Enabled | CIS 2.3.55 | Prevent account enumeration |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network access: Do not allow anonymous enumeration of SAM accounts and shares | Enabled | CIS 2.3.56 | Prevent share enumeration |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network access: Do not allow storage of passwords and credentials for network authentication | Enabled | CIS 2.3.57 | Prevent credential storage |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network access: Let Everyone permissions apply to anonymous users | Disabled | CIS 2.3.58 | Restrict anonymous access |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network access: Named Pipes that can be accessed anonymously | None (remove all) | CIS 2.3.59 | Restrict anonymous pipes |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network access: Remotely accessible registry paths | Configure minimal paths | CIS 2.3.60 | Restrict remote registry |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network access: Remotely accessible registry paths and subpaths | Configure minimal paths | CIS 2.3.61 | Restrict remote registry |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network access: Restrict anonymous access to Named Pipes and Shares | Enabled | CIS 2.3.62 | Restrict anonymous access |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network access: Shares that can be accessed anonymously | None (remove all) | CIS 2.3.63 | Restrict anonymous shares |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network access: Sharing and security model for local accounts | Classic - local users authenticate as themselves | CIS 2.3.64 | Use classic model |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network security: Allow Local System to use computer identity for NTLM | Enabled | CIS 2.3.65 | System requirement |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network security: Allow PKU2U authentication requests to this computer to use online identities | Disabled | CIS 2.3.66 | Disable PKU2U |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network security: Configure encryption types allowed for Kerberos | AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types | CIS 2.3.67 | Strong encryption only |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network security: Do not store LAN Manager hash value on next password change | Enabled | CIS 2.3.68 | Prevent LM hash storage |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network security: Force logoff when logon hours expire | Enabled | CIS 2.3.69 | Enforce logon hours |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network security: LAN Manager authentication level | Send NTLMv2 response only. Refuse LM & NTLM | CIS 2.3.70 | Require NTLMv2 |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network security: Minimum session security for NTLM SSP based (including secure RPC) clients | Require NTLMv2, Require 128-bit encryption | CIS 2.3.71 | Strong NTLM security |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network security: Minimum session security for NTLM SSP based (including secure RPC) servers | Require NTLMv2, Require 128-bit encryption | CIS 2.3.72 | Strong NTLM security |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication | Configure as needed | CIS 2.3.73 | Audit NTLM first |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network security: Restrict NTLM: Add server exceptions in this domain | Configure as needed | CIS 2.3.74 | Audit NTLM first |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network security: Restrict NTLM: Audit Incoming NTLM Traffic | Enable auditing for all accounts | CIS 2.3.75 | Audit NTLM usage |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network security: Restrict NTLM: Audit NTLM authentication in this domain | Enable all | CIS 2.3.76 | Audit NTLM usage |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers | Audit all | CIS 2.3.77 | Audit NTLM usage |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Recovery console: Allow automatic administrative logon | Disabled | CIS 2.3.78 | Require authentication |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Recovery console: Allow floppy copy and access to all drives and folders | Disabled | CIS 2.3.79 | Restrict recovery console |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Shutdown: Allow system to be shut down without having to log on | Disabled | CIS 2.3.80 | Require authentication |
| `Windows Settings → Security Settings → Local Policies → Security Options` | Shutdown: Clear virtual memory pagefile | Enabled | CIS 2.3.81 | Clear pagefile on shutdown |
| `Windows Settings → Security Settings → Local Policies → Security Options` | System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing | Disabled (unless required) | CIS 2.3.82 | May break compatibility |
| `Windows Settings → Security Settings → Local Policies → Security Options` | System objects: Require case insensitivity for non-Windows subsystems | Enabled | CIS 2.3.83 | System requirement |
| `Windows Settings → Security Settings → Local Policies → Security Options` | System objects: Strengthen default permissions of internal system objects | Enabled | CIS 2.3.84 | Strengthen permissions |
| `Windows Settings → Security Settings → Local Policies → Security Options` | System settings: Optional subsystems | None (remove all) | CIS 2.3.85 | Remove POSIX/OS2 |
| `Windows Settings → Security Settings → Local Policies → Security Options` | User Account Control: Admin Approval Mode for the Built-in Administrator account | Enabled | CIS 2.3.86 | Require UAC for admin |
| `Windows Settings → Security Settings → Local Policies → Security Options` | User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop | Disabled | CIS 2.3.87 | Require secure desktop |
| `Windows Settings → Security Settings → Local Policies → Security Options` | User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode | Prompt for consent on the secure desktop | CIS 2.3.88 | Require secure desktop |
| `Windows Settings → Security Settings → Local Policies → Security Options` | User Account Control: Behavior of the elevation prompt for standard users | Automatically deny elevation requests | CIS 2.3.89 | Deny standard user elevation |
| `Windows Settings → Security Settings → Local Policies → Security Options` | User Account Control: Detect application installations and prompt for elevation | Enabled | CIS 2.3.90 | Detect installations |
| `Windows Settings → Security Settings → Local Policies → Security Options` | User Account Control: Only elevate executables that are signed and validated | Enabled | CIS 2.3.91 | Require signed executables |
| `Windows Settings → Security Settings → Local Policies → Security Options` | User Account Control: Only elevate UIAccess applications that are installed in secure locations | Enabled | CIS 2.3.92 | Require secure locations |
| `Windows Settings → Security Settings → Local Policies → Security Options` | User Account Control: Run all administrators in Admin Approval Mode | Enabled | CIS 2.3.93 | Require UAC for all admins |
| `Windows Settings → Security Settings → Local Policies → Security Options` | User Account Control: Switch to the secure desktop when prompting for elevation | Enabled | CIS 2.3.94 | Require secure desktop |
| `Windows Settings → Security Settings → Local Policies → Security Options` | User Account Control: Virtualize file and registry write failures to per-user locations | Enabled | CIS 2.3.95 | Enable virtualization |

---

## Table 5: Windows Defender Antivirus

| Policy Path | Policy Name | Recommended Value | CIS Reference | Notes |
|-------------|-------------|------------------|---------------|-------|
| `Administrative Templates → Windows Components → Microsoft Defender Antivirus` | Turn on real-time protection | Enabled | CIS 9.1 | Critical |
| `Administrative Templates → Windows Components → Microsoft Defender Antivirus` | Turn on cloud-delivered protection | Enabled | CIS 9.2 | Enable cloud protection |
| `Administrative Templates → Windows Components → Microsoft Defender Antivirus` | Configure local setting override for cloud-delivered protection | Disabled | CIS 9.2 | Prevent local override |
| `Administrative Templates → Windows Components → Microsoft Defender Antivirus` | Turn on sample submission | Enabled (Send safe samples automatically) | CIS 9.3 | Enable telemetry |
| `Administrative Templates → Windows Components → Microsoft Defender Antivirus` | Configure local setting override for reporting to Microsoft MAPS | Disabled | CIS 9.3 | Prevent local override |
| `Administrative Templates → Windows Components → Microsoft Defender Antivirus` | Turn on behavior monitoring | Enabled | CIS 9.4 | Enable behavior monitoring |
| `Administrative Templates → Windows Components → Microsoft Defender Antivirus` | Turn on process scanning whenever real-time protection is enabled | Enabled | CIS 9.5 | Enable process scanning |
| `Administrative Templates → Windows Components → Microsoft Defender Antivirus` | Turn on protection against Potentially Unwanted Applications | Enabled | CIS 9.6 | Enable PUA protection |
| `Administrative Templates → Windows Components → Microsoft Defender Antivirus` | Scan removable drives | Enabled | CIS 9.7 | Scan removable media |
| `Administrative Templates → Windows Components → Microsoft Defender Antivirus` | Turn on removal of items from Quarantine folder | Enabled | CIS 9.8 | Auto-cleanup quarantine |
| `Administrative Templates → Windows Components → Microsoft Defender Antivirus` | Configure scheduled scan day | Daily | CIS 9.9 | Daily scans |
| `Administrative Templates → Windows Components → Microsoft Defender Antivirus` | Configure scheduled scan time | Configure time | CIS 9.9 | Off-peak hours |
| `Administrative Templates → Windows Components → Microsoft Defender Antivirus` | Turn on e-mail scanning | Enabled | CIS 9.10 | Scan email |
| `Administrative Templates → Windows Components → Microsoft Defender Antivirus` | Turn on network protection | Enabled | CIS 9.11 | Enable network protection |
| `Administrative Templates → Windows Components → Microsoft Defender Antivirus` | Configure network protection | Block mode | CIS 9.11 | Block malicious network activity |
| `Administrative Templates → Windows Components → Microsoft Defender Antivirus` | Turn on tamper protection | Enabled | CIS 9.12 | Prevent tampering |

---

## Table 6: Windows Defender Exploit Guard

| Policy Path | Policy Name | Recommended Value | CIS Reference | Notes |
|-------------|-------------|------------------|---------------|-------|
| `Administrative Templates → Windows Components → Windows Defender Exploit Guard → Exploit Protection` | Use Exploit Protection | Enabled | MS Baseline | Enable exploit protection |
| `Administrative Templates → Windows Components → Windows Defender Exploit Guard → Attack Surface Reduction Rules` | Configure Attack Surface Reduction rules | Enabled | MS Baseline | Configure ASR rules (see script) |

**Note**: ASR rules are configured via PowerShell (see `Configure-ExploitGuard.ps1`). GPO can enable the feature, but individual rule configuration is done via PowerShell or Intune.

---

## Table 7: Remote Desktop Services

| Policy Path | Policy Name | Recommended Value | CIS Reference | Notes |
|-------------|-------------|------------------|---------------|-------|
| `Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Security` | Require user authentication for remote connections by using Network Level Authentication | Enabled | CIS 2.3.7 | Require NLA |
| `Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Security` | Set client connection encryption level | High Level | CIS 2.3.9 | High encryption |
| `Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Sessions` | Set time limit for active Remote Desktop Services sessions | 15 minutes | CIS 2.3.12 | Idle timeout |
| `Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Sessions` | Set time limit for disconnected sessions | 15 minutes | CIS 2.3.13 | Disconnect timeout |
| `Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Device and Resource Redirection` | Do not allow clipboard redirection | Enabled | CIS 2.3.14 | Disable clipboard |
| `Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Device and Resource Redirection` | Do not allow drive redirection | Enabled | CIS 2.3.15 | Disable drive mapping |

---

## Table 8: Windows Firewall with Advanced Security

**Note**: Firewall rules are best configured via PowerShell (see `Configure-Firewall.ps1`). GPO can manage firewall profiles.

| Policy Path | Policy Name | Recommended Value | CIS Reference | Notes |
|-------------|-------------|------------------|---------------|-------|
| `Windows Settings → Security Settings → Windows Firewall with Advanced Security → Windows Firewall with Advanced Security` | Domain Profile → Firewall state | On (recommended) | CIS 9.1 | Enable firewall |
| `Windows Settings → Security Settings → Windows Firewall with Advanced Security → Windows Firewall with Advanced Security` | Domain Profile → Inbound connections | Block (default) | CIS 9.1 | Block by default |
| `Windows Settings → Security Settings → Windows Firewall with Advanced Security → Windows Firewall with Advanced Security` | Domain Profile → Outbound connections | Allow (default) | CIS 9.1 | Allow outbound |
| `Windows Settings → Security Settings → Windows Firewall with Advanced Security → Windows Firewall with Advanced Security` | Private Profile → Firewall state | On (recommended) | CIS 9.1 | Enable firewall |
| `Windows Settings → Security Settings → Windows Firewall with Advanced Security → Windows Firewall with Advanced Security` | Private Profile → Inbound connections | Block (default) | CIS 9.1 | Block by default |
| `Windows Settings → Security Settings → Windows Firewall with Advanced Security → Windows Firewall with Advanced Security` | Public Profile → Firewall state | On (recommended) | CIS 9.1 | Enable firewall |
| `Windows Settings → Security Settings → Windows Firewall with Advanced Security → Windows Firewall with Advanced Security` | Public Profile → Inbound connections | Block (default) | CIS 9.1 | Block by default |

---

## Table 9: PowerShell Execution Policy

| Policy Path | Policy Name | Recommended Value | CIS Reference | Notes |
|-------------|-------------|------------------|---------------|-------|
| `Administrative Templates → Windows Components → Windows PowerShell` | Turn on Script Execution | Enabled | CIS 18.9.1 | Configure execution policy |
| `Administrative Templates → Windows Components → Windows PowerShell` | Turn on Script Execution → Execution Policy | Allow only signed scripts | CIS 18.9.1 | Require signed scripts |

---

## Implementation Notes

1. **GPO Application Order**: Apply account policies at the domain level, other settings at OU level
2. **Testing**: Test all GPOs in lab environment before production
3. **Backup**: Export GPOs before making changes
4. **Documentation**: Document any deviations from recommended values
5. **Monitoring**: Monitor Event Viewer for policy application errors

---

## Next Steps

After configuring GPOs, run the PowerShell scripts in `Scripts/` to:
- Configure settings not available via GPO
- Apply firewall rules
- Configure Defender ASR rules
- Enable PowerShell logging
- Configure Credential Guard


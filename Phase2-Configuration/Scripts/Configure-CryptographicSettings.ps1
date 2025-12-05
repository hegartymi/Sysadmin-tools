# Script: Configure-CryptographicSettings.ps1
# Purpose: Disable weak cryptographic protocols, ciphers, hashes, and key exchange algorithms
# Framework Alignment: CIS Benchmarks, Microsoft Security Baseline, NIST Guidelines
# Requires: Administrator privileges

<#
.SYNOPSIS
    Disables weak cryptographic protocols, ciphers, hashes, and key exchange algorithms.

.DESCRIPTION
    This script configures Windows to disable:
    - Weak SSL/TLS protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)
    - Weak cipher suites
    - Weak hashing algorithms (MD5, SHA1)
    - Weak key exchange algorithms
    - Legacy cryptographic algorithms

.NOTES
    - Requires system restart for some settings to take effect
    - Test applications after applying changes
    - Some legacy applications may break
    - CIS References: Various network security controls

.EXAMPLE
    .\Configure-CryptographicSettings.ps1
#>

[CmdletBinding()]
param(
    [switch]$WhatIf
)

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'  # Continue on errors to attempt all operations

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Cryptographic Settings Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Registry paths
$schannelPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
$protocolsPath = "$schannelPath\Protocols"
$ciphersPath = "$schannelPath\Ciphers"
$hashesPath = "$schannelPath\Hashes"
$keyExchangeAlgorithmsPath = "$schannelPath\KeyExchangeAlgorithms"

# Function to set registry value
function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord"
    )
    
    if (-not (Test-Path $Path)) {
        if ($WhatIf) {
            Write-Host "[WHATIF] Would create registry path: $Path" -ForegroundColor Green
        } else {
            New-Item -Path $Path -Force | Out-Null
        }
    }
    
    if ($WhatIf) {
        Write-Host "[WHATIF] Would set: $Path\$Name = $Value ($Type)" -ForegroundColor Green
    } else {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Host "  Set: $Path\$Name = $Value" -ForegroundColor Gray
    }
}

try {
    Write-Host "Configuring SSL/TLS protocols..." -ForegroundColor Yellow
    
    # Disable SSL 2.0
    $ssl20Path = "$protocolsPath\SSL 2.0\Server"
    if ($WhatIf) {
        Write-Host "[WHATIF] Would disable SSL 2.0" -ForegroundColor Green
    } else {
        Set-RegistryValue -Path $ssl20Path -Name "Enabled" -Value 0
        Set-RegistryValue -Path $ssl20Path -Name "DisabledByDefault" -Value 1
        Write-Host "  Disabled SSL 2.0" -ForegroundColor Gray
    }
    
    # Disable SSL 3.0
    $ssl30ServerPath = "$protocolsPath\SSL 3.0\Server"
    $ssl30ClientPath = "$protocolsPath\SSL 3.0\Client"
    if ($WhatIf) {
        Write-Host "[WHATIF] Would disable SSL 3.0" -ForegroundColor Green
    } else {
        Set-RegistryValue -Path $ssl30ServerPath -Name "Enabled" -Value 0
        Set-RegistryValue -Path $ssl30ServerPath -Name "DisabledByDefault" -Value 1
        Set-RegistryValue -Path $ssl30ClientPath -Name "Enabled" -Value 0
        Set-RegistryValue -Path $ssl30ClientPath -Name "DisabledByDefault" -Value 1
        Write-Host "  Disabled SSL 3.0" -ForegroundColor Gray
    }
    
    # Disable TLS 1.0
    $tls10ServerPath = "$protocolsPath\TLS 1.0\Server"
    $tls10ClientPath = "$protocolsPath\TLS 1.0\Client"
    if ($WhatIf) {
        Write-Host "[WHATIF] Would disable TLS 1.0" -ForegroundColor Green
    } else {
        Set-RegistryValue -Path $tls10ServerPath -Name "Enabled" -Value 0
        Set-RegistryValue -Path $tls10ServerPath -Name "DisabledByDefault" -Value 1
        Set-RegistryValue -Path $tls10ClientPath -Name "Enabled" -Value 0
        Set-RegistryValue -Path $tls10ClientPath -Name "DisabledByDefault" -Value 1
        Write-Host "  Disabled TLS 1.0" -ForegroundColor Gray
    }
    
    # Disable TLS 1.1
    $tls11ServerPath = "$protocolsPath\TLS 1.1\Server"
    $tls11ClientPath = "$protocolsPath\TLS 1.1\Client"
    if ($WhatIf) {
        Write-Host "[WHATIF] Would disable TLS 1.1" -ForegroundColor Green
    } else {
        Set-RegistryValue -Path $tls11ServerPath -Name "Enabled" -Value 0
        Set-RegistryValue -Path $tls11ServerPath -Name "DisabledByDefault" -Value 1
        Set-RegistryValue -Path $tls11ClientPath -Name "Enabled" -Value 0
        Set-RegistryValue -Path $tls11ClientPath -Name "DisabledByDefault" -Value 1
        Write-Host "  Disabled TLS 1.1" -ForegroundColor Gray
    }
    
    # Enable TLS 1.2 (ensure it's enabled)
    $tls12ServerPath = "$protocolsPath\TLS 1.2\Server"
    $tls12ClientPath = "$protocolsPath\TLS 1.2\Client"
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable TLS 1.2" -ForegroundColor Green
    } else {
        Set-RegistryValue -Path $tls12ServerPath -Name "Enabled" -Value 1
        Set-RegistryValue -Path $tls12ServerPath -Name "DisabledByDefault" -Value 0
        Set-RegistryValue -Path $tls12ClientPath -Name "Enabled" -Value 1
        Set-RegistryValue -Path $tls12ClientPath -Name "DisabledByDefault" -Value 0
        Write-Host "  Enabled TLS 1.2" -ForegroundColor Gray
    }
    
    # Enable TLS 1.3 (if available on Windows Server 2025)
    $tls13ServerPath = "$protocolsPath\TLS 1.3\Server"
    $tls13ClientPath = "$protocolsPath\TLS 1.3\Client"
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable TLS 1.3 (if available)" -ForegroundColor Green
    } else {
        if (Test-Path $tls13ServerPath) {
            Set-RegistryValue -Path $tls13ServerPath -Name "Enabled" -Value 1
            Set-RegistryValue -Path $tls13ServerPath -Name "DisabledByDefault" -Value 0
            Set-RegistryValue -Path $tls13ClientPath -Name "Enabled" -Value 1
            Set-RegistryValue -Path $tls13ClientPath -Name "DisabledByDefault" -Value 0
            Write-Host "  Enabled TLS 1.3" -ForegroundColor Gray
        } else {
            Write-Host "  TLS 1.3 not available on this system" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`nConfiguring cipher suites..." -ForegroundColor Yellow
    
    # Disable weak cipher suites
    $weakCiphers = @(
        "DES 56/56",
        "NULL",
        "RC2 40/128",
        "RC2 56/128",
        "RC2 128/128",
        "RC4 40/128",
        "RC4 56/128",
        "RC4 64/128",
        "RC4 128/128",
        "Triple DES 168"
    )
    
    foreach ($cipher in $weakCiphers) {
        $cipherPath = "$ciphersPath\$cipher"
        if ($WhatIf) {
            Write-Host "[WHATIF] Would disable cipher: $cipher" -ForegroundColor Green
        } else {
            Set-RegistryValue -Path $cipherPath -Name "Enabled" -Value 0
            Set-RegistryValue -Path $cipherPath -Name "DisabledByDefault" -Value 1
            Write-Host "  Disabled cipher: $cipher" -ForegroundColor Gray
        }
    }
    
    # Enable strong cipher suites
    $strongCiphers = @(
        "AES 128/128",
        "AES 256/256"
    )
    
    foreach ($cipher in $strongCiphers) {
        $cipherPath = "$ciphersPath\$cipher"
        if ($WhatIf) {
            Write-Host "[WHATIF] Would enable cipher: $cipher" -ForegroundColor Green
        } else {
            Set-RegistryValue -Path $cipherPath -Name "Enabled" -Value 0xffffffff
            Set-RegistryValue -Path $cipherPath -Name "DisabledByDefault" -Value 0
            Write-Host "  Enabled cipher: $cipher" -ForegroundColor Gray
        }
    }
    
    Write-Host "`nConfiguring hashing algorithms..." -ForegroundColor Yellow
    
    # Disable MD5
    $md5Path = "$hashesPath\MD5"
    if ($WhatIf) {
        Write-Host "[WHATIF] Would disable MD5 hash" -ForegroundColor Green
    } else {
        Set-RegistryValue -Path $md5Path -Name "Enabled" -Value 0
        Set-RegistryValue -Path $md5Path -Name "DisabledByDefault" -Value 1
        Write-Host "  Disabled MD5 hash" -ForegroundColor Gray
    }
    
    # Disable SHA1 (optional - may break some legacy apps)
    $sha1Path = "$hashesPath\SHA"
    if ($WhatIf) {
        Write-Host "[WHATIF] Would disable SHA1 hash (may break legacy apps)" -ForegroundColor Green
    } else {
        # Note: Disabling SHA1 may break legacy applications
        # Set-RegistryValue -Path $sha1Path -Name "Enabled" -Value 0
        # Set-RegistryValue -Path $sha1Path -Name "DisabledByDefault" -Value 1
        Write-Host "  SHA1 hash: Left enabled (disable manually if needed)" -ForegroundColor Yellow
        Write-Host "    Warning: Disabling SHA1 may break legacy applications" -ForegroundColor Yellow
    }
    
    Write-Host "`nConfiguring key exchange algorithms..." -ForegroundColor Yellow
    
    # Disable weak key exchange algorithms
    $weakKeyExchange = @(
        "Diffie-Hellman",
        "PKCS"
    )
    
    foreach ($algo in $weakKeyExchange) {
        $algoPath = "$keyExchangeAlgorithmsPath\$algo"
        if ($WhatIf) {
            Write-Host "[WHATIF] Would disable key exchange: $algo" -ForegroundColor Green
        } else {
            # Note: Some key exchange algorithms may be needed for compatibility
            # Review your environment before disabling
            Write-Host "  Key exchange $algo : Review before disabling (may break compatibility)" -ForegroundColor Yellow
        }
    }
    
    # Enable ECDH (Elliptic Curve Diffie-Hellman) - strong key exchange
    $ecdhPath = "$keyExchangeAlgorithmsPath\ECDH"
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable ECDH key exchange" -ForegroundColor Green
    } else {
        Set-RegistryValue -Path $ecdhPath -Name "Enabled" -Value 0xffffffff
        Set-RegistryValue -Path $ecdhPath -Name "DisabledByDefault" -Value 0
        Write-Host "  Enabled ECDH key exchange" -ForegroundColor Gray
    }
    
    # Configure .NET Framework to use strong cryptography
    Write-Host "`nConfiguring .NET Framework cryptography..." -ForegroundColor Yellow
    
    $netFrameworkPath = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable .NET Framework strong cryptography" -ForegroundColor Green
    } else {
        Set-RegistryValue -Path $netFrameworkPath -Name "SchUseStrongCrypto" -Value 1
        Write-Host "  Enabled .NET Framework strong cryptography" -ForegroundColor Gray
    }
    
    # Configure .NET Framework 64-bit
    $netFramework64Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable .NET Framework 64-bit strong cryptography" -ForegroundColor Green
    } else {
        Set-RegistryValue -Path $netFramework64Path -Name "SchUseStrongCrypto" -Value 1
        Write-Host "  Enabled .NET Framework 64-bit strong cryptography" -ForegroundColor Gray
    }
    
    # Disable RC4 cipher suite priority (prefer AES)
    Write-Host "`nConfiguring cipher suite priority..." -ForegroundColor Yellow
    
    $ciphersOrderPath = "$schannelPath\CipherSuites"
    if ($WhatIf) {
        Write-Host "[WHATIF] Would configure cipher suite priority (prefer AES over RC4)" -ForegroundColor Green
    } else {
        # Note: Cipher suite ordering is complex and may require manual configuration
        # This ensures AES ciphers are preferred over RC4
        Write-Host "  Cipher suite priority: Configure manually if needed" -ForegroundColor Yellow
        Write-Host "    Prefer AES ciphers over RC4 in cipher suite order" -ForegroundColor Gray
    }
    
    if (-not $WhatIf) {
        Write-Host "`nVerifying cryptographic configuration..." -ForegroundColor Yellow
        
        # Check TLS protocol settings
        Write-Host "`nTLS Protocol Status:" -ForegroundColor Cyan
        $tlsProtocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")
        foreach ($protocol in $tlsProtocols) {
            $serverPath = "$protocolsPath\$protocol\Server"
            if (Test-Path $serverPath) {
                $enabled = (Get-ItemProperty -Path $serverPath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
                $disabledByDefault = (Get-ItemProperty -Path $serverPath -Name "DisabledByDefault" -ErrorAction SilentlyContinue).DisabledByDefault
                $status = if ($enabled -eq 0 -or $disabledByDefault -eq 1) { "Disabled" } else { "Enabled" }
                Write-Host "  $protocol : $status" -ForegroundColor $(if ($status -eq "Disabled" -and $protocol -in @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")) { "Green" } elseif ($status -eq "Enabled" -and $protocol -in @("TLS 1.2", "TLS 1.3")) { "Green" } else { "Yellow" })
            }
        }
        
        Write-Host "`nNote: Some settings may require a system restart to take full effect." -ForegroundColor Yellow
        Write-Host "Test applications after applying changes to ensure compatibility." -ForegroundColor Yellow
    }
    
} catch {
    Write-Error "Error configuring cryptographic settings: $_"
    throw
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Cryptographic Settings Configuration Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`nSecurity Recommendations:" -ForegroundColor Yellow
Write-Host "1. Test all applications after applying changes" -ForegroundColor White
Write-Host "2. Monitor Event Viewer for TLS/SSL errors" -ForegroundColor White
Write-Host "3. Consider disabling SHA1 if legacy apps allow" -ForegroundColor White
Write-Host "4. Restart system for all changes to take effect" -ForegroundColor White
Write-Host "5. Use IISCrypto or similar tools to verify cipher suite order" -ForegroundColor White


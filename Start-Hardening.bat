@echo off
REM Batch script to start Windows Server 2025 hardening
REM This script launches the PowerShell hardening script with proper elevation

echo ========================================
echo Windows Server 2025 Hardening
echo ========================================
echo.

REM Check for administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo This script requires Administrator privileges.
    echo Please right-click and select "Run as Administrator"
    pause
    exit /b 1
)

REM Get the directory where this batch file is located
set "SCRIPT_DIR=%~dp0"

REM Launch PowerShell script
echo Starting hardening process...
echo.

powershell.exe -ExecutionPolicy Bypass -File "%SCRIPT_DIR%Start-Hardening.ps1" %*

if %errorLevel% equ 0 (
    echo.
    echo Hardening completed successfully!
) else (
    echo.
    echo Hardening completed with errors. Review output above.
)

echo.
pause


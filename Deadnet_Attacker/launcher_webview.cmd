@echo off
REM Launcher script for DeadNet Attacker (WebView Version)
REM This launches the app with integrated webview (no browser needed)

REM Change to the script's directory
cd /d "%~dp0"

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo ========================================
echo DeadNet Attacker - WebView Version
echo ========================================
echo.

REM Check Python installation
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python not found!
    echo Please install Python 3.8 or newer from python.org
    pause
    exit /b 1
)

REM Check if Npcap is installed
echo [*] Checking for Npcap installation...
if not exist "C:\Windows\System32\Npcap\wpcap.dll" (
    if not exist "C:\Windows\SysWOW64\Npcap\wpcap.dll" (
        echo.
        echo [WARNING] Npcap not detected!
        echo Please install Npcap from: https://npcap.com
        echo.
        echo Install with "WinPcap API-compatible Mode" enabled!
        echo.
        pause
    )
)

REM Check and install requirements if needed
echo [*] Checking dependencies...
python -c "import webview" >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Installing missing dependencies...
    python -m pip install -r requirements.txt
    if %errorLevel% neq 0 (
        echo [ERROR] Failed to install dependencies!
        pause
        exit /b 1
    )
)

REM Run the application
echo [+] Starting DeadNet Attacker with WebView...
echo.
python main_webview.py

REM If script exits, pause to see any errors
if %errorLevel% neq 0 (
    echo.
    echo [ERROR] Application exited with error code: %errorLevel%
    pause
)

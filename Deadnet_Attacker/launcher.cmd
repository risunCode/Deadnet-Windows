@echo off
REM DeadNet Launcher - Auto-elevate to Administrator
REM ================================================

cd /d "%~dp0"

REM Check for admin privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :run
) else (
    goto :elevate
)

:elevate
echo Requesting administrator privileges...
echo.

REM Create temporary VBS script for elevation
set "tempVBS=%temp%\elevate_%random%.vbs"
echo Set UAC = CreateObject^("Shell.Application"^) > "%tempVBS%"
echo UAC.ShellExecute "cmd.exe", "/c ""%~f0""", "", "runas", 1 >> "%tempVBS%"

REM Execute the VBS script
cscript //nologo "%tempVBS%"
del "%tempVBS%"
exit /b

:run
cls
echo ================================================
echo DeadNet Attacker - Network Security Testing
echo ================================================
echo.
echo Based on DeadNet by @flashnuke
echo Windows Port by @risuncode
echo.
echo Running with Administrator privileges...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    echo.
    pause
    exit /b 1
)

REM Check if virtual environment exists
if not exist "venv\" (
    echo Creating virtual environment...
    python -m venv venv
    if %errorLevel% neq 0 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Check if requirements are installed
pip show scapy >nul 2>&1
if %errorLevel% neq 0 (
    echo Installing dependencies...
    echo This may take a few minutes...
    echo.
    pip install -r requirements.txt
    if %errorLevel% neq 0 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
    echo.
    echo Dependencies installed successfully!
    echo.
)

REM Install Npcap if not already installed (required for Scapy on Windows)
echo.
echo ================================================
echo IMPORTANT: Scapy requires Npcap to be installed
echo ================================================
echo.
echo If you haven't installed Npcap yet, please:
echo 1. Download from: https://npcap.com/#download
echo 2. Install with "WinPcap API-compatible Mode" enabled
echo 3. Restart this launcher
echo.
echo Press any key to continue if Npcap is already installed...
pause >nul

cls
echo ================================================
echo DeadNet Attacker - Web Interface
echo ================================================
echo.
echo Original: DeadNet by @flashnuke
echo Windows Port ^& Web UI: @risuncode
echo.
echo Starting web control panel...
echo Open: http://localhost:5000
echo.

REM Start the application
python main.py

REM If Python exits, pause to show any errors
if %errorLevel% neq 0 (
    echo.
    echo ================================================
    echo Application exited with error code: %errorLevel%
    echo ================================================
    echo.
)

echo.
pause

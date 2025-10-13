@echo off
title Deadnet Defender - Network Security Monitor

:: Save current directory
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

:: Check for administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo ====================================================
    echo  ADMINISTRATOR PRIVILEGES REQUIRED
    echo ====================================================
    echo.
    echo This tool requires administrator privileges to
    echo capture network packets.
    echo.
    echo Please right-click this file and select
    echo "Run as administrator"
    echo.
    echo ====================================================
    pause
    exit /b 1
)

:: ASCII Art Banner
echo.
echo ====================================================
echo  ____                _            _   
echo ^|  _ \  ___  __ _  ^| ^|  _ __    ^| ^|_ 
echo ^| ^| ^| ^|^/ _ \^/ _` ^| ^| ^| ^| '_ \   ^| __^|
echo ^| ^|_^| ^|  __/ (_^| ^| ^| ^| ^| ^| ^| ^|  ^| ^|_ 
echo ^|____/ \___^|\__^,_^| ^|_^| ^|_^| ^|_^|   \__^|
echo.
echo           DEFENDER
echo.
echo    Network Security Monitoring Tool
echo ====================================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [+] Python detected
echo.

:: Check if virtual environment exists
if not exist "venv\" (
    echo [*] Creating virtual environment...
    python -m venv venv
    if %errorLevel% neq 0 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
    echo [+] Virtual environment created
    echo.
)

:: Activate virtual environment
echo [*] Activating virtual environment...
if not exist "%SCRIPT_DIR%venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment activation script not found
    echo Looking in: %SCRIPT_DIR%venv\Scripts\
    pause
    exit /b 1
)
call "%SCRIPT_DIR%venv\Scripts\activate.bat"
if %errorLevel% neq 0 (
    echo [ERROR] Failed to activate virtual environment
    pause
    exit /b 1
)
echo [+] Virtual environment activated
echo [*] Current directory: %CD%
echo.

:: Install/update dependencies
echo [*] Installing dependencies...
if not exist "%SCRIPT_DIR%requirements.txt" (
    echo [ERROR] requirements.txt not found
    echo Looking in: %SCRIPT_DIR%
    echo Files in directory:
    dir /b "%SCRIPT_DIR%"
    pause
    exit /b 1
)
pip install -r "%SCRIPT_DIR%requirements.txt" --quiet
if %errorLevel% neq 0 (
    echo [WARNING] Some dependencies may have failed to install
    echo [*] Trying without --quiet flag...
    pip install -r "%SCRIPT_DIR%requirements.txt"
    pause
)
echo [+] Dependencies ready
echo.

:: Check for Npcap
echo [*] Checking for Npcap...
if not exist "C:\Windows\System32\Npcap\" (
    if not exist "C:\Windows\System32\wpcap.dll" (
        echo.
        echo ====================================================
        echo  WARNING: Npcap not detected
        echo ====================================================
        echo.
        echo Npcap is required for packet capture on Windows.
        echo.
        echo Please download and install Npcap from:
        echo https://npcap.com/
        echo.
        echo Make sure to install with "WinPcap API-compatible Mode"
        echo ====================================================
        echo.
        choice /C YN /M "Continue anyway?"
        if errorlevel 2 exit /b 1
    )
) else (
    echo [+] Npcap detected
)
echo.

:: Check if main.py exists
if not exist "%SCRIPT_DIR%main.py" (
    echo [ERROR] main.py not found in script directory
    echo Script directory: %SCRIPT_DIR%
    echo Current directory: %CD%
    echo.
    echo Please make sure all files are in the same folder
    pause
    exit /b 1
)

:: Start the application
echo ====================================================
echo  Starting Deadnet Defender...
echo ====================================================
echo.
echo [+] Web dashboard will be available at:
echo     http://localhost:5001
echo.
echo [*] Press Ctrl+C to stop the defender
echo.

python "%SCRIPT_DIR%main.py"

if %errorLevel% neq 0 (
    echo.
    echo [ERROR] Deadnet Defender exited with error code: %errorLevel%
    echo.
    echo Common issues:
    echo - Missing dependencies (utils folder)
    echo - Port 5001 already in use
    echo - Import errors
    echo.
    pause
)

:: Deactivate virtual environment on exit
call deactivate 2>nul

echo.
echo ====================================================
echo  Deadnet Defender stopped
echo ====================================================
echo.
pause

@echo off
title Deadnet Defender - Network Security Monitor

:: Save current directory
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

:: Check for admin privileges
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

:start_app
:: Start the application
cls
echo ====================================================
echo  Starting Deadnet Defender...
echo ====================================================
echo.
echo  ____                 _            _     ____        __               _           
echo ^|  _ \  ___  __ _  __^| ^| _ __   ___^| ^|_  ^|  _ \  ___ ^/ _^| ___ _ __   __^| ^| ___ _ __ 
echo ^| ^| ^| ^|/ _ \/ _` ^|/ _` ^|^| '_ \ / _ \ __^| ^| ^| ^| ^|/ _ \ ^|_ / _ \ '_ \ / _` ^|/ _ \ '__^|
echo ^| ^|_^| ^|  __/ (_^| ^| (_^| ^|^| ^| ^| ^|  __/ ^|_  ^| ^|_^| ^|  __/  _^|  __/ ^| ^| ^| (_^| ^|  __/ ^|   
echo ^|____/ \___^|\__,_^|\__,_^|^|_^| ^|_^|\___^|\__^| ^|____/ \___^|_^|  \___^|_^| ^|_^|\__,_^|\___^|_^|   
echo.
echo.

start /B cmd /C "python "%SCRIPT_DIR%main.py" 2>&1"
set pid=%errorlevel%

:wait_for_input
choice /C R /N /M "Press R to restart the application"
if %errorlevel% equ 1 (
    echo.
    echo [*] Restarting application...
    taskkill /F /PID %pid% >nul 2>&1
    goto start_app
)
goto wait_for_input

:: Deactivate virtual environment on exit
call deactivate 2>nul

echo.
echo ====================================================
echo  Deadnet Defender stopped
echo ====================================================
echo.
pause

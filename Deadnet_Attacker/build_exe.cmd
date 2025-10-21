@echo off
REM Build script for DeadNet Attacker Executable
REM This script compiles the application into a portable executable

REM Change to the script's directory
cd /d "%~dp0"

echo.
echo ========================================
echo DeadNet Attacker - Build Script
echo ========================================
echo.
echo Current directory: %CD%
echo.

REM Check if running as administrator (warn if admin)
net session >nul 2>&1
if %errorLevel% equ 0 (
    echo [WARNING] Running as administrator!
    echo PyInstaller should NOT be run as admin.
    echo This may cause issues with PyInstaller 7.0+
    echo.
    echo Press Ctrl+C to cancel, or
    pause
)

echo [+] Checking Python installation...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python not found! Please install Python 3.8 or newer.
    pause
    exit /b 1
)

echo [+] Installing/Updating dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements-webview.txt

if %errorLevel% neq 0 (
    echo [ERROR] Failed to install dependencies!
    pause
    exit /b 1
)

echo.
echo [+] Cleaning previous build artifacts...
if exist "build" rmdir /s /q "build" 2>nul
if exist "dist" rmdir /s /q "dist" 2>nul
for /d /r . %%d in (__pycache__) do @if exist "%%d" rmdir /s /q "%%d" 2>nul
del /s /q *.pyc 2>nul

echo [+] Building executable with PyInstaller...
echo [*] This may take several minutes...
echo.

pyinstaller --clean DeadNet.spec

if %errorLevel% neq 0 (
    echo.
    echo [ERROR] Build failed!
    pause
    exit /b 1
)

echo.
echo ========================================
echo [SUCCESS] Build completed!
echo ========================================
echo.
echo The executable is located at:
echo   dist\DeadNet_Attacker.exe
echo.
echo You can now run it as a portable application.
echo Remember: This tool requires administrator privileges!
echo.
pause

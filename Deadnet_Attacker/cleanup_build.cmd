@echo off
REM Cleanup script for DeadNet Attacker build artifacts
REM This removes all build-related temporary files and folders

REM Change to the script's directory
cd /d "%~dp0"

echo.
echo ========================================
echo DeadNet Attacker - Build Cleanup
echo ========================================
echo.
echo This will remove all build artifacts:
echo   - build/ folder
echo   - dist/ folder
echo   - __pycache__/ folders
echo   - *.pyc files
echo   - *.pyo files
echo   - *.spec backup files
echo   - PyInstaller cache
echo.
echo NOTE: venv/ folder will NOT be removed
echo.
echo Current directory: %CD%
echo.

choice /C YN /M "Do you want to proceed with cleanup"
if %errorLevel% neq 1 (
    echo.
    echo [*] Cleanup cancelled.
    pause
    exit /b 0
)

echo.
echo [*] Starting cleanup...
echo.

REM Remove build folder
if exist "build" (
    echo [+] Removing build/ folder...
    rmdir /s /q "build" 2>nul
    if %errorLevel% equ 0 (
        echo [+] build/ removed successfully
    ) else (
        echo [!] Could not remove build/ folder
    )
) else (
    echo [-] build/ folder not found
)

REM Remove dist folder
if exist "dist" (
    echo [+] Removing dist/ folder...
    rmdir /s /q "dist" 2>nul
    if %errorLevel% equ 0 (
        echo [+] dist/ removed successfully
    ) else (
        echo [!] Could not remove dist/ folder
    )
) else (
    echo [-] dist/ folder not found
)

REM Remove __pycache__ folders
echo [+] Removing __pycache__/ folders...
for /d /r . %%d in (__pycache__) do @if exist "%%d" (
    echo [+] Removing: %%d
    rmdir /s /q "%%d" 2>nul
)

REM Remove .pyc files
echo [+] Removing .pyc files...
del /s /q *.pyc 2>nul
if %errorLevel% equ 0 (
    echo [+] .pyc files removed
)

REM Remove .pyo files
echo [+] Removing .pyo files...
del /s /q *.pyo 2>nul
if %errorLevel% equ 0 (
    echo [+] .pyo files removed
)

REM Remove .spec backup files (but keep DeadNet.spec!)
echo [+] Removing .spec backup files...
if exist "*.spec.bak" (
    del /q *.spec.bak 2>nul
    echo [+] .spec backup files removed
) else (
    echo [-] No .spec backup files found
)

REM Remove PyInstaller cache
if exist "%LOCALAPPDATA%\pyinstaller" (
    echo [+] Removing PyInstaller cache...
    rmdir /s /q "%LOCALAPPDATA%\pyinstaller" 2>nul
    if %errorLevel% equ 0 (
        echo [+] PyInstaller cache removed
    )
)

echo.
echo ========================================
echo [SUCCESS] Cleanup completed!
echo ========================================
echo.
echo Build artifacts have been removed.
echo Your venv/ folder remains intact.
echo You can now run build_exe.cmd for a fresh build.
echo.
pause

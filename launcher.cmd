@echo off
title DeadNet - Network Security Tool
cd /d "%~dp0"

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Set venv paths
set VENV_DIR=.venv
set VENV_PYTHON=%VENV_DIR%\Scripts\python.exe
set VENV_PYTHONW=%VENV_DIR%\Scripts\pythonw.exe
set VENV_PIP=%VENV_DIR%\Scripts\pip.exe

:menu
cls
echo.
echo  ========================================
echo    DeadNet - Network Security Tool
echo  ========================================
echo.
echo    [1] Run (WebView)
echo    [2] Run (WebView, Hide Terminal)
echo    [3] Run (Browser)
echo    [4] Build Executable
echo    [5] Install Dependencies
echo    [6] Clean Build Files
echo    [7] Exit
echo.
set /p choice="  Select: "

if "%choice%"=="1" goto webview_show
if "%choice%"=="2" goto webview_hide
if "%choice%"=="3" goto browser
if "%choice%"=="4" goto build
if "%choice%"=="5" goto install
if "%choice%"=="6" goto clean
if "%choice%"=="7" exit /b
goto menu

:check_venv
if not exist "%VENV_PYTHON%" (
    echo.
    echo  [!] Virtual environment not found!
    echo  [!] Please run option [5] Install Dependencies first.
    pause
    goto menu
)
goto :eof

:check_dist
if not exist "dist\index.html" (
    echo.
    echo  [!] Building web assets...
    call npm install >nul 2>&1
    call npm run build
    if not exist "dist\index.html" (
        echo  [!] Build failed!
        pause
        goto menu
    )
)
goto :eof

:webview_show
call :check_venv
call :check_dist
echo.
echo  [+] Starting WebView...
"%VENV_PYTHON%" main.py --webview
pause
goto menu

:webview_hide
call :check_venv
call :check_dist
echo.
echo  [+] Starting WebView (hiding terminal)...
start "" /B "%VENV_PYTHONW%" main.py --webview
timeout /t 2 /nobreak >nul
exit

:browser
call :check_venv
call :check_dist
echo.
echo  [+] Starting Browser mode...
echo  [*] Opening http://localhost:5000
"%VENV_PYTHON%" main.py --browser
pause
goto menu

:install
echo.
echo  [+] Setting up virtual environment...

:: Create venv if not exists
if not exist "%VENV_DIR%" (
    echo  [*] Creating virtual environment...
    python -m venv %VENV_DIR%
)

:: Upgrade pip
echo  [*] Upgrading pip...
"%VENV_PYTHON%" -m pip install --upgrade pip >nul 2>&1

:: Install Python dependencies
echo  [*] Installing Python dependencies...
"%VENV_PIP%" install -r requirements.txt

:: Install Node dependencies
echo  [*] Installing Node dependencies...
call npm install

:: Build web assets
echo  [*] Building web assets...
call npm run build

echo.
echo  [+] Done! Virtual environment ready at: %VENV_DIR%
pause
goto menu

:build
echo.
echo  ========================================
echo    Building Executable
echo  ========================================
echo.

call :check_venv
call :check_dist

echo  [1/2] Checking dependencies...
"%VENV_PIP%" install -r requirements.txt >nul 2>&1

echo  [2/2] Building with PyInstaller...
echo.

"%VENV_PYTHON%" -m PyInstaller --noconfirm --onefile --windowed ^
    --name "DeadNet" ^
    --add-data "dist;dist" ^
    --add-data "backend;backend" ^
    --hidden-import "netifaces" ^
    --hidden-import "scapy.all" ^
    --hidden-import "scapy.layers.l2" ^
    --hidden-import "scapy.layers.inet" ^
    --hidden-import "scapy.layers.inet6" ^
    --hidden-import "flask" ^
    --hidden-import "flask_cors" ^
    --hidden-import "webview" ^
    --hidden-import "webview.platforms.winforms" ^
    --exclude-module "tkinter" ^
    --exclude-module "scapy.contrib" ^
    --exclude-module "scapy.tools" ^
    --exclude-module "scapy.modules" ^
    --exclude-module "matplotlib" ^
    --exclude-module "numpy" ^
    --exclude-module "pandas" ^
    --exclude-module "scipy" ^
    --exclude-module "cryptography" ^
    --uac-admin ^
    main.py

:: Cleanup build artifacts
if exist "build" rmdir /s /q build >nul 2>&1
if exist "DeadNet.spec" del DeadNet.spec >nul 2>&1

echo.
if exist "dist\DeadNet.exe" (
    echo  [+] Success: dist\DeadNet.exe
    echo  [*] Size: 
    for %%A in (dist\DeadNet.exe) do echo     %%~zA bytes
) else (
    echo  [!] Build failed
)
echo.
pause
goto menu

:clean
echo.
echo  [+] Cleaning build files...
if exist "build" rmdir /s /q build
if exist "DeadNet.spec" del DeadNet.spec
if exist "dist\DeadNet.exe" del dist\DeadNet.exe
if exist "__pycache__" rmdir /s /q __pycache__
if exist "backend\__pycache__" rmdir /s /q backend\__pycache__
if exist "deadnet.log" del deadnet.log
echo  [+] Done!
pause
goto menu

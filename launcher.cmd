@echo off
setlocal

pushd "%~dp0" >nul 2>&1
if errorlevel 1 (
  echo Error: Unable to set working directory to script location.
  exit /b 1
)

set "PYTHON_EXE=.venv\Scripts\python.exe"
if exist "%PYTHON_EXE%" goto run

set "PYTHON_EXE=python"
where python >nul 2>&1
if errorlevel 1 (
  echo Error: Python not found. Install Python or create .venv\Scripts\python.exe.
  popd
  exit /b 1
)

:run
"%PYTHON_EXE%" -m app --browser %*
set "EXIT_CODE=%ERRORLEVEL%"
popd
exit /b %EXIT_CODE%

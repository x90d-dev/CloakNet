@echo off
cd /d "%~dp0"
title CloakNet - Automated Layer-2 Identity Obfuscation [github.com/x90d/CloakNet]

echo ===============================================================================
echo   CLOAKNET v1.4.0 - ENVIRONMENT CHECK ^& LAUNCHER
echo   Automated Layer-2 Identity Obfuscation ^& Local Traffic Randomizer
echo   Repository: https://github.com/x90d/CloakNet
echo ===============================================================================
echo.

:: 1. Detect working Python 3.9+ command (supports standard 'python' and Windows 'py -3' launcher)
set "SYS_PY="

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul
if not errorlevel 1 (
    set "SYS_PY=python"
)

if "%SYS_PY%"=="" (
    py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul
    if not errorlevel 1 (
        set "SYS_PY=py -3"
    )
)

if "%SYS_PY%"=="" (
    echo [ERROR] Python 3.9+ was not found on this system.
    echo         Please install Python 3.9 or newer from https://www.python.org/downloads/
    echo         and check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [OK]    Detected compatible Python runtime via: %SYS_PY%

:: 2. Create isolated virtual environment (.venv) if not present
if not exist ".venv\Scripts\python.exe" (
    echo [SETUP] Creating isolated Python virtual environment in .venv ...
    %SYS_PY% -m venv .venv
    if errorlevel 1 (
        echo [WARN]  Could not create .venv. Falling back to system Python runtime.
        set "RUN_PY=%SYS_PY%"
        set "RUN_PIP=%SYS_PY% -m pip"
        goto :CHECK_DEPS
    )
)

set "RUN_PY=".venv\Scripts\python.exe""
set "RUN_PIP=".venv\Scripts\python.exe" -m pip"

:CHECK_DEPS
:: 3. Check if dependencies (rich, psutil) are installed; install automatically if missing
%RUN_PY% -c "import rich, psutil" >nul 2>nul
if errorlevel 1 (
    echo [SETUP] Installing required dependencies from requirements.txt ...
    %RUN_PIP% install --upgrade pip
    %RUN_PIP% install -r requirements.txt
    if errorlevel 1 (
        echo.
        echo [ERROR] Failed to install packages from requirements.txt.
        echo         Please verify your internet connection and run this script again.
        echo.
        pause
        exit /b 1
    )
    echo [OK]    Dependencies installed successfully.
    echo.
)

:: 4. Launch CloakNet interactive console (or forward CLI arguments if provided)
echo [START] Launching CloakNet...
echo.
if "%~1"=="" (
    %RUN_PY% cloaknet.py --interactive
) else (
    %RUN_PY% cloaknet.py %*
)

echo.
echo ===============================================================================
echo   CloakNet session finished. Press any key to close this window...
echo ===============================================================================
pause >nul
exit /b 0

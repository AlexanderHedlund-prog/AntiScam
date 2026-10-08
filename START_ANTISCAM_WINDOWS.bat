@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title AntiScam - local server

echo ========================================
echo AntiScam - first run on Windows
echo ========================================
echo.

if exist ".venv\Scripts\python.exe" goto install_packages

where py >nul 2>&1
if not errorlevel 1 (
    py -3 -m venv .venv
) else (
    python -m venv .venv
)
if errorlevel 1 (
    echo.
    echo ERROR: Python 3.11 or newer is required.
    echo Install Python from https://www.python.org/downloads/windows/
    echo Reopen this file after installation.
    pause
    exit /b 1
)

:install_packages
echo Installing / checking dependencies...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Cannot install dependencies. Check your internet connection.
    pause
    exit /b 1
)

echo.
echo ========================================
echo AntiScam is starting.
echo Open http://127.0.0.1:8000 in your browser.
echo Keep this window open while using the site.
echo To stop the site, press Ctrl+C.
echo ========================================
echo.
".venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
pause

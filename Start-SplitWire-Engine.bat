@echo off
chcp 65001 >nul
title SplitWire Browser - DPI Motoru
cd /d "%~dp0"

where node >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] Node.js bulunamadi!
    echo Lutfen https://nodejs.org adresinden Node.js LTS surumunu kurun.
    pause
    exit /b 1
)

node engine\server.js
pause

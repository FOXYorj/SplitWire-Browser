@echo off
chcp 65001 >nul
echo SplitWire Browser DPI Motoru durduruluyor...
powershell -NoProfile -Command "try { Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8081/shutdown' -TimeoutSec 2 | Out-Null; Write-Host 'Motor basariyla durduruldu.' -ForegroundColor Green } catch { Write-Host 'Calisan bir SplitWire motoru bulunamadi.' -ForegroundColor Yellow }"
timeout /t 2 >nul

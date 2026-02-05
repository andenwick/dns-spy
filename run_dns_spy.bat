@echo off
cd /d "%~dp0"
echo.
echo ============================================
echo   DNS Spy - Red Team Edition v2.0
echo ============================================
echo.
echo Right-click this file and "Run as Administrator"
echo if you didn't already.
echo.
echo Press Ctrl+C to stop and view statistics.
echo.
dns_spy.exe %*
pause

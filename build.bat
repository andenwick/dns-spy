@echo off
setlocal

set PATH=%W64DEVKIT%\bin;%PATH%
set SDK=%NPCAP_SDK%

echo Building DNS Spy - Red Team Edition...

gcc -o dns_spy.exe dns_spy.c -I"%SDK%\Include" -L"%SDK%\Lib\x64" -lwpcap -lws2_32 -lm

if %ERRORLEVEL% == 0 (
    echo.
    echo Build successful!
    echo.
    echo To run: Right-click run_dns_spy.bat and "Run as Administrator"
) else (
    echo Build failed.
)

endlocal

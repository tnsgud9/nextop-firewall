@echo off
echo Disabling proxy...

REM 프록시 비활성화
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" ^
    /v ProxyEnable /t REG_DWORD /d 0 /f

echo Proxy disabled.

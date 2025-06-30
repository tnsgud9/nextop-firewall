@echo off
setlocal enabledelayedexpansion

REM .env 파일 경로 (배치 파일과 동일 경로에 있다고 가정)
set ENV_FILE=.env

REM 기본값 설정
set "PROXY_IP=127.0.0.1"
set "PROXY_PORT=8080"

REM .env 파일이 있으면 PROXY_IP와 PROXY_PORT 읽기
if exist %ENV_FILE% (
    for /f "usebackq tokens=1,* delims==" %%A in (`findstr /b "PROXY_IP=" %ENV_FILE%`) do (
        set "value=%%B"
        set "value=!value:"=!"
        if defined value (
            set "PROXY_IP=!value!"
        )
    )
    for /f "usebackq tokens=1,* delims==" %%A in (`findstr /b "PROXY_PORT=" %ENV_FILE%`) do (
        set "value=%%B"
        set "value=!value:"=!"
        if defined value (
            set "PROXY_PORT=!value!"
        )
    )
) else (
    echo %ENV_FILE% not found. Using default proxy IP and port: %PROXY_IP%:%PROXY_PORT%
)

REM PROXY_IP와 PROXY_PORT 합쳐서 PROXY_SERVER 생성
set "PROXY_SERVER=%PROXY_IP%:%PROXY_PORT%"

echo Setting proxy to %PROXY_SERVER%...

REM 현재 사용자에 대해 프록시 설정
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" ^
    /v ProxyEnable /t REG_DWORD /d 1 /f

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" ^
    /v ProxyServer /t REG_SZ /d %PROXY_SERVER% /f

echo Proxy set to %PROXY_SERVER%

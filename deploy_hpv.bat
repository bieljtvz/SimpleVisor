@echo off
REM Compila o SimpleVisor e envia o shv.sys pra C:\Users\admin\Desktop\hpv
REM na maquina 192.168.0.107, sem mexer no servico (inicio e manual).
REM
REM Uso:
REM   deploy_hpv.bat            -> compila e envia
REM   deploy_hpv.bat -NoBuild   -> so envia o .sys ja compilado (nao recompila)

setlocal
set SCRIPT_DIR=%~dp0

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%deploy_hpv.ps1" %*

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [FALHOU] codigo de saida %ERRORLEVEL%
    ping -n 11 127.0.0.1 >nul
    exit /b %ERRORLEVEL%
)

echo.
echo Janela fecha em alguns segundos... (feche antes se quiser ler com calma)
ping -n 6 127.0.0.1 >nul

@echo off
REM Compila o usermode_teste e envia o usermode.exe pra C:\Users\admin\Desktop\hpv
REM na maquina 192.168.0.107 -- mesma pasta usada por deploy_hpv.bat.
REM
REM Uso:
REM   deploy_usermode.bat            -> compila e envia
REM   deploy_usermode.bat -NoBuild   -> so envia o .exe ja compilado (nao recompila)

setlocal
set SCRIPT_DIR=%~dp0

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%deploy_gui.ps1" %*

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [FALHOU] codigo de saida %ERRORLEVEL%
    ping -n 11 127.0.0.1 >nul
    exit /b %ERRORLEVEL%
)

echo.
echo Janela fecha em alguns segundos... (feche antes se quiser ler com calma)
ping -n 6 127.0.0.1 >nul

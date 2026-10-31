@echo off
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERRO: Execute como Administrador.
    pause
    exit /b 1
)

echo.
echo === Lendo estado atual (bcdedit) ===
echo.
bcdedit /enum "{current}"
echo.
echo ====================================
echo.

set DEBUG_ON=0
set TESTSIGN_ON=0
set NOINTEG_ON=0

for /f "tokens=1,2" %%A in ('bcdedit /enum "{current}"') do (
    if /i "%%A"=="debug"              if /i "%%B"=="Yes" set DEBUG_ON=1
    if /i "%%A"=="testsigning"        if /i "%%B"=="Yes" set TESTSIGN_ON=1
    if /i "%%A"=="nointegritychecks"  if /i "%%B"=="Yes" set NOINTEG_ON=1
)

echo   DEBUG_ON=%DEBUG_ON%
echo   TESTSIGN_ON=%TESTSIGN_ON%
echo   NOINTEG_ON=%NOINTEG_ON%
echo.

set TARGET=%~1

if not "%TARGET%"=="" goto :aplicar

:: Sem argumento: detecta e inverte
set /a QUALQUER=%DEBUG_ON% + %TESTSIGN_ON% + %NOINTEG_ON%
if %QUALQUER% GTR 0 (
    set TARGET=off
    echo Inferindo: desativar tudo.
) else (
    set TARGET=on
    echo Inferindo: ativar tudo.
)
echo.

:aplicar
if /i "%TARGET%"=="on"  goto :ativar
if /i "%TARGET%"=="off" goto :desativar

echo Argumento invalido. Use: toggle_devmode.bat [on^|off]
pause
exit /b 1

:ativar
echo ^>^>^> Ativando modo desenvolvimento...
echo.

echo [1] bcdedit /debug on
bcdedit /debug on
echo     Errorlevel: %errorlevel%
echo.

echo [2] bcdedit /set testsigning on
bcdedit /set testsigning on
echo     Errorlevel: %errorlevel%
echo.

echo [3] bcdedit /set nointegritychecks yes
bcdedit /set nointegritychecks yes
echo     Errorlevel: %errorlevel%
echo.

echo AVISO: Driver Signature Enforcement desativado.
echo        Reinicie para aplicar.
goto :reiniciar

:desativar
echo ^>^>^> Restaurando modo normal...
echo.

echo [1] bcdedit /debug off
bcdedit /debug off
echo     Errorlevel: %errorlevel%
echo.

echo [2] bcdedit /set testsigning off
bcdedit /set testsigning off
echo     Errorlevel: %errorlevel%
echo.

echo [3] bcdedit /set nointegritychecks no
bcdedit /set nointegritychecks no
echo     Errorlevel: %errorlevel%
echo.

echo Driver Signature Enforcement ativo novamente.
echo Reinicie para aplicar.

:reiniciar
echo.
set /p RESP=Reiniciar agora? (s/N):
if /i "%RESP%"=="s" shutdown /r /t 0
echo.
echo Fechando em 30 segundos...
timeout /t 30
exit /b 0

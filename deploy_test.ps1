#
# deploy_test.ps1 - Compila e faz deploy do SimpleVisor na maquina de teste
#
# Uso: .\deploy_test.ps1
# Requer: Visual Studio com MSBuild no PATH, maquina de teste com WinRM ativo
#

param(
    [string]$TargetIP   = "192.168.0.102",
    [string]$TargetUser = "admin",
    [string]$DriverName = "hpv",
    [string]$SysPath    = "$PSScriptRoot\x64\Release\shv.sys"
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# 1. Compilar com MSBuild (Release|x64)
# ---------------------------------------------------------------------------
Write-Host "[1/4] Compilando SimpleVisor (Release x64)..." -ForegroundColor Cyan

$msbuild = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
    -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe 2>$null |
    Select-Object -First 1

if (-not $msbuild) {
    # Fallback: procura MSBuild no PATH
    $msbuild = (Get-Command msbuild -ErrorAction SilentlyContinue).Source
}

if (-not $msbuild) {
    Write-Error "MSBuild nao encontrado. Abra o 'Developer PowerShell for VS' e tente novamente."
}

& $msbuild "$PSScriptRoot\shv.sln" /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
if ($LASTEXITCODE -ne 0) { Write-Error "Compilacao falhou (codigo $LASTEXITCODE)" }

Write-Host "   OK: $SysPath" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 2. Conectar na maquina de teste via WinRM
# ---------------------------------------------------------------------------
Write-Host "[2/4] Conectando em $TargetIP como $TargetUser..." -ForegroundColor Cyan

$cred = New-Object System.Management.Automation.PSCredential(
    $TargetUser,
    (ConvertTo-SecureString "@123" -AsPlainText -Force)
)

$session = New-PSSession -ComputerName $TargetIP -Credential $cred
Write-Host "   Sessao aberta." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Parar driver antigo e copiar o novo
# ---------------------------------------------------------------------------
Write-Host "[3/4] Copiando shv.sys para a maquina de teste..." -ForegroundColor Cyan

# Para o driver se estiver rodando (ignora erro se ja estiver parado)
Invoke-Command -Session $session {
    $result = & sc.exe stop hpv 2>&1
    Write-Host "   sc stop hpv: $result"
}

Start-Sleep -Seconds 2   # aguarda o driver descarregar completamente

Copy-Item $SysPath -Destination "C:\Windows\System32\drivers\shv.sys" -ToSession $session -Force
Write-Host "   Copiado OK." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 4. Iniciar o driver e verificar
# ---------------------------------------------------------------------------
Write-Host "[4/4] Iniciando driver e verificando contadores..." -ForegroundColor Cyan

Invoke-Command -Session $session {
    $result = & sc.exe start hpv 2>&1
    Write-Host "   sc start hpv: $result"
}

Start-Sleep -Seconds 3   # aguarda inicializacao

# Le os contadores do driver via WinDbg (opcional, requer WinDbg na maquina host)
# Para verificar manualmente no WinDbg do host:
#   dq shv!ShvSyscallCount
#   dq shv!ShvLastSyscallNumber
#   dq shv!ShvOriginalLstar
#   dq shv!ShvExitCount

# Verificacao rapida: checa se o servico esta RUNNING
$status = Invoke-Command -Session $session {
    (Get-Service -Name hpv -ErrorAction SilentlyContinue).Status
}

if ($status -eq "Running") {
    Write-Host ""
    Write-Host "Driver iniciado com sucesso!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Para verificar o hook no WinDbg (maquina host):" -ForegroundColor Yellow
    Write-Host "  dq shv!ShvSyscallCount       <- deve incrementar rapidamente"
    Write-Host "  dq shv!ShvLastSyscallNumber  <- numero da ultima syscall interceptada"
    Write-Host "  dq shv!ShvOriginalLstar       <- deve apontar para nt!KiSystemCall64"
    Write-Host "  dq shv!ShvExitCount           <- total de VM-exits desde o load"
} else {
    Write-Warning "Driver nao esta RUNNING (status: $status). Verifique o WinDbg para erros."
}

Remove-PSSession $session

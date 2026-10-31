#
# deploy_usermode.ps1 - Compila o usermode_teste e envia o .exe pra pasta
# de upload na maquina remota (mesma pasta usada por deploy_hpv.ps1).
#
# Uso:
#   .\deploy_usermode.ps1                 # compila e envia
#   .\deploy_usermode.ps1 -NoBuild        # so envia o .exe ja existente (nao recompila)
#
# Chamado tambem por deploy_usermode.bat (duplo-clique).
#

param(
    [string]$TargetIP     = "192.168.0.102",
    [string]$TargetUser   = "admin",
    [string]$TargetPass   = "@123",
    [string]$RemoteFolder = "C:\Users\admin\Desktop\hpv",
    [string]$SlnPath      = "$PSScriptRoot\usermode_gui\usermode_gui\usermode_gui.slnx",
    [string]$ExePath      = "$PSScriptRoot\usermode_gui\usermode_gui\x64\Release\usermode_gui.exe",
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# 1. Compilar (Release|x64) -- pula se -NoBuild
# ---------------------------------------------------------------------------
if (-not $NoBuild) {
    Write-Host "[1/3] Compilando usermode (Release|x64)..." -ForegroundColor Cyan

    $msbuild = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
        -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe 2>$null |
        Select-Object -First 1

    if (-not $msbuild) {
        $msbuild = (Get-Command msbuild -ErrorAction SilentlyContinue).Source
    }
    if (-not $msbuild) {
        Write-Error "MSBuild nao encontrado. Abra o 'Developer PowerShell for VS' e tente novamente, ou use -NoBuild pra so enviar o .exe ja compilado."
    }

    & $msbuild $SlnPath /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
    if ($LASTEXITCODE -ne 0) { Write-Error "Compilacao falhou (codigo $LASTEXITCODE)" }

    Write-Host "   OK: $ExePath" -ForegroundColor Green
} else {
    Write-Host "[1/3] -NoBuild: usando $ExePath como esta." -ForegroundColor Yellow
}

if (-not (Test-Path $ExePath)) {
    Write-Error "Nao achei $ExePath. Compile primeiro (sem -NoBuild) ou confira o caminho."
}

# ---------------------------------------------------------------------------
# 2. Conectar na maquina remota via WinRM
# ---------------------------------------------------------------------------
Write-Host "[2/3] Conectando em $TargetIP como $TargetUser..." -ForegroundColor Cyan

$cred = New-Object System.Management.Automation.PSCredential(
    $TargetUser,
    (ConvertTo-SecureString $TargetPass -AsPlainText -Force)
)

try {
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $TargetIP -Force -ErrorAction Stop
} catch {
    Write-Host "   (Aviso: nao consegui atualizar TrustedHosts -- ok se $TargetIP ja estiver la.)" -ForegroundColor DarkYellow
}

$session = New-PSSession -ComputerName $TargetIP -Credential $cred
Write-Host "   Sessao aberta." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Copiar o .exe pra pasta de upload (mesma pasta do shv.sys)
# ---------------------------------------------------------------------------
Write-Host "[3/3] Enviando usermode.exe para $RemoteFolder ..." -ForegroundColor Cyan

Invoke-Command -Session $session -ArgumentList $RemoteFolder {
    param($folder)
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
}

$destino = Join-Path $RemoteFolder "usermode.exe"
Copy-Item $ExePath -Destination $destino -ToSession $session -Force

$remoteInfo = Invoke-Command -Session $session -ArgumentList $destino {
    param($path)
    Get-Item $path | Select-Object Name, Length, LastWriteTime
}

Remove-PSSession $session

Write-Host ""
Write-Host "Enviado com sucesso:" -ForegroundColor Green
$remoteInfo | Format-List

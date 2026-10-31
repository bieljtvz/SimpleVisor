#
# deploy_hpv.ps1 - Compila o SimpleVisor e envia o .sys pra pasta de upload
# na maquina remota, SEM instalar/iniciar o servico (isso fica manual).
#
# Uso:
#   .\deploy_hpv.ps1                 # compila e envia
#   .\deploy_hpv.ps1 -NoBuild        # so envia o .sys ja existente (nao recompila)
#
# Chamado tambem por deploy_hpv.bat (duplo-clique).
#

param(
    [string]$TargetIP     = "192.168.0.102",
    [string]$TargetUser   = "admin",
    [string]$TargetPass   = "@123",
    [string]$RemoteFolder = "C:\Users\admin\Desktop\hpv",
    [string]$SysPath      = "$PSScriptRoot\x64\NT\shv.sys",
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# 1. Compilar (Windows NT|x64) -- pula se -NoBuild
# ---------------------------------------------------------------------------
if (-not $NoBuild) {
    Write-Host "[1/3] Compilando SimpleVisor (Windows NT|x64)..." -ForegroundColor Cyan

    $msbuild = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
        -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe 2>$null |
        Select-Object -First 1

    if (-not $msbuild) {
        $msbuild = (Get-Command msbuild -ErrorAction SilentlyContinue).Source
    }
    if (-not $msbuild) {
        Write-Error "MSBuild nao encontrado. Abra o 'Developer PowerShell for VS' e tente novamente, ou use -NoBuild pra so enviar o .sys ja compilado."
    }

    & $msbuild "$PSScriptRoot\shv.sln" "/p:Configuration=Windows NT" /p:Platform=x64 /v:minimal /nologo
    if ($LASTEXITCODE -ne 0) { Write-Error "Compilacao falhou (codigo $LASTEXITCODE)" }

    Write-Host "   OK: $SysPath" -ForegroundColor Green
} else {
    Write-Host "[1/3] -NoBuild: usando $SysPath como esta." -ForegroundColor Yellow
}

if (-not (Test-Path $SysPath)) {
    Write-Error "Nao achei $SysPath. Compile primeiro (sem -NoBuild) ou confira o caminho."
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
# 3. Copiar o .sys pra pasta de upload (NAO mexe em servico nenhum)
# ---------------------------------------------------------------------------
Write-Host "[3/3] Enviando shv.sys para $RemoteFolder ..." -ForegroundColor Cyan

Invoke-Command -Session $session -ArgumentList $RemoteFolder {
    param($folder)
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
}

$destino = Join-Path $RemoteFolder "shv.sys"
Copy-Item $SysPath -Destination $destino -ToSession $session -Force

$remoteInfo = Invoke-Command -Session $session -ArgumentList $destino {
    param($path)
    Get-Item $path | Select-Object Name, Length, LastWriteTime
}

Remove-PSSession $session

Write-Host ""
Write-Host "Enviado com sucesso:" -ForegroundColor Green
$remoteInfo | Format-List
Write-Host "Servico NAO foi tocado -- inicie manualmente quando quiser." -ForegroundColor Yellow

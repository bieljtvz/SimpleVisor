#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Ativa ou desativa Debug Mode, Driver Signature Enforcement e Test Signing juntos.
.USAGE
    .\toggle_devmode.ps1          # detecta estado atual e inverte
    .\toggle_devmode.ps1 on       # ativa tudo (modo dev)
    .\toggle_devmode.ps1 off      # desativa tudo (modo normal)
#>

param(
    [ValidateSet("on","off","")]
    [string]$Mode = ""
)

function Get-BcdValue([string]$Key) {
    $out = bcdedit /enum "{current}" 2>$null | Where-Object { $_ -match "^\s*$Key\s+(.+)$" }
    if ($out -match "^\s*$Key\s+(.+)$") { return $Matches[1].Trim() }
    return $null
}

# --- Estado atual ---
$debugVal      = Get-BcdValue "debug"
$testSignVal   = Get-BcdValue "testsigning"
$noIntegVal    = Get-BcdValue "nointegritychecks"

$debugOn    = $debugVal    -eq "Yes"
$testSignOn = $testSignVal -eq "Yes"
$noIntegOn  = $noIntegVal  -eq "Yes"

Write-Host ""
Write-Host "=== Estado atual ===" -ForegroundColor Cyan
Write-Host ("  Debug mode           : {0}" -f $(if ($debugOn)    { "ON" } else { "off" })) -ForegroundColor $(if ($debugOn)    { "Green" } else { "Gray" })
Write-Host ("  Test signing         : {0}" -f $(if ($testSignOn) { "ON" } else { "off" })) -ForegroundColor $(if ($testSignOn) { "Green" } else { "Gray" })
Write-Host ("  No integrity checks  : {0}" -f $(if ($noIntegOn)  { "ON" } else { "off" })) -ForegroundColor $(if ($noIntegOn)  { "Green" } else { "Gray" })
Write-Host ""

# --- Determina alvo ---
if ($Mode -eq "") {
    # Inverte: se qualquer coisa estiver ON, desliga tudo; senao liga tudo
    $target = if ($debugOn -or $testSignOn -or $noIntegOn) { "off" } else { "on" }
    Write-Host "Modo nao especificado — inferindo '$target' pelo estado atual." -ForegroundColor Yellow
} else {
    $target = $Mode
}

# --- Aplica ---
Write-Host ""
if ($target -eq "on") {
    Write-Host ">>> Ativando modo desenvolvimento..." -ForegroundColor Yellow

    bcdedit /debug on             | Out-Null
    bcdedit /set testsigning on   | Out-Null
    bcdedit /set nointegritychecks yes | Out-Null

    Write-Host "  [OK] debug mode           = ON" -ForegroundColor Green
    Write-Host "  [OK] test signing         = ON" -ForegroundColor Green
    Write-Host "  [OK] no integrity checks  = ON" -ForegroundColor Green
    Write-Host ""
    Write-Host "AVISO: Driver Signature Enforcement desativado." -ForegroundColor Red
    Write-Host "       Reinicie para aplicar." -ForegroundColor Yellow
} else {
    Write-Host ">>> Restaurando modo normal..." -ForegroundColor Cyan

    bcdedit /debug off            | Out-Null
    bcdedit /set testsigning off  | Out-Null
    bcdedit /set nointegritychecks no | Out-Null

    Write-Host "  [OK] debug mode           = off" -ForegroundColor Gray
    Write-Host "  [OK] test signing         = off" -ForegroundColor Gray
    Write-Host "  [OK] no integrity checks  = off" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Driver Signature Enforcement ativo novamente." -ForegroundColor Green
    Write-Host "Reinicie para aplicar." -ForegroundColor Yellow
}

Write-Host ""
$r = Read-Host "Reiniciar agora? (s/N)"
if ($r -match "^[sS]$") { Restart-Computer -Force }

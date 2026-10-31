# Depuração de Kernel via KDNET — SimpleVisor

Guia do setup atual: máquina de desenvolvimento (WinDbg) → máquina de teste (192.168.0.107) via rede Ethernet.

---

## Visão geral

```
[Dev machine]  WinDbg  ←—— TCP/IP ——→  [Test machine 192.168.0.107]
                                         Windows 10 x64
                                         testsigning ativo
                                         shv.sys carregado
```

---

## Configuração única (já feita na máquina de teste)

Estes comandos só precisam ser executados uma vez. Registrados aqui para o caso de reinstalação do Windows.

### 1. Habilitar modo de teste (aceitar drivers não assinados)

```cmd
bcdedit /set testsigning on
```

Reiniciar. Uma marca d'água "Test Mode" aparece no canto da área de trabalho.

### 2. Habilitar debug de kernel via rede (KDNET)

```cmd
bcdedit /dbgsettings net hostip:192.168.0.XXX port:50000 key:1.2.3.4
bcdedit /debug on
```

> Substituir `192.168.0.XXX` pelo IP atual da **máquina de desenvolvimento**.  
> A `key` pode ser qualquer string no formato `a.b.c.d` — use a mesma no WinDbg.

### 3. Registrar o serviço do driver

```cmd
sc create hpv type= kernel start= demand binPath= C:\Windows\System32\drivers\shv.sys
```

### 4. Habilitar WinRM (para deploy remoto via PowerShell)

```powershell
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
```

### 5. Abrir porta 50000 no Firewall

```cmd
netsh advfirewall firewall add rule name="KDNET" dir=in action=allow protocol=TCP localport=50000
```

---

## Verificar conexão de debug na máquina de teste

Execute estes comandos **na máquina de teste** (via WinRM ou diretamente) para confirmar que o kernel debugging está configurado e ativo.

### Verificar configuração KDNET

```cmd
bcdedit /dbgsettings
```

Saída esperada:
```
debugtype               NET
hostip                  192.168.0.XXX   ← IP da máquina de desenvolvimento
port                    50000
key                     1.2.3.4
dhcp                    Yes
```

### Verificar se o boot está com debug ativo

```cmd
bcdedit /enum {current} | findstr /i "debug"
```

Saída esperada:
```
debug                   Yes
```

### Verificar em tempo real se o WinDbg está conectado

Lê o byte `KdDebuggerEnabled` de `KUSER_SHARED_DATA` (0x7FFE02D4) — disponível para qualquer processo sem privilégios:

```powershell
$kd = [System.Runtime.InteropServices.Marshal]::ReadByte([IntPtr]::new(0x7FFE02D4))
if ($kd -ne 0) { Write-Host "Kernel debugger CONECTADO (0x$($kd.ToString('X2')))" -ForegroundColor Green }
else            { Write-Host "Kernel debugger NAO conectado" -ForegroundColor Red }
```

| Valor retornado | Significado |
|---|---|
| `0x03` | Debug ativo **e** WinDbg conectado |
| `0x01` | Debug ativo mas WinDbg ainda não conectou (aguardando) |
| `0x00` | Debug desabilitado no boot |

### Verificar tudo de uma vez (via WinRM da máquina de dev)

```powershell
$cred = New-Object System.Management.Automation.PSCredential(
    "admin", (ConvertTo-SecureString "@123" -AsPlainText -Force))
$s = New-PSSession -ComputerName 192.168.0.107 -Credential $cred

Invoke-Command -Session $s {
    Write-Host "`n=== Configuração KDNET ===" -ForegroundColor Cyan
    bcdedit /dbgsettings

    Write-Host "`n=== Debug no boot atual ===" -ForegroundColor Cyan
    bcdedit /enum '{current}' | Select-String -Pattern 'debug'

    Write-Host "`n=== Debugger conectado agora? ===" -ForegroundColor Cyan
    $kd = [System.Runtime.InteropServices.Marshal]::ReadByte([IntPtr]::new(0x7FFE02D4))
    if ($kd -ne 0) { Write-Host "CONECTADO (KdDebuggerEnabled=0x$($kd.ToString('X2')))" -ForegroundColor Green }
    else            { Write-Host "NAO conectado" -ForegroundColor Red }
}
Remove-PSSession $s
```

---

## Conectar o WinDbg (cada sessão de debug)

### Na máquina de desenvolvimento — abrir WinDbg como administrador

**Opção A — linha de comando:**

```cmd
windbg -k net:port=50000,key=1.2.3.4
```

**Opção B — menu WinDbg:**

```
File → Attach to kernel → Net
  Port : 50000
  Key  : 1.2.3.4
```

### Aguardar conexão

O WinDbg fica exibindo:

```
Waiting for connection on port 50000
```

**Reinicie a máquina de teste.** Durante o boot, o Windows carrega o agente KDNET e a conexão é estabelecida automaticamente:

```
Connected to Windows 10 19041 x64 target at ...
Debuggee is running...
```

### Pausar a execução

`Debug → Break` (ou **Ctrl+Break**) — pausa o guest e entrega o prompt `kd>`.

---

## Comandos WinDbg usados neste projeto

### Carregar símbolos do SimpleVisor

```
.sympath+ C:\Users\admin\Documents\Github\SimpleVisor\x64\Release
.reload /f shv.sys
```

### Verificar que o driver está carregado

```
lm m shv
```

### Inspecionar contadores do hypervisor

```
dq shv!ShvExitCount
dq shv!ShvLstarReadCount
dq shv!ShvLstarWriteCount
dq shv!ShvLastLstarValue
dq shv!ShvEventCount
```

### Verificar o valor real do LSTAR (deve apontar para nt!KiSystemCall64)

```
rdmsr c0000082
ln <endereço retornado>
```

### Listar módulos do kernel carregados

```
lm
```

### Ver call stack no momento do break

```
kv
```

### Retomar execução

```
g
```

---

## Deploy do driver (após compilar no VS)

Execute na **máquina de desenvolvimento** (PowerShell como administrador):

```powershell
.\deploy_test.ps1
```

O script faz automaticamente:
1. Compila via MSBuild (Release x64)
2. Conecta via WinRM em 192.168.0.107
3. Para o driver antigo (`sc stop hpv`)
4. Copia o novo `shv.sys`
5. Inicia o driver (`sc start hpv`)

### Deploy manual (caso o script falhe)

```powershell
$cred = New-Object System.Management.Automation.PSCredential(
    "admin",
    (ConvertTo-SecureString "@123" -AsPlainText -Force)
)
$s = New-PSSession -ComputerName 192.168.0.107 -Credential $cred

Copy-Item "x64\Release\shv.sys" `
    -Destination "C:\Windows\System32\drivers\shv.sys" -ToSession $s -Force

Invoke-Command -Session $s { sc.exe stop hpv; sc.exe start hpv }
Remove-PSSession $s
```

---

## Executar o monitor usermode na máquina de teste

Via WinRM:

```powershell
Invoke-Command -Session $s {
    Start-Process "C:\shv_monitor\usermode.exe" -WindowStyle Normal
}
```

Ou copiando e executando manualmente na máquina de teste:

```powershell
Copy-Item "usermode_teste\usermode\x64\Release\usermode.exe" `
    -Destination "C:\shv_monitor\usermode.exe" -ToSession $s -Force

Invoke-Command -Session $s { & "C:\shv_monitor\usermode.exe" }
```

---

## Solução de problemas

| Sintoma | Causa provável | Solução |
|---|---|---|
| WinDbg mostra "Waiting..." para sempre | IP errado no bcdedit, ou firewall bloqueando | Verificar IP do dev no bcdedit da máquina de teste; abrir porta 50000 |
| "Debuggee not connected" após reboot | KDNET não inicializou | Confirmar `bcdedit /debug on` e reiniciar novamente |
| `sc start hpv` retorna erro 577 | Testsigning desativado | `bcdedit /set testsigning on` + reiniciar |
| BSOD 0x7F (double fault) | KPTI ativo + hook LSTAR | Desativar KPTI (veja shvvmxhv.c) ou usar EPT hook |
| BSOD 0xD1 | VT-x desativado na BIOS | Habilitar Intel Virtualization Technology na BIOS |
| `SHV_STATUS_NOT_AVAILABLE (-1)` | VT-x desabilitado por firmware | Verificar e habilitar na BIOS |
| ShvExitCount == 0 | VMware nested VT-x não funciona | Usar hardware físico |

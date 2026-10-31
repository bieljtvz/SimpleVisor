# PowerShell Remoting (WinRM) — Máquina de Teste

Guia para configurar e usar o WinRM para executar comandos PowerShell remotamente na máquina de teste (192.168.0.107) a partir da máquina de desenvolvimento.

---

## Visão geral

```
[Dev machine]  PowerShell  ——— WinRM/HTTP (porta 5985) ———→  [Test machine 192.168.0.107]
               New-PSSession                                   admin / @123
               Invoke-Command                                  standalone (sem domínio)
```

---

## Configuração única — máquina de teste

Execute tudo **na máquina de teste** como administrador.

### 1. Habilitar o WinRM

```powershell
Enable-PSRemoting -Force
```

Esse comando:
- Inicia e configura o serviço WinRM
- Cria o listener HTTP na porta 5985
- Abre a porta no firewall do Windows
- Define a política de execução como `RemoteSigned`

### 2. Verificar que o serviço está rodando

```powershell
Get-Service WinRM
```

Saída esperada:
```
Status   Name    DisplayName
------   ----    -----------
Running  WinRM   Windows Remote Management (WS-Management)
```

Se não estiver rodando:

```powershell
Start-Service WinRM
Set-Service WinRM -StartupType Automatic
```

### 3. Confirmar que o listener está ativo

```powershell
winrm enumerate winrm/config/listener
```

Saída esperada:
```
Listener
    Address = *
    Transport = HTTP
    Port = 5985
    ...
    Enabled = true
```

### 4. Abrir a porta 5985 no firewall (se necessário)

Normalmente o `Enable-PSRemoting` já faz isso. Para confirmar manualmente:

```powershell
netsh advfirewall firewall add rule `
    name="WinRM HTTP" dir=in action=allow protocol=TCP localport=5985
```

### 5. Configurar conta local sem senha inicial

A máquina de teste usa conta local `admin`. Se a conta não tiver senha, o WinRM recusa a conexão (segurança padrão do Windows para contas sem senha em rede).

Definir senha via cmd:

```cmd
net user admin @123
```

Ou via PowerShell:

```powershell
$senha = ConvertTo-SecureString "@123" -AsPlainText -Force
Set-LocalUser -Name "admin" -Password $senha
```

---

## Configuração única — máquina de desenvolvimento

Execute na **máquina de desenvolvimento** como administrador.

### Adicionar a máquina de teste à lista de hosts confiáveis

Por padrão o WinRM só aceita conexões com hosts no mesmo domínio. Como a máquina de teste é standalone (sem domínio), é necessário adicioná-la manualmente:

```powershell
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.0.107" -Force
```

Para permitir qualquer host (útil em lab, não recomendado em produção):

```powershell
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
```

Verificar o valor atual:

```powershell
Get-Item WSMan:\localhost\Client\TrustedHosts
```

---

## Uso no dia a dia

### Abrir uma sessão remota

```powershell
$cred = New-Object System.Management.Automation.PSCredential(
    "admin",
    (ConvertTo-SecureString "@123" -AsPlainText -Force)
)
$s = New-PSSession -ComputerName 192.168.0.107 -Credential $cred
```

### Executar um comando remoto

```powershell
Invoke-Command -Session $s { Get-Service hpv }
```

### Entrar em uma sessão interativa

```powershell
Enter-PSSession -Session $s
# Agora o prompt mostra: [192.168.0.107]: PS C:\Users\admin\Documents>
# Digite 'exit' para sair
```

### Copiar arquivos para a máquina de teste

```powershell
Copy-Item "x64\Release\shv.sys" `
    -Destination "C:\Windows\System32\drivers\shv.sys" `
    -ToSession $s -Force
```

### Copiar arquivos da máquina de teste para o dev

```powershell
Copy-Item "C:\logs\shv_dump.txt" `
    -Destination ".\shv_dump.txt" `
    -FromSession $s
```

### Fechar a sessão

```powershell
Remove-PSSession $s
```

---

## Bloco completo de conexão (copie e cole)

```powershell
$cred = New-Object System.Management.Automation.PSCredential(
    "admin",
    (ConvertTo-SecureString "@123" -AsPlainText -Force)
)
$s = New-PSSession -ComputerName 192.168.0.107 -Credential $cred

Invoke-Command -Session $s {
    # seus comandos aqui
    Write-Host "Conectado em $env:COMPUTERNAME"
}

Remove-PSSession $s
```

---

## Verificar se a conexão está funcionando

```powershell
$cred = New-Object System.Management.Automation.PSCredential(
    "admin",
    (ConvertTo-SecureString "@123" -AsPlainText -Force)
)
Test-WSMan -ComputerName 192.168.0.107 -Credential $cred
```

Saída esperada (conexão OK):
```
wsmid           : http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd
ProtocolVersion : http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd
ProductVendor   : Microsoft Corporation
ProductVersion  : OS: 10.0.19041 SP: 0.0 Stack: 3.0
```

---

## Solução de problemas

| Erro | Causa | Solução |
|---|---|---|
| `Access is denied` | Senha errada ou conta sem senha | `net user admin @123` na máquina de teste |
| `The client cannot connect` | Host não está em TrustedHosts | `Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.0.107" -Force` no dev |
| `Connection refused` / timeout | WinRM não está rodando | `Start-Service WinRM` na máquina de teste |
| `WinRM firewall exception` | Porta 5985 bloqueada | Executar `Enable-PSRemoting -Force` novamente como admin |
| `Connecting to remote server failed` | Máquina de teste inacessível | Verificar IP com `ping 192.168.0.107` e confirmar que estão na mesma rede |

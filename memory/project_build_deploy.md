---
name: project-build-deploy
description: "Como compilar, fazer deploy e reiniciar driver/GUI no SimpleVisor"
metadata:
  node_type: memory
  type: project
  originSessionId: 9e1e8b0f-464b-44e8-95dc-e10a4dc509ea
  modified: 2026-11-05T19:40:42.120Z
---

## Build

**Driver (shv.sys)**:
```powershell
# Usando deploy_hpv.ps1 (compila + envia):
.\deploy_hpv.ps1

# Só compilar:
$msbuild = & "...\vswhere.exe" -latest ... -find MSBuild\**\Bin\MSBuild.exe
& $msbuild shv.sln "/p:Configuration=Windows NT" /p:Platform=x64 /v:minimal /nologo
# Resultado: x64\NT\shv.sys (assinado automaticamente)
```

**GUI (usermode_gui.exe)**:
```powershell
.\deploy_gui.ps1
# Resultado: usermode_gui\usermode_gui\x64\Release\usermode_gui.exe
# Enviado como: C:\Users\admin\Desktop\hpv\usermode.exe na VM
```

## VM e serviço

- **IP**: 192.168.0.102, **user**: admin, **pass**: @123
- **Pasta**: `C:\Users\admin\Desktop\hpv\`
- **Serviço**: nome `hpv` (kernel driver)
  - Iniciar: `sc.exe start hpv`
  - Parar: `sc.exe stop hpv` — pode falhar para tipo-1 hypervisor; requer reboot
  - **Para substituir shv.sys**: parar serviço → copiar → iniciar. Se não parar: copiar e fazer reboot.

## Deploy só o binário (sem rebuild)

```powershell
.\deploy_hpv.ps1 -NoBuild   # usa shv.sys já compilado
.\deploy_gui.ps1 -NoBuild   # usa usermode_gui.exe já compilado
```

## Fluxo completo de update

1. `.\deploy_hpv.ps1` → compila + copia shv.sys para VM
2. Na VM: `sc.exe stop hpv` + `sc.exe start hpv` (ou reboot se stop falhar)
3. `.\deploy_gui.ps1` → compila + copia usermode.exe para VM
4. Na VM: fechar e reabrir usermode.exe

**Why:** O driver é tipo-1 VMX; quando rodando, `sc stop` pode falhar com erro 1062. Nesse caso, shv.sys no disco já está atualizado — reboot carrega o novo binário.

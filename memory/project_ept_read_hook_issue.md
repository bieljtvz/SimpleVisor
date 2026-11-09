---
name: project-ept-read-hook-issue
description: "READ hook (SHV_HOOK_READ) só dispara via ReadProcessMemory, não via acesso direto usermode — causa e hipóteses"
metadata:
  node_type: memory
  type: project
  originSessionId: 9e1e8b0f-464b-44e8-95dc-e10a4dc509ea
  modified: 2026-11-05T19:40:22.767Z
---

## Problema

EPT READ hooks (SHV_HOOK_READ=0x04) geram eventos `SHV_EVENT_EPT_READ` apenas quando a leitura vem de `ReadProcessMemory` (kernel-mode). Acesso direto usermode (`*(DWORD*)addr`) NÃO gera eventos.

## Estado do código

Arquivo `shvvmxhv.c`, função `ShvVmxHandleEptViolation`:
- Bit 0 de exitQual → handler de leitura → `ShvHvPushEvent(SHV_EVENT_EPT_READ, ...)`
- Lógica está correta (confirmado por `git diff faa0e70 HEAD` = vazio)

## Hipóteses

### 1. Execute-only EPT não suportado (mais provável)
READ hook usa r=0, w=0, **x=1**. Se `ShvEptExecuteOnlySupported=0`, este layout é EPT misconfiguration → exit reason 50 (EPT_MISCONFIG), não 48 (EPT_VIOLATION). Handler de violação nunca roda.

ReadProcessMemory pode funcionar por razão diferente: MmCopyVirtualMemory pode usar um path que gera exit com bit1 (write) em vez de bit0 — ou porque o acesso kernel ao mesmo PA foi feito antes do hook ser aplicado a esse vCPU.

**Fix**: mudar `x = (type & SHV_HOOK_EXEC) ? 0 : 1` para `x = ((type & SHV_HOOK_EXEC) || (r == 0)) ? 0 : 1` em `ShvVmxEptApplyHooks` e `ShvVmxEptRearmHook`. Isso usa r=0,w=0,x=0 para READ hooks, que é sempre válido.

### 2. KPTI ativo na VM
Com KVA Shadow: acesso usermode usa `UserDirectoryTableBase` (user CR3), kernel usa `DirectoryTableBase`. Não impacta o EPT diretamente (EPT é por PA, não por CR3), mas influencia __readcr3() capture.

### 3. Binário antigo rodando
Versão com filtro CR3 (commit 6664e55) no driver em memória: filtrava acessos usermode (CR3 user ≠ kernel CR3 capturado). Revertido em d1a548b. Reiniciar serviço `hpv` ou reboot na VM para carregar novo binário.

## O que NÃO é o problema
- Lógica de routing do exitQual (else-if chain correta: bit2>bit1>bit0)
- MDL locking (correto; implementado em nt/shvos.c)
- Ring buffer / SeqNum (corrigido em 3cedd98)
- GUI display (tab EPT mostra tipo 5 com filtro `(1<<3)|(1<<4)|(1<<5)`)

## Próximo passo para diagnosticar
Via WinDbg na VM:
```
dt ShvHookTable[0] — verificar PhysAddr, Type=4, HitCount (deve ser 0 se hook nunca disparou)
dt ShvEventCount — se 0 após read direto, confirma que EPT violation não está chegando ao handler
dt ShvEptExecuteOnlySupported — se 0, confirma hipótese 1
```

**Why:** ReadProcessMemory passa por kernel mode (pode acertar um path diferente ou usar o vCPU correto). Acesso direto ring-3 pode estar causando exit reason 50 em vez de 48.  
**How to apply:** Antes de qualquer work em READ hooks, verificar se `ShvEptExecuteOnlySupported` é 1. Se 0, aplicar fix x=0 nas duas funções.

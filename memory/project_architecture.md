---
name: project-architecture
description: "Arquitetura completa do SimpleVisor — arquivos, globals, fluxo de boot, camadas"
metadata:
  node_type: memory
  type: project
  originSessionId: 9e1e8b0f-464b-44e8-95dc-e10a4dc509ea
  modified: 2026-11-05T19:40:01.591Z
---

## SimpleVisor — Arquitetura

**Tipo**: Type-1 VMX hypervisor como driver kernel Windows (shv.sys).  
**Compilação**: Visual Studio, `shv.sln`, configuração `"Windows NT" | x64`. Resultado: `x64/NT/shv.sys` (assinado).  
**Deploy**: `.\deploy_hpv.ps1` (VM 192.168.0.102, user admin/@123, pasta `C:\Users\admin\Desktop\hpv`).  
**Serviço na VM**: nome `hpv` (`sc start hpv` / `sc stop hpv`).  
**GUI**: `usermode_gui.sln`, `Release|x64` → `usermode_gui.exe`. Deploy: `.\deploy_gui.ps1`.

---

## Camadas

```
GUI (usermode_gui.exe)
  └─ shv_client.h/shv_backend.cpp — CPUID polling + IOCTL via ShvClient
  └─ tab_events.cpp — ring buffer display (SeqNum, filtros por tipo)

NT-side driver (nt/)
  └─ shvos.c          — IOCTL handler (SHV_CMD_*)
  └─ hpv_hooks.c      — shadow hooks / syscall hook install
  └─ shvos_beep.c     — beep-based shadow hook setup
  └─ shvos_internal.h — interface NT-side ↔ hypervisor

Hypervisor (VMX root mode)
  └─ shvvmxhv.c  — VM-exit handler (CPUID, EPT, MTF, RDMSR/WRMSR)
  └─ shvvmx.c    — VMCS setup, ShvLoad, vCPU init
  └─ shvvp.c     — per-vCPU state (ShvVpData)
  └─ shv.h       — exports do hypervisor para o NT-side
```

---

## Arquivos chave

| Arquivo | Papel |
|---------|-------|
| `shvvmxhv.c` | Handler de VM-exits: EPT, MTF, CPUID, MSR. Hook table, ring buffer de eventos |
| `shvvmx.c` | Setup do VMCS por vCPU, ShvLoad/ShvUnload, EPT init |
| `shv.h` | Declarações exportadas (ShvHookInstall, ShvHookTable, ShvEventBuffer...) |
| `shv_comm.h` | Protocolo CPUID/IOCTL compartilhado kernel↔user (SHV_QUERY_*, SHV_EVENT_*, SHV_CMD_*) |
| `shv_dbg.h` | Structs IOCTL (SHV_REQUEST, SHV_RESPONSE), constantes SHV_HOOK_*, SHV_CMD_* |
| `nt/shvos.c` | IOCTL dispatch: HOOK_EPT, UNHOOK_EPT, UNHOOK_ALL, TRANSLATE_VA, etc. MDL locking |
| `nt/shvos_internal.h` | Interface interna NT↔hypervisor (ShvHookInstall, ShvHookSetMdl, etc.) |
| `shv_client/shv_client.h` | Client library: ShvClient::HookEpt, UnhookEpt, QueryEventInfo |

---

## Globals importantes (shvvmxhv.c)

```c
SHV_HOOK_ENTRY  ShvHookTable[16];    // tabela de EPT hooks (ShvHookVersion dispara apply)
volatile UINT64 ShvHookVersion;      // incrementado por ShvHookInstall; cada vCPU aplica lazy
UINT64          ShvEptHookPhysical;  // hook legado de KiSystemCall64 (PA fixo)
UINT64          ShvEptHookHitCount;  // hits do hook legado
SHV_HV_EVENT    ShvEventBuffer[256]; // ring buffer (SeqNum 1-based, wrap-around)
volatile INT64  ShvEventCount;       // total de eventos escritos (InterlockedIncrement64)
UINT8           ShvEptExecuteOnlySupported; // 1 se CPU suporta execute-only EPT (r=0 w=0 x=1)
```

---

## SHV_HOOK_ENTRY (56 bytes)

```c
typedef struct {
    UINT64 PhysAddr;       // GPA 4KB-aligned; 0 = slot livre
    UINT64 ShadowPhysAddr; // PA shadow page; 0 = hook EPT normal
    UINT8  Type;           // SHV_HOOK_EXEC|SHV_HOOK_WRITE|SHV_HOOK_READ
    UINT64 HitCount;       // (7 bytes padding antes deste)
    UINT64 VirtAddr;       // VA original
    UINT64 Pid;            // PID alvo (0 = kernel)
    UINT64 RangeSize;      // número de páginas
} SHV_HOOK_ENTRY;          // 56 bytes = 7 QWORDs
```

**How to apply**: cada vCPU checa `VpData->EptHookVersion != ShvHookVersion` no início de ShvVmxHandleExit; se diferente, chama `ShvVmxEptApplyHooks` (lazy per-vCPU).

---

## Fluxo de EPT violation

1. Guest acessa PA hookada → EPT violation (exit reason 48)
2. `ShvVmxHandleExit` → atualiza hooks se versão diferente → `ShvVmxHandleEptViolation`
3. Exit qualification: bit2=exec, bit1=write, bit0=read
4. Handler correto é chamado; `ShvHvPushEvent` escreve no ring buffer
5. Permissões restauradas para r=1,w=1,x=1; MTF armado; `SkipRipAdvance=TRUE`
6. Guest re-executa a instrução com permissões completas (1 instrução)
7. MTF dispara: `ShvVmxEptRearmHook` restaura r=0/w=0/x=? conforme tipo do hook

---

## Tipos de hook EPT

| Constante | Valor | EPT perms | Violação |
|-----------|-------|-----------|----------|
| SHV_HOOK_EXEC  | 0x01 | r=1,w=1,x=0 | bit2 → SHV_EVENT_EPT_EXEC  |
| SHV_HOOK_WRITE | 0x02 | r=1,w=0,x=1 | bit1 → SHV_EVENT_EPT_WRITE |
| SHV_HOOK_READ  | 0x04 | r=0,w=0,x=1 | bit0 → SHV_EVENT_EPT_READ; bit1 (write numa r=0 page) → EPT_READ também |

**ATENÇÃO READ hooks**: r=0,w=0,x=1 requer `ShvEptExecuteOnlySupported=1`. Se não suportado, causa EPT_MISCONFIG (exit 50) em vez de EPT_VIOLATION (exit 48) → handler nunca roda. Fix potencial: usar x=0 para READ hooks (r=0,w=0,x=0).

---

## MDL locking (nt/shvos.c SHV_CMD_HOOK_EPT)

Para Pid != 0 (user-mode hooks):
1. `IoAllocateMdl(vaBase, regionBytes)`
2. `KeStackAttachProcess` → `MmProbeAndLockPages(mdl, UserMode, IoReadAccess)` → `KeUnstackDetachProcess`
3. Itera `MmGetMdlPfnArray(mdl)` → `ShvHookInstall(gpa, type, va, pid, rangeSize)` por página
4. `ShvHookSetMdl(firstPa, mdl)` — MDL indexado pela PA da primeira página

Para unhook: `ShvHookTakeMdl(pa)` → remove hooks → `MmUnlockPages` → `IoFreeMdl`.  
Tabela MDL: `g_MdlTable[SHV_MDL_TABLE_MAX]` em shvos.c.

---

## Ring buffer de eventos (GUI ↔ hypervisor via CPUID)

**Kernel**: `ShvHvPushEvent(type, value, retAddr, aux)` → `ShvEventBuffer[idx % 256]`, SeqNum = idx+1 (1-based).  
**GUI** (shv_backend.cpp `PollOnce`):
- `SHV_QUERY_EVENT_INFO` (sub-leaf 10): retorna total=ShvEventCount, ringSize=256
- Se `total == m_lastSeqSeen`: sem novos eventos, retorna
- Para cada slot: `SHV_QUERY_EVENT_BASE+slot` → SHV_HV_EVENT
- Skipa se `e.seqNum <= m_lastSeqSeen`
- Atualiza `m_lastSeqSeen = max(m_lastSeqSeen, e.seqNum)`

**Bug histórico resolvido**: SeqNum era 0-based (`idx`), GUI skipava seqNum==0. Fix: `SeqNum = idx+1`.

---

## Protocolo CPUID (SHV_CPUID_LEAF = 0x80000042)

| Sub-leaf | Retorno |
|----------|---------|
| 0  | presença: EAX=leaf, EBX=cpu, ECX=versão |
| 10 | total eventos (EAX) + ring size (EBX) |
| 11+slot | evento: EAX=SeqNum, EBX=Value.Low, ECX=Value.High, EDX=(Type<<8)\|CpuNum |
| 11+256+slot | ext: EAX=ReturnAddr.Low, EBX=ReturnAddr.High, ECX=Aux.Low, EDX=Aux.High |
| 6  | EPT caps: EAX bit0=execute-only suportado |

---

## RESTRIÇÕES CONHECIDAS

- **KPTI (KVA Shadow)**: código assume KPTI desativado na VM de teste. Com KPTI, CR3 user ≠ CR3 kernel.
- **Execute-only EPT**: READ hooks usam r=0,w=0,x=1; requer suporte na CPU.
- **SHV_HOOK_MAX_ENTRIES = 16**: máximo 16 hooks EPT simultâneos.
- **Ring buffer = 256**: overwrite silencioso de eventos antigos.

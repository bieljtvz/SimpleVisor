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
**Desmontador da GUI**: Zydis (vcpkg, instalado em modo classic/global — sem `vcpkg.json` manifest no repo, integração via `vcpkg integrate install` já feita no sistema). `usermode_gui.vcxproj` tem `<VcpkgTriplet>x64-windows-static-md</VcpkgTriplet>` (propriedade `Globals`, vale pra Debug e Release) pra linkar Zydis/Zycore estaticamente — **não gera DLL**, então `deploy_gui.ps1` (que só envia `usermode_gui.exe`) continua funcionando sem mudança. `usermode_gui/usermode_gui/usermode_gui/tab_disasm.h/.cpp` — `RenderDisasmView(Buf, Size, BaseAddr, Pid, KernMods)`, helper que só desmonta e renderiza uma tabela ImGui (Endereco/Bytes/Instrucao) com `ZydisDecoderDecodeFull`/`ZydisFormatterFormatInstruction` (x86-64, Intel syntax); NÃO faz leitura própria. Integrado dentro da aba Memoria → sub-aba "Leitura" (`tab_memory.cpp`), logo abaixo do hex editor: checkbox "Desmontar (Zydis)" reusa o mesmo buffer (`s_buf`/`s_bufSize`/`s_baseAddr`) já lido por `ReadVirt`/`ReadPhys` pro hex view, sem ler memória de novo.

**Simbolização modulo+offset**: hook em `ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS` (padrão in/out do Zydis: `ZydisFormatterSetHook` recebe o novo hook e devolve o anterior no mesmo ponteiro — guardado uma vez em `s_defaultPrintAddressAbs` como fallback) intercepta todo endereço absoluto que o Zydis formataria (operando de memória sem base/index, ex. `lea rcx, [0x40000000]`, e alvos de `call`/`jmp`), resolve contra `KernMods` (`backend.State().kernelModules`, passado pelo `tab_memory.cpp` com `Lock()`/`Unlock()`) e, se um PID foi informado (leitura virtual), também contra os módulos (EXE+DLLs) desse processo via **IOCTL no driver** (`ShvBackend::ListProcessModules`, cache de 2s por PID em `GetProcessModules` de `tab_disasm.cpp`, mesmo esquema de refresh usado em `tab_events.cpp`). Se resolvido, imprime `modulo+0xOFFSET`; senão cai no formatter padrão (hex cru).

**SHV_CMD_LIST_PROCESS_MODULES (26)**: lista módulos (EXE+DLLs) de um processo lendo a PEB dele a partir do **kernel**, em vez de `CreateToolhelp32Snapshot`/`OpenProcess` em usermode — funciona mesmo contra processos protegidos (PPL), que negam `PROCESS_QUERY_INFORMATION` pra um chamador usermode comum. Fluxo: `req.ListProcModules.Pid` → `nt/shvos.c` (`PsLookupProcessByProcessId` → `KeStackAttachProcess` → `PsGetProcessPeb` → percorre `PEB->Ldr->InLoadOrderModuleList`, tudo dentro de `__try/__except` pois é memória do processo alvo) → devolve `SHV_MODULE_ENTRY[]` no mesmo formato de `SHV_CMD_LIST_MODULES` (kernel). Structs `HPV_PEB`/`HPV_PEB_LDR_DATA`/`HPV_LDR_DATA_TABLE_ENTRY_USER` definidas localmente em `nt/shvos.c` (não documentadas na WDK pública; layout x64 estável desde Vista) — **não confundir** com `HPV_LDR_DATA_TABLE_ENTRY` de `nt/hpv_pattern.c`, que é o layout do LDR do **kernel** (`PsLoadedModuleList`), diferente do LDR de **usermode** (PEB). `PsGetProcessPeb` é exportada pelo `ntoskrnl` mas não declarada nos headers da WDK — declarada manualmente (mesmo padrão já usado pra `ZwQuerySystemInformation` neste arquivo).

**WOW64 (processo 32-bit em Windows x64)**: a PEB nativa (64-bit) de um processo WOW64 tem `Ldr` vazio/não-representativo — os módulos de verdade ficam na **PEB32**, achada via `PsGetProcessWow64Process(process)` (NULL = processo nativo x64, não-NULL = PEB32 do processo WOW64). O handler tenta esse caminho primeiro; se WOW64, percorre `HPV_PEB32`/`HPV_PEB_LDR_DATA32`/`HPV_LDR_DATA_TABLE_ENTRY32` (campos `ULONG`, zero-extendidos pra ponteiro — válido porque WOW64 mapeia abaixo de 4GB no mesmo address space do processo); senão cai no caminho nativo de sempre. Ver [[fixes]] (entrada "SHV_CMD_LIST_PROCESS_MODULES: processos WOW64"). Limitação que permanece: processos "minimal" sem PEB real (System, Registry, Secure System, Memory Compression) não retornam módulos — não é bug. Client: `ShvClient::ListProcessModules(pid, ...)` (`shv_client.cpp`) → `ShvBackend::ListProcessModules(pid, out)` (`shv_backend.cpp`, com `Lock()`/`Unlock()`).

**Dois consumidores na GUI** (não confundir — são listagens de módulo independentes):
1. `tab_disasm.cpp` (`GetProcessModules`, dentro de Memória→Leitura→Desmontar) — usa o IOCTL pra simbolizar `modulo+offset` no desmontador.
2. `tab_procs.cpp` (`FetchModules`, aba Processos→Modules) — usa o IOCTL como caminho principal, com fallback pro `CreateToolhelp32Snapshot` antigo só se o backend não estiver conectado ou o IOCTL não retornar nada.

**Coluna "ThreadObject" (aba Processos→Threads)**: `SHV_THREAD_ENTRY.Object` — endereço do `PETHREAD` no kernel, só pra exibição (igual a coluna "Object" do Process Hacker). Preenchido em `SHV_CMD_LIST_PROCESS_THREADS` (`nt/shvos.c`) via `PsLookupThreadByThreadId(tid)` por thread (a struct `SYSTEM_THREAD_INFORMATION` do `ZwQuerySystemInformation` não traz o ponteiro direto) — pega o valor do endereço e solta a referência na hora (`ObDereferenceObject`), não mantém a thread referenciada. Só preenchido no caminho via IOCTL; o fallback usermode (Toolhelp32, quando o backend não está conectado) deixa `object = 0` (coluna mostra `---`), já que não há API usermode simples pra isso.

**SHV_CMD_LIST_PROCESS_THREADS (27)**: lista `{Tid, StartAddress}` de cada thread de um processo via `ZwQuerySystemInformation(SystemProcessInformation)` no kernel — não precisa de handle pro processo (diferente de `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` + `OpenThread` em usermode, que falha contra PPL). Para achar o array de threads de cada processo, foi necessário **expandir** `SYSTEM_PROCESS_INFORMATION_SHV` (em `nt/shvos.c`, usada também por `SHV_CMD_LIST_PROCS`) com TODOS os campos reais entre `SessionId` e o array de threads (`UniqueProcessKey`, `PeakVirtualSize`, `VirtualSize`, contadores de I/O etc.) — antes a struct só ia até `SessionId` (suficiente pra `LIST_PROCS`, que só lê campos por nome), mas o offset do array de threads (`entry + sizeof(SYSTEM_PROCESS_INFORMATION_SHV)`) só fica correto com o struct completo. Nova struct `SYSTEM_THREAD_INFORMATION_SHV` (layout clássico `SYSTEM_THREAD_INFORMATION`, campos `StartAddress`/`ClientId`/etc.). Client/backend: `ShvClient::ListProcessThreads` → `ShvBackend::ListProcessThreads`.

**SHV_CMD_LIST_PROCESS_MEMORY (28)**: lista regiões de memória virtual (`Base/Size/Protect/State/Type`, equivalente a `MEMORY_BASIC_INFORMATION`) de um processo via `KeStackAttachProcess` + `ZwQueryVirtualMemory(HPV_CURRENT_PROCESS, ...)` (pseudo-handle `(HANDLE)-1` = "processo atual", **sem handle de verdade, sem access check** — funciona mesmo contra PPL, diferente de `VirtualQueryEx` em usermode que precisa de `OpenProcess(PROCESS_QUERY_INFORMATION)`). `ZwQueryVirtualMemory`/`MEMORY_BASIC_INFORMATION`/`MemoryBasicInformation` já vêm declaradas em `ntifs.h` (diferente de `PsGetProcessPeb`/`PsGetProcessWow64Process`/`ZwQuerySystemInformation`, que são hand-declared neste arquivo por não estarem nos headers públicos — **não redeclarar** essas três, dá erro de conflito de assinatura/linkage, `C4028`/`C4273`). Client/backend: `ShvClient::ListProcessMemory` → `ShvBackend::ListProcessMemory`.

**Resolução dinâmica de APIs não-documentadas** (`nt/shvos.c`, `HpvResolveOptionalApis`,
chamada no início do `DriverEntry`): `ZwQuerySystemInformation`, `PsGetProcessPeb`,
`PsGetProcessWow64Process`, `ZwSuspendThread`, `ZwResumeThread`, `PsGetContextThread` — todas
exportadas pelo `ntoskrnl` mas sem prototype público na WDK — são resolvidas via
`MmGetSystemRoutineAddress` em vez de import estático (ponteiros `g_pZwQuerySystemInformation`
etc.), cada uma logada em `C:\ShvL.txt` ("OK"/"NAO ENCONTRADA"). **Motivo**: um import estático
de função não exportada pela build do Windows em uso faz o `sc start` falhar com
`STATUS_PROCEDURE_NOT_FOUND` **antes do `DriverEntry` rodar** — sem log nenhum (ver
[[fixes]], entrada "`sc start hpv` falhava com procedimento não encontrado"). Handlers que usam
essas APIs checam o ponteiro antes de chamar e devolvem `SHVD_STATUS_ERR_UNSUPPORTED` (status 6,
novo) se `NULL`. **Regra daqui pra frente**: qualquer API de kernel não documentada nova deve
seguir esse padrão (resolução dinâmica + log), nunca prototype+link estático direto.

**Ambos os novos comandos reusam `req.ProcFilter.Pid`** (struct já existente no protocolo, `{Pid}`) em vez de criar membros de request dedicados — mesmo padrão de reuso de `SHV_CMD_LIST_PROCESS_MODULES`.

`tab_procs.cpp`: `FetchThreads`/`FetchMemRegions` agora recebem `ShvBackend&`, tentam o IOCTL primeiro e caem pro código usermode antigo (Toolhelp32/`VirtualQueryEx`) só como fallback (backend desconectado ou IOCTL sem resultado) — mesmo padrão de `FetchModules`.

**SHV_CMD_THREAD_SUSPEND/RESUME (29/30)**: abre a thread via `ObOpenObjectByPointer(..., KernelMode, ...)` a partir do `PETHREAD` achado por `PsLookupThreadByThreadId` (handle kernel-mode, sem `OpenThread` usermode — funciona com PPL), depois `ZwSuspendThread`/`ZwResumeThread`. Essas duas funções e `PsGetContextThread` (usada por `GET_CONTEXT`) são exportadas pelo `ntoskrnl` mas **não têm prototype em nenhum header da WDK** (confirmado via `dumpbin /exports` no `ntoskrnl.lib`) — hand-declared em `nt/shvos.c`, mesmo padrão de `PsGetProcessPeb`. **`ZwTerminateThread` NÃO é exportada pro kernel** (confirmado no mesmo `dumpbin`) — por isso não existe `SHV_CMD_THREAD_TERMINATE`; terminar uma thread arbitrária via kernel exige outra técnica (ex.: APC quando a thread estiver sob controle), deixado pra depois a pedido do usuário.

**SHV_CMD_THREAD_GET_CONTEXT (31)**: suspende a thread, lê `Rip`/`Rsp`/`Rbp` via `PsGetContextThread(thread, &ctx, UserMode)`, resume. Usado pra sementear stack walk sem handle usermode.

**Stack walk de thread protegida (PPL) — `nt/thread_utils.h`/`.c`**: `PsGetContextThread` **não funciona** de forma confiável pra isso (ver [[fixes]]: decompilação do `ntoskrnl.exe` mostrou que `PspGetContextThreadInternal` enfileira sua própria APC especial via `KeInsertQueueApc`, que falha com `STATUS_UNSUCCESSFUL` quando o bit `ApcQueueable` do `_KTHREAD.MiscFlags` está zerado — na prática correlacionado com threads de processo protegido nos testes). A solução, igual o **Process Hacker/KProcessHacker** faz (`thread.c`, `KphCaptureStackBackTraceThread`): implementar a própria APC especial de kernel em vez de usar a API "oficial". `HpvCaptureThreadStack(PETHREAD, PHPV_THREAD_STACK_CAPTURE)` faz `KeInitializeApc`+`KeInsertQueueApc` com uma rotina própria que roda **dentro do contexto de execução da thread alvo** (é assim que entrega de APC de kernel funciona) e ali chama `RtlCaptureContext`/`RtlWalkFrameChain` pra pegar `Rip`/`Rsp`/`Rbp` + até 32 endereços de retorno da pilha de **KERNEL** da thread naquele instante (não é a stack de usermode — é onde a thread está rodando de verdade, geralmente no meio de um syscall, por isso os frames são de módulos do kernel, igual o Process Hacker mostra). `KeInitializeApc`/`KeInsertQueueApc`/`KeWaitForSingleObject`/`RtlWalkFrameChain` resolvidas dinamicamente (mesmo padrão das outras APIs não-documentadas desta sessão) via `HpvThreadUtilsResolveApis()`, chamada no `DriverEntry` junto com `HpvResolveOptionalApis()`.

Protocolo: `SHV_CMD_THREAD_GET_STACK` (32) → `SHV_THREAD_STACK{Rip,Rsp,Rbp,FrameCount,Frames[32]}`.

**`tab_procs.cpp` (`WalkThreadStack`/`WalkThreadStackViaApc`)**: o caminho clássico (`OpenProcess`+`OpenThread`+`GetThreadContext`+`StackWalk64` com handles de verdade, `SymInitialize(hProc, nullptr, TRUE)` — stack de **usermode** com símbolos de verdade via dbghelp) continua tentado primeiro; se `OpenProcess`/`OpenThread`/`GetThreadContext` falhar (PPL), cai pra `WalkThreadStackViaApc`: chama `backend.GetThreadStack` (IOCTL acima) e resolve cada endereço contra `backend.State().kernelModules` (módulo+offset do kernel) — sem StackWalk64/dbghelp nenhum, já vem a lista de frames pronta do `RtlWalkFrameChain`.

**Build estático do Zydis/Zycore**: triplet `x64-windows-static-md` NÃO ativa sozinho a build estática dos headers — como o projeto consome `*.lib` via glob (`vcxproj` sem CMake), é preciso definir `ZYDIS_STATIC_BUILD`/`ZYCORE_STATIC_BUILD` manualmente em `PreprocessorDefinitions` (ambas as configs Debug/Release do `usermode_gui.vcxproj`), senão os headers marcam as funções como `__declspec(dllimport)` e o link falha (`LNK2001 __imp_Zyan...`) mesmo linkando a lib estática certa. Se precisar reinstalar/trocar de máquina: `vcpkg install zydis:x64-windows-static-md` (o triplet dinâmico `x64-windows` NÃO é usado por este projeto).

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

## HOST_CR3 da VMCS (`ShvOsGetSystemCr3`)

`shv.c` (`ShvLoad()`, compartilhado NT/UEFI) usa `ShvOsGetSystemCr3()` (não `__readcr3()`
direto) pra obter o CR3 que vira `HOST_CR3` da VMCS (via `vpData->SystemDirectoryTableBase`,
`shvvmx.c:725`). No NT, devolve o CR3 do processo System (`PsInitialSystemProcess`), estável
pra sempre, cacheado — `__readcr3()` sozinho capturaria o CR3 de QUALQUER processo em cujo
contexto `DriverEntry` estivesse rodando, e se esse processo saísse logo depois, `HOST_CR3`
ficaria morto → triple fault silencioso no próximo VM-exit (ver [[fixes]]). No UEFI,
`ShvOsGetSystemCr3()` continua `__readcr3()` direto (sem esse problema nessa fase). **Não
confundir** com `ShvCaptureSpecialRegisters` (`shvvp.c`), que lê `__readcr3()` por CPU pra
`GUEST_CR3` — esse é intencional e correto, representa o processo/thread rodando naquela CPU
no momento do `VMLAUNCH`.

## RESTRIÇÕES CONHECIDAS

- **KPTI (KVA Shadow)**: código assume KPTI desativado na VM de teste. Com KPTI, CR3 user ≠ CR3 kernel.
- **Execute-only EPT**: READ hooks usam r=0,w=0,x=1; requer suporte na CPU.
- **SHV_HOOK_MAX_ENTRIES = 256** (era 16 até 2026-11-16, aumentado a pedido do usuário): máximo de hooks EPT simultâneos. `ShvHookTable[256]` em `shvvmxhv.c` — array estático simples (56 bytes/entrada, ~14KB total), sem bitmask/contador de tamanho fixo amarrado a esse número (`ShvHookVersion` é só um `UINT64` incremental). Os três `#define` (um em `shv.h`, um em `nt/shvos_internal.h`, um sem guard em `shvvmxhv.c`) precisam ser trocados juntos se mudar de novo. `SHV_RESPONSE.EptHookInfos[]` (buffer do IOCTL `SHV_CMD_LIST_EPT_HOOKS`) comporta até `SHV_MAX_READ_SIZE/sizeof(SHV_EPT_HOOK_INFO)` ≈ 292 entradas — então ainda dá folga acima de 256 nessa listagem.
- **Ring buffer = 256**: overwrite silencioso de eventos antigos.

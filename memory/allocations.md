---
name: driver-allocations
description: "Lista de alocações de memória de VIDA LONGA do SimpleVisor (não as transientes de um IOCTL) -- o que fica alocado enquanto o driver está carregado, onde é liberado, e os vazamentos encontrados/corrigidos"
metadata:
  type: project
---

# Alocações de memória de vida longa do SimpleVisor

Levantamento de 2026-11-16, a pedido do usuário: toda alocação (`ExAllocatePoolWithTag`,
`MmAllocateContiguousNodeMemory`/`ShvOsAllocateContigousAlignedMemory`, `IoAllocateMdl`,
referência via `ObReferenceObject*`) que **começa enquanto o driver está carregado** (não os
buffers transientes alocados e liberados dentro do handler de um único IOCTL, tipo os de
`ZwQuerySystemInformation` em `LIST_PROCS`/`LIST_MODULES`/`LIST_PROCESS_THREADS` — esses já
foram auditados e estão corretos, sem vazamento, mas não entram aqui por serem de vida curta).

Cada entrada: **o quê** → **onde aloca** → **onde libera** → **status**.

---

## 1. Trampoline pool (`g_TrampolinePool`)

- **Aloca**: `HpvTrampolinePoolInit()` (`nt/hpv_hooks.c`) — 4KB contíguo RWX, via
  `MmAllocateContiguousNodeMemory`. Chamado uma vez em `DriverEntry`, antes de `ShvLoad()`.
- **Libera**: `HpvTrampolinePoolFree()` — normalmente em `DriverUnload`, **depois** de
  `ShvUnload()` (VMXOFF). Ordem importa: com EPT ainda ativo, uma CPU poderia estar no meio de
  um salto pra dentro do pool.
- **Status**: ✅ **corrigido** (2026-11-16). Faltava liberar nos dois caminhos de erro de
  `DriverEntry` que rodam DEPOIS do `HpvTrampolinePoolInit()` ter sucesso:
  - `ShvBeepHijackSetup()` falha → agora chama `HpvTrampolinePoolFree()` antes do `return`
    (seguro liberar direto aqui, sem a ordenação pós-VMXOFF, porque VMX/EPT nunca chegaram a
    rodar nesse ponto).
  - `ShvLoad()` falha → idem, `HpvTrampolinePoolFree()` antes do `return` (nenhuma CPU chegou a
    rodar com EPT ativo).
  - Antes do fix, vazava os 4KB até reboot se qualquer uma dessas duas etapas falhasse durante
    o carregamento do driver.

## 2. Shadow pages (`g_ShadowPages[SHV_SHADOW_MAX]`, definido em `shvvmxhv.c`)

Pool compartilhado por DOIS caminhos de instalação (mesmo array, mesma técnica split-page EPT):

### 2a. Automático (`HpvHookFuncByVa`, `nt/hpv_hooks.c`) — os 3 hooks de política
- **Aloca**: dentro de `HpvHookFuncByVa`, se não existir shadow pra aquela GPA ainda
  (`MmAllocateContiguousNodeMemory`, 4KB RWX). Usado pelos 3 hooks automáticos
  (`NtOpenProcess`, `MmCopyVirtualMemory`, `PspExitProcess`) instalados em `ShvPolicyHooksInit`.
- **Libera**: `HpvUnhookFuncByVa()`, chamado por `ShvPolicyHooksUninit()` em `DriverUnload` —
  procura o hook em `g_SyscallHooks[]` pelo `FuncVa`, decrementa `RefCount` do shadow
  correspondente, libera a página física quando `RefCount` chega a 0.
- **Status**: ✅ **corrigido** (2026-11-16). Havia um caminho onde a shadow page (e o slot de
  trampolim) eram alocados ANTES de reservar uma entrada em `g_SyscallHooks[SHV_SYSCALL_HOOK_MAX]`
  (32 vagas) — se as 32 já estivessem em uso, o código simplesmente não registrava a entrada e
  seguia em frente retornando sucesso mesmo assim. Sem entrada em `g_SyscallHooks`,
  `HpvUnhookFuncByVa` nunca acharia esse hook pra desfazer (procura por `FuncVa` ali) — shadow
  page e trampolim ficavam órfãos até o driver descarregar. Agora `HpvHookFuncByVa` desfaz tudo
  (libera a shadow page nova ou decrementa o refcount de uma existente, e recua
  `g_TrampolineUsed`) e devolve `STATUS_INSUFFICIENT_RESOURCES` em vez de "sucesso" fantasma.
  Baixa probabilidade na prática hoje (só 3 hooks automáticos existem, longe do limite de 32),
  mas era uma falha real pronta pra morder se mais hooks forem adicionados no futuro.

### 2b. Manual (`SHV_CMD_HOOK_SHADOW`/`SHV_CMD_UNHOOK_SHADOW`, `nt/shvos.c`) — aba "Shadow Patch" da GUI
- **Aloca**: handler de `SHV_CMD_HOOK_SHADOW` — mesma lógica (`MmAllocateContiguousNodeMemory`
  se a GPA ainda não tem shadow; senão só reaplica o patch e incrementa `RefCount`).
- **Libera**: handler de `SHV_CMD_UNHOOK_SHADOW` — decrementa `RefCount`, libera quando chega a
  0 (`MmFreeContiguousMemory`).
- **Status**: ✅ **corrigido** (2026-11-16). `DriverUnload` **nunca varria `g_ShadowPages[]`**
  pra limpar o que sobrasse ativo — só desfazia os 3 hooks automáticos via
  `ShvPolicyHooksUninit()` (que só conhece os `FuncVa` fixos desses 3, não os GPAs manuais).
  Se o usuário instalasse um shadow patch manual e parasse/descarregasse o driver sem chamar
  `SHV_CMD_UNHOOK_SHADOW` antes, aquela página de 4KB ficava alocada até reiniciar a VM.
  Fix: nova função `HpvShadowPagesReleaseAll()` (`nt/hpv_hooks.c`), chamada em `DriverUnload`
  logo depois de `ShvUnload()` (mesma ordenação pós-VMXOFF do trampoline pool) — varre
  `g_ShadowPages[]` inteiro e libera qualquer `ShadowVa != NULL` que tenha sobrado,
  independente de qual caminho (2a ou 2b) instalou.

## 3. Per-vCPU data (`ShvOsAllocateContigousAlignedMemory`, `shvvp.c`)

- **Aloca**: `ShvVpAllocateProcessorData` (ou equivalente em `shvvp.c`) — um bloco contíguo de
  `sizeof(SHV_VP_DATA) * CpuCount`, via `MmAllocateContiguousNodeMemory` (wrapper em
  `nt/shvos.c`/`uefi/shvos.c`). Alocado uma vez em `ShvLoad`.
- **Libera**: `ShvOsFreeContiguousAlignedMemory`, chamado em `ShvUnload`.
- **Status**: ✅ sem vazamento — pareado corretamente (`shvvp.c:172` libera o bloco inteiro,
  não por-vCPU individualmente, consistente com a alocação em bloco único).
- **Nota (não é vazamento)**: `ShvOsFreeContiguousAlignedMemory` é **declarada** em `shv.h`
  com 2 parâmetros (`BaseAddress`, `Size`), mas **definida** em `nt/shvos.c` com só 1
  (`Size` nunca chega a ser usado na implementação NT). Inofensivo no x64 (o argumento extra
  simplesmente é ignorado), mas é uma inconsistência de assinatura que vale limpar um dia
  (ainda não corrigido).

## 4. MDLs de hook EPT em usermode (`g_MdlTable[SHV_MDL_TABLE_MAX]`, `nt/shvos.c`)

- **Aloca**: `SHV_CMD_HOOK_EPT` com `Pid != 0` — `IoAllocateMdl` + `MmProbeAndLockPages`,
  indexado pela PA da primeira página via `ShvHookSetMdl`.
- **Libera**: três caminhos, todos corretos —
  1. `SHV_CMD_UNHOOK_EPT` (usuário pede pra tirar o hook).
  2. `ShvCleanupExitedProcess` (hook de `PspExitProcess`, processo terminou sem desinstalar o
     hook antes — evita o bugcheck `PROCESS_HAS_LOCKED_PAGES`).
  3. `ShvHookReleaseMdls()` em `DriverUnload` — varre `g_MdlTable[]` inteiro e libera o que
     sobrar.
- **Status**: ✅ sem vazamento.

## 5. Referência ao `\Driver\Beep` (`ObReferenceObjectByName`, `nt/shvos_beep.c`)

- **Referencia**: `ShvBeepGetDriverObject()`, via `ObReferenceObjectByName` resolvida
  dinamicamente (não exportada nos headers — ver `memory/fixes.md`).
- **Dereferencia**: `ShvBeepHijackSetup()` solta a referência **na mesma função**, logo depois
  de copiar o ponteiro pra `g_BeepDriverObject` (só precisa do ponteiro bruto pra comparar
  depois, não de mantê-lo referenciado). `ShvBeepHijackTeardown()` **não reusa** esse ponteiro
  antigo — resolve o objeto de novo do zero (nova referência, novo `ObDereferenceObject` logo
  em seguida).
- **Status**: ✅ sem vazamento e sem ponteiro pendurado (`g_BeepDriverObject` nunca é
  desreferenciado duas vezes nem usado depois de solto — é só comparado/zerado).

## 6. Context de captura de stack via APC (`nt/thread_utils.c`)

- **Aloca**: `HpvCaptureThreadStack()` — `ExAllocatePoolWithTag(NonPagedPoolNx, ...)` pro
  `HPV_CAPTURE_APC_CTX` (contém o `KAPC` + evento + resultado), um por chamada do IOCTL
  `SHV_CMD_THREAD_GET_STACK`.
- **Libera**: nos dois caminhos — se `KeInsertQueueApc` falhar na hora (`ExFreePoolWithTag`
  imediato) e depois de `KeWaitForSingleObject` completar (sucesso ou rundown da thread alvo).
- **Status**: ✅ sem vazamento (é por-IOCTL, vida curta — listado aqui só por ser uma alocação
  não-óbvia ligada a um mecanismo que fica ativo "durante o uso do shv", mas não persiste além
  de uma chamada).

---

## Resumo

| # | O quê | Status antes | Status agora |
|---|---|---|---|
| 1 | Trampoline pool (erro em `DriverEntry`) | 🔴 vazava em 2 caminhos de erro | ✅ corrigido |
| 2a | Shadow page (automático, `g_SyscallHooks` cheio) | 🔴 vazava (caso de borda) | ✅ corrigido |
| 2b | Shadow page (manual, sem sweep no unload) | 🔴 vazava sempre que não desinstalado antes do unload | ✅ corrigido |
| 3 | Per-vCPU data | ✅ nunca vazou | ✅ (nota de assinatura não corrigida, inofensiva) |
| 4 | MDL de hook EPT usermode | ✅ nunca vazou | ✅ |
| 5 | Referência `\Driver\Beep` | ✅ nunca vazou | ✅ |
| 6 | Context de APC (`thread_utils.c`) | ✅ nunca vazou | ✅ |

Driver recompilado limpo (rebuild completo) depois dos 3 fixes. Ainda não testado em execução
real (precisa fazer um shadow patch manual + descarregar sem desinstalar, e/ou forçar os
caminhos de erro de `DriverEntry`, pra confirmar na prática).

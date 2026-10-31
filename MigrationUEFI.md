# SimpleVisor — Roteiro de Migração para UEFI

Este documento lista todas as dependências do Windows NT identificadas no código atual
e o que precisa ser feito para portar o hypervisor para um ambiente UEFI (pre-boot ou
runtime service).

---

## 1. Camada de OS (`nt/shvos.c`) — substituir inteiramente

O arquivo `nt/shvos.c` é a única camada OS-específica. Em UEFI ele seria substituído
por `uefi/shvos.c` implementando as mesmas funções com APIs do EDK2/UEFI.

| Função atual (NT) | Equivalente UEFI |
|---|---|
| `MmAllocateContiguousNodeMemory` | `AllocatePages` / `gBS->AllocatePages` (EfiConventionalMemory) |
| `MmFreeContiguousMemory` | `gBS->FreePages` |
| `KeGenericCallDpc` / `KeSignalCallDpc*` | Loop manual por CPU via `MpServices->StartupAllAPs` (EFI_MP_SERVICES_PROTOCOL) |
| `MmGetPhysicalAddress` | Identidade VA=PA no UEFI pre-boot; `GetMemoryMap` para verificar |
| `ExAllocatePoolWithTag` / `ExFreePoolWithTag` | `AllocatePool` / `FreePool` |
| `ZwQuerySystemInformation` | Não existe — remover ou reimplementar via estruturas UEFI |
| `PsLookupProcessByProcessId` | Não existe — conceito de processo não existe em UEFI |
| `KeStackAttachProcess` | Não existe — remover |
| `IoCreateDevice` / `IoCreateSymbolicLink` | Não existe — substituir por shared memory ou CPUID-only |
| `DeviceIoControl` / IRP dispatch | Não existe — toda comunicação via CPUID leaf |
| `vDbgPrintEx` | `Print()` do EDK2 / `gST->ConOut->OutputString` |
| `RtlCaptureContext` | Implementar manualmente em assembly UEFI |
| `ShvOsRestoreContext2` (iretq) | Reescrever — UEFI não tem syscall/iretq do Windows |
| `ExRegisterCallback` (PowerCallback) | Registrar `EFI_EVENT` de `EVT_SIGNAL_EXIT_BOOT_SERVICES` |
| `KeGetCurrentProcessorNumberEx` | `MpServices->WhoAmI` |
| `KeQueryActiveProcessorCountEx` | `MpServices->GetNumberOfProcessors` |

---

## 2. Interface de comunicação — IOCTL → CPUID puro

O transporte atual usa `DeviceIoControl` (`\\.\SimpleVisor`), que não existe em UEFI.

**Mudança:** toda comunicação passa a ser via CPUID leaf `0x80000042` (já implementado).
- Comandos que hoje chegam via IOCTL (hook, unhook, translate, read) precisam ser
  encodados em sub-leaves CPUID ou via **shared memory** alocada pelo hypervisor e
  exposta ao guest por outro sub-leaf.
- Sugestão: sub-leaf `SHV_QUERY_SHARED_MEM_BASE` retorna o PA de um buffer de
  comunicação; guest escreve `SHV_REQUEST`, faz CPUID para notificar, lê `SHV_RESPONSE`.

Arquivos afetados: `shv_comm.h`, `shv_dbg.h`, `nt/shvos.c`, `shvvmxhv.c`.

---

## 3. `SHV_CMD_LIST_PROCS` e `DirBase` — remover ou reimplementar

`ZwQuerySystemInformation(SystemProcessInformation)` não existe em UEFI.
`PageDirectoryBase` dentro dessa struct já está errado no Windows 10 (campo virou
`UniqueProcessKey` em `+0x068`).

**Mudança:**
- Remover `SHV_CMD_LIST_PROCS` e `SHV_CMD_LIST_MODULES` da interface (sem SO guest,
  sem lista de processos/módulos no pré-boot).
- Se necessário em runtime UEFI, expor `GUEST_CR3` via sub-leaf CPUID em vez de
  tentar ler structs do SO guest.

---

## 4. Tradução VA→PA (`SHV_CMD_TRANSLATE_VA`)

Hoje usa `MmGetPhysicalAddress` (Windows) e `KeStackAttachProcess` para processos.

**Mudança:** em UEFI pre-boot VA=PA (identity map), então a tradução é trivial.
Para runtime UEFI com SO guest, o hypervisor pode implementar um walker de page tables
usando o `GUEST_CR3` do VMCS — portável e sem dependência de API do SO.

---

## 5. `ShvReadGuestReturnAddress` — acesso direto à stack do guest

```c
// shvvmxhv.c
return *(volatile UINT64*)rsp;
```

Acessa diretamente um endereço de kernel Windows (`>= 0xFFFF800000000000`) assumindo
que está mapeado no host CR3 do SYSTEM process.

**Mudança:** em UEFI o host CR3 é diferente. A verificação de range precisa usar o
memory map do UEFI, ou o acesso deve ser feito via walker de page tables do guest
(traduzir RSP guest VA → PA → ler via direct map do host).

---

## 6. `ShvVmxCleanup` — segmentos DS/ES/FS pós-iretq

```c
// nt/shvos.c — ShvOsDpcRoutine
ShvVmxCleanup(KGDT64_R3_DATA | RPL_MASK, KGDT64_R3_CMTEB | RPL_MASK);
```

Corrige segmentos corrompidos pelo `iretq` do Windows. Em UEFI os segmentos são flat
(CS=0x38, DS=0x30 típico no EDK2) e esse problema não ocorre.

**Mudança:** remover a chamada; a função pode ser um no-op em UEFI.

---

## 7. `PowerCallback` — suspend/resume

Registra callback de energia para reload do hypervisor em S3 resume.

**Mudança:** substituir por `EFI_EVENT` do tipo `EVT_SIGNAL_EXIT_BOOT_SERVICES` para
descarregar antes do SO tomar controle, e por ACPI S3 resume path se necessário.

---

## 8. `KERNEL_STACK_SIZE = 24 KB` — tamanho da stack do hypervisor

Definido em `ntint.h`. O valor de 24 KB é o tamanho padrão de stack de kernel thread
no Windows.

**Mudança:** em UEFI a stack padrão é menor (8 KB no EDK2). Avaliar se 24 KB ainda é
adequado ou reduzir. O `C_ASSERT` em `shv_x.h` garante que o tamanho da struct bate.

---

## 9. Alocação de memória contígua — `MmAllocateContiguousNodeMemory`

Aloca memória contígua fisicamente para o `SHV_VP_DATA` de cada CPU.

**Mudança:** `gBS->AllocatePages(AllocateAnyPages, EfiBootServicesData, pages, &addr)`
já retorna memória fisicamente contígua por página. Para alinhamento de página usar
`AllocateAlignedPages` se disponível, ou alinhar manualmente.

---

## 10. Símbolos de debug (`ShvGlobalData`, `ShvExitCount`, etc.)

Hoje expostos como globais para inspeção via WinDbg.

**Mudança:** em UEFI não há WinDbg. Expor via sub-leaves CPUID ou via shared memory
(ver item 2). Os globais podem ser mantidos para UEFI shell debuggers (como o
`EFI Shell` com extensão de debug).

---

## Resumo — o que NÃO muda

- `shvvmx.c` — setup do VMCS: portável, pura Intel VT-x
- `shvvmxhv.c` — handler de VM-exits: portável (exceto item 5 acima)
- `shv_x.h`, `vmx.h` — structs e defines Intel: portáveis
- `shv_comm.h` — protocolo CPUID: portável
- `shvvp.c` — lógica de VP load/unload: quase portável (remover `ShvGlobalData` NT-specific)
- Tabela de hooks EPT (`ShvHookTable`, `ShvHookInstall`, `ShvHookRemove`): portável
- Ring buffer de eventos (`ShvEventBuffer`, `ShvHvPushEvent`): portável

/*++

Module Name:

    shvos_internal.h

Abstract:

    Declaracoes compartilhadas entre os modulos NT do SimpleVisor
    (nt/shvos*.c, nt/hpv_*.c). Nao inclui shv.h (conflita com ntifs.h,
    igual o resto do codigo NT) -- repete os poucos tipos/externs que
    precisam ser identicos aos de shv.h/shvvmxhv.c.

    Cada .c que usa algo daqui ja deve ter incluido <ntifs.h>/<intrin.h>
    antes deste header.

Environment:

    Kernel mode only.

--*/

#pragma once

#include "../shv_dbg.h"   // SHV_SHADOW_PAGE_RECORD, SHV_SYSCALL_HOOK_ENTRY, SHV_SHADOW_MAX, etc.

// ============================================================
// Funcoes do hipervisor (definidas em shvvmxhv.c) usadas pelo lado NT.
// Repetidas aqui (nao incluimos shv.h) para evitar conflito com ntifs.h.
// ============================================================
#ifndef SHV_HOOK_MAX_ENTRIES
#define SHV_HOOK_MAX_ENTRIES 256
#endif

UINT32 ShvHookInstall(_In_ UINT64 PhysAddr, _In_ UINT8 HookType, _In_ UINT64 VirtAddr, _In_ UINT64 Pid, _In_ UINT64 RangeSize, _In_ UINT64 ByteLen);
UINT32 ShvListEptHooks(_Out_writes_(MaxCount) VOID* OutBuffer, _In_ UINT32 MaxCount, _In_ UINT32 EntrySize);
UINT32 ShvHookRemove(_In_ UINT64 PhysAddr);
UINT32 ShvHookRemoveByPid(_In_ UINT64 Pid, _Out_writes_to_(MaxOut, return) UINT64* OutPhysAddrs, _In_ UINT32 MaxOut);
VOID   ShvHookRemoveAll(VOID);
// MDL helpers: mantem paginas user-mode travadas para o PA nao mudar durante o hook.
// PMDL e definido por <ntifs.h> que todo .c NT inclui antes deste header.
VOID   ShvHookSetMdl(_In_ UINT64 Pa, _In_ PMDL Mdl);
PMDL   ShvHookTakeMdl(_In_ UINT64 Pa);
VOID   ShvHookReleaseMdls(VOID);
VOID   ShvClearEvents(VOID);
VOID   ShvSetStackFilterEnabled(_In_ UINT8 Enabled);
UINT32 ShvHookInstallShadow(_In_ UINT64 OriginalPhys, _In_ UINT64 ShadowPhys);
UINT32 ShvHookRemoveShadow(_In_ UINT64 OriginalPhys);
UINT32 ShvHookFreeSlot(_In_ UINT64 OriginalPhys);
VOID   ShvVmxClearRestoreTables(VOID);

extern UINT8 ShvEptExecuteOnlySupported;
extern UINT64 ShvOriginalLstar;
extern UINT64 ShvDirectMapBase;    // obsoleto, ver ShvPaRanges
extern volatile UINT64 ShvSyscallHookVa;

// Tabela de regioes do direct physical map (shvvmxhv.c) -- layout precisa
// ficar identico ao de shv.h/shvvmxhv.c.
#define SHV_MAX_PA_RANGES 64

typedef struct _SHV_PA_RANGE
{
    UINT64 BasePa;
    UINT64 BaseVa;
    UINT64 SizeBytes;
} SHV_PA_RANGE, *PSHV_PA_RANGE;

extern SHV_PA_RANGE ShvPaRanges[SHV_MAX_PA_RANGES];
extern volatile UINT32 ShvPaRangeCount;

// ============================================================
// Estado do motor de hooks (shadow pages + trampolim).
// Tipos definidos em shv_dbg.h (incluido acima). Definicoes em shvvmxhv.c.
// ============================================================

extern SHV_SHADOW_PAGE_RECORD  g_ShadowPages[SHV_SHADOW_MAX];
extern void*                   g_TrampolinePool;
extern UINT32                  g_TrampolineUsed;
extern SHV_SYSCALL_HOOK_ENTRY  g_SyscallHooks[SHV_SYSCALL_HOOK_MAX];

// nt/shvos.c -- forca TODOS os CPUs a processar um VM-exit (via KeGenericCallDpc)
// antes de retornar, garantindo que cada vCPU reaplicou ShvHookTable (e rodou
// INVEPT local) com a versao atual. So entao e seguro liberar memoria fisica
// que deixou de estar referenciada no EPT (ex.: shadow page apos unhook).
VOID     ShvOsForceAllCpuVmExit(VOID);

// nt/hpv_hooks.c
VOID     ShvFlushHooksAllCpus(VOID);
UINT32   ShvInstrLen(_In_ const UINT8* p);
NTSTATUS HpvTrampolinePoolInit(VOID);
VOID     HpvTrampolinePoolFree(VOID);
VOID     HpvShadowPagesReleaseAll(VOID);
NTSTATUS HpvHookFuncByVa(_In_ PVOID FuncVa, _In_ PVOID HookFunc, _Out_ PVOID* OriginalFunc);
NTSTATUS HpvHookFuncByName(_In_ PCWSTR FuncName, _In_ PVOID HookFunc, _Out_ PVOID* OriginalFunc);
NTSTATUS HpvUnhookFuncByVa(_In_ PVOID FuncVa);
NTSTATUS HpvShadowPatchAddress(_In_reads_bytes_(Size) const VOID* Buffer, _In_ PVOID Address, _In_ SIZE_T Size);

// nt/hpv_pattern.c -- busca de assinatura de bytes (pattern/signature scan),
// usada pra achar funcoes NAO exportadas do ntoskrnl.exe (MmGetSystemRoutineAddress
// so resolve exports). Mascara: 'x' = compara o byte, qualquer outro char = wildcard.
UINT64 HpvFindPattern(_In_ UINT64 Base, _In_ SIZE_T Size, _In_ const UINT8* Pattern, _In_z_ const CHAR* Mask);
BOOLEAN HpvFindNtoskrnlTextSection(_Out_ UINT64* Base, _Out_ SIZE_T* Size);
BOOLEAN HpvFindNtoskrnlModule(_Out_ UINT64* Base, _Out_ SIZE_T* Size);

// nt/shvos.c -- limpa MDL/EPT hooks de um PID que terminou (ver PspExitProcess
// hook em hpv_policy_hooks.c).
VOID ShvCleanupExitedProcess(_In_ UINT64 Pid);

// nt/shvos.c -- acha o primeiro processo cujo ImageName bate com Name
// (case-insensitive). *OutProcess sai referenciado (ObDereferenceObject
// depois de usar). Usado por nt/hpv_win32k_hooks.c pra achar o winlogon.exe
// antes de dar KeStackAttachProcess (win32k.sys e por sessao, nao global).
NTSTATUS ShvOsFindProcessByName(_In_z_ PCSTR Name, _Out_ PEPROCESS* OutProcess);

// nt/shvos.c -- acha a base de um modulo de kernel (incl. win32k.sys/
// win32kfull.sys, carregado por sessao) pelo nome de arquivo. Chamar com o
// processo atual ja attached na sessao desejada (ver nt/hpv_win32k_hooks.c).
NTSTATUS ShvOsFindKernelModuleBase(_In_z_ PCSTR Name, _Out_ PVOID* OutBase);

// nt/hpv_hooks_legacy.c -- SSDT + LSTAR, NAO usados atualmente em nenhum
// caminho ativo (ver comentario no topo do arquivo). Mantidos pra estudo.
NTSTATUS ShvSsdtGetFuncVa(_In_ ULONG SyscallIndex, _Out_ PVOID* FuncVa);
NTSTATUS ShvSsdtGetIndexByVa(_In_ PVOID FuncVa, _Out_ PULONG Index);
NTSTATUS HpvHookSyscall(_In_ ULONG SyscallIndex, _In_ PVOID HookFunc, _Out_ PVOID* OriginalFunc);
NTSTATUS HpvUnhookSyscall(_In_ ULONG SyscallIndex);
NTSTATUS ShvLstarHookInit(_In_ UINT32 NtopIdx, _In_ PVOID FilterFunc);
VOID     ShvLstarHookUninit(VOID);

// nt/hpv_policy_hooks.c
extern volatile UINT64 ShvReadVirtualMemoryHookHitCount;
NTSTATUS ShvPolicyHooksInit(VOID);
VOID     ShvPolicyHooksUninit(VOID);

// nt/hpv_registry_hooks.c -- monitoramento de acesso a registro (ZwOpenKey/
// ZwOpenKeyEx/ZwCreateKey/ZwQueryKey) de processos monitorados.
NTSTATUS ShvRegistryHooksInit(VOID);
VOID     ShvRegistryHooksUninit(VOID);
UINT32   ShvRegistryListEvents(_Out_writes_(MaxCount) SHV_REGISTRY_EVENT* Out, _In_ UINT32 MaxCount);
VOID     ShvRegistryClearEvents(VOID);

// nt/hpv_win32k_hooks.c -- shadow hook em NtGdiBitBlt (win32kfull.sys,
// carregado por sessao -- precisa de attach num processo Win32 interativo
// pra resolver/instalar, ver comentario no topo do arquivo).
NTSTATUS ShvWin32kHooksInit(VOID);
VOID     ShvWin32kHooksUninit(VOID);

// nt/hpv_memprotect_hooks.c -- shadow hook em ZwAllocateVirtualMemory/
// ZwProtectVirtualMemory, monitora paginas executaveis surgindo na memoria
// de processos monitorados (alocacao RWX/RX ou mudanca de protecao
// adicionando execucao -- padrao de shellcode/injecao).
NTSTATUS ShvMemProtectHooksInit(VOID);
VOID     ShvMemProtectHooksUninit(VOID);

// nt/shvos_log.c
VOID ShvLog(_In_z_ _Printf_format_string_ const char* Fmt, ...);

// nt/shvos_beep.c (so existe quando SHV_COMM_MODE == SHV_COMM_BEEP_HIJACK)
NTSTATUS ShvBeepHijackSetup(VOID);
VOID     ShvBeepHijackTeardown(VOID);
PDRIVER_DISPATCH ShvBeepGetOriginalControl(VOID);
NTSTATUS ShvBeepGetDriverObject(_Out_ PDRIVER_OBJECT* OutObject);

// nt/shvos_beep.c -- Etapa 2 (SHV_CMD_BEEP_SHADOW_SETUP): upgrade do hijack
// de tabela pra shadow hook via EPT na funcao original do Beep. Chamar
// ShvBeepShadowTeardown no DriverUnload ANTES do VMXOFF.
NTSTATUS ShvBeepShadowSetup(_Out_ UINT64* OutGpa);
VOID     ShvBeepShadowTeardown(VOID);

// nt/shvos_beep.c -- downgrade de volta pra Etapa 1 (hijack de tabela),
// usado pelo checkbox "Beep Shadow" da GUI ao desmarcar: mantem a
// comunicacao funcionando (diferente de ShvBeepShadowTeardown, so usada no
// DriverUnload, onde a comunicacao nao precisa mais continuar).
NTSTATUS ShvBeepShadowRemove(VOID);

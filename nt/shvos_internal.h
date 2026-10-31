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
UINT32 ShvHookInstall(_In_ UINT64 PhysAddr, _In_ UINT8 HookType);
UINT32 ShvListEptHooks(_Out_writes_(MaxCount) VOID* OutBuffer, _In_ UINT32 MaxCount, _In_ UINT32 EntrySize);
UINT32 ShvHookRemove(_In_ UINT64 PhysAddr);
VOID   ShvHookRemoveAll(VOID);
// MDL helpers: mantem paginas user-mode travadas para o PA nao mudar durante o hook.
// PMDL e definido por <ntifs.h> que todo .c NT inclui antes deste header.
VOID   ShvHookSetMdl(_In_ UINT64 Pa, _In_ PMDL Mdl);
PMDL   ShvHookTakeMdl(_In_ UINT64 Pa);
VOID   ShvHookReleaseMdls(VOID);
VOID   ShvClearEvents(VOID);
UINT32 ShvHookInstallShadow(_In_ UINT64 OriginalPhys, _In_ UINT64 ShadowPhys);
UINT32 ShvHookRemoveShadow(_In_ UINT64 OriginalPhys);
VOID   ShvVmxClearRestoreTables(VOID);

extern UINT8 ShvEptExecuteOnlySupported;
extern UINT64 ShvOriginalLstar;
extern UINT64 ShvDirectMapBase;    // obsoleto, ver ShvPaRanges
extern UINT64 ShvSystemCr3;
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

// nt/hpv_hooks.c
VOID     ShvFlushHooksAllCpus(VOID);
UINT32   ShvInstrLen(_In_ const UINT8* p);
NTSTATUS HpvTrampolinePoolInit(VOID);
VOID     HpvTrampolinePoolFree(VOID);
NTSTATUS HpvHookFuncByVa(_In_ PVOID FuncVa, _In_ PVOID HookFunc, _Out_ PVOID* OriginalFunc);
NTSTATUS HpvHookFuncByName(_In_ PCWSTR FuncName, _In_ PVOID HookFunc, _Out_ PVOID* OriginalFunc);
NTSTATUS HpvUnhookFuncByVa(_In_ PVOID FuncVa);
NTSTATUS HpvShadowPatchAddress(_In_reads_bytes_(Size) const VOID* Buffer, _In_ PVOID Address, _In_ SIZE_T Size);

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

// nt/shvos_log.c
VOID ShvLog(_In_z_ _Printf_format_string_ const char* Fmt, ...);

// nt/shvos_beep.c (so existe quando SHV_COMM_MODE == SHV_COMM_BEEP_HIJACK)
NTSTATUS ShvBeepHijackSetup(VOID);
VOID     ShvBeepHijackTeardown(VOID);
PDRIVER_DISPATCH ShvBeepGetOriginalControl(VOID);
NTSTATUS ShvBeepGetDriverObject(_Out_ PDRIVER_OBJECT* OutObject);

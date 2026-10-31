/*++

Module Name:

    shvhooks.h

Abstract:

    API de hooks de syscall de alto nivel para SimpleVisor.
    Atualmente implementa NtOpenProcess com protecao e monitoramento por PID.

    Listas acumulativas: cada chamada adiciona um PID a lista existente.
    O mesmo PID pode ser adicionado a protecao e monitoramento simultaneamente.

--*/

#pragma once

#include "shv_dbg.h"

#define SHV_HOOKS_MAX_PROCS  32   // max PIDs por lista (protegidos ou monitorados)
#define SHV_HOOKS_MAX_NAMES  32   // max nomes por lista (protegidos ou monitorados por nome)

// Listas de PIDs exportadas para leitura lock-free pelo hook inline
// (HpvOpenProcessHook em shvos.c). Escritas atomicamente (UINT64/UINT32
// alinhados), lidas sem lock -- seguro pois a escrita e feita so por IOCTL
// enquanto o leitor apenas itera sobre uma contagem estavel por chamada.
extern volatile UINT64 ShvHookProtectedPids[SHV_HOOKS_MAX_PROCS];
extern volatile UINT32 ShvHookProtectedCount;
extern volatile UINT64 ShvHookMonitoredPids[SHV_HOOKS_MAX_PROCS];
extern volatile UINT32 ShvHookMonitoredCount;

//
// Inicializa o subsistema de hooks: instala NtOpenProcess hook via HpvHookSyscall.
// Chame em DriverEntry, apos HpvTrampolinePoolInit() e ShvLoad().
//
NTSTATUS ShvHooksInit(VOID);

//
// Desinicializa: remove o NtOpenProcess hook via HpvUnhookSyscall.
// Chame em ShvDoUnload, antes de HpvTrampolinePoolFree().
//
VOID ShvHooksUninit(VOID);

//
// Adiciona/remove PID da lista de PROTEGIDOS.
// OpenProcess por processo nao-confiavel retorna STATUS_ACCESS_DENIED.
// Pode ser chamado multiplas vezes para acumular PIDs.
//
NTSTATUS ShvHooksAddProtected(_In_ UINT64 Pid);
NTSTATUS ShvHooksRemoveProtected(_In_ UINT64 Pid);

//
// Adiciona/remove PID da lista de MONITORADOS.
// Cada OpenProcess e logado em C:\SimpleVisor.txt.
// Pode ser chamado multiplas vezes para acumular PIDs.
//
NTSTATUS ShvHooksAddMonitored(_In_ UINT64 Pid);
NTSTATUS ShvHooksRemoveMonitored(_In_ UINT64 Pid);

//
// Retorna TRUE se Name consta em g_AutoMonitorNames (verificacao por nome,
// usada pelo hook NtOpenProcess para monitorar processos sem PID pre-cadastrado).
//
BOOLEAN ShvHooksIsAutoMonitorName(_In_opt_ PCHAR Name);

//
// Adiciona/remove nome da lista de PROTEGIDOS por nome.
//
NTSTATUS ShvHooksAddProtectedName(_In_ const char* Name);
NTSTATUS ShvHooksRemoveProtectedName(_In_ const char* Name);

//
// Adiciona/remove nome da lista de MONITORADOS por nome.
//
NTSTATUS ShvHooksAddMonitoredName(_In_ const char* Name);
NTSTATUS ShvHooksRemoveMonitoredName(_In_ const char* Name);

//
// Preenche Out com as entradas das listas de filtros (protegidos + monitorados).
// Nome do processo e resolvido no momento da chamada.
// Retorna o numero de entradas via *Count.
//
VOID ShvHooksListFilters(
    _Out_writes_(MaxCount) SHV_PROC_FILTER_ENTRY* Out,
    _Out_ UINT32* Count,
    _In_  UINT32  MaxCount
    );

//
// Verifica se Pid pertence a alguma lista de nome (protegidos/monitorados por nome).
// Resolve o nome do processo internamente. Requer IRQL <= APC_LEVEL.
//
VOID ShvHooksCheckPid(
    _In_  UINT64    Pid,
    _Out_ BOOLEAN*  pProtected,
    _Out_ BOOLEAN*  pMonitored
    );

//
// Retorna TRUE se Name esta na lista interna de processos confiaveis do SO.
//
BOOLEAN ShvHooksIsTrustedName(_In_opt_ const char* Name);

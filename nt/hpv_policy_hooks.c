/*++

Module Name:

    hpv_policy_hooks.c

Abstract:

    EPT shadow hook de politica de acesso para SimpleVisor.

    Hook instalado via HpvHookFuncByName (split-page EPT):
      - NtOpenProcess: bloqueia abertura de handles para processos protegidos.

    A lista de PIDs/nomes protegidos e monitorados e gerenciada por shvhooks.c.

Environment:

    Kernel mode only, PASSIVE_LEVEL (chamado pelo caminho de system call).

--*/

#pragma warning(disable:4996)
#pragma warning(disable:4152)  // conversao ponteiro de funcao / dado
#include <ntifs.h>
#include <intrin.h>
#include "..\shv_dbg.h"
#include "..\shvhooks.h"
#include "shvos_internal.h"

// PsGetProcessImageFileName nao declarado em todos os ntifs.h
NTKERNELAPI PCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

// ============================================================
// Contador: total de chamadas interceptadas em MmCopyVirtualMemory
// (antes so existia pra compatibilidade de ABI, sempre 0 -- agora
// incrementado de verdade pelo hook abaixo).
// ============================================================
volatile UINT64 ShvReadVirtualMemoryHookHitCount = 0;

// ============================================================
// Tipo de trampolim
// ============================================================
typedef NTSTATUS (NTAPI* PfnNtOpenProcess)(
    _Out_    PHANDLE            ProcessHandle,
    _In_     ACCESS_MASK        DesiredAccess,
    _In_     POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID         ClientId
    );

static PfnNtOpenProcess g_OrigNtOpenProcess = NULL;

// MmCopyVirtualMemory nao e declarada em todos os ntifs.h/wdm.h desta WDK --
// resolvida dinamicamente por nome via HpvHookFuncByName (MmGetSystemRoutineAddress),
// entao so precisamos do tipo do trampolim, nao de uma declaracao estatica importada.
typedef NTSTATUS (NTAPI* PfnMmCopyVirtualMemory)(
    _In_  PEPROCESS       FromProcess,
    _In_  PVOID           FromAddress,
    _In_  PEPROCESS       ToProcess,
    _Out_ PVOID           ToAddress,
    _In_  SIZE_T          BufferSize,
    _In_  KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T         NumberOfBytesCopied
    );

static PfnMmCopyVirtualMemory g_OrigMmCopyVirtualMemory = NULL;

// ============================================================
// Helpers internos
// ============================================================
static BOOLEAN PidProtected(_In_ UINT64 Pid)
{
    UINT32 i;
    for (i = 0; i < ShvHookProtectedCount; i++)
        if (ShvHookProtectedPids[i] == Pid) return TRUE;
    return FALSE;
}

static BOOLEAN PidMonitored(_In_ UINT64 Pid)
{
    UINT32 i;
    for (i = 0; i < ShvHookMonitoredCount; i++)
        if (ShvHookMonitoredPids[i] == Pid) return TRUE;
    return FALSE;
}

// Verifica protecao/monitoramento por PID e por nome.
// NtOpenProcess e chamado com baixa frequencia, entao o custo e aceitavel.
static VOID CheckProcess(
    _In_  UINT64   Pid,
    _Out_ BOOLEAN* pProt,
    _Out_ BOOLEAN* pMon
    )
{
    BOOLEAN np = FALSE, nm = FALSE;

    *pProt = PidProtected(Pid);
    *pMon  = PidMonitored(Pid);

    if (!(*pProt) || !(*pMon))
    {
        ShvHooksCheckPid(Pid, &np, &nm);
        if (np) *pProt = TRUE;
        if (nm) *pMon  = TRUE;
    }
}

// ============================================================
// Hook: NtOpenProcess
// ============================================================
static NTSTATUS NTAPI HpvOpenProcessHook(
    _Out_    PHANDLE            ProcessHandle,
    _In_     ACCESS_MASK        DesiredAccess,
    _In_     POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID         ClientId
    )
{
    UINT64  targetPid   = 0;
    BOOLEAN isProtected = FALSE;
    BOOLEAN isMonitored = FALSE;

    if (ClientId != NULL)
    {
        __try
        {
            targetPid = (UINT64)(ULONG_PTR)ClientId->UniqueProcess;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    if (targetPid != 0)
    {
        CheckProcess(targetPid, &isProtected, &isMonitored);

        if (isMonitored)
        {
            PCHAR cn = PsGetProcessImageFileName(PsGetCurrentProcess());
            ShvLog("[POLICY] NtOpenProcess: caller=%s (PID=%llu) -> PID=%llu access=0x%08X\n",
                   cn ? cn : "?",
                   (UINT64)(ULONG_PTR)PsGetCurrentProcessId(),
                   targetPid, (UINT32)DesiredAccess);
        }

        if (isProtected)
        {
            PCHAR cn = PsGetProcessImageFileName(PsGetCurrentProcess());
            if (!ShvHooksIsTrustedName(cn))
            {
                ShvLog("[POLICY] NtOpenProcess BLOQUEADO: caller=%s -> PID=%llu\n",
                       cn ? cn : "?", targetPid);
                return STATUS_ACCESS_DENIED;
            }
        }
    }

    return g_OrigNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

// ============================================================
// Hook: MmCopyVirtualMemory
// ============================================================
// Usada pelo kernel pra copiar memoria entre processos (NtReadVirtualMemory/
// NtWriteVirtualMemory -> ReadProcessMemory/WriteProcessMemory em usermode,
// e tambem por drivers que fazem acesso cross-process diretamente). Dispara
// com FromProcess != ToProcess tipicamente num read/write cross-process real
// (o caso que a aba Eventos->EPT ja tenta identificar via GUEST_CR3, mas aqui
// pegamos o PID/PEPROCESS de verdade dos dois lados, sem precisar inferir).
static NTSTATUS NTAPI HpvCopyVirtualMemoryHook(
    _In_  PEPROCESS       FromProcess,
    _In_  PVOID           FromAddress,
    _In_  PEPROCESS       ToProcess,
    _Out_ PVOID           ToAddress,
    _In_  SIZE_T          BufferSize,
    _In_  KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T         NumberOfBytesCopied
    )
{
    UINT64  fromPid = 0, toPid = 0;
    BOOLEAN fromProt = FALSE, fromMon = FALSE;
    BOOLEAN toProt   = FALSE, toMon   = FALSE;

    _InterlockedIncrement64((LONG64*)&ShvReadVirtualMemoryHookHitCount);

    __try
    {
        if (FromProcess) fromPid = (UINT64)(ULONG_PTR)PsGetProcessId(FromProcess);
        if (ToProcess)   toPid   = (UINT64)(ULONG_PTR)PsGetProcessId(ToProcess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (fromPid != 0) CheckProcess(fromPid, &fromProt, &fromMon);
    if (toPid   != 0) CheckProcess(toPid,   &toProt,   &toMon);

    if (fromMon || toMon)
    {
        // Nome do processo sendo LIDO (FromProcess) -- PsGetProcessImageFileName
        // so exige que o processo exista (sem __try: nao toca memoria de
        // usuario, so le o campo ImageFileName do proprio EPROCESS).
        PCHAR fromName = FromProcess ? PsGetProcessImageFileName(FromProcess) : NULL;
        ShvLog("[POLICY] MmCopyVirtualMemory: From PID=%llu (%s) @%p -> To PID=%llu @%p (size=%zu)\n",
               fromPid, fromName ? fromName : "?", FromAddress, toPid, ToAddress, BufferSize);
    }

    // So bloqueia leitura de um processo PROTEGIDO por outro processo nao
    // confiavel -- mesma politica/excecao de nome confiavel que NtOpenProcess
    // ja usa, pra nao quebrar ferramentas legitimas do proprio sistema
    // (ex.: o antivirus escaneando memoria) que tambem passam por aqui.
    if (fromProt)
    {
        PCHAR cn = PsGetProcessImageFileName(PsGetCurrentProcess());
        if (!ShvHooksIsTrustedName(cn))
        {
            PCHAR fromName = FromProcess ? PsGetProcessImageFileName(FromProcess) : NULL;
            ShvLog("[POLICY] MmCopyVirtualMemory BLOQUEADO: caller=%s -> PID=%llu (%s)\n",
                   cn ? cn : "?", fromPid, fromName ? fromName : "?");
            if (NumberOfBytesCopied) *NumberOfBytesCopied = 0;
            return STATUS_ACCESS_DENIED;
        }
    }

    return g_OrigMmCopyVirtualMemory(FromProcess, FromAddress, ToProcess, ToAddress,
                                      BufferSize, PreviousMode, NumberOfBytesCopied);
}

// ============================================================
// API publica
// ============================================================
NTSTATUS ShvPolicyHooksInit(VOID)
{
    NTSTATUS status;
    PVOID    origFunc;

    status = HpvHookFuncByName(L"NtOpenProcess",
                                HpvOpenProcessHook,
                                &origFunc);
    if (!NT_SUCCESS(status))
    {
        ShvLog("[POLICY] HpvHookFuncByName(NtOpenProcess) falhou: 0x%08X\n", status);
        return status;
    }

    g_OrigNtOpenProcess = (PfnNtOpenProcess)origFunc;
    ShvLog("[POLICY] NtOpenProcess shadow hook OK (trampoline=%p)\n", origFunc);

    status = HpvHookFuncByName(L"MmCopyVirtualMemory",
                                HpvCopyVirtualMemoryHook,
                                &origFunc);
    if (!NT_SUCCESS(status))
    {
        // Nao fatal -- NtOpenProcess ja esta hookeado e e o hook critico;
        // MmCopyVirtualMemory e um bonus (visibilidade sobre ReadProcessMemory).
        ShvLog("[POLICY] HpvHookFuncByName(MmCopyVirtualMemory) falhou: 0x%08X (nao fatal)\n", status);
    }
    else
    {
        g_OrigMmCopyVirtualMemory = (PfnMmCopyVirtualMemory)origFunc;
        ShvLog("[POLICY] MmCopyVirtualMemory shadow hook OK (trampoline=%p)\n", origFunc);
    }

    return STATUS_SUCCESS;
}

VOID ShvPolicyHooksUninit(VOID)
{
    if (g_OrigNtOpenProcess != NULL)
    {
        UNICODE_STRING ustr;
        PVOID funcVa;
        RtlInitUnicodeString(&ustr, L"NtOpenProcess");
        funcVa = MmGetSystemRoutineAddress(&ustr);
        if (funcVa)
            HpvUnhookFuncByVa(funcVa);
        g_OrigNtOpenProcess = NULL;
        ShvLog("[POLICY] NtOpenProcess hook removido\n");
    }

    if (g_OrigMmCopyVirtualMemory != NULL)
    {
        UNICODE_STRING ustr;
        PVOID funcVa;
        RtlInitUnicodeString(&ustr, L"MmCopyVirtualMemory");
        funcVa = MmGetSystemRoutineAddress(&ustr);
        if (funcVa)
            HpvUnhookFuncByVa(funcVa);
        g_OrigMmCopyVirtualMemory = NULL;
        ShvLog("[POLICY] MmCopyVirtualMemory hook removido\n");
    }
}

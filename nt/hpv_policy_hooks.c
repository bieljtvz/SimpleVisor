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
// Contador exportado (mantido para compatibilidade de ABI; sempre 0)
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
}

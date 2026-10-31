/*++

Module Name:

    shvhooks.c

Abstract:

    Hooks de syscall de alto nivel para SimpleVisor.

    NtOpenProcess por PID via ObRegisterCallbacks:
      - Protecao: bloqueia OpenProcess de processos nao-confiaveis para
                  qualquer PID na lista de protegidos (STATUS_ACCESS_DENIED).
      - Monitor:  loga cada OpenProcess para PIDs na lista de monitorados
                  em C:\SimpleVisor.txt.

    ObRegisterCallbacks é o mecanismo oficial do kernel (PG-safe, KPTI-safe).
    Funciona registrando um pre-callback em PsProcessType que intercepta
    criacao de handles antes do kernel conceder acesso.

--*/

#include <ntifs.h>
#include <intrin.h>
#include <ntstrsafe.h>
#include "..\shv_dbg.h"
#include "..\shvhooks.h"

// -----------------------------------------------------------------------
// PsGetProcessImageFileName nao e declarado em todos os ntifs.h do WDK.
// -----------------------------------------------------------------------
NTKERNELAPI PCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

VOID ShvLog(_In_z_ _Printf_format_string_ const char* Fmt, ...);

// -----------------------------------------------------------------------
// Tipos
// -----------------------------------------------------------------------

typedef struct _CLIENT_ID_SHV {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID_SHV, *PCLIENT_ID_SHV;

// -----------------------------------------------------------------------
// Estado do modulo
// -----------------------------------------------------------------------

static FAST_MUTEX g_FilterMutex;

// Exportadas para o hypervisor ler em VMX root mode (lock-free, escrita atomica de 64 bits).
// O hipervisor le ShvHookProtectedPids para decisao de ALLOW/DENY em ShvSyscallDispatch.
volatile UINT64 ShvHookProtectedPids[SHV_HOOKS_MAX_PROCS];
volatile UINT32 ShvHookProtectedCount = 0;

volatile UINT64 ShvHookMonitoredPids[SHV_HOOKS_MAX_PROCS];
volatile UINT32 ShvHookMonitoredCount = 0;

// Aliases locais para o restante do modulo
#define g_ProtectedPids   ShvHookProtectedPids
#define g_ProtectedCount  ShvHookProtectedCount
#define g_MonitoredPids   ShvHookMonitoredPids
#define g_MonitoredCount  ShvHookMonitoredCount

static BOOLEAN g_Installed        = FALSE;
static PVOID   g_ObCallbackHandle = NULL;

// Listas de nomes para filtro por nome (protecao e monitoramento)
static char   g_ProtectedNames[SHV_HOOKS_MAX_NAMES][SHV_PROC_NAME_LEN];
static UINT32 g_ProtectedNamesCount = 0;
static char   g_MonitoredNames[SHV_HOOKS_MAX_NAMES][SHV_PROC_NAME_LEN];
static UINT32 g_MonitoredNamesCount = 0;

// Processos adicionados automaticamente ao monitoramento quando o driver carrega.
// Adicione novos nomes aqui -- NULL termina a lista.
// Maximo SHV_PROC_NAME_LEN-1 caracteres, comparacao case-insensitive.
static const char* const g_AutoMonitorNames[] = {
    "crossfire.exe",
    NULL
};

// Processos do SO que sempre podem abrir qualquer processo sem bloqueio.
static const char* const g_TrustedProcs[] = {
    "System",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "WerFault.exe",
    "WerFaultSecure.exe",
    "MsMpEng.exe",
    "SgrmBroker.exe",
    "taskhostw.exe",
    "dwm.exe",
    NULL
};

// -----------------------------------------------------------------------
// Helpers internos
// -----------------------------------------------------------------------

static BOOLEAN ShvStrEqiA(_In_ const char* a, _In_ const char* b)
{
    while (*a && *b)
    {
        char ca = (*a >= 'A' && *a <= 'Z') ? (char)(*a + 32) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (char)(*b + 32) : *b;
        if (ca != cb) return FALSE;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

static VOID ShvCopyStrA(
    _Out_writes_(DstLen) char* Dst,
    _In_ SIZE_T DstLen,
    _In_ const char* Src
    )
{
    SIZE_T i = 0;
    while (i < DstLen - 1 && Src[i]) { Dst[i] = Src[i]; i++; }
    Dst[i] = '\0';
}

static BOOLEAN IsTrustedProc(_In_ const char* Name)
{
    for (int i = 0; g_TrustedProcs[i] != NULL; i++)
        if (ShvStrEqiA(Name, g_TrustedProcs[i])) return TRUE;
    return FALSE;
}

static BOOLEAN NameInList(_In_ char Names[][SHV_PROC_NAME_LEN], _In_ UINT32 Count, _In_ const char* Name)
{
    UINT32 i;
    if (!Name || !Name[0]) return FALSE;
    for (i = 0; i < Count; i++)
        if (ShvStrEqiA(Names[i], Name)) return TRUE;
    return FALSE;
}

static BOOLEAN PidInList(_In_ volatile UINT64* List, _In_ UINT32 Count, _In_ UINT64 Pid)
{
    UINT32 i;
    for (i = 0; i < Count; i++)
        if (List[i] == Pid) return TRUE;
    return FALSE;
}

static VOID GetProcName(_In_ HANDLE Pid, _Out_writes_(SHV_PROC_NAME_LEN) char* Buf)
{
    PEPROCESS proc = NULL;
    Buf[0] = '\0';

    if (!NT_SUCCESS(PsLookupProcessByProcessId(Pid, &proc)))
    {
        ShvCopyStrA(Buf, SHV_PROC_NAME_LEN, "<unknown>");
        return;
    }

    PCHAR imgName = PsGetProcessImageFileName(proc);
    if (imgName && imgName[0])
        ShvCopyStrA(Buf, SHV_PROC_NAME_LEN, imgName);
    else
        ShvCopyStrA(Buf, SHV_PROC_NAME_LEN, "<unknown>");

    ObDereferenceObject(proc);
}

// -----------------------------------------------------------------------
// ObRegisterCallbacks pre-callback
// Chamado pelo kernel ANTES de criar/duplicar um handle para qualquer processo.
// Aqui e possivel modificar DesiredAccess para 0 para bloquear efetivamente.
// -----------------------------------------------------------------------

static OB_PREOP_CALLBACK_STATUS
ShvObPreCallback (
    _In_ PVOID                          RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OpInfo
    )
{
    PEPROCESS  targetProc;
    HANDLE     targetPid;
    char       callerName[SHV_PROC_NAME_LEN] = "<unknown>";
    char       targetName[SHV_PROC_NAME_LEN] = "<unknown>";
    UINT64     targetPidVal = 0;
    BOOLEAN    isProtected, isMonitored;

    UNREFERENCED_PARAMETER(RegistrationContext);

    // Filtramos apenas abertura/duplicacao de handles de processo
    if (OpInfo->ObjectType != *PsProcessType)
        return OB_PREOP_SUCCESS;

    targetProc = (PEPROCESS)OpInfo->Object;
    if (targetProc == NULL)
        return OB_PREOP_SUCCESS;

    targetPid    = PsGetProcessId(targetProc);
    targetPidVal = (UINT64)(ULONG_PTR)targetPid;

    // Nome do processo alvo
    {
        PCHAR n = PsGetProcessImageFileName(targetProc);
        if (n && n[0])
            ShvCopyStrA(targetName, sizeof(targetName), n);
    }

    // Nome do chamador
    {
        PEPROCESS caller = PsGetCurrentProcess();
        if (caller)
        {
            PCHAR n = PsGetProcessImageFileName(caller);
            if (n && n[0])
                ShvCopyStrA(callerName, sizeof(callerName), n);
        }
    }

    ExAcquireFastMutex(&g_FilterMutex);
    isProtected = PidInList(g_ProtectedPids, g_ProtectedCount, targetPidVal) ||
                  NameInList(g_ProtectedNames, g_ProtectedNamesCount, targetName);
    isMonitored = PidInList(g_MonitoredPids, g_MonitoredCount, targetPidVal) ||
                  NameInList(g_MonitoredNames, g_MonitoredNamesCount, targetName);
    ExReleaseFastMutex(&g_FilterMutex);

    if (isMonitored)
    {
        ACCESS_MASK req = (OpInfo->Operation == OB_OPERATION_HANDLE_CREATE)
            ? OpInfo->Parameters->CreateHandleInformation.DesiredAccess
            : OpInfo->Parameters->DuplicateHandleInformation.DesiredAccess;

        ShvLog("[MONITOR] OpenProcess: caller=%s (PID=%llu) -> alvo=%s (PID=%llu)"
               " access=0x%08X\n",
               callerName,
               (UINT64)(ULONG_PTR)PsGetCurrentProcessId(),
               targetName, targetPidVal, (UINT32)req);
    }

    if (isProtected && !IsTrustedProc(callerName))
    {
        ShvLog("[PROTECT] OpenProcess BLOQUEADO: caller=%s (PID=%llu)"
               " tentou abrir %s (PID=%llu)\n",
               callerName,
               (UINT64)(ULONG_PTR)PsGetCurrentProcessId(),
               targetName, targetPidVal);

        // Zera DesiredAccess → handle criado sem permissoes → acesso negado efetivo
        if (OpInfo->Operation == OB_OPERATION_HANDLE_CREATE)
            OpInfo->Parameters->CreateHandleInformation.DesiredAccess = 0;
        else
            OpInfo->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
    }

    return OB_PREOP_SUCCESS;
}

// -----------------------------------------------------------------------
// API publica
// -----------------------------------------------------------------------

NTSTATUS ShvHooksInit(VOID)
{
    ExInitializeFastMutex(&g_FilterMutex);
    RtlZeroMemory((PVOID)(ULONG_PTR)g_ProtectedPids, sizeof(ShvHookProtectedPids));
    RtlZeroMemory((PVOID)(ULONG_PTR)g_MonitoredPids, sizeof(ShvHookMonitoredPids));
    RtlZeroMemory(g_ProtectedNames, sizeof(g_ProtectedNames));
    RtlZeroMemory(g_MonitoredNames, sizeof(g_MonitoredNames));
    g_ProtectedCount      = 0;
    g_MonitoredCount      = 0;
    g_ProtectedNamesCount = 0;
    g_MonitoredNamesCount = 0;

    // Semeia g_MonitoredNames com os nomes estaticos de g_AutoMonitorNames
    // para que possam ser listados e removidos normalmente pela GUI.
    {
        UINT32 i;
        for (i = 0; g_AutoMonitorNames[i] != NULL && g_MonitoredNamesCount < SHV_HOOKS_MAX_NAMES; i++)
            ShvCopyStrA(g_MonitoredNames[g_MonitoredNamesCount++], SHV_PROC_NAME_LEN, g_AutoMonitorNames[i]);
    }

    g_Installed        = FALSE;
    g_ObCallbackHandle = NULL;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[HOOKS] Tabelas de PID inicializadas (protecao via EFER hook)\n");
    ShvLog("[HOOKS] Tabelas de PID inicializadas\n");
    return STATUS_SUCCESS;
}

VOID ShvHooksUninit(VOID)
{
    if (!g_Installed)
        return;

    if (g_ObCallbackHandle != NULL)
    {
        ObUnRegisterCallbacks(g_ObCallbackHandle);
        g_ObCallbackHandle = NULL;
    }

    g_Installed = FALSE;
    ShvLog("[HOOKS] ObRegisterCallbacks removido\n");
}

NTSTATUS ShvHooksAddProtected(_In_ UINT64 Pid)
{
    if (Pid == 0)
        return STATUS_INVALID_PARAMETER;

    ExAcquireFastMutex(&g_FilterMutex);

    if (PidInList(g_ProtectedPids, g_ProtectedCount, Pid))
    {
        ExReleaseFastMutex(&g_FilterMutex);
        return STATUS_SUCCESS;
    }
    if (g_ProtectedCount >= SHV_HOOKS_MAX_PROCS)
    {
        ExReleaseFastMutex(&g_FilterMutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_ProtectedPids[g_ProtectedCount++] = Pid;
    ExReleaseFastMutex(&g_FilterMutex);

    ShvLog("[HOOKS] Protegido adicionado: PID=%llu\n", Pid);
    return STATUS_SUCCESS;
}

NTSTATUS ShvHooksRemoveProtected(_In_ UINT64 Pid)
{
    UINT32 i;

    ExAcquireFastMutex(&g_FilterMutex);
    for (i = 0; i < g_ProtectedCount; i++)
    {
        if (g_ProtectedPids[i] == Pid)
        {
            g_ProtectedPids[i] = g_ProtectedPids[--g_ProtectedCount];
            g_ProtectedPids[g_ProtectedCount] = 0;
            ExReleaseFastMutex(&g_FilterMutex);
            ShvLog("[HOOKS] Protegido removido: PID=%llu\n", Pid);
            return STATUS_SUCCESS;
        }
    }
    ExReleaseFastMutex(&g_FilterMutex);
    return STATUS_NOT_FOUND;
}

NTSTATUS ShvHooksAddMonitored(_In_ UINT64 Pid)
{
    if (Pid == 0)
        return STATUS_INVALID_PARAMETER;

    ExAcquireFastMutex(&g_FilterMutex);

    if (PidInList(g_MonitoredPids, g_MonitoredCount, Pid))
    {
        ExReleaseFastMutex(&g_FilterMutex);
        return STATUS_SUCCESS;
    }
    if (g_MonitoredCount >= SHV_HOOKS_MAX_PROCS)
    {
        ExReleaseFastMutex(&g_FilterMutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_MonitoredPids[g_MonitoredCount++] = Pid;
    ExReleaseFastMutex(&g_FilterMutex);

    ShvLog("[HOOKS] Monitorado adicionado: PID=%llu\n", Pid);
    return STATUS_SUCCESS;
}

NTSTATUS ShvHooksRemoveMonitored(_In_ UINT64 Pid)
{
    UINT32 i;

    ExAcquireFastMutex(&g_FilterMutex);
    for (i = 0; i < g_MonitoredCount; i++)
    {
        if (g_MonitoredPids[i] == Pid)
        {
            g_MonitoredPids[i] = g_MonitoredPids[--g_MonitoredCount];
            g_MonitoredPids[g_MonitoredCount] = 0;
            ExReleaseFastMutex(&g_FilterMutex);
            ShvLog("[HOOKS] Monitorado removido: PID=%llu\n", Pid);
            return STATUS_SUCCESS;
        }
    }
    ExReleaseFastMutex(&g_FilterMutex);
    return STATUS_NOT_FOUND;
}

NTSTATUS ShvHooksAddProtectedName(_In_ const char* Name)
{
    UINT32 i;
    if (!Name || !Name[0]) return STATUS_INVALID_PARAMETER;

    ExAcquireFastMutex(&g_FilterMutex);
    for (i = 0; i < g_ProtectedNamesCount; i++)
        if (ShvStrEqiA(g_ProtectedNames[i], Name))
        {
            ExReleaseFastMutex(&g_FilterMutex);
            return STATUS_SUCCESS;
        }
    if (g_ProtectedNamesCount >= SHV_HOOKS_MAX_NAMES)
    {
        ExReleaseFastMutex(&g_FilterMutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ShvCopyStrA(g_ProtectedNames[g_ProtectedNamesCount++], SHV_PROC_NAME_LEN, Name);
    ExReleaseFastMutex(&g_FilterMutex);
    ShvLog("[HOOKS] Protegido por nome adicionado: %s\n", Name);
    return STATUS_SUCCESS;
}

NTSTATUS ShvHooksRemoveProtectedName(_In_ const char* Name)
{
    UINT32 i;
    if (!Name || !Name[0]) return STATUS_INVALID_PARAMETER;

    ExAcquireFastMutex(&g_FilterMutex);
    for (i = 0; i < g_ProtectedNamesCount; i++)
    {
        if (ShvStrEqiA(g_ProtectedNames[i], Name))
        {
            UINT32 last = --g_ProtectedNamesCount;
            if (i != last) ShvCopyStrA(g_ProtectedNames[i], SHV_PROC_NAME_LEN, g_ProtectedNames[last]);
            RtlZeroMemory(g_ProtectedNames[last], SHV_PROC_NAME_LEN);
            ExReleaseFastMutex(&g_FilterMutex);
            ShvLog("[HOOKS] Protegido por nome removido: %s\n", Name);
            return STATUS_SUCCESS;
        }
    }
    ExReleaseFastMutex(&g_FilterMutex);
    return STATUS_NOT_FOUND;
}

NTSTATUS ShvHooksAddMonitoredName(_In_ const char* Name)
{
    UINT32 i;
    if (!Name || !Name[0]) return STATUS_INVALID_PARAMETER;

    ExAcquireFastMutex(&g_FilterMutex);
    for (i = 0; i < g_MonitoredNamesCount; i++)
        if (ShvStrEqiA(g_MonitoredNames[i], Name))
        {
            ExReleaseFastMutex(&g_FilterMutex);
            return STATUS_SUCCESS;
        }
    if (g_MonitoredNamesCount >= SHV_HOOKS_MAX_NAMES)
    {
        ExReleaseFastMutex(&g_FilterMutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ShvCopyStrA(g_MonitoredNames[g_MonitoredNamesCount++], SHV_PROC_NAME_LEN, Name);
    ExReleaseFastMutex(&g_FilterMutex);
    ShvLog("[HOOKS] Monitorado por nome adicionado: %s\n", Name);
    return STATUS_SUCCESS;
}

NTSTATUS ShvHooksRemoveMonitoredName(_In_ const char* Name)
{
    UINT32 i;
    if (!Name || !Name[0]) return STATUS_INVALID_PARAMETER;

    ExAcquireFastMutex(&g_FilterMutex);
    for (i = 0; i < g_MonitoredNamesCount; i++)
    {
        if (ShvStrEqiA(g_MonitoredNames[i], Name))
        {
            UINT32 last = --g_MonitoredNamesCount;
            if (i != last) ShvCopyStrA(g_MonitoredNames[i], SHV_PROC_NAME_LEN, g_MonitoredNames[last]);
            RtlZeroMemory(g_MonitoredNames[last], SHV_PROC_NAME_LEN);
            ExReleaseFastMutex(&g_FilterMutex);
            ShvLog("[HOOKS] Monitorado por nome removido: %s\n", Name);
            return STATUS_SUCCESS;
        }
    }
    ExReleaseFastMutex(&g_FilterMutex);
    return STATUS_NOT_FOUND;
}

BOOLEAN ShvHooksIsTrustedName(_In_opt_ const char* Name)
{
    if (!Name || !Name[0]) return FALSE;
    return IsTrustedProc(Name);
}

VOID ShvHooksCheckPid(
    _In_  UINT64    Pid,
    _Out_ BOOLEAN*  pProtected,
    _Out_ BOOLEAN*  pMonitored
    )
{
    PEPROCESS proc = NULL;
    char      name[SHV_PROC_NAME_LEN] = "";

    *pProtected = FALSE;
    *pMonitored = FALSE;

    if (Pid == 0) return;

    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc)))
    {
        PCHAR n = PsGetProcessImageFileName(proc);
        if (n && n[0])
        {
            SIZE_T i = 0;
            while (i < SHV_PROC_NAME_LEN - 1 && n[i]) { name[i] = n[i]; i++; }
            name[i] = '\0';
        }
        ObDereferenceObject(proc);
    }

    if (!name[0]) return;

    ExAcquireFastMutex(&g_FilterMutex);
    *pProtected = NameInList(g_ProtectedNames,  g_ProtectedNamesCount,  name);
    *pMonitored = NameInList(g_MonitoredNames, g_MonitoredNamesCount, name);
    ExReleaseFastMutex(&g_FilterMutex);
}

// Retorna TRUE se o nome do processo esta em g_AutoMonitorNames.
// Chamada pelo hook NtOpenProcess para monitorar automaticamente sem PID pre-cadastrado.
BOOLEAN ShvHooksIsAutoMonitorName(_In_opt_ PCHAR Name)
{
    UINT32 i;
    if (!Name || !Name[0])
        return FALSE;
    for (i = 0; g_AutoMonitorNames[i] != NULL; i++)
        if (ShvStrEqiA(Name, g_AutoMonitorNames[i]))
            return TRUE;
    return FALSE;
}

VOID ShvHooksListFilters(
    _Out_writes_(MaxCount) SHV_PROC_FILTER_ENTRY* Out,
    _Out_ UINT32* Count,
    _In_  UINT32  MaxCount
    )
{
    UINT32 n = 0;
    UINT32 i;

    ExAcquireFastMutex(&g_FilterMutex);

    // Protegidos por PID
    for (i = 0; i < g_ProtectedCount && n < MaxCount; i++, n++)
    {
        Out[n].Pid    = g_ProtectedPids[i];
        Out[n].Type   = SHV_FILTER_TYPE_PROTECT;
        Out[n].ByName = 0;
        Out[n].Pad[0] = Out[n].Pad[1] = 0;
    }

    // Monitorados por PID
    for (i = 0; i < g_MonitoredCount && n < MaxCount; i++, n++)
    {
        Out[n].Pid    = g_MonitoredPids[i];
        Out[n].Type   = SHV_FILTER_TYPE_MONITOR;
        Out[n].ByName = 0;
        Out[n].Pad[0] = Out[n].Pad[1] = 0;
    }

    // Protegidos por nome
    for (i = 0; i < g_ProtectedNamesCount && n < MaxCount; i++, n++)
    {
        Out[n].Pid    = 0;
        Out[n].Type   = SHV_FILTER_TYPE_PROTECT;
        Out[n].ByName = 1;
        Out[n].Pad[0] = Out[n].Pad[1] = 0;
        ShvCopyStrA(Out[n].Name, SHV_PROC_NAME_LEN, g_ProtectedNames[i]);
    }

    // Monitorados por nome (lista dinamica)
    for (i = 0; i < g_MonitoredNamesCount && n < MaxCount; i++, n++)
    {
        Out[n].Pid    = 0;
        Out[n].Type   = SHV_FILTER_TYPE_MONITOR;
        Out[n].ByName = 1;
        Out[n].Pad[0] = Out[n].Pad[1] = 0;
        ShvCopyStrA(Out[n].Name, SHV_PROC_NAME_LEN, g_MonitoredNames[i]);
    }

    ExReleaseFastMutex(&g_FilterMutex);


    // Resolve nomes apenas para entradas por PID
    for (i = 0; i < n; i++)
        if (!Out[i].ByName)
            GetProcName((HANDLE)(ULONG_PTR)Out[i].Pid, Out[i].Name);

    *Count = n;
}

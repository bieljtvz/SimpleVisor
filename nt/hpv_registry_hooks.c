/*++

Module Name:

    hpv_registry_hooks.c

Abstract:

    Monitoramento de acesso a registro para processos MONITORADOS, via
    shadow hook (EPT split-page, mesmo motor de nt/hpv_hooks.c) em
    ZwOpenKey, ZwOpenKeyEx, ZwCreateKey e ZwQueryKey.

    ATENCAO: estas sao as variantes Zw* (callable direto do kernel, com
    PreviousMode=KernelMode), NAO as Nt* (dispatch de syscall de usermode,
    PreviousMode=UserMode) -- um driver chamando a API de registro do
    kernel passa por aqui do mesmo jeito que RegOpenKeyEx/RegCreateKeyEx
    em usermode (que descem para Nt*, e Nt* e Zw* convergem na mesma
    implementacao interna no ntoskrnl). Confirmado por dumpbin /exports
    que ZwOpenKey/ZwOpenKeyEx/ZwCreateKey/ZwQueryKey sao exportados nesta
    WDK (as variantes Nt* correspondentes NAO sao).

    So gera evento (ShvLog + DbgPrintEx + ring buffer p/ GUI) quando o
    processo CHAMADOR (nao um "processo alvo" -- registro nao tem esse
    conceito) esta na lista de MONITORADOS (ShvHookMonitoredPids / nome).
    Nao bloqueia nada -- so observa, igual o log de NtOpenProcess p/
    processos monitorados em hpv_policy_hooks.c.

    O caminho do caminho (RootDirectory + ObjectName, ou so handle pra
    ZwQueryKey) e resolvido via ObReferenceObjectByHandle + ObQueryNameString
    (ou ZwQueryObject p/ ZwQueryKey), todas resolvidas DINAMICAMENTE via
    MmGetSystemRoutineAddress -- mesmo motivo de todas as outras APIs
    "nao garantidas" deste projeto (ver HpvResolveOptionalApis em shvos.c):
    um import estatico nao resolvido impede o driver de carregar.

Environment:

    Kernel mode only, PASSIVE_LEVEL (chamado pelo caminho de registro).

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
// APIs resolvidas dinamicamente (ver motivo no cabecalho do arquivo)
// ============================================================
typedef NTSTATUS (NTAPI* PFN_ObReferenceObjectByHandle)(
    _In_      HANDLE          Handle,
    _In_      ACCESS_MASK     DesiredAccess,
    _In_opt_  PVOID           ObjectType,
    _In_      KPROCESSOR_MODE AccessMode,
    _Out_     PVOID*          Object,
    _Out_opt_ PVOID           HandleInformation
    );

typedef NTSTATUS (NTAPI* PFN_ObQueryNameString)(
    _In_  PVOID  Object,
    _Out_ PVOID  ObjectNameInfo,  // HPV_OBJECT_NAME_INFORMATION*
    _In_  ULONG  Length,
    _Out_ PULONG ReturnLength
    );

typedef NTSTATUS (NTAPI* PFN_ZwQueryObject)(
    _In_opt_  HANDLE Handle,
    _In_      ULONG  ObjectInformationClass,
    _Out_opt_ PVOID  ObjectInformation,
    _In_      ULONG  ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

static PFN_ObReferenceObjectByHandle g_pObReferenceObjectByHandle = NULL;
static PFN_ObQueryNameString         g_pObQueryNameString         = NULL;
static PFN_ZwQueryObject             g_pZwQueryObject              = NULL;

#define HPV_OBJECT_NAME_INFORMATION_CLASS 1  // ObjectNameInformation

// Layout identico a OBJECT_NAME_INFORMATION (wdm.h) -- redeclarado com nome
// proprio pra nao depender de o header publico ja ter essa definicao.
typedef struct _HPV_OBJECT_NAME_INFORMATION
{
    UNICODE_STRING Name;
    // bytes do nome (wide) vem logo apos este struct no mesmo buffer --
    // Name.Buffer aponta pra dentro dele.
} HPV_OBJECT_NAME_INFORMATION;

static VOID
HpvRegistryResolveApis (
    VOID
    )
{
    struct {
        PCWSTR Name;
        PVOID* Target;
    } apis[] = {
        { L"ObReferenceObjectByHandle", (PVOID*)&g_pObReferenceObjectByHandle },
        { L"ObQueryNameString",         (PVOID*)&g_pObQueryNameString         },
        { L"ZwQueryObject",             (PVOID*)&g_pZwQueryObject             },
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(apis); i++)
    {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, apis[i].Name);
        *apis[i].Target = MmGetSystemRoutineAddress(&name);

        ShvLog("[REGMON] API %ws: %s\n", apis[i].Name,
               *apis[i].Target ? "OK" : "NAO ENCONTRADA nesta build do Windows");
    }
}

// ============================================================
// Ring buffer de eventos (consumido via IOCTL pela GUI)
// ============================================================
#define SHV_REG_EVENT_RING_MAX 512

static SHV_REGISTRY_EVENT g_RegEvents[SHV_REG_EVENT_RING_MAX];
static UINT32              g_RegEventHead  = 0;   // proximo slot a escrever
static UINT32              g_RegEventCount = 0;   // quantos slots validos (satura em MAX)
static UINT64              g_RegEventSeq   = 0;   // contador monotonico (nunca reseta, so Clear zera o ring)
static KSPIN_LOCK           g_RegEventLock;
static BOOLEAN              g_RegEventLockInit = FALSE;

static VOID
ConvertUnicodeToAnsiTruncated (
    _In_opt_  PCUNICODE_STRING Src,
    _Out_writes_z_(MaxChars) PCHAR Dst,
    _In_      ULONG MaxChars
    )
{
    ULONG i, n;

    if (Src == NULL || Src->Buffer == NULL || MaxChars == 0)
    {
        if (MaxChars > 0) Dst[0] = '\0';
        return;
    }

    n = Src->Length / sizeof(WCHAR);
    if (n > MaxChars - 1) n = MaxChars - 1;

    for (i = 0; i < n; i++)
    {
        WCHAR wc = Src->Buffer[i];
        Dst[i] = (wc < 0x80) ? (CHAR)wc : '?';
    }
    Dst[n] = '\0';
}

static VOID
ShvRegistryPushEvent (
    _In_     UINT64            Pid,
    _In_opt_ PCHAR             ProcName,
    _In_     UCHAR             Operation,
    _In_     UINT32            DesiredAccess,
    _In_     NTSTATUS          Status,
    _In_opt_ PCUNICODE_STRING  KeyPath
    )
{
    KIRQL  oldIrql;
    SHV_REGISTRY_EVENT* slot;

    if (!g_RegEventLockInit) return;

    KeAcquireSpinLock(&g_RegEventLock, &oldIrql);

    slot = &g_RegEvents[g_RegEventHead];
    RtlZeroMemory(slot, sizeof(*slot));
    slot->SeqNum        = ++g_RegEventSeq;
    slot->Pid            = Pid;
    slot->Operation      = Operation;
    slot->DesiredAccess  = DesiredAccess;
    slot->Status         = (long)Status;

    if (ProcName != NULL)
        RtlCopyMemory(slot->ProcessName, ProcName,
                      min((SIZE_T)strlen(ProcName), sizeof(slot->ProcessName) - 1));

    ConvertUnicodeToAnsiTruncated(KeyPath, slot->KeyPath, SHV_REG_PATH_LEN);

    g_RegEventHead = (g_RegEventHead + 1) % SHV_REG_EVENT_RING_MAX;
    if (g_RegEventCount < SHV_REG_EVENT_RING_MAX) g_RegEventCount++;

    KeReleaseSpinLock(&g_RegEventLock, oldIrql);
}

UINT32
ShvRegistryListEvents (
    _Out_writes_(MaxCount) SHV_REGISTRY_EVENT* Out,
    _In_ UINT32 MaxCount
    )
{
    KIRQL  oldIrql;
    UINT32 n, i, startIdx;

    if (!g_RegEventLockInit || Out == NULL || MaxCount == 0) return 0;

    KeAcquireSpinLock(&g_RegEventLock, &oldIrql);

    n = min(g_RegEventCount, MaxCount);

    // Slot mais antigo ainda valido no ring.
    startIdx = (g_RegEventCount < SHV_REG_EVENT_RING_MAX)
                   ? 0
                   : g_RegEventHead;

    for (i = 0; i < n; i++)
    {
        UINT32 idx = (startIdx + i) % SHV_REG_EVENT_RING_MAX;
        Out[i] = g_RegEvents[idx];
    }

    KeReleaseSpinLock(&g_RegEventLock, oldIrql);
    return n;
}

VOID
ShvRegistryClearEvents (
    VOID
    )
{
    KIRQL oldIrql;

    if (!g_RegEventLockInit) return;

    KeAcquireSpinLock(&g_RegEventLock, &oldIrql);
    g_RegEventHead  = 0;
    g_RegEventCount = 0;
    KeReleaseSpinLock(&g_RegEventLock, oldIrql);
}

// ============================================================
// Helper: processo chamador esta na lista de MONITORADOS?
// (por PID direto ou por nome -- mesma logica de PidMonitored/
// ShvHooksCheckPid usada em hpv_policy_hooks.c)
// ============================================================
static BOOLEAN
CallerIsMonitored (
    _Out_opt_ PCHAR* OutName
    )
{
    UINT64  pid = (UINT64)(ULONG_PTR)PsGetCurrentProcessId();
    UINT32  i;
    BOOLEAN mon = FALSE;
    PCHAR   name = PsGetProcessImageFileName(PsGetCurrentProcess());

    if (OutName) *OutName = name;

    for (i = 0; i < ShvHookMonitoredCount; i++)
    {
        if (ShvHookMonitoredPids[i] == pid) return TRUE;
    }

    {
        BOOLEAN np = FALSE;
        ShvHooksCheckPid(pid, &np, &mon);
    }

    return mon;
}

// ============================================================
// Resolucao do caminho completo da chave
// ============================================================

// RootDirectory (se houver) + ObjectAttributes->ObjectName -- usado por
// OpenKey/OpenKeyEx/CreateKey. Se RootDirectory for NULL, ObjectName ja e
// o caminho absoluto (ex. "\REGISTRY\MACHINE\...").
static VOID
ResolvePathFromObjectAttributes (
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ UNICODE_STRING* OutPath,
    _Inout_updates_bytes_(BufBytes) PWCHAR WorkBuf,
    _In_ ULONG BufBytes
    )
{
    OutPath->Buffer = WorkBuf;
    OutPath->Length = 0;
    OutPath->MaximumLength = (USHORT)BufBytes;
    WorkBuf[0] = L'\0';

    if (ObjectAttributes == NULL)
        return;

    __try
    {
        if (ObjectAttributes->RootDirectory != NULL &&
            g_pObReferenceObjectByHandle != NULL &&
            g_pObQueryNameString != NULL)
        {
            PVOID rootObj = NULL;
            NTSTATUS st = g_pObReferenceObjectByHandle(
                ObjectAttributes->RootDirectory, 0, NULL, KernelMode, &rootObj, NULL);

            if (NT_SUCCESS(st) && rootObj != NULL)
            {
                UCHAR   nameInfoBuf[512];
                ULONG   retLen = 0;
                HPV_OBJECT_NAME_INFORMATION* nameInfo =
                    (HPV_OBJECT_NAME_INFORMATION*)nameInfoBuf;

                st = g_pObQueryNameString(rootObj, nameInfo, sizeof(nameInfoBuf), &retLen);
                if (NT_SUCCESS(st) && nameInfo->Name.Length > 0)
                {
                    RtlCopyUnicodeString(OutPath, &nameInfo->Name);
                }

                ObDereferenceObject(rootObj);
            }
        }

        if (ObjectAttributes->ObjectName != NULL &&
            ObjectAttributes->ObjectName->Length > 0)
        {
            UNICODE_STRING sep;
            RtlInitUnicodeString(&sep, L"\\");

            if (OutPath->Length > 0)
                RtlAppendUnicodeStringToString(OutPath, &sep);
            RtlAppendUnicodeStringToString(OutPath, ObjectAttributes->ObjectName);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Caminho a partir de um HANDLE ja aberto (usado por ZwQueryKey, que nao
// recebe OBJECT_ATTRIBUTES) via ZwQueryObject(ObjectNameInformation).
static VOID
ResolvePathFromHandle (
    _In_ HANDLE KeyHandle,
    _Out_ UNICODE_STRING* OutPath,
    _Inout_updates_bytes_(BufBytes) PWCHAR WorkBuf,
    _In_ ULONG BufBytes
    )
{
    OutPath->Buffer = WorkBuf;
    OutPath->Length = 0;
    OutPath->MaximumLength = (USHORT)BufBytes;
    WorkBuf[0] = L'\0';

    if (g_pZwQueryObject == NULL) return;

    __try
    {
        UCHAR  nameInfoBuf[512];
        ULONG  retLen = 0;
        HPV_OBJECT_NAME_INFORMATION* nameInfo = (HPV_OBJECT_NAME_INFORMATION*)nameInfoBuf;
        NTSTATUS st = g_pZwQueryObject(KeyHandle, HPV_OBJECT_NAME_INFORMATION_CLASS,
                                        nameInfo, sizeof(nameInfoBuf), &retLen);
        if (NT_SUCCESS(st) && nameInfo->Name.Length > 0)
        {
            RtlCopyUnicodeString(OutPath, &nameInfo->Name);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ============================================================
// Trampolins + tipos
// ============================================================
typedef NTSTATUS (NTAPI* PfnZwOpenKey)(
    _Out_ PHANDLE            KeyHandle,
    _In_  ACCESS_MASK        DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS (NTAPI* PfnZwOpenKeyEx)(
    _Out_ PHANDLE            KeyHandle,
    _In_  ACCESS_MASK        DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes,
    _In_  ULONG              OpenOptions
    );

typedef NTSTATUS (NTAPI* PfnZwCreateKey)(
    _Out_    PHANDLE            KeyHandle,
    _In_     ACCESS_MASK        DesiredAccess,
    _In_     POBJECT_ATTRIBUTES ObjectAttributes,
    _In_     ULONG              TitleIndex,
    _In_opt_ PUNICODE_STRING    Class,
    _In_     ULONG              CreateOptions,
    _Out_opt_ PULONG            Disposition
    );

typedef NTSTATUS (NTAPI* PfnZwQueryKey)(
    _In_      HANDLE  KeyHandle,
    _In_      ULONG   KeyInformationClass,
    _Out_opt_ PVOID   KeyInformation,
    _In_      ULONG   Length,
    _Out_     PULONG  ResultLength
    );

static PfnZwOpenKey   g_OrigZwOpenKey   = NULL;
static PfnZwOpenKeyEx g_OrigZwOpenKeyEx = NULL;
static PfnZwCreateKey g_OrigZwCreateKey = NULL;
static PfnZwQueryKey  g_OrigZwQueryKey  = NULL;

#define HPV_REG_PATH_WORKBUF_CHARS 520

// ============================================================
// Hook: ZwOpenKey
// ============================================================
static NTSTATUS NTAPI
HpvZwOpenKeyHook (
    _Out_ PHANDLE            KeyHandle,
    _In_  ACCESS_MASK        DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes
    )
{
    NTSTATUS status;
    PCHAR    callerName = NULL;
    BOOLEAN  monitored  = CallerIsMonitored(&callerName);
    WCHAR    workBuf[HPV_REG_PATH_WORKBUF_CHARS];
    UNICODE_STRING path = { 0 };

    if (monitored)
        ResolvePathFromObjectAttributes(ObjectAttributes, &path,
                                         workBuf, sizeof(workBuf));

    status = g_OrigZwOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);

    if (monitored)
    {
        UINT64 pid = (UINT64)(ULONG_PTR)PsGetCurrentProcessId();

        ShvLog("[REGMON] ZwOpenKey: caller=%s (PID=%llu) access=0x%08X path=%wZ status=0x%08X\n",
               callerName ? callerName : "?", pid, (UINT32)DesiredAccess, &path, status);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[REGMON] ZwOpenKey: caller=%s (PID=%llu) access=0x%08X path=%wZ status=0x%08X\n",
                   callerName ? callerName : "?", pid, (UINT32)DesiredAccess, &path, status);

        ShvRegistryPushEvent(pid, callerName, SHV_REGOP_OPENKEY,
                              (UINT32)DesiredAccess, status, &path);
    }

    return status;
}

// ============================================================
// Hook: ZwOpenKeyEx
// ============================================================
static NTSTATUS NTAPI
HpvZwOpenKeyExHook (
    _Out_ PHANDLE            KeyHandle,
    _In_  ACCESS_MASK        DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes,
    _In_  ULONG              OpenOptions
    )
{
    NTSTATUS status;
    PCHAR    callerName = NULL;
    BOOLEAN  monitored  = CallerIsMonitored(&callerName);
    WCHAR    workBuf[HPV_REG_PATH_WORKBUF_CHARS];
    UNICODE_STRING path = { 0 };

    if (monitored)
        ResolvePathFromObjectAttributes(ObjectAttributes, &path,
                                         workBuf, sizeof(workBuf));

    status = g_OrigZwOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);

    if (monitored)
    {
        UINT64 pid = (UINT64)(ULONG_PTR)PsGetCurrentProcessId();

        ShvLog("[REGMON] ZwOpenKeyEx: caller=%s (PID=%llu) access=0x%08X path=%wZ status=0x%08X\n",
               callerName ? callerName : "?", pid, (UINT32)DesiredAccess, &path, status);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[REGMON] ZwOpenKeyEx: caller=%s (PID=%llu) access=0x%08X path=%wZ status=0x%08X\n",
                   callerName ? callerName : "?", pid, (UINT32)DesiredAccess, &path, status);

        ShvRegistryPushEvent(pid, callerName, SHV_REGOP_OPENKEYEX,
                              (UINT32)DesiredAccess, status, &path);
    }

    return status;
}

// ============================================================
// Hook: ZwCreateKey
// ============================================================
static NTSTATUS NTAPI
HpvZwCreateKeyHook (
    _Out_    PHANDLE            KeyHandle,
    _In_     ACCESS_MASK        DesiredAccess,
    _In_     POBJECT_ATTRIBUTES ObjectAttributes,
    _In_     ULONG              TitleIndex,
    _In_opt_ PUNICODE_STRING    Class,
    _In_     ULONG              CreateOptions,
    _Out_opt_ PULONG            Disposition
    )
{
    NTSTATUS status;
    PCHAR    callerName = NULL;
    BOOLEAN  monitored  = CallerIsMonitored(&callerName);
    WCHAR    workBuf[HPV_REG_PATH_WORKBUF_CHARS];
    UNICODE_STRING path = { 0 };

    if (monitored)
        ResolvePathFromObjectAttributes(ObjectAttributes, &path,
                                         workBuf, sizeof(workBuf));

    status = g_OrigZwCreateKey(KeyHandle, DesiredAccess, ObjectAttributes,
                                TitleIndex, Class, CreateOptions, Disposition);

    if (monitored)
    {
        UINT64 pid = (UINT64)(ULONG_PTR)PsGetCurrentProcessId();

        ShvLog("[REGMON] ZwCreateKey: caller=%s (PID=%llu) access=0x%08X path=%wZ status=0x%08X\n",
               callerName ? callerName : "?", pid, (UINT32)DesiredAccess, &path, status);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[REGMON] ZwCreateKey: caller=%s (PID=%llu) access=0x%08X path=%wZ status=0x%08X\n",
                   callerName ? callerName : "?", pid, (UINT32)DesiredAccess, &path, status);

        ShvRegistryPushEvent(pid, callerName, SHV_REGOP_CREATEKEY,
                              (UINT32)DesiredAccess, status, &path);
    }

    return status;
}

// ============================================================
// Hook: ZwQueryKey
// ============================================================
// Sem OBJECT_ATTRIBUTES (so handle) -- caminho resolvido via ZwQueryObject.
// DesiredAccess nao se aplica aqui (fica 0 no evento).
static NTSTATUS NTAPI
HpvZwQueryKeyHook (
    _In_      HANDLE  KeyHandle,
    _In_      ULONG   KeyInformationClass,
    _Out_opt_ PVOID   KeyInformation,
    _In_      ULONG   Length,
    _Out_     PULONG  ResultLength
    )
{
    NTSTATUS status;
    PCHAR    callerName = NULL;
    BOOLEAN  monitored  = CallerIsMonitored(&callerName);
    WCHAR    workBuf[HPV_REG_PATH_WORKBUF_CHARS];
    UNICODE_STRING path = { 0 };

    if (monitored)
        ResolvePathFromHandle(KeyHandle, &path, workBuf, sizeof(workBuf));

    status = g_OrigZwQueryKey(KeyHandle, KeyInformationClass, KeyInformation,
                               Length, ResultLength);

    if (monitored)
    {
        UINT64 pid = (UINT64)(ULONG_PTR)PsGetCurrentProcessId();

        ShvLog("[REGMON] ZwQueryKey: caller=%s (PID=%llu) path=%wZ status=0x%08X\n",
               callerName ? callerName : "?", pid, &path, status);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[REGMON] ZwQueryKey: caller=%s (PID=%llu) path=%wZ status=0x%08X\n",
                   callerName ? callerName : "?", pid, &path, status);

        ShvRegistryPushEvent(pid, callerName, SHV_REGOP_QUERYKEY,
                              0, status, &path);
    }

    return status;
}

// ============================================================
// API publica
// ============================================================
NTSTATUS
ShvRegistryHooksInit (
    VOID
    )
{
    NTSTATUS status;
    PVOID    origFunc;

    if (!g_RegEventLockInit)
    {
        KeInitializeSpinLock(&g_RegEventLock);
        g_RegEventLockInit = TRUE;
    }

    HpvRegistryResolveApis();

    status = HpvHookFuncByName(L"ZwOpenKey", HpvZwOpenKeyHook, &origFunc);
    if (NT_SUCCESS(status))
    {
        g_OrigZwOpenKey = (PfnZwOpenKey)origFunc;
        ShvLog("[REGMON] ZwOpenKey shadow hook OK (trampoline=%p)\n", origFunc);
    }
    else
    {
        ShvLog("[REGMON] HpvHookFuncByName(ZwOpenKey) falhou: 0x%08X (nao fatal)\n", status);
    }

    status = HpvHookFuncByName(L"ZwOpenKeyEx", HpvZwOpenKeyExHook, &origFunc);
    if (NT_SUCCESS(status))
    {
        g_OrigZwOpenKeyEx = (PfnZwOpenKeyEx)origFunc;
        ShvLog("[REGMON] ZwOpenKeyEx shadow hook OK (trampoline=%p)\n", origFunc);
    }
    else
    {
        ShvLog("[REGMON] HpvHookFuncByName(ZwOpenKeyEx) falhou: 0x%08X (nao fatal)\n", status);
    }

    status = HpvHookFuncByName(L"ZwCreateKey", HpvZwCreateKeyHook, &origFunc);
    if (NT_SUCCESS(status))
    {
        g_OrigZwCreateKey = (PfnZwCreateKey)origFunc;
        ShvLog("[REGMON] ZwCreateKey shadow hook OK (trampoline=%p)\n", origFunc);
    }
    else
    {
        ShvLog("[REGMON] HpvHookFuncByName(ZwCreateKey) falhou: 0x%08X (nao fatal)\n", status);
    }

    status = HpvHookFuncByName(L"ZwQueryKey", HpvZwQueryKeyHook, &origFunc);
    if (NT_SUCCESS(status))
    {
        g_OrigZwQueryKey = (PfnZwQueryKey)origFunc;
        ShvLog("[REGMON] ZwQueryKey shadow hook OK (trampoline=%p)\n", origFunc);
    }
    else
    {
        ShvLog("[REGMON] HpvHookFuncByName(ZwQueryKey) falhou: 0x%08X (nao fatal)\n", status);
    }

    // Nao-fatal: cada hook e independente, perder um so reduz a cobertura
    // do monitoramento de registro, nao afeta o resto do driver.
    return STATUS_SUCCESS;
}

VOID
ShvRegistryHooksUninit (
    VOID
    )
{
    struct {
        PCWSTR Name;
        PVOID* OrigFunc;
    } hooks[] = {
        { L"ZwOpenKey",   (PVOID*)&g_OrigZwOpenKey   },
        { L"ZwOpenKeyEx", (PVOID*)&g_OrigZwOpenKeyEx },
        { L"ZwCreateKey", (PVOID*)&g_OrigZwCreateKey },
        { L"ZwQueryKey",  (PVOID*)&g_OrigZwQueryKey  },
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(hooks); i++)
    {
        if (*hooks[i].OrigFunc != NULL)
        {
            UNICODE_STRING ustr;
            PVOID funcVa;
            RtlInitUnicodeString(&ustr, hooks[i].Name);
            funcVa = MmGetSystemRoutineAddress(&ustr);
            if (funcVa)
                HpvUnhookFuncByVa(funcVa);
            *hooks[i].OrigFunc = NULL;
            ShvLog("[REGMON] %ws hook removido\n", hooks[i].Name);
        }
    }
}

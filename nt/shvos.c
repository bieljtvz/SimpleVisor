/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    shvos.c

Abstract:

    This module implements the OS-facing Windows stubs for SimpleVisor.

Author:

    Alex Ionescu (@aionescu) 29-Aug-2016 - Initial version

Environment:

    Kernel mode only.

--*/

#include <ntifs.h>
#include <stdarg.h>
#include "..\shv_x.h"
#include "..\shv_dbg.h"
#include "..\shvhooks.h"
#pragma warning(disable:4221)
#pragma warning(disable:4204)
#pragma warning(disable:4996)  // ExAllocatePoolWithTag deprecated em WDK recente

#include "shvos_internal.h"

NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc (
    _In_ PKDEFERRED_ROUTINE Routine,
    _In_opt_ PVOID Context
    );

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone (
    _In_ PVOID SystemArgument1
    );

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize (
    _In_ PVOID SystemArgument2
    );

DRIVER_INITIALIZE DriverEntry;

DECLSPEC_NORETURN
VOID
__cdecl
ShvOsRestoreContext2 (
    _In_ PCONTEXT ContextRecord,
    _In_opt_ struct _EXCEPTION_RECORD * ExceptionRecord
    );

VOID
ShvVmxCleanup (
    _In_ UINT16 Data,
    _In_ UINT16 Teb
    );

typedef struct _SHV_DPC_CONTEXT
{
    PSHV_CPU_CALLBACK Routine;
    struct _SHV_CALLBACK_CONTEXT* Context;
} SHV_DPC_CONTEXT, *PSHV_DPC_CONTEXT;

#define KGDT64_R3_DATA      0x28
#define KGDT64_R3_CMTEB     0x50

PVOID           g_PowerCallbackRegistration;
PDEVICE_OBJECT  g_ShvDeviceObject;

// ============================================================
// IOCTL Dispatcher
// ============================================================

//
// ZwQuerySystemInformation -- nao importado automaticamente pelo ntifs.h
//
typedef enum _SYSTEM_INFORMATION_CLASS_SHV
{
    SystemProcessInformation  = 5,
    SystemModuleInformation   = 11
} SYSTEM_INFORMATION_CLASS_SHV;

NTSTATUS
ZwQuerySystemInformation (
    _In_      ULONG  SystemInformationClass,
    _Out_opt_ PVOID  SystemInformation,
    _In_      ULONG  SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef struct _SYSTEM_PROCESS_INFORMATION_SHV
{
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  Reserved[3];
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY      BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
    ULONG          HandleCount;
    ULONG          SessionId;
    // NOTA: em Vista+ o campo +104 e UniqueProcessKey, NAO PageDirectoryBase.
    // PageDirectoryBase foi removido de ZwQuerySystemInformation; usar EPROCESS+0x28.
} SYSTEM_PROCESS_INFORMATION_SHV, *PSYSTEM_PROCESS_INFORMATION_SHV;

// Offset de KPROCESS.DirectoryTableBase dentro de EPROCESS no x64 Win10.
// EPROCESS comeca com KPROCESS; Pcb.DirectoryTableBase esta em +0x28.
#define EPROCESS_DIR_TABLE_BASE_OFFSET 0x28

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG                       NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

// ============================================================
// Tabela de MDLs: guarda os MDLs que travam paginas user-mode durante hooks EPT.
// Indexado pela PA do primeiro byte da regiao (page-aligned).
// ============================================================
#define SHV_MDL_TABLE_MAX 64
typedef struct _SHV_MDL_ENTRY { UINT64 FirstPa; PMDL Mdl; } SHV_MDL_ENTRY;
static SHV_MDL_ENTRY g_MdlTable[SHV_MDL_TABLE_MAX];

VOID ShvHookSetMdl(_In_ UINT64 Pa, _In_ PMDL Mdl)
{
    UINT32 i;
    for (i = 0; i < SHV_MDL_TABLE_MAX; i++)
    {
        if (g_MdlTable[i].Mdl == NULL)
        {
            g_MdlTable[i].FirstPa = Pa;
            g_MdlTable[i].Mdl     = Mdl;
            return;
        }
    }
}

PMDL ShvHookTakeMdl(_In_ UINT64 Pa)
{
    UINT32 i;
    for (i = 0; i < SHV_MDL_TABLE_MAX; i++)
    {
        if (g_MdlTable[i].Mdl != NULL && g_MdlTable[i].FirstPa == Pa)
        {
            PMDL mdl = g_MdlTable[i].Mdl;
            g_MdlTable[i].Mdl     = NULL;
            g_MdlTable[i].FirstPa = 0;
            return mdl;
        }
    }
    return NULL;
}

VOID ShvHookReleaseMdls(VOID)
{
    UINT32 i;
    for (i = 0; i < SHV_MDL_TABLE_MAX; i++)
    {
        if (g_MdlTable[i].Mdl != NULL)
        {
            MmUnlockPages(g_MdlTable[i].Mdl);
            IoFreeMdl(g_MdlTable[i].Mdl);
            g_MdlTable[i].Mdl     = NULL;
            g_MdlTable[i].FirstPa = 0;
        }
    }
}

NTSTATUS
ShvDispatchIoctl (
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    PIO_STACK_LOCATION  ioStack;
    SHV_REQUEST         req;        // ~68 bytes, fine on stack
    PSHV_RESPONSE       resp;       // points into SystemBuffer (pool alloc by I/O manager)
    ULONG               inputLen;
    ULONG               outputLen;
    NTSTATUS            status = STATUS_SUCCESS;
    PVOID               buffer;

    UNREFERENCED_PARAMETER(DeviceObject);

    ioStack   = IoGetCurrentIrpStackLocation(Irp);
    buffer    = Irp->AssociatedIrp.SystemBuffer;
    inputLen  = ioStack->Parameters.DeviceIoControl.InputBufferLength;
    outputLen = ioStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (ioStack->Parameters.DeviceIoControl.IoControlCode != SHV_IOCTL_SUBMIT)
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto Exit;
    }

    if (inputLen < sizeof(SHV_REQUEST) || outputLen < sizeof(SHV_RESPONSE) || buffer == NULL)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    // Copy request before zeroing the SystemBuffer (input and output share it)
    RtlCopyMemory(&req, buffer, sizeof(SHV_REQUEST));

    // Use SystemBuffer directly as response -- it is already a pool allocation
    // of at least outputLen >= sizeof(SHV_RESPONSE) bytes.
    resp = (PSHV_RESPONSE)buffer;
    RtlZeroMemory(resp, sizeof(SHV_RESPONSE));
    resp->Status = SHVD_STATUS_ERR_INVALID;

    switch (req.Command)
    {
    case SHV_CMD_HOOK_EPT:
    {
        UINT64 vaBase, vaEnd;
        ULONG  regionBytes;
        UINT32 hooked = 0;

        if (req.Hook.VirtAddr == 0)
        {
            resp->Status = SHVD_STATUS_ERR_INVALID;
            break;
        }

        // Page-align o intervalo
        vaBase      = req.Hook.VirtAddr & ~(UINT64)0xFFF;
        vaEnd       = (req.Hook.VirtAddr + (req.Hook.RangeSize ? req.Hook.RangeSize : PAGE_SIZE) + 0xFFF)
                      & ~(UINT64)0xFFF;
        regionBytes = (ULONG)(vaEnd - vaBase);
        if (regionBytes == 0) regionBytes = PAGE_SIZE;

        if (req.Hook.Pid == 0)
        {
            // Kernel: paginas nao-paginadas; itera direto por VA
            UINT64 va;
            for (va = vaBase; va < vaEnd; va += PAGE_SIZE)
            {
                PHYSICAL_ADDRESS pa;
                __try { pa = MmGetPhysicalAddress((PVOID)(ULONG_PTR)va); }
                __except (EXCEPTION_EXECUTE_HANDLER) { pa.QuadPart = 0; }
                if ((pa.QuadPart & ~0xFFFULL) != 0)
                {
                    ShvHookInstall(pa.QuadPart & ~0xFFFULL, req.Hook.HookType,
                                   va, 0, req.Hook.RangeSize ? req.Hook.RangeSize : 1);
                    hooked++;
                }
            }
            resp->Status = hooked ? SHVD_STATUS_OK : SHVD_STATUS_ERR_ACCESS;
            ShvLog("[SHV-IOCTL] HOOK_EPT kernel VA=%016llX-%016llX pages=%u\n",
                   vaBase, vaEnd, hooked);
        }
        else
        {
            // User-mode: trava todas as paginas com MDL para PA nao mudar
            PEPROCESS process;
            PMDL      mdl;
            PPFN_NUMBER pfnArray;
            ULONG       pageCount, i;
            KAPC_STATE  apcState;
            UINT64      firstPa = 0;

            if (!NT_SUCCESS(PsLookupProcessByProcessId(
                    (HANDLE)(ULONG_PTR)req.Hook.Pid, &process)))
            {
                resp->Status = SHVD_STATUS_ERR_ACCESS;
                break;
            }

            mdl = IoAllocateMdl((PVOID)(ULONG_PTR)vaBase, regionBytes,
                                 FALSE, FALSE, NULL);
            if (mdl == NULL)
            {
                ObDereferenceObject(process);
                resp->Status = SHVD_STATUS_ERR_NOMEM;
                break;
            }

            // Trava as paginas fisicas (impede paging-out enquanto hook estiver ativo)
            KeStackAttachProcess(process, &apcState);
            __try
            {
                MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                IoFreeMdl(mdl);
                mdl = NULL;
            }
            KeUnstackDetachProcess(&apcState);
            ObDereferenceObject(process);

            if (mdl == NULL)
            {
                resp->Status = SHVD_STATUS_ERR_ACCESS;
                break;
            }

            // Itera PFNs e instala hook em cada pagina
            pfnArray  = MmGetMdlPfnArray(mdl);
            pageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(vaBase, regionBytes);
            for (i = 0; i < pageCount; i++)
            {
                UINT64 gpa = (UINT64)pfnArray[i] << PAGE_SHIFT;
                if (gpa != 0)
                {
                    if (i == 0) firstPa = gpa;
                    ShvHookInstall(gpa, req.Hook.HookType,
                                   vaBase + (UINT64)i * PAGE_SIZE,
                                   req.Hook.Pid,
                                   req.Hook.RangeSize ? req.Hook.RangeSize : 1);
                    hooked++;
                }
            }

            // Guarda MDL indexado pela PA da primeira pagina para desbloquear no unhook
            if (firstPa != 0)
                ShvHookSetMdl(firstPa, mdl);
            else
            {
                MmUnlockPages(mdl);
                IoFreeMdl(mdl);
            }

            resp->Status = hooked ? SHVD_STATUS_OK : SHVD_STATUS_ERR_ACCESS;
            ShvLog("[SHV-IOCTL] HOOK_EPT PID=%llu VA=%016llX-%016llX pages=%u locked\n",
                   req.Hook.Pid, vaBase, vaEnd, hooked);
        }
        break;
    }

    case SHV_CMD_UNHOOK_EPT:
    {
        PHYSICAL_ADDRESS pa;
        UINT64           vaBase;

        if (req.Unhook.VirtAddr == 0)
        {
            resp->Status = SHVD_STATUS_ERR_INVALID;
            break;
        }

        vaBase = req.Unhook.VirtAddr & ~(UINT64)0xFFF;

        if (req.Unhook.Pid == 0)
        {
            // Kernel: traduz VA e remove hook da pagina
            __try
            {
                pa = MmGetPhysicalAddress((PVOID)(ULONG_PTR)vaBase);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                resp->Status = SHVD_STATUS_ERR_ACCESS;
                break;
            }
            resp->Status = ShvHookRemove(pa.QuadPart & ~0xFFFULL);
        }
        else
        {
            // User-mode: recupera MDL pelo PA da primeira pagina e remove todos os hooks
            PEPROCESS process;
            KAPC_STATE apcState;
            PMDL       mdl;

            if (!NT_SUCCESS(PsLookupProcessByProcessId(
                    (HANDLE)(ULONG_PTR)req.Unhook.Pid, &process)))
            {
                resp->Status = SHVD_STATUS_ERR_ACCESS;
                break;
            }
            KeStackAttachProcess(process, &apcState);
            __try { pa = MmGetPhysicalAddress((PVOID)(ULONG_PTR)vaBase); }
            __except (EXCEPTION_EXECUTE_HANDLER) { pa.QuadPart = 0; }
            KeUnstackDetachProcess(&apcState);
            ObDereferenceObject(process);

            if ((pa.QuadPart & ~0xFFFULL) == 0)
            {
                resp->Status = SHVD_STATUS_ERR_ACCESS;
                break;
            }

            // Remove hook de todas as paginas do MDL
            mdl = ShvHookTakeMdl(pa.QuadPart & ~0xFFFULL);
            if (mdl != NULL)
            {
                PPFN_NUMBER pfnArray = MmGetMdlPfnArray(mdl);
                ULONG pageCount = (MmGetMdlByteCount(mdl) + PAGE_SIZE - 1) / PAGE_SIZE;
                ULONG i;
                for (i = 0; i < pageCount; i++)
                {
                    UINT64 gpa = (UINT64)pfnArray[i] << PAGE_SHIFT;
                    if (gpa != 0) ShvHookRemove(gpa);
                }
                MmUnlockPages(mdl);
                IoFreeMdl(mdl);
            }
            else
            {
                // Sem MDL (ex: hook por kernel path) — remove apenas a pagina base
                ShvHookRemove(pa.QuadPart & ~0xFFFULL);
            }
            resp->Status = SHVD_STATUS_OK;
        }
        break;
    }

    case SHV_CMD_TRANSLATE_VA:
    {
        PHYSICAL_ADDRESS pa;

        if (req.Translate.Pid == 0)
        {
            __try
            {
                pa = MmGetPhysicalAddress((PVOID)(ULONG_PTR)req.Translate.VirtAddr);
                resp->PhysAddr = pa.QuadPart;
                resp->Status   = SHVD_STATUS_OK;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                resp->Status = SHVD_STATUS_ERR_ACCESS;
            }
        }
        else
        {
            PEPROCESS process;
            KAPC_STATE apcState;
            if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req.Translate.Pid, &process)))
            {
                resp->Status = SHVD_STATUS_ERR_ACCESS;
                break;
            }
            KeStackAttachProcess(process, &apcState);
            __try
            {
                pa = MmGetPhysicalAddress((PVOID)(ULONG_PTR)req.Translate.VirtAddr);
                resp->PhysAddr = pa.QuadPart;
                resp->Status   = SHVD_STATUS_OK;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                resp->Status = SHVD_STATUS_ERR_ACCESS;
            }
            KeUnstackDetachProcess(&apcState);
            ObDereferenceObject(process);
        }
        break;
    }

    case SHV_CMD_READ_PHYS:
    {
        PHYSICAL_ADDRESS physAddr;
        PVOID            mapped;
        ULONG            size;

        size = req.ReadPhys.Size;
        if (size == 0 || size > SHV_MAX_READ_SIZE)
        {
            resp->Status = SHVD_STATUS_ERR_INVALID;
            break;
        }

        physAddr.QuadPart = req.ReadPhys.PhysAddr;
        mapped = MmMapIoSpace(physAddr, size, MmNonCached);
        if (mapped == NULL)
        {
            resp->Status = SHVD_STATUS_ERR_ACCESS;
            break;
        }

        RtlCopyMemory(resp->Data, mapped, size);
        MmUnmapIoSpace(mapped, size);
        resp->Count  = size;
        resp->Status = SHVD_STATUS_OK;
        break;
    }

    case SHV_CMD_LIST_PROCS:
    {
        ULONG    bufSize = 0x80000;   // 512KB inicial; sistemas com muitos processos/threads precisam de mais
        PVOID    sysInfo = NULL;
        NTSTATUS qStatus = STATUS_UNSUCCESSFUL;
        UINT32   tries;

        for (tries = 0; tries < 4; tries++)
        {
            if (sysInfo) ExFreePoolWithTag(sysInfo, 'vhSP');
            sysInfo = ExAllocatePoolWithTag(PagedPool, bufSize, 'vhSP');
            if (sysInfo == NULL)
            {
                resp->Status = SHVD_STATUS_ERR_NOMEM;
                break;
            }
            qStatus = ZwQuerySystemInformation(SystemProcessInformation,
                                               sysInfo, bufSize, NULL);
            if (qStatus != STATUS_INFO_LENGTH_MISMATCH)
                break;
            bufSize *= 2;
        }

        if (sysInfo == NULL)
            break;

        if (!NT_SUCCESS(qStatus))
        {
            ExFreePoolWithTag(sysInfo, 'vhSP');
            resp->Status = SHVD_STATUS_ERR_ACCESS;
            break;
        }

        {
            PSYSTEM_PROCESS_INFORMATION_SHV entry =
                (PSYSTEM_PROCESS_INFORMATION_SHV)sysInfo;
            UINT32 count = 0;
            UINT32 maxEntries = SHV_MAX_READ_SIZE / sizeof(SHV_PROC_ENTRY);

            while (count < maxEntries)
            {
                PSHV_PROC_ENTRY pe = &resp->Procs[count];
                RtlZeroMemory(pe, sizeof(*pe));

                pe->Pid     = (unsigned long long)(ULONG_PTR)entry->UniqueProcessId;

                // Ler DirBase real do EPROCESS+0x28 (KPROCESS.DirectoryTableBase).
                // ZwQuerySystemInformation nao expoe mais o CR3 em Vista+.
                {
                    PEPROCESS proc = NULL;
                    if (NT_SUCCESS(PsLookupProcessByProcessId(entry->UniqueProcessId, &proc)))
                    {
                        pe->DirBase = *(UINT64*)((UINT8*)proc + EPROCESS_DIR_TABLE_BASE_OFFSET);
                        ObDereferenceObject(proc);
                    }
                }

                if (entry->ImageName.Buffer != NULL && entry->ImageName.Length > 0)
                {
                    ULONG nameChars = entry->ImageName.Length / sizeof(WCHAR);
                    ULONG i;
                    if (nameChars >= SHV_PROC_NAME_LEN)
                        nameChars = SHV_PROC_NAME_LEN - 1;
                    for (i = 0; i < nameChars; i++)
                        pe->Name[i] = (char)entry->ImageName.Buffer[i];
                }

                count++;

                if (entry->NextEntryOffset == 0)
                    break;
                entry = (PSYSTEM_PROCESS_INFORMATION_SHV)
                        ((ULONG_PTR)entry + entry->NextEntryOffset);
            }

            resp->Count  = count;
            resp->Status = SHVD_STATUS_OK;
        }

        ExFreePoolWithTag(sysInfo, 'vhSP');
        break;
    }

    case SHV_CMD_LIST_MODULES:
    {
        ULONG  bufSize = 0x20000;
        PVOID  sysInfo = ExAllocatePoolWithTag(PagedPool, bufSize, 'vhSM');
        if (sysInfo == NULL)
        {
            resp->Status = SHVD_STATUS_ERR_NOMEM;
            break;
        }

        {
            NTSTATUS qStatus = ZwQuerySystemInformation(SystemModuleInformation,
                                                        sysInfo, bufSize, NULL);
            if (!NT_SUCCESS(qStatus))
            {
                ExFreePoolWithTag(sysInfo, 'vhSM');
                resp->Status = SHVD_STATUS_ERR_ACCESS;
                break;
            }
        }

        {
            PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)sysInfo;
            UINT32 count = 0;
            UINT32 maxEntries = SHV_MAX_READ_SIZE / sizeof(SHV_MODULE_ENTRY);
            UINT32 i;

            for (i = 0; i < mods->NumberOfModules && count < maxEntries; i++)
            {
                PRTL_PROCESS_MODULE_INFORMATION mi = &mods->Modules[i];
                PSHV_MODULE_ENTRY               me = &resp->Modules[count];

                RtlZeroMemory(me, sizeof(*me));
                me->Base = (unsigned long long)(ULONG_PTR)mi->ImageBase;
                me->Size = (unsigned long long)mi->ImageSize;

                {
                    ULONG nameLen = 0;
                    const char* src = (const char*)(mi->FullPathName + mi->OffsetToFileName);
                    while (nameLen < SHV_MOD_NAME_LEN - 1 && src[nameLen] != '\0') nameLen++;
                    RtlCopyMemory(me->Name, src, nameLen);
                }
                count++;
            }

            resp->Count  = count;
            resp->Status = SHVD_STATUS_OK;
        }

        ExFreePoolWithTag(sysInfo, 'vhSM');
        break;
    }

    // ----------------------------------------------------------------
    // EPT hook management
    // ----------------------------------------------------------------
    case SHV_CMD_UNHOOK_ALL:
        ShvLog("[SHV-IOCTL] UNHOOK_ALL\n");
        ShvHookReleaseMdls();   // desbloqueia paginas user-mode antes de remover hooks
        ShvHookRemoveAll();
        resp->Status = SHVD_STATUS_OK;
        break;

    case SHV_CMD_LIST_EPT_HOOKS:
    {
        UINT32 maxEntries = SHV_MAX_READ_SIZE / sizeof(SHV_EPT_HOOK_INFO);
        resp->Count  = ShvListEptHooks(resp->EptHookInfos, maxEntries, sizeof(SHV_EPT_HOOK_INFO));
        resp->Status = SHVD_STATUS_OK;
        break;
    }

    case SHV_CMD_CLEAR_EVENTS:
        ShvClearEvents();
        resp->Status = SHVD_STATUS_OK;
        break;

    // ----------------------------------------------------------------
    // Filtros de processo (NtOpenProcess via ObRegisterCallbacks)
    // ----------------------------------------------------------------
    case SHV_CMD_NTOP_PROTECT:
        if (req.ProcFilter.Pid == 0)
            resp->Status = SHVD_STATUS_ERR_INVALID;
        else
        {
            resp->Status = NT_SUCCESS(ShvHooksAddProtected(req.ProcFilter.Pid))
                           ? SHVD_STATUS_OK : SHVD_STATUS_ERR_FULL;
            ShvLog("[SHV-IOCTL] PROTECT PID=%llu -> status=%u\n",
                   req.ProcFilter.Pid, resp->Status);
        }
        break;

    case SHV_CMD_NTOP_UNPROTECT:
        if (req.ProcFilter.Pid == 0)
            resp->Status = SHVD_STATUS_ERR_INVALID;
        else
        {
            resp->Status = NT_SUCCESS(ShvHooksRemoveProtected(req.ProcFilter.Pid))
                           ? SHVD_STATUS_OK : SHVD_STATUS_ERR_NOTFOUND;
            ShvLog("[SHV-IOCTL] UNPROTECT PID=%llu -> status=%u\n",
                   req.ProcFilter.Pid, resp->Status);
        }
        break;

    case SHV_CMD_NTOP_MONITOR:
        if (req.ProcFilter.Pid == 0)
            resp->Status = SHVD_STATUS_ERR_INVALID;
        else
        {
            resp->Status = NT_SUCCESS(ShvHooksAddMonitored(req.ProcFilter.Pid))
                           ? SHVD_STATUS_OK : SHVD_STATUS_ERR_FULL;
            ShvLog("[SHV-IOCTL] MONITOR PID=%llu -> status=%u\n",
                   req.ProcFilter.Pid, resp->Status);
        }
        break;

    case SHV_CMD_NTOP_UNMONITOR:
        if (req.ProcFilter.Pid == 0)
            resp->Status = SHVD_STATUS_ERR_INVALID;
        else
        {
            resp->Status = NT_SUCCESS(ShvHooksRemoveMonitored(req.ProcFilter.Pid))
                           ? SHVD_STATUS_OK : SHVD_STATUS_ERR_NOTFOUND;
            ShvLog("[SHV-IOCTL] UNMONITOR PID=%llu -> status=%u\n",
                   req.ProcFilter.Pid, resp->Status);
        }
        break;

    case SHV_CMD_NTOP_PROTECT_NAME:
    {
        req.NameFilter.Name[SHV_PROC_NAME_LEN - 1] = '\0';
        resp->Status = NT_SUCCESS(ShvHooksAddProtectedName(req.NameFilter.Name))
                       ? SHVD_STATUS_OK : SHVD_STATUS_ERR_FULL;
        ShvLog("[SHV-IOCTL] PROTECT_NAME \"%s\" -> status=%u\n",
               req.NameFilter.Name, resp->Status);
        break;
    }

    case SHV_CMD_NTOP_UNPROTECT_NAME:
    {
        req.NameFilter.Name[SHV_PROC_NAME_LEN - 1] = '\0';
        resp->Status = NT_SUCCESS(ShvHooksRemoveProtectedName(req.NameFilter.Name))
                       ? SHVD_STATUS_OK : SHVD_STATUS_ERR_NOTFOUND;
        ShvLog("[SHV-IOCTL] UNPROTECT_NAME \"%s\" -> status=%u\n",
               req.NameFilter.Name, resp->Status);
        break;
    }

    case SHV_CMD_NTOP_MONITOR_NAME:
    {
        req.NameFilter.Name[SHV_PROC_NAME_LEN - 1] = '\0';
        resp->Status = NT_SUCCESS(ShvHooksAddMonitoredName(req.NameFilter.Name))
                       ? SHVD_STATUS_OK : SHVD_STATUS_ERR_FULL;
        ShvLog("[SHV-IOCTL] MONITOR_NAME \"%s\" -> status=%u\n",
               req.NameFilter.Name, resp->Status);
        break;
    }

    case SHV_CMD_NTOP_UNMONITOR_NAME:
    {
        req.NameFilter.Name[SHV_PROC_NAME_LEN - 1] = '\0';
        resp->Status = NT_SUCCESS(ShvHooksRemoveMonitoredName(req.NameFilter.Name))
                       ? SHVD_STATUS_OK : SHVD_STATUS_ERR_NOTFOUND;
        ShvLog("[SHV-IOCTL] UNMONITOR_NAME \"%s\" -> status=%u\n",
               req.NameFilter.Name, resp->Status);
        break;
    }

    case SHV_CMD_NTOP_LIST:
    {
        UINT32 maxEntries = SHV_MAX_READ_SIZE / sizeof(SHV_PROC_FILTER_ENTRY);
        ShvHooksListFilters(resp->Filters, &resp->Count, maxEntries);
        resp->Status = SHVD_STATUS_OK;
        break;
    }

    // ----------------------------------------------------------------
    // Leitura de memoria virtual
    // ----------------------------------------------------------------
    case SHV_CMD_READ_VIRT:
    {
        ULONG size = req.ReadVirt.Size;
        if (size == 0 || size > SHV_MAX_READ_SIZE)
        {
            resp->Status = SHVD_STATUS_ERR_INVALID;
            break;
        }

        if (req.ReadVirt.Pid == 0)
        {
            __try
            {
                RtlCopyMemory(resp->Data, (PVOID)(ULONG_PTR)req.ReadVirt.VirtAddr, size);
                resp->Count  = size;
                resp->Status = SHVD_STATUS_OK;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                resp->Status = SHVD_STATUS_ERR_ACCESS;
            }
        }
        else
        {
            PEPROCESS  process;
            KAPC_STATE apcState;
            if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req.ReadVirt.Pid, &process)))
            {
                resp->Status = SHVD_STATUS_ERR_ACCESS;
                break;
            }
            KeStackAttachProcess(process, &apcState);
            __try
            {
                RtlCopyMemory(resp->Data, (PVOID)(ULONG_PTR)req.ReadVirt.VirtAddr, size);
                resp->Count  = size;
                resp->Status = SHVD_STATUS_OK;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                resp->Status = SHVD_STATUS_ERR_ACCESS;
            }
            KeUnstackDetachProcess(&apcState);
            ObDereferenceObject(process);
        }
        break;
    }

    // ----------------------------------------------------------------
    // Shadow hooks: split-page EPT
    // ----------------------------------------------------------------
    case SHV_CMD_HOOK_SHADOW:
    {
        UINT64           gpa      = req.Shadow.Gpa & ~0xFFFULL;
        UINT32           offset   = req.Shadow.PatchOffset;
        UINT32           patchLen = req.Shadow.PatchLen;
        UINT32           i, freeSlot;
        PVOID            shadowVa = NULL;
        PHYSICAL_ADDRESS physAddr, lowest, highest, boundary;

        if (gpa == 0 || patchLen == 0 || patchLen > SHV_SHADOW_PATCH_MAX ||
            (UINT64)offset + patchLen > PAGE_SIZE)
        {
            resp->Status = SHVD_STATUS_ERR_INVALID;
            break;
        }

        freeSlot = (UINT32)-1;
        resp->Status = SHVD_STATUS_ERR_NOTFOUND;

        for (i = 0; i < SHV_SHADOW_MAX; i++)
        {
            if (g_ShadowPages[i].Gpa == gpa)
            {
                // Shadow page already exists -- just apply new patch
                RtlCopyMemory((UINT8*)g_ShadowPages[i].ShadowVa + offset,
                              req.Shadow.PatchBytes, patchLen);
                g_ShadowPages[i].RefCount++;
                resp->Status = SHVD_STATUS_OK;
                break;
            }
            if (g_ShadowPages[i].Gpa == 0 && freeSlot == (UINT32)-1)
                freeSlot = i;
        }

        if (resp->Status == SHVD_STATUS_OK)
            break;

        if (freeSlot == (UINT32)-1)
        {
            resp->Status = SHVD_STATUS_ERR_FULL;
            break;
        }

        lowest.QuadPart   = 0;
        highest.QuadPart  = -1LL;
        boundary.QuadPart = 0;

        shadowVa = MmAllocateContiguousNodeMemory(PAGE_SIZE, lowest, highest, boundary,
                                                  PAGE_EXECUTE_READWRITE,
                                                  KeGetCurrentNodeNumber());
        if (shadowVa == NULL)
        {
            resp->Status = SHVD_STATUS_ERR_NOMEM;
            break;
        }

        // Copy original physical page content
        physAddr.QuadPart = gpa;
        {
            PVOID origVa = MmMapIoSpace(physAddr, PAGE_SIZE, MmNonCached);
            if (origVa == NULL)
            {
                MmFreeContiguousMemory(shadowVa);
                resp->Status = SHVD_STATUS_ERR_ACCESS;
                break;
            }
            RtlCopyMemory(shadowVa, origVa, PAGE_SIZE);
            MmUnmapIoSpace(origVa, PAGE_SIZE);
        }

        // Apply patch to shadow copy
        RtlCopyMemory((UINT8*)shadowVa + offset, req.Shadow.PatchBytes, patchLen);

        physAddr = MmGetPhysicalAddress(shadowVa);
        g_ShadowPages[freeSlot].Gpa      = gpa;
        g_ShadowPages[freeSlot].ShadowPa = physAddr.QuadPart;
        g_ShadowPages[freeSlot].ShadowVa = shadowVa;
        g_ShadowPages[freeSlot].RefCount  = 1;
        g_ShadowPages[freeSlot].Offset    = offset;
        g_ShadowPages[freeSlot].PatchLen  = patchLen;
        RtlCopyMemory(g_ShadowPages[freeSlot].PatchBytes, req.Shadow.PatchBytes, patchLen);

        resp->Status = ShvHookInstallShadow(gpa, physAddr.QuadPart);
        ShvLog("[SHV-IOCTL] HOOK_SHADOW GPA=%016llX shadowPA=%016llX offset=%u len=%u -> status=%u\n",
               gpa, physAddr.QuadPart, offset, patchLen, resp->Status);
        if (resp->Status != SHVD_STATUS_OK)
        {
            MmFreeContiguousMemory(shadowVa);
            RtlZeroMemory(&g_ShadowPages[freeSlot], sizeof(SHV_SHADOW_PAGE_RECORD));
        }
        break;
    }

    case SHV_CMD_UNHOOK_SHADOW:
    {
        UINT64  gpa = req.Shadow.Gpa & ~0xFFFULL;
        UINT32  i;
        BOOLEAN found = FALSE;

        for (i = 0; i < SHV_SHADOW_MAX; i++)
        {
            if (g_ShadowPages[i].Gpa == gpa)
            {
                found = TRUE;
                if (g_ShadowPages[i].RefCount > 0)
                    g_ShadowPages[i].RefCount--;
                if (g_ShadowPages[i].RefCount == 0)
                {
                    ShvHookRemoveShadow(gpa);
                    MmFreeContiguousMemory(g_ShadowPages[i].ShadowVa);
                    RtlZeroMemory(&g_ShadowPages[i], sizeof(SHV_SHADOW_PAGE_RECORD));
                }
                resp->Status = SHVD_STATUS_OK;
                break;
            }
        }

        if (!found)
            resp->Status = SHVD_STATUS_ERR_NOTFOUND;
        ShvLog("[SHV-IOCTL] UNHOOK_SHADOW GPA=%016llX found=%d -> status=%u\n",
               (req.Shadow.Gpa & ~0xFFFULL), (int)found, resp->Status);
        break;
    }

    case SHV_CMD_BEEP_SHADOW_SETUP:
        // Beep hijack is already set up via dispatch table replacement in DriverEntry.
        // EPT shadow upgrade is a future enhancement.
        resp->Status = SHVD_STATUS_OK;
        break;

    case SHV_CMD_LIST_SYSCALL_HOOKS:
    {
        UINT32 count = 0;
        UINT32 maxEntries = SHV_MAX_READ_SIZE / sizeof(SHV_HOOK_INFO);
        UINT32 i;

        for (i = 0; i < SHV_SYSCALL_HOOK_MAX && count < maxEntries; i++)
        {
            if (g_SyscallHooks[i].InUse)
            {
                PSHV_HOOK_INFO hi = &resp->HookInfos[count];
                RtlZeroMemory(hi, sizeof(*hi));
                hi->SyscallIndex  = g_SyscallHooks[i].SyscallIndex;
                hi->DisplacedSize = g_SyscallHooks[i].DisplacedSize;
                hi->HookFuncVa    = (UINT64)(ULONG_PTR)g_SyscallHooks[i].HookFunc;
                hi->TrampolineVa  = (UINT64)(ULONG_PTR)g_SyscallHooks[i].Trampoline;
                hi->FuncGpa       = g_SyscallHooks[i].FuncGpa;
                hi->FuncVa        = (UINT64)(ULONG_PTR)g_SyscallHooks[i].FuncVa;
                count++;
            }
        }

        resp->Count  = count;
        resp->Status = SHVD_STATUS_OK;
        break;
    }

    case SHV_CMD_LIST_SHADOW_PATCHES:
    {
        UINT32 count = 0;
        UINT32 maxEntries = SHV_MAX_READ_SIZE / sizeof(SHV_SHADOW_HOOK_INFO);
        UINT32 i;

        for (i = 0; i < SHV_SHADOW_MAX && count < maxEntries; i++)
        {
            if (g_ShadowPages[i].Gpa != 0)
            {
                PSHV_SHADOW_HOOK_INFO shi = &resp->ShadowHookInfos[count];
                RtlZeroMemory(shi, sizeof(*shi));
                shi->GpaPage  = g_ShadowPages[i].Gpa;
                shi->Offset   = g_ShadowPages[i].Offset;
                shi->PatchLen = g_ShadowPages[i].PatchLen;
                shi->FuncVa   = 0;
                if (g_ShadowPages[i].PatchLen <= SHV_SHADOW_PATCH_MAX)
                    RtlCopyMemory(shi->PatchBytes, g_ShadowPages[i].PatchBytes,
                                  g_ShadowPages[i].PatchLen);
                count++;
            }
        }

        resp->Count  = count;
        resp->Status = SHVD_STATUS_OK;
        break;
    }

    default:
        resp->Status = SHVD_STATUS_ERR_INVALID;
        break;
    }

    Irp->IoStatus.Information = sizeof(SHV_RESPONSE);

Exit:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS
ShvDispatchPassthrough (
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
FORCEINLINE
ShvOsErrorToError (
    INT32 Error
    )
{
    //
    // Convert the possible SimpleVisor errors into NT Hyper-V Errors
    //
    if (Error == SHV_STATUS_NOT_AVAILABLE)
    {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }
    if (Error == SHV_STATUS_NO_RESOURCES)
    {
        return STATUS_HV_NO_RESOURCES;
    }
    if (Error == SHV_STATUS_NOT_PRESENT)
    {
        return STATUS_HV_NOT_PRESENT;
    }
    if (Error == SHV_STATUS_SUCCESS)
    {
        return STATUS_SUCCESS;
    }

    //
    // Unknown/unexpected error
    //
    return STATUS_UNSUCCESSFUL;
}

VOID
ShvOsDpcRoutine (
    _In_ struct _KDPC *Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PSHV_DPC_CONTEXT dpcContext = DeferredContext;
    UNREFERENCED_PARAMETER(Dpc);

    __analysis_assume(DeferredContext != NULL);
    __analysis_assume(SystemArgument1 != NULL);
    __analysis_assume(SystemArgument2 != NULL);

    //
    // Execute the internal callback function
    //
    dpcContext->Routine(dpcContext->Context);

    //
    // During unload SimpleVisor uses the RtlRestoreContext function which will
    // unfortunately use the "iretq" opcode in order to restore execution back.
    // This causes the processor to remove the RPL bits off the segments. As
    // the x64 kernel does not expect kernel-mode code to change the value of
    // any segments, this results in the DS and ES segments being stuck 0x20,
    // and the FS segment being stuck at 0x50, until the next context switch.
    //
    // If the DPC happened to have interrupted either the idle thread or system
    // thread, that's perfectly fine (albeit unusual). If the DPC interrupted a
    // 64-bit long-mode thread, that's also fine. However if the DPC interrupts
    // a thread in compatibility-mode, running as part of WoW64, it will hit a
    // GPF instantaneously and crash.
    //
    // Thus, set the segments to their correct value, one more time, as a fix.
    //
    ShvVmxCleanup(KGDT64_R3_DATA | RPL_MASK, KGDT64_R3_CMTEB | RPL_MASK);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

INT32
ShvOsPrepareProcessor (
    _In_ PSHV_VP_DATA VpData
    )
{
    //
    // Nothing to do on NT, only return SHV_STATUS_SUCCESS
    //
    UNREFERENCED_PARAMETER(VpData);
    return SHV_STATUS_SUCCESS;
}

VOID
ShvOsUnprepareProcessor (
    _In_ PSHV_VP_DATA VpData
    )
{
    //
    // When running in VMX root mode, the processor will set limits of the
    // GDT and IDT to 0xFFFF (notice that there are no Host VMCS fields to
    // set these values). This causes problems with PatchGuard, which will
    // believe that the GDTR and IDTR have been modified by malware, and
    // eventually crash the system. Since we know what the original state
    // of the GDTR and IDTR was, simply restore it now.
    //
    __lgdt(&VpData->SpecialRegisters.Gdtr.Limit);
    __lidt(&VpData->SpecialRegisters.Idtr.Limit);
}

VOID
PowerCallback (
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    UNREFERENCED_PARAMETER(CallbackContext);

    //
    // Ignore non-Sx changes
    //
    if (Argument1 != (PVOID)PO_CB_SYSTEM_STATE_LOCK)
    {
        return;
    }

    //
    // Check if this is S0->Sx, or Sx->S0
    //
    if (ARGUMENT_PRESENT(Argument2))
    {
        //
        // Reload the hypervisor
        //
        ShvLoad();
    }
    else
    {
        //
        // Unload the hypervisor
        //
        ShvUnload();
    }
}

VOID
ShvOsFreeContiguousAlignedMemory (
    _In_ PVOID BaseAddress
    )
{
    //
    // Free the memory
    //
    MmFreeContiguousMemory(BaseAddress);
}

PVOID
ShvOsAllocateContigousAlignedMemory (
    _In_ SIZE_T Size
    )
{
    PHYSICAL_ADDRESS lowest, highest;

    //
    // The entire address range is OK for this allocation
    //
    lowest.QuadPart = 0;
    highest.QuadPart = lowest.QuadPart - 1;

    //
    // Allocate a contiguous chunk of RAM to back this allocation and make sure
    // that it is RW only, instead of RWX, by using the new Windows 8 API.
    //
    return MmAllocateContiguousNodeMemory(Size,
                                          lowest,
                                          highest,
                                          lowest,
                                          PAGE_READWRITE,
                                          KeGetCurrentNodeNumber());
}

ULONGLONG
ShvOsGetPhysicalAddress (
    _In_ PVOID BaseAddress
    )
{
    //
    // Let the memory manager convert it
    //
    return MmGetPhysicalAddress(BaseAddress).QuadPart;
}

VOID
ShvOsRunCallbackOnProcessors (
    _In_ PSHV_CPU_CALLBACK Routine,
    _In_opt_ PVOID Context
    )
{
    SHV_DPC_CONTEXT dpcContext;

    //
    // Wrap the internal routine and context under a Windows DPC
    //
    dpcContext.Routine = Routine;
    dpcContext.Context = Context;
    KeGenericCallDpc(ShvOsDpcRoutine, &dpcContext);
}

VOID
ShvOsRestoreContext(
    _In_ PCONTEXT ContextRecord
    )
{
    ShvOsRestoreContext2(ContextRecord, NULL);
}

VOID
ShvOsCaptureContext (
    _In_ PCONTEXT ContextRecord
    )
{
    //
    // Windows provides a nice OS function to do this
    //
    RtlCaptureContext(ContextRecord);
}

INT32
ShvOsGetCurrentProcessorNumber (
    VOID
    )
{
    //
    // Get the group-wide CPU index
    //
    return (INT32)KeGetCurrentProcessorNumberEx(NULL);
}

INT32
ShvOsGetActiveProcessorCount (
    VOID
    )
{
    //
    // Get the group-wide CPU count
    //
    return (INT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
}

VOID
ShvOsDebugPrint (
    _In_ PCCH Format,
    ...
    )
{
    va_list arglist;

    //
    // Call the debugger API
    //
    va_start(arglist, Format);
    vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, arglist);
    va_end(arglist);
}

VOID
DriverUnload (
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(SHV_DEVICE_LINK);

    UNREFERENCED_PARAMETER(DriverObject);

    ShvLog("[SHV] DriverUnload iniciado...\n");

    // Remove symbolic link e device object
    IoDeleteSymbolicLink(&symLink);
    if (g_ShvDeviceObject != NULL)
    {
        IoDeleteDevice(g_ShvDeviceObject);
        g_ShvDeviceObject = NULL;
    }

    //
    // Uninit process filters (ObRegisterCallbacks)
    //
    ShvLog("[SHV] Removendo filtros de processo...\n");
    ShvHooksUninit();

    //
    // Remove EPT shadow policy hooks BEFORE freeing trampoline pool
    //
    ShvLog("[SHV] Removendo hooks de politica EPT...\n");
    ShvPolicyHooksUninit();

    //
    // Restore Beep dispatch table
    //
    ShvLog("[SHV] Restaurando Beep dispatch...\n");
    ShvBeepHijackTeardown();

    //
    // Free trampoline pool (after hypervisor unload so no more EPT violations)
    //
    ShvLog("[SHV] Liberando trampoline pool...\n");
    HpvTrampolinePoolFree();

    //
    // Unregister the power callback. We would not have loaded without it
    //
    ExUnregisterCallback(g_PowerCallbackRegistration);

    //
    // Unload the hypervisor
    //
    ShvLog("[SHV] Descarregando hipervisor VMX (ShvUnload)...\n");
    ShvUnload();
    ShvLog("[SHV] DriverUnload concluido.\n");
}

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    PCALLBACK_OBJECT callbackObject;
    UNICODE_STRING callbackName =
        RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
    UNICODE_STRING devName  = RTL_CONSTANT_STRING(SHV_DEVICE_NAME);
    UNICODE_STRING symLink  = RTL_CONSTANT_STRING(SHV_DEVICE_LINK);
    OBJECT_ATTRIBUTES objectAttributes =
        RTL_CONSTANT_OBJECT_ATTRIBUTES(&callbackName,
                                       OBJ_CASE_INSENSITIVE |
                                       OBJ_KERNEL_HANDLE);
    UNREFERENCED_PARAMETER(RegistryPath);

    //
    // Make the driver (and SHV itself) unloadable
    //
    DriverObject->DriverUnload                         = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = ShvDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = ShvDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ShvDispatchIoctl;

    //
    // Create device object para o IOCTL interface
    //
    status = IoCreateDevice(DriverObject,
                            0,
                            &devName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &g_ShvDeviceObject);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(g_ShvDeviceObject);
        g_ShvDeviceObject = NULL;
        return status;
    }

    //
    // Create the power state callback
    //
    status = ExCreateCallback(&callbackObject, &objectAttributes, FALSE, TRUE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    //
    // Now register our routine with this callback
    //
    g_PowerCallbackRegistration = ExRegisterCallback(callbackObject,
                                                     PowerCallback,
                                                     NULL);

    //
    // Dereference it in both cases -- either it's registered, so that is now
    // taking a reference, and we'll unregister later, or it failed to register
    // so we failing now, and it's gone.
    //
    ObDereferenceObject(callbackObject);

    //
    // Fail if we couldn't register the power callback
    //
    if (g_PowerCallbackRegistration == NULL)
    {
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_ShvDeviceObject);
        g_ShvDeviceObject = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ShvLog("[SHV] DriverEntry iniciado\n");

    //
    // Init trampoline pool BEFORE ShvLoad (shadow hooks need it at any time)
    //
    ShvLog("[SHV] Iniciando pool de trampolins...\n");
    status = HpvTrampolinePoolInit();
    if (!NT_SUCCESS(status))
    {
        ShvLog("[SHV] HpvTrampolinePoolInit FALHOU: 0x%08X\n", status);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[SHV] HpvTrampolinePoolInit falhou: 0x%08X\n", status);
        ExUnregisterCallback(g_PowerCallbackRegistration);
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_ShvDeviceObject);
        g_ShvDeviceObject = NULL;
        return status;
    }
    ShvLog("[SHV] Trampoline pool OK: %p\n", g_TrampolinePool);

    //
    // Setup Beep hijack BEFORE ShvLoad -- ShvBeepHijackSetup apenas substitui
    // a entrada da tabela de dispatch, nao requer o hipervisor ainda rodando.
    //
    ShvLog("[SHV] Iniciando Beep hijack...\n");
    status = ShvBeepHijackSetup();
    if (!NT_SUCCESS(status))
    {
        ShvLog("[SHV] ShvBeepHijackSetup FALHOU: 0x%08X\n", status);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[SHV] ShvBeepHijackSetup falhou: 0x%08X\n", status);
        ExUnregisterCallback(g_PowerCallbackRegistration);
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_ShvDeviceObject);
        g_ShvDeviceObject = NULL;
        return status;
    }
    ShvLog("[SHV] Beep hijack OK\n");

    //
    // Load the hypervisor
    //
    ShvLog("[SHV] Carregando hipervisor VMX (ShvLoad)...\n");
    status = ShvOsErrorToError(ShvLoad());

    //
    // If load of the hypervisor happened to fail, unregister previously registered
    // power callback, otherwise we would get BSOD on shutdown.
    //
    if (!NT_SUCCESS(status))
    {
        ShvLog("[SHV] ShvLoad FALHOU: 0x%08X\n", status);
        ShvBeepHijackTeardown();
        ExUnregisterCallback(g_PowerCallbackRegistration);
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_ShvDeviceObject);
        g_ShvDeviceObject = NULL;
        return status;
    }
    ShvLog("[SHV] Hipervisor VMX carregado OK\n");

    //
    // Init process filter subsystem (ObRegisterCallbacks) AFTER ShvLoad
    //
    ShvLog("[SHV] Iniciando filtros de processo (ShvHooksInit)...\n");
    ShvHooksInit();
    ShvLog("[SHV] ShvHooksInit OK\n");

    //
    // Install EPT shadow hooks: NtOpenProcess + MmCopyVirtualMemory
    //
    ShvLog("[SHV] Instalando hooks de politica EPT (NtOpenProcess+MmCopyVirtualMemory)...\n");
    status = ShvPolicyHooksInit();
    if (!NT_SUCCESS(status))
    {
        ShvLog("[SHV] ShvPolicyHooksInit FALHOU: 0x%08X (nao fatal, continuando)\n", status);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[SHV] ShvPolicyHooksInit falhou: 0x%08X (nao fatal)\n", status);
        // Nao e fatal; o driver funciona sem os hooks de politica
    }
    else
    {
        ShvLog("[SHV] Hooks de politica EPT instalados OK\n");
    }

    ShvLog("[SHV] DriverEntry concluido com sucesso. Driver pronto.\n");
    return STATUS_SUCCESS;
}


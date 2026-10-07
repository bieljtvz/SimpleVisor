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
#pragma warning(disable:4221)
#pragma warning(disable:4204)

// Declaracoes das funcoes de hook (definidas em shvvmxhv.c)
// Nao incluimos shv.h aqui para evitar conflito com ntifs.h.
UINT32 ShvHookInstall(_In_ UINT64 PhysAddr, _In_ UINT8 HookType);
UINT32 ShvHookRemove(_In_ UINT64 PhysAddr);

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
    ULONG_PTR      PageDirectoryBase;     // CR3 do processo
    // ... campos restantes nao precisamos
} SYSTEM_PROCESS_INFORMATION_SHV, *PSYSTEM_PROCESS_INFORMATION_SHV;

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

static NTSTATUS
ShvDispatchIoctl (
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    PIO_STACK_LOCATION  ioStack;
    SHV_REQUEST         req;
    SHV_RESPONSE        resp;
    ULONG               inputLen;
    ULONG               outputLen;
    NTSTATUS            status = STATUS_SUCCESS;
    PVOID               buffer;

    UNREFERENCED_PARAMETER(DeviceObject);

    RtlZeroMemory(&resp, sizeof(resp));
    resp.Status = SHVD_STATUS_ERR_INVALID;

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
        resp.Status = SHVD_STATUS_ERR_INVALID;
        goto CopyOut;
    }

    RtlCopyMemory(&req, buffer, sizeof(SHV_REQUEST));

    switch (req.Command)
    {
    case SHV_CMD_HOOK_EPT:
    {
        UINT64 page = req.Hook.PhysAddr & ~0xFFFULL;
        if (page == 0)
        {
            resp.Status = SHVD_STATUS_ERR_INVALID;
            break;
        }
        resp.Status = ShvHookInstall(page, req.Hook.HookType);
        break;
    }

    case SHV_CMD_UNHOOK_EPT:
    {
        UINT64 page = req.Unhook.PhysAddr & ~0xFFFULL;
        resp.Status = ShvHookRemove(page);
        break;
    }

    case SHV_CMD_TRANSLATE_VA:
    {
        PHYSICAL_ADDRESS pa;

        if (req.Translate.Pid == 0)
        {
            // Kernel VA: MmGetPhysicalAddress direto
            __try
            {
                pa = MmGetPhysicalAddress((PVOID)(ULONG_PTR)req.Translate.VirtAddr);
                resp.PhysAddr = pa.QuadPart;
                resp.Status   = SHVD_STATUS_OK;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                resp.Status = SHVD_STATUS_ERR_ACCESS;
            }
        }
        else
        {
            // Process VA: attach -> translate -> detach
            PEPROCESS process;
            KAPC_STATE apcState;
            NTSTATUS   lookupStatus;

            lookupStatus = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req.Translate.Pid,
                                                      &process);
            if (!NT_SUCCESS(lookupStatus))
            {
                resp.Status = SHVD_STATUS_ERR_ACCESS;
                break;
            }

            KeStackAttachProcess(process, &apcState);
            __try
            {
                pa = MmGetPhysicalAddress((PVOID)(ULONG_PTR)req.Translate.VirtAddr);
                resp.PhysAddr = pa.QuadPart;
                resp.Status   = SHVD_STATUS_OK;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                resp.Status = SHVD_STATUS_ERR_ACCESS;
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
            resp.Status = SHVD_STATUS_ERR_INVALID;
            break;
        }

        physAddr.QuadPart = req.ReadPhys.PhysAddr;
        mapped = MmMapIoSpace(physAddr, size, MmNonCached);
        if (mapped == NULL)
        {
            resp.Status = SHVD_STATUS_ERR_ACCESS;
            break;
        }

        RtlCopyMemory(resp.Data, mapped, size);
        MmUnmapIoSpace(mapped, size);
        resp.Count  = size;
        resp.Status = SHVD_STATUS_OK;
        break;
    }

    case SHV_CMD_LIST_PROCS:
    {
        ULONG  bufSize = 0x10000;
        PVOID  sysInfo = ExAllocatePoolWithTag(PagedPool, bufSize, 'vhSP');
        if (sysInfo == NULL)
        {
            resp.Status = SHVD_STATUS_ERR_NOMEM;
            break;
        }

        {
            NTSTATUS qStatus = ZwQuerySystemInformation(SystemProcessInformation,
                                                        sysInfo, bufSize, NULL);
            if (!NT_SUCCESS(qStatus))
            {
                ExFreePoolWithTag(sysInfo, 'vhSP');
                resp.Status = SHVD_STATUS_ERR_ACCESS;
                break;
            }
        }

        {
            PSYSTEM_PROCESS_INFORMATION_SHV entry =
                (PSYSTEM_PROCESS_INFORMATION_SHV)sysInfo;
            UINT32 count = 0;
            UINT32 maxEntries = SHV_MAX_READ_SIZE / sizeof(SHV_PROC_ENTRY);

            while (count < maxEntries)
            {
                PSHV_PROC_ENTRY pe = &resp.Procs[count];
                RtlZeroMemory(pe, sizeof(*pe));

                pe->Pid     = (unsigned long long)(ULONG_PTR)entry->UniqueProcessId;
                pe->DirBase = (unsigned long long)entry->PageDirectoryBase;

                if (entry->ImageName.Buffer != NULL && entry->ImageName.Length > 0)
                {
                    ULONG nameChars = entry->ImageName.Length / sizeof(WCHAR);
                    ULONG i;
                    if (nameChars >= SHV_PROC_NAME_LEN)
                    {
                        nameChars = SHV_PROC_NAME_LEN - 1;
                    }
                    for (i = 0; i < nameChars; i++)
                    {
                        pe->Name[i] = (char)entry->ImageName.Buffer[i];
                    }
                }

                count++;

                if (entry->NextEntryOffset == 0)
                {
                    break;
                }
                entry = (PSYSTEM_PROCESS_INFORMATION_SHV)
                        ((ULONG_PTR)entry + entry->NextEntryOffset);
            }

            resp.Count  = count;
            resp.Status = SHVD_STATUS_OK;
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
            resp.Status = SHVD_STATUS_ERR_NOMEM;
            break;
        }

        {
            NTSTATUS qStatus = ZwQuerySystemInformation(SystemModuleInformation,
                                                        sysInfo, bufSize, NULL);
            if (!NT_SUCCESS(qStatus))
            {
                ExFreePoolWithTag(sysInfo, 'vhSM');
                resp.Status = SHVD_STATUS_ERR_ACCESS;
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
                PSHV_MODULE_ENTRY               me = &resp.Modules[count];

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

            resp.Count  = count;
            resp.Status = SHVD_STATUS_OK;
        }

        ExFreePoolWithTag(sysInfo, 'vhSM');
        break;
    }

    default:
        resp.Status = SHVD_STATUS_ERR_INVALID;
        break;
    }

CopyOut:
    RtlCopyMemory(buffer, &resp, sizeof(SHV_RESPONSE));
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

    // Remove symbolic link e device object
    IoDeleteSymbolicLink(&symLink);
    if (g_ShvDeviceObject != NULL)
    {
        IoDeleteDevice(g_ShvDeviceObject);
        g_ShvDeviceObject = NULL;
    }

    //
    // Unregister the power callback. We would not have loaded without it
    //
    ExUnregisterCallback(g_PowerCallbackRegistration);

    //
    // Unload the hypervisor
    //
    ShvUnload();
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

    //
    // Load the hypervisor
    //
    status = ShvOsErrorToError(ShvLoad());

    //
    // If load of the hypervisor happened to fail, unregister previously registered
    // power callback, otherwise we would get BSOD on shutdown.
    //
    if (!NT_SUCCESS(status))
    {
        ExUnregisterCallback(g_PowerCallbackRegistration);
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_ShvDeviceObject);
        g_ShvDeviceObject = NULL;
    }

    return status;
}


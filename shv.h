/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    shv.h

Abstract:

    This header defines the structures and functions of the Simple Hyper Visor.

Author:

    Alex Ionescu (@aionescu) 14-Mar-2016 - Initial version

Environment:

    Kernel mode only.

--*/

#pragma once
#pragma warning(disable:4201)
#pragma warning(disable:4214)

#ifndef __BASE_H__
#include <basetsd.h>
#endif
#define _INC_MALLOC
#include <intrin.h>
#include "ntint.h"
#include "shv_x.h"

typedef struct _SHV_VP_STATE
{
    PCONTEXT VpRegs;
    uintptr_t GuestRip;
    uintptr_t GuestRsp;
    uintptr_t GuestEFlags;
    UINT16 ExitReason;
    UINT8 ExitVm;
    UINT8 SkipRipAdvance; // TRUE = nao adiantar RIP (EPT violation, MTF)
} SHV_VP_STATE, *PSHV_VP_STATE;

typedef struct _SHV_CALLBACK_CONTEXT
{
    UINT64 Cr3;
    volatile long InitCount;
    INT32 FailedCpu;
    INT32 FailureStatus;
} SHV_CALLBACK_CONTEXT, *PSHV_CALLBACK_CONTEXT;

SHV_CPU_CALLBACK ShvVpLoadCallback;
SHV_CPU_CALLBACK ShvVpUnloadCallback;

VOID
ShvVmxEntry (
    VOID
    );

UINT64
ShvVmxCall (
    _In_ UINT64 Magic
    );

//
// ShvSyscallTrampoline e ShvVmxInstallSyscallHook estao desativados.
// Requerem KPTI desativado -- veja o bloco #if 0 em shvvmxhv.c.
//
// VOID ShvSyscallTrampoline (VOID);
// VOID ShvVmxInstallSyscallHook (VOID);

INT32
ShvVmxLaunchOnVp (
    _In_ PSHV_VP_DATA VpData
    );

VOID
ShvUtilConvertGdtEntry (
    _In_ VOID* GdtBase,
    _In_ UINT16 Offset,
    _Out_ PVMX_GDTENTRY64 VmxGdtEntry
    );

UINT32
ShvUtilAdjustMsr (
    _In_ LARGE_INTEGER ControlValue,
    _In_ UINT32 DesiredValue
    );

PSHV_VP_DATA
ShvVpAllocateData (
    _In_ UINT32 CpuCount
    );

VOID
ShvVpFreeData  (
    _In_ PSHV_VP_DATA Data,
    _In_ UINT32 CpuCount
    );

INT32
ShvVmxLaunch (
    VOID
    );

UINT8
ShvVmxProbe (
    VOID
    );

VOID
ShvVmxEptInitialize (
    _In_ PSHV_VP_DATA VpData
    );

VOID
ShvVmxMsrBitmapInitialize (
    _In_ PSHV_VP_DATA VpData
    );

UINT8
ShvVmxEptSplitLargePage (
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 GuestPhysical
    );

VOID
ShvVmxEptSetPermissions (
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 GuestPhysical,
    _In_ UINT8 Read,
    _In_ UINT8 Write,
    _In_ UINT8 Execute
    );

VOID
ShvVmxEptSetPhysAndPerms (
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 GuestPhysical,
    _In_ UINT64 NewPhysAddr,
    _In_ UINT8 Read,
    _In_ UINT8 Write,
    _In_ UINT8 Execute
    );

VOID
ShvVmxInvept (
    _In_ UINT64 Type,
    _In_ VOID* Descriptor
    );

VOID
ShvVmxInveptLocal (
    _In_ PSHV_VP_DATA VpData
    );

DECLSPEC_NORETURN
VOID
ShvVpRestoreAfterLaunch (
    VOID
    );

//
// OS Layer
//
DECLSPEC_NORETURN
VOID
__cdecl
ShvOsRestoreContext (
    _In_ PCONTEXT ContextRecord
    );

VOID
ShvOsCaptureContext (
    _In_ PCONTEXT ContextRecord
    );

VOID
ShvOsUnprepareProcessor (
    _In_ PSHV_VP_DATA VpData
    );

INT32
ShvOsPrepareProcessor (
    _In_ PSHV_VP_DATA VpData
    );

INT32
ShvOsGetActiveProcessorCount (
    VOID
    );

INT32
ShvOsGetCurrentProcessorNumber (
    VOID
    );

VOID
ShvOsFreeContiguousAlignedMemory (
    _In_ VOID* BaseAddress,
    _In_ size_t Size
    );

VOID*
ShvOsAllocateContigousAlignedMemory (
    _In_ size_t Size
    );

UINT64
ShvOsGetPhysicalAddress (
    _In_ VOID* BaseAddress
    );

#ifndef __BASE_H__
VOID
ShvOsDebugPrint (
    _In_ const char* Format,
    ...
    );
#else
VOID
ShvOsDebugPrintWide (
    _In_ const CHAR16* Format,
    ...
    );
#define ShvOsDebugPrint(format, ...) ShvOsDebugPrintWide(_CRT_WIDE(format), __VA_ARGS__)
#endif

VOID
ShvOsRunCallbackOnProcessors (
    _In_ PSHV_CPU_CALLBACK Routine,
    _In_opt_ VOID* Context
    );

extern PSHV_VP_DATA* ShvGlobalData;

// Endereco fisico do hook EPT (KiSystemCall64). Zero = hook nao instalado.
// Definido em shvvmxhv.c, usado em shvvmx.c para saber onde instalar.
extern volatile UINT64 ShvEptHookPhysical;
extern volatile UINT64 ShvEptHookHitCount;
extern UINT8 ShvEptExecuteOnlySupported;

// Tabela de hooks EPT instalados via IOCTL (shvvmxhv.c)
// Retornam SHVD_STATUS_* de shv_dbg.h
UINT32 ShvHookInstall(_In_ UINT64 PhysAddr, _In_ UINT8 HookType, _In_ UINT64 VirtAddr, _In_ UINT64 Pid, _In_ UINT64 RangeSize);
UINT32 ShvHookRemove(_In_ UINT64 PhysAddr);


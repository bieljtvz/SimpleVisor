/*++

Module Name:

    hpv_hooks.c

Abstract:

    NT-side shadow hook and trampoline pool management for SimpleVisor.

    Implements the split-page EPT hook technique:
      - Shadow page: execute-only (R=0 W=0 X=1); contains patched bytes.
      - Original page: read+write (R=1 W=1 X=0); served by hypervisor on
        read/write EPT violations via MTF.

    Trampoline pool: 4KB contiguous RWX page divided into 64-byte slots.
    Each slot holds: displaced bytes + 14-byte absolute JMP back.

Environment:

    Kernel mode only, PASSIVE_LEVEL.

--*/

#include <ntifs.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include "..\shv_dbg.h"
#include "shvos_internal.h"
#include "hde64.h"

//
// Build a 14-byte indirect JMP: FF 25 00000000 <8-byte target>
// Writes to Dst; target = Target.
// Used for the trampoline JMP-back (trampoline pool is RWX, R=1, no EPT issue).
//
static VOID
HpvWriteJmp14 (
    _Out_writes_bytes_(14) UINT8* Dst,
    _In_  UINT64 Target
    )
{
    Dst[0] = 0xFF;
    Dst[1] = 0x25;
    Dst[2] = 0x00;
    Dst[3] = 0x00;
    Dst[4] = 0x00;
    Dst[5] = 0x00;
    RtlCopyMemory(Dst + 6, &Target, 8);
}

//
// Build a 12-byte direct JMP via RAX: 48 B8 <8-byte imm64> FF E0
//   MOV RAX, imm64   (10 bytes, no memory read required)
//   JMP RAX          ( 2 bytes)
//
// Used for the shadow page hook patch (shadow page has R=0 / execute-only).
// FF 25 (indirect JMP) would need to READ the target address from the shadow
// page — R=0 causes an EPT violation that breaks execution. This encoding
// embeds the target directly in the instruction stream, so no data read occurs.
// RAX is a scratch/return-value register in Windows x64; safe to clobber at
// a function entry point before any caller-saved-register setup.
//
static VOID
HpvWriteJmp12 (
    _Out_writes_bytes_(12) UINT8* Dst,
    _In_  UINT64 Target
    )
{
    Dst[0] = 0x48; // REX.W
    Dst[1] = 0xB8; // MOV RAX, imm64
    RtlCopyMemory(Dst + 2, &Target, 8);
    Dst[10] = 0xFF; // JMP r/m64
    Dst[11] = 0xE0; // ModRM: mod=11 reg=4(JMP) rm=0(RAX)
}

//
// ShvFlushHooksAllCpus -- causes a CPUID VM-exit on the current CPU so the
// hypervisor's lazy hook applicator picks up the new ShvHookVersion.
// Other CPUs pick it up on their next natural VM-exit.
//
VOID
ShvFlushHooksAllCpus (
    VOID
    )
{
    INT32 info[4];
    __cpuid(info, 0);
}

//
// ShvInstrLen -- return length of one x86-64 instruction using hde64.
// Returns 0 on decode error.
//
UINT32
ShvInstrLen (
    _In_ const UINT8* p
    )
{
    hde64s hs;
    hde64_disasm(p, &hs);
    return (hs.flags & F_ERROR) ? 0 : (UINT32)hs.len;
}

//
// HpvTrampolinePoolInit -- allocate 4KB contiguous RWX page for trampolines.
//
NTSTATUS
HpvTrampolinePoolInit (
    VOID
    )
{
    PHYSICAL_ADDRESS lowest, highest, boundary;

    lowest.QuadPart   = 0;
    highest.QuadPart  = -1LL;
    boundary.QuadPart = 0;

    g_TrampolinePool = MmAllocateContiguousNodeMemory(PAGE_SIZE,
                                                      lowest,
                                                      highest,
                                                      boundary,
                                                      PAGE_EXECUTE_READWRITE,
                                                      KeGetCurrentNodeNumber());
    if (g_TrampolinePool == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    g_TrampolineUsed = 0;
    RtlZeroMemory(g_TrampolinePool, PAGE_SIZE);
    return STATUS_SUCCESS;
}

//
// HpvTrampolinePoolFree -- release the trampoline pool.
//
VOID
HpvTrampolinePoolFree (
    VOID
    )
{
    if (g_TrampolinePool != NULL)
    {
        MmFreeContiguousMemory(g_TrampolinePool);
        g_TrampolinePool = NULL;
        g_TrampolineUsed = 0;
    }
}

//
// HpvShadowPatchAddress -- write Buffer into the shadow page at the same
// offset as Address within its 4KB physical page.
// Returns STATUS_NOT_FOUND if no shadow page has been installed for that GPA.
//
NTSTATUS
HpvShadowPatchAddress (
    _In_reads_bytes_(Size) const VOID* Buffer,
    _In_ PVOID   Address,
    _In_ SIZE_T  Size
    )
{
    PHYSICAL_ADDRESS pa;
    UINT64           gpa;
    UINT32           offset;
    UINT32           i;

    __try
    {
        pa = MmGetPhysicalAddress(Address);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_ACCESS_VIOLATION;
    }

    gpa    = pa.QuadPart & ~0xFFFULL;
    offset = (UINT32)(pa.QuadPart & 0xFFF);

    if (Size == 0 || (UINT64)offset + Size > PAGE_SIZE)
        return STATUS_INVALID_PARAMETER;

    for (i = 0; i < SHV_SHADOW_MAX; i++)
    {
        if (g_ShadowPages[i].Gpa == gpa && g_ShadowPages[i].ShadowVa != NULL)
        {
            RtlCopyMemory((UINT8*)g_ShadowPages[i].ShadowVa + offset, Buffer, Size);
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

//
// HpvHookFuncByVa -- install an EPT shadow hook on FuncVa.
//
// Allocates (or reuses) a shadow page for FuncVa's 4KB GPA, patches the
// shadow copy with a 14-byte JMP to HookFunc, and registers the EPT hook
// so the hypervisor redirects executes to the shadow page and serves the
// original page on reads/writes.
//
// If OriginalFunc != NULL, *OriginalFunc receives the trampoline VA which
// calls the displaced bytes and then falls through to the rest of FuncVa.
//
NTSTATUS
HpvHookFuncByVa (
    _In_  PVOID  FuncVa,
    _In_  PVOID  HookFunc,
    _Out_ PVOID* OriginalFunc
    )
{
    PHYSICAL_ADDRESS origPa, shadowPa;
    UINT64           gpa;
    UINT32           offset;
    UINT32           i, slot, tramSlot;
    UINT8*           trampoline;
    UINT8*           shadowPage;
    UINT32           displaced;
    BOOLEAN          newShadow;

    if (FuncVa == NULL || HookFunc == NULL)
        return STATUS_INVALID_PARAMETER;

    __try
    {
        origPa = MmGetPhysicalAddress(FuncVa);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_ACCESS_VIOLATION;
    }

    gpa    = origPa.QuadPart & ~0xFFFULL;
    offset = (UINT32)(origPa.QuadPart & 0xFFF);

    // Find or create shadow page for this GPA
    slot      = (UINT32)-1;
    newShadow = FALSE;

    for (i = 0; i < SHV_SHADOW_MAX; i++)
    {
        if (g_ShadowPages[i].Gpa == gpa)
        {
            slot = i;
            g_ShadowPages[i].RefCount++;
            break;
        }
    }

    if (slot == (UINT32)-1)
    {
        // No existing shadow -- allocate one
        PHYSICAL_ADDRESS lowest, highest, boundary;
        PVOID            shadowVa;
        PVOID            origPageVa;

        lowest.QuadPart   = 0;
        highest.QuadPart  = -1LL;
        boundary.QuadPart = 0;

        shadowVa = MmAllocateContiguousNodeMemory(PAGE_SIZE,
                                                  lowest, highest, boundary,
                                                  PAGE_EXECUTE_READWRITE,
                                                  KeGetCurrentNodeNumber());
        if (shadowVa == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;

        // Copy original page (FuncVa is a kernel VA; read the whole 4KB page)
        origPageVa = (PVOID)((ULONG_PTR)FuncVa & ~(PAGE_SIZE - 1));
        __try
        {
            RtlCopyMemory(shadowVa, origPageVa, PAGE_SIZE);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            MmFreeContiguousMemory(shadowVa);
            return STATUS_ACCESS_VIOLATION;
        }

        // Find free slot
        for (i = 0; i < SHV_SHADOW_MAX; i++)
        {
            if (g_ShadowPages[i].Gpa == 0)
            {
                shadowPa = MmGetPhysicalAddress(shadowVa);
                g_ShadowPages[i].Gpa      = gpa;
                g_ShadowPages[i].ShadowPa = shadowPa.QuadPart;
                g_ShadowPages[i].ShadowVa = shadowVa;
                g_ShadowPages[i].RefCount  = 1;
                slot      = i;
                newShadow = TRUE;
                break;
            }
        }

        if (slot == (UINT32)-1)
        {
            MmFreeContiguousMemory(shadowVa);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    // Allocate trampoline slot
    if (g_TrampolinePool == NULL || g_TrampolineUsed >= SHV_TRAMPOLINE_MAX)
    {
        if (newShadow)
        {
            MmFreeContiguousMemory(g_ShadowPages[slot].ShadowVa);
            RtlZeroMemory(&g_ShadowPages[slot], sizeof(SHV_SHADOW_PAGE_RECORD));
        }
        else
        {
            g_ShadowPages[slot].RefCount--;
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    tramSlot   = g_TrampolineUsed;
    trampoline = (UINT8*)g_TrampolinePool + tramSlot * SHV_TRAMPOLINE_SLOT_SIZE;
    g_TrampolineUsed++;

    // Compute displaced bytes (enough to cover a 12-byte JMP for the shadow page patch)
    displaced = 0;
    __try
    {
        while (displaced < 12)
        {
            UINT32 len = ShvInstrLen((UINT8*)FuncVa + displaced);
            if (len == 0)
            {
                displaced = 0;
                break;
            }
            displaced += len;
            if (displaced > SHV_TRAMPOLINE_SLOT_SIZE - 14)
            {
                displaced = 0;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        displaced = 0;
    }

    if (displaced == 0)
    {
        g_TrampolineUsed--;
        if (newShadow)
        {
            MmFreeContiguousMemory(g_ShadowPages[slot].ShadowVa);
            RtlZeroMemory(&g_ShadowPages[slot], sizeof(SHV_SHADOW_PAGE_RECORD));
        }
        else
        {
            g_ShadowPages[slot].RefCount--;
        }
        return STATUS_INVALID_PARAMETER;
    }

    // Build trampoline: displaced bytes + JMP back to FuncVa+displaced
    RtlCopyMemory(trampoline, FuncVa, displaced);
    HpvWriteJmp14(trampoline + displaced, (UINT64)(ULONG_PTR)FuncVa + displaced);

    // Patch shadow page: write 12-byte direct JMP (MOV RAX+JMP RAX) to HookFunc.
    // Must NOT use FF 25 (indirect JMP) here because the shadow page has R=0;
    // FF 25 needs to READ the target address from [RIP+0] which would fault.
    shadowPage = (UINT8*)g_ShadowPages[slot].ShadowVa;
    HpvWriteJmp12(shadowPage + offset, (UINT64)(ULONG_PTR)HookFunc);

    // Register EPT shadow hook (installs on next VM-exit on each CPU)
    if (newShadow)
    {
        ShvHookInstallShadow(gpa, g_ShadowPages[slot].ShadowPa);
    }

    // Record in g_SyscallHooks
    for (i = 0; i < SHV_SYSCALL_HOOK_MAX; i++)
    {
        if (!g_SyscallHooks[i].InUse)
        {
            g_SyscallHooks[i].SyscallIndex  = 0;
            g_SyscallHooks[i].DisplacedSize = displaced;
            g_SyscallHooks[i].HookFunc      = HookFunc;
            g_SyscallHooks[i].Trampoline    = trampoline;
            g_SyscallHooks[i].FuncGpa       = gpa;
            g_SyscallHooks[i].FuncVa        = FuncVa;
            g_SyscallHooks[i].InUse         = 1;
            g_SyscallHooks[i].IsInlinePatch  = 0;
            break;
        }
    }

    ShvFlushHooksAllCpus();

    if (OriginalFunc != NULL)
        *OriginalFunc = trampoline;

    ShvLog("[SHV-HOOK] EPT shadow hook instalado: FuncVa=%p GPA=%016llX shadowPA=%016llX "
           "hookFunc=%p trampoline=%p displaced=%u bytes\n",
           FuncVa, gpa, g_ShadowPages[slot].ShadowPa, HookFunc, trampoline, displaced);

    return STATUS_SUCCESS;
}

//
// HpvHookFuncByName -- resolve a kernel export by name and hook it.
//
NTSTATUS
HpvHookFuncByName (
    _In_  PCWSTR FuncName,
    _In_  PVOID  HookFunc,
    _Out_ PVOID* OriginalFunc
    )
{
    UNICODE_STRING name;
    PVOID          funcVa;
    NTSTATUS       status;

    RtlInitUnicodeString(&name, FuncName);
    funcVa = MmGetSystemRoutineAddress(&name);
    if (funcVa == NULL)
    {
        ShvLog("[SHV-HOOK] Funcao nao encontrada para hook: exportacao nao disponivel\n");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    ShvLog("[SHV-HOOK] Instalando EPT shadow hook por nome: VA=%p hookFunc=%p\n",
           funcVa, HookFunc);
    status = HpvHookFuncByVa(funcVa, HookFunc, OriginalFunc);
    if (!NT_SUCCESS(status))
        ShvLog("[SHV-HOOK] HpvHookFuncByVa FALHOU: 0x%08X\n", status);
    return status;
}

//
// HpvUnhookFuncByVa -- remove the shadow hook installed on FuncVa.
//
NTSTATUS
HpvUnhookFuncByVa (
    _In_ PVOID FuncVa
    )
{
    UINT32  i;
    UINT64  gpa = 0;

    for (i = 0; i < SHV_SYSCALL_HOOK_MAX; i++)
    {
        if (g_SyscallHooks[i].InUse && g_SyscallHooks[i].FuncVa == FuncVa)
        {
            gpa = g_SyscallHooks[i].FuncGpa;
            RtlZeroMemory(&g_SyscallHooks[i], sizeof(SHV_SYSCALL_HOOK_ENTRY));
            break;
        }
    }

    if (gpa == 0)
    {
        ShvLog("[SHV-HOOK] HpvUnhookFuncByVa: FuncVa=%p nao encontrado nos SyscallHooks\n", FuncVa);
        return STATUS_NOT_FOUND;
    }

    ShvLog("[SHV-HOOK] Removendo EPT shadow hook: FuncVa=%p GPA=%016llX\n", FuncVa, gpa);

    for (i = 0; i < SHV_SHADOW_MAX; i++)
    {
        if (g_ShadowPages[i].Gpa == gpa)
        {
            if (g_ShadowPages[i].RefCount > 0)
                g_ShadowPages[i].RefCount--;

            if (g_ShadowPages[i].RefCount == 0)
            {
                ShvHookRemoveShadow(gpa);
                ShvFlushHooksAllCpus();
                MmFreeContiguousMemory(g_ShadowPages[i].ShadowVa);
                RtlZeroMemory(&g_ShadowPages[i], sizeof(SHV_SHADOW_PAGE_RECORD));
                ShvLog("[SHV-HOOK] Shadow page liberada: GPA=%016llX\n", gpa);
            }
            else
            {
                ShvLog("[SHV-HOOK] Shadow page ainda em uso (refcount=%u): GPA=%016llX\n",
                       g_ShadowPages[i].RefCount, gpa);
            }
            break;
        }
    }

    return STATUS_SUCCESS;
}

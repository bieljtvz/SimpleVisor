#include <ntifs.h>
#include <intrin.h>
#include "shvssdt.h"
#include "..\shv_dbg.h"

VOID ShvLog(_In_z_ _Printf_format_string_ const char* Fmt, ...);

PSYSTEM_SERVICE_TABLE g_KeServiceDescriptorTable = NULL;

static ULONGLONG GetKeServiceDescriptorTable64(VOID)
{
    UNICODE_STRING ustr;
    PVOID resolved;
    PUCHAR p, pEnd;
    INT32  disp;
    PSYSTEM_SERVICE_TABLE candidate;

    // Metodo 1: export direto (funciona em algumas builds)
    RtlInitUnicodeString(&ustr, L"KeServiceDescriptorTable");
    resolved = MmGetSystemRoutineAddress(&ustr);
    if (resolved)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SSDT] export: %p\n", resolved);
        return (ULONGLONG)resolved;
    }

    // Metodo 2: scan LEA R10,[RIP+disp32] em KiSystemCall64
    p    = (PUCHAR)(ULONG_PTR)__readmsr(0xC0000082);
    pEnd = p + 8 * PAGE_SIZE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[SSDT] LSTAR=%p scan %p..%p\n", p, p, pEnd);

    for (; p < pEnd - 7; p++)
    {
        if (p[0] == 0x4C && p[1] == 0x8D && p[2] == 0x15)
        {
            disp      = *(INT32 *)(p + 3);
            candidate = (PSYSTEM_SERVICE_TABLE)((PUCHAR)(p + 7) + disp);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[SSDT] 4C8D15 @ %p disp=%08X -> candidate=%p\n",
                p, (UINT32)disp, candidate);

            __try
            {
                ULONG  n   = candidate->NumberOfServices;
                PULONG tbl = candidate->ServiceTableBase;

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[SSDT]   n=%u tbl=%p\n", n, tbl);

                if (n > 100 && n < 0x500 && tbl != NULL)
                    return (ULONGLONG)candidate;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[SSDT]   exception em candidate=%p\n", candidate);
                continue;
            }
        }
    }

    return 0;
}

BOOLEAN ShvSsdtInit(VOID)
{
    g_KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)GetKeServiceDescriptorTable64();

    if (g_KeServiceDescriptorTable)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SSDT] OK: table=%p base=%p count=%u\n",
            g_KeServiceDescriptorTable,
            g_KeServiceDescriptorTable->ServiceTableBase,
            g_KeServiceDescriptorTable->NumberOfServices);
        ShvLog("[SSDT] OK: table=%p base=%p count=%u\n",
               g_KeServiceDescriptorTable,
               g_KeServiceDescriptorTable->ServiceTableBase,
               g_KeServiceDescriptorTable->NumberOfServices);
        return TRUE;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[SSDT] KeServiceDescriptorTable nao encontrada\n");
    ShvLog("[SSDT] KeServiceDescriptorTable nao encontrada\n");
    return FALSE;
}

ULONGLONG ShvSsdtGetFuncAddr(ULONG Id)
{
    LONG   dwtmp;
    PULONG ServiceTableBase;

    if (!g_KeServiceDescriptorTable)
        return 0;

    ServiceTableBase = (PULONG)g_KeServiceDescriptorTable->ServiceTableBase;
    dwtmp = (LONG)(ServiceTableBase[Id] >> 4);
    return (LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase;
}

ULONG ShvSsdtGetOffset(ULONGLONG FuncAddr)
{
    PULONG ServiceTableBase;

    if (!g_KeServiceDescriptorTable)
        return 0;

    ServiceTableBase = (PULONG)g_KeServiceDescriptorTable->ServiceTableBase;
    return (ULONG)(FuncAddr - (ULONGLONG)ServiceTableBase) << 4;
}

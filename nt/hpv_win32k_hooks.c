/*++

Module Name:

    hpv_win32k_hooks.c

Abstract:

    Shadow hook (EPT split-page, mesmo motor de nt/hpv_hooks.c) em
    NtGdiBitBlt, exportada por win32kfull.sys.

    DIFERENCA CRITICA em relacao aos outros hooks deste projeto (ntoskrnl.exe,
    sempre mapeado globalmente): win32k.sys/win32kfull.sys e carregado POR
    SESSAO (cada sessao interativa do Terminal Services/Fast User Switching
    tem sua propria instancia), e MmGetSystemRoutineAddress NAO resolve
    exports dele -- confirmado na pratica (STATUS_PROCEDURE_NOT_FOUND / VA=0),
    mesmo com KeStackAttachProcess num processo Win32: essa API consulta a
    lista global de modulos do kernel, e win32k nao entra nela (fica numa
    lista por sessao separada).

    O caminho que funciona:
      1. Achar um processo Win32 de sessao interativa (winlogon.exe --
         sempre presente numa sessao com logon ativo, ver
         ShvOsFindProcessByName em nt/shvos.c);
      2. KeStackAttachProcess nele (entra no espaco de enderecamento dele,
         que inclui o win32k da sessao dele);
      3. Achar a BASE do win32kfull.sys ali (ShvOsFindKernelModuleBase, via
         ZwQuerySystemInformation(SystemModuleInformation) -- essa consulta
         SIM lista os modulos de sessao, so o MmGetSystemRoutineAddress que
         nao os resolve por nome de rotina);
      4. Resolver "NtGdiBitBlt" dentro do PE dessa base com
         RtlFindExportedRoutineByName (rotina interna do ntoskrnl --
         exportada por ELE, nao pelo win32k, entao MmGetSystemRoutineAddress
         resolve ela normalmente -- percorre o Export Directory do PE em
         memoria recebido como parametro);
      5. Instalar o shadow hook (HpvHookFuncByVa tambem precisa estar
         attached, pois traduz a VA pra PA via MmGetPhysicalAddress usando
         as tabelas de pagina do processo ATUAL);
      6. KeStackAttachProcess de volta (KeUnstackDetachProcess).

    O desinstall (HpvUnhookFuncByVa) NAO precisa de attach -- so faz lookup
    por VA em g_SyscallHooks[] e opera por GPA (ja resolvida), sem tocar
    tabela de pagina nenhuma; por isso a VA e cacheada em g_NtGdiBitBltVa
    (mesmo padrao de g_PspExitProcessVa em hpv_policy_hooks.c, usado la por
    PspExitProcess nao ser exportada -- aqui a razao e so nao precisar
    re-attach pra desinstalar).

    So gera evento (ShvLog + DbgPrintEx) quando o processo CHAMADOR esta na
    lista de MONITORADOS -- mesmo criterio/infra de hpv_policy_hooks.c e
    hpv_registry_hooks.c. Nao bloqueia nada.

Environment:

    Kernel mode only. ShvWin32kHooksInit roda a PASSIVE_LEVEL (chamado do
    DriverEntry/ShvPolicyHooksInit); o hook em si roda no contexto de
    qualquer processo Win32 que chame BitBlt/StretchBlt/etc (GDI32 desce
    pra NtGdiBitBlt via win32u.dll).

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
// NtGdiBitBlt -- assinatura classica (ReactOS/win32k leaks), nao documentada
// publicamente na WDK. HDC/tipos GDI tratados como handles opacos (PVOID) --
// so precisamos do numero/tamanho certo de argumentos pra calling convention
// x64 bater, nao da definicao exata de cada tipo.
//
//   BOOL NtGdiBitBlt(HDC hdcDst, int x, int y, int cx, int cy,
//                     HDC hdcSrc, int x1, int y1,
//                     DWORD rop4, DWORD crBackColor, FLONG fl);
// ============================================================
typedef INT (NTAPI* PfnNtGdiBitBlt)(
    PVOID  HdcDst,
    INT    X,
    INT    Y,
    INT    Cx,
    INT    Cy,
    PVOID  HdcSrc,
    INT    X1,
    INT    Y1,
    UINT32 Rop4,
    UINT32 CrBackColor,
    UINT32 Fl
    );

static PfnNtGdiBitBlt g_OrigNtGdiBitBlt = NULL;
static PVOID           g_NtGdiBitBltVa   = NULL; // cache p/ unhook sem re-attach

// RtlFindExportedRoutineByName -- rotina interna do ntoskrnl (nao declarada
// nos headers publicos, resolvida dinamicamente, mesmo motivo de toda API
// "hand-declared" deste projeto) que percorre o Export Directory de um PE
// em memoria (ImageBase) procurando RoutineName. E a UNICA forma pratica de
// achar exports de win32k.sys/win32kfull.sys, ja que MmGetSystemRoutineAddress
// nao os resolve (ver comentario no topo do arquivo).
typedef PVOID (NTAPI* PfnRtlFindExportedRoutineByName)(
    _In_ PVOID ImageBase,
    _In_ PCCH  RoutineName
    );

// ============================================================
// Caller na lista de MONITORADOS? (mesma logica duplicada em
// hpv_policy_hooks.c / hpv_registry_hooks.c -- cada modulo de hook deste
// projeto mantem sua propria copia, nao ha header comum pra isso)
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
// Hook: NtGdiBitBlt
// ============================================================
static INT NTAPI
HpvNtGdiBitBltHook (
    PVOID  HdcDst,
    INT    X,
    INT    Y,
    INT    Cx,
    INT    Cy,
    PVOID  HdcSrc,
    INT    X1,
    INT    Y1,
    UINT32 Rop4,
    UINT32 CrBackColor,
    UINT32 Fl
    )
{
    PCHAR   callerName = NULL;
    BOOLEAN monitored  = CallerIsMonitored(&callerName);
    INT     result;

    result = g_OrigNtGdiBitBlt(HdcDst, X, Y, Cx, Cy, HdcSrc, X1, Y1,
                                Rop4, CrBackColor, Fl);

    if (monitored)
    {
        UINT64 pid = (UINT64)(ULONG_PTR)PsGetCurrentProcessId();

        ShvLog("[WIN32K] NtGdiBitBlt: caller=%s (PID=%llu) hdcDst=%p (%d,%d %dx%d) "
               "hdcSrc=%p (%d,%d) rop4=0x%08X result=%d\n",
               callerName ? callerName : "?", pid, HdcDst, X, Y, Cx, Cy,
               HdcSrc, X1, Y1, Rop4, result);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[WIN32K] NtGdiBitBlt: caller=%s (PID=%llu) hdcDst=%p (%d,%d %dx%d) "
                   "hdcSrc=%p (%d,%d) rop4=0x%08X result=%d\n",
                   callerName ? callerName : "?", pid, HdcDst, X, Y, Cx, Cy,
                   HdcSrc, X1, Y1, Rop4, result);
    }

    return result;
}

// ============================================================
// API publica
// ============================================================
NTSTATUS
ShvWin32kHooksInit (
    VOID
    )
{
    PEPROCESS  winlogon = NULL;
    NTSTATUS   status;
    KAPC_STATE apcState;
    PVOID      win32kBase = NULL;
    PVOID      funcVa = NULL;
    PVOID      origFunc = NULL;
    PfnRtlFindExportedRoutineByName pRtlFindExportedRoutineByName = NULL;

    {
        UNICODE_STRING rname;
        RtlInitUnicodeString(&rname, L"RtlFindExportedRoutineByName");
        pRtlFindExportedRoutineByName =
            (PfnRtlFindExportedRoutineByName)MmGetSystemRoutineAddress(&rname);
    }
    if (pRtlFindExportedRoutineByName == NULL)
    {
        ShvLog("[WIN32K] RtlFindExportedRoutineByName nao encontrada nesta build -- "
               "NtGdiBitBlt hook NAO instalado (nao fatal)\n");
        return STATUS_SUCCESS;
    }

    status = ShvOsFindProcessByName("winlogon.exe", &winlogon);
    if (!NT_SUCCESS(status) || winlogon == NULL)
    {
        ShvLog("[WIN32K] winlogon.exe nao encontrado (0x%08X) -- NtGdiBitBlt "
               "hook NAO instalado (sessao interativa ainda nao iniciou? "
               "nao fatal, driver continua)\n", status);
        return STATUS_SUCCESS;
    }

    // Entra no espaco de enderecamento do winlogon -- so dali win32kfull.sys
    // (carregado por sessao) e visivel pro ZwQuerySystemInformation(
    // SystemModuleInformation) usado em ShvOsFindKernelModuleBase, e e
    // preciso pra traducao VA->PA dentro de HpvHookFuncByVa (ver comentario
    // no topo do arquivo).
    KeStackAttachProcess(winlogon, &apcState);

    __try
    {
        status = ShvOsFindKernelModuleBase("win32kfull.sys", &win32kBase);
        if (!NT_SUCCESS(status))
        {
            // nao fatal -- builds mais antigas podem usar win32k.sys sem o
            // split win32kfull/win32kbase; sem suporte a essa variante nesta
            // versao.
        }
        else
        {
            funcVa = pRtlFindExportedRoutineByName(win32kBase, "NtGdiBitBlt");
            if (funcVa == NULL)
            {
                status = STATUS_PROCEDURE_NOT_FOUND;
            }
            else
            {
                status = HpvHookFuncByVa(funcVa, HpvNtGdiBitBltHook, &origFunc);
            }
        }
    }
    __finally
    {
        KeUnstackDetachProcess(&apcState);
    }

    ObDereferenceObject(winlogon);

    if (!NT_SUCCESS(status))
    {
        ShvLog("[WIN32K] NtGdiBitBlt: falhou (0x%08X) -- win32kBase=%p va=%p (nao fatal)\n",
               status, win32kBase, funcVa);
        return STATUS_SUCCESS;
    }

    g_OrigNtGdiBitBlt = (PfnNtGdiBitBlt)origFunc;
    g_NtGdiBitBltVa   = funcVa;
    ShvLog("[WIN32K] NtGdiBitBlt shadow hook OK (win32kfull=%p, va=%p, trampoline=%p, via winlogon.exe)\n",
           win32kBase, funcVa, origFunc);

    return STATUS_SUCCESS;
}

VOID
ShvWin32kHooksUninit (
    VOID
    )
{
    if (g_NtGdiBitBltVa != NULL)
    {
        // Sem attach: HpvUnhookFuncByVa so faz lookup por VA em
        // g_SyscallHooks[] e opera por GPA ja resolvida, nao traduz VA->PA
        // de novo (ver comentario no topo do arquivo).
        HpvUnhookFuncByVa(g_NtGdiBitBltVa);
        g_OrigNtGdiBitBlt = NULL;
        g_NtGdiBitBltVa   = NULL;
        ShvLog("[WIN32K] NtGdiBitBlt hook removido\n");
    }
}

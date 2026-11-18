/*++

Module Name:

    hpv_memprotect_hooks.c

Abstract:

    Shadow hook (EPT split-page, mesmo motor de nt/hpv_hooks.c) em
    ZwAllocateVirtualMemory e ZwProtectVirtualMemory.

    Monitora o surgimento de paginas EXECUTAVEIS na memoria de um processo
    MONITORADO -- padrao classico de shellcode/packer/injecao (memoria
    alocada ou re-protegida pra RWX/RX em runtime, em vez de vir de uma
    secao de imagem PE normal mapeada no load). Cobre os dois cenarios:
      - auto-alocacao: o proprio processo monitorado chama Alloc/Protect
        pra si mesmo (ProcessHandle = NtCurrentProcess()/-1 ou um handle
        pro proprio PID);
      - injecao remota: outro processo chama VirtualAllocEx/VirtualProtectEx
        (que descem pra estes dois Zw*) tendo o processo MONITORADO como
        alvo (ProcessHandle de um handle aberto via OpenProcess).
    Em ambos, o que importa pra decidir se loga e o PROCESSO ALVO
    (ProcessHandle resolvido), nao o chamador -- mesmo criterio usado pelo
    "PID alvo" de NtOpenProcess em hpv_policy_hooks.c.

    So gera evento (ShvLog + DbgPrintEx) quando:
      - ZwAllocateVirtualMemory: Protect final tem bit de execucao
        (PAGE_EXECUTE/_READ/_READWRITE/_WRITECOPY) E o processo alvo esta
        monitorado;
      - ZwProtectVirtualMemory: NewProtect tem bit de execucao E o
        OldProtect (devolvido pela chamada ORIGINAL, que preenche esse
        parametro com a protecao ANTES da troca) NAO tinha -- ou seja, so
        loga quando execucao esta sendo ADICIONADA agora, nao em toda
        chamada que meramente MANTEM paginas ja executaveis (ex. RWX->RX,
        ainda executavel antes e depois, nao e o evento interessante aqui).
    Nao bloqueia nada -- so observa, mesmo comportamento dos outros hooks
    de monitoramento (nao-protecao) deste projeto.

Environment:

    Kernel mode only, PASSIVE_LEVEL (caminho de alocacao/protecao de memoria).

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

// Mascara de bits de protecao com execucao (winnt.h / wdm.h: PAGE_EXECUTE,
// PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY --
// todos 0x10/0x20/0x40/0x80, ou seja, byte baixo 0xF0).
#define SHV_PAGE_EXECUTE_MASK \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

#define SHV_IS_EXECUTABLE(Protect) (((Protect) & SHV_PAGE_EXECUTE_MASK) != 0)

// ============================================================
// ObReferenceObjectByHandle -- resolvida dinamicamente (mesmo motivo de
// toda API "nao garantida" deste projeto, ver HpvResolveOptionalApis em
// shvos.c) pra traduzir o ProcessHandle recebido por Allocate/Protect no
// PEPROCESS alvo. Trata corretamente os pseudo-handles NtCurrentProcess()
// (-1) / NtCurrentThread() (-2) -- comportamento embutido na propria
// rotina do kernel, nao algo que precisamos tratar aqui.
// ============================================================
typedef NTSTATUS (NTAPI* PFN_ObReferenceObjectByHandle)(
    _In_      HANDLE          Handle,
    _In_      ACCESS_MASK     DesiredAccess,
    _In_opt_  PVOID           ObjectType,
    _In_      KPROCESSOR_MODE AccessMode,
    _Out_     PVOID*          Object,
    _Out_opt_ PVOID           HandleInformation
    );

static PFN_ObReferenceObjectByHandle g_pObReferenceObjectByHandle = NULL;

static VOID
HpvMemProtectResolveApis (
    VOID
    )
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"ObReferenceObjectByHandle");
    g_pObReferenceObjectByHandle = MmGetSystemRoutineAddress(&name);

    ShvLog("[MEMPROT] API ObReferenceObjectByHandle: %s\n",
           g_pObReferenceObjectByHandle ? "OK" : "NAO ENCONTRADA nesta build do Windows");
}

// ============================================================
// Resolve o PID/nome/PEPROCESS do processo ALVO a partir do ProcessHandle
// recebido por Allocate/Protect. *OutProcess sai REFERENCIADO -- quem
// chama precisa ObDereferenceObject depois de usar.
// ============================================================
static BOOLEAN
ResolveTargetProcess (
    _In_  HANDLE     ProcessHandle,
    _Out_ PEPROCESS* OutProcess,
    _Out_ UINT64*    OutPid
    )
{
    NTSTATUS st;
    PVOID    obj = NULL;

    *OutProcess = NULL;
    *OutPid     = 0;

    if (g_pObReferenceObjectByHandle == NULL)
        return FALSE;

    st = g_pObReferenceObjectByHandle(ProcessHandle, 0, NULL, KernelMode, &obj, NULL);
    if (!NT_SUCCESS(st) || obj == NULL)
        return FALSE;

    *OutProcess = (PEPROCESS)obj;
    *OutPid     = (UINT64)(ULONG_PTR)PsGetProcessId((PEPROCESS)obj);
    return TRUE;
}

// ============================================================
// PID na lista de MONITORADOS? (mesma logica duplicada em
// hpv_policy_hooks.c / hpv_registry_hooks.c / hpv_win32k_hooks.c -- cada
// modulo de hook deste projeto mantem sua propria copia)
// ============================================================
static BOOLEAN
PidIsMonitored (
    _In_ UINT64 Pid
    )
{
    UINT32  i;
    BOOLEAN mon = FALSE, prot = FALSE;

    for (i = 0; i < ShvHookMonitoredCount; i++)
    {
        if (ShvHookMonitoredPids[i] == Pid) return TRUE;
    }

    ShvHooksCheckPid(Pid, &prot, &mon);
    return mon;
}

// ============================================================
// Trampolins + tipos
// ============================================================
typedef NTSTATUS (NTAPI* PfnZwAllocateVirtualMemory)(
    _In_    HANDLE    ProcessHandle,
    _Inout_ PVOID*    BaseAddress,
    _In_    ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T   RegionSize,
    _In_    ULONG     AllocationType,
    _In_    ULONG     Protect
    );

typedef NTSTATUS (NTAPI* PfnZwProtectVirtualMemory)(
    _In_    HANDLE  ProcessHandle,
    _Inout_ PVOID*  BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_    ULONG   NewProtect,
    _Out_   PULONG  OldProtect
    );

static PfnZwAllocateVirtualMemory g_OrigZwAllocateVirtualMemory = NULL;
static PfnZwProtectVirtualMemory  g_OrigZwProtectVirtualMemory  = NULL;

// ============================================================
// Hook: ZwAllocateVirtualMemory
// ============================================================
static NTSTATUS NTAPI
HpvZwAllocateVirtualMemoryHook (
    _In_    HANDLE    ProcessHandle,
    _Inout_ PVOID*    BaseAddress,
    _In_    ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T   RegionSize,
    _In_    ULONG     AllocationType,
    _In_    ULONG     Protect
    )
{
    NTSTATUS  status;
    PEPROCESS targetProc = NULL;
    UINT64    targetPid  = 0;
    BOOLEAN   haveTarget;
    BOOLEAN   executable = SHV_IS_EXECUTABLE(Protect);

    // So paga o custo de resolver o alvo (Ob + checagem de lista) quando a
    // protecao pedida ja e executavel -- a imensa maioria das alocacoes
    // (heap, stacks, buffers normais) nao e, e esse hook roda em qualquer
    // processo do sistema, entao o caminho comum precisa ser barato.
    haveTarget = executable && ResolveTargetProcess(ProcessHandle, &targetProc, &targetPid);

    status = g_OrigZwAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
                                            RegionSize, AllocationType, Protect);

    if (haveTarget && NT_SUCCESS(status) && PidIsMonitored(targetPid))
    {
        PCHAR targetName = PsGetProcessImageFileName(targetProc);
        PCHAR callerName = PsGetProcessImageFileName(PsGetCurrentProcess());
        UINT64 callerPid = (UINT64)(ULONG_PTR)PsGetCurrentProcessId();

        ShvLog("[MEMPROT] ZwAllocateVirtualMemory EXECUTAVEL: alvo=%s (PID=%llu) "
               "caller=%s (PID=%llu) base=%p size=0x%zX type=0x%08X protect=0x%08X status=0x%08X\n",
               targetName ? targetName : "?", targetPid,
               callerName ? callerName : "?", callerPid,
               BaseAddress ? *BaseAddress : NULL,
               RegionSize ? *RegionSize : 0,
               AllocationType, Protect, status);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[MEMPROT] ZwAllocateVirtualMemory EXECUTAVEL: alvo=%s (PID=%llu) "
                   "caller=%s (PID=%llu) base=%p size=0x%zX type=0x%08X protect=0x%08X status=0x%08X\n",
                   targetName ? targetName : "?", targetPid,
                   callerName ? callerName : "?", callerPid,
                   BaseAddress ? *BaseAddress : NULL,
                   RegionSize ? *RegionSize : 0,
                   AllocationType, Protect, status);
    }

    if (haveTarget) ObDereferenceObject(targetProc);

    return status;
}

// ============================================================
// Hook: ZwProtectVirtualMemory
// ============================================================
static NTSTATUS NTAPI
HpvZwProtectVirtualMemoryHook (
    _In_    HANDLE  ProcessHandle,
    _Inout_ PVOID*  BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_    ULONG   NewProtect,
    _Out_   PULONG  OldProtect
    )
{
    NTSTATUS  status;
    PEPROCESS targetProc = NULL;
    UINT64    targetPid  = 0;
    BOOLEAN   haveTarget;
    BOOLEAN   newExecutable = SHV_IS_EXECUTABLE(NewProtect);

    // Mesma otimizacao do hook de Allocate: so resolve o alvo se a NOVA
    // protecao pedida ja e executavel (sem isso, nunca pode ser o caso de
    // "execucao sendo adicionada" que este hook busca).
    haveTarget = newExecutable && ResolveTargetProcess(ProcessHandle, &targetProc, &targetPid);

    status = g_OrigZwProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize,
                                           NewProtect, OldProtect);

    if (haveTarget && NT_SUCCESS(status) && OldProtect != NULL)
    {
        // OldProtect foi preenchido pela chamada ORIGINAL com a protecao de
        // ANTES da troca -- so interessa o caso em que ela NAO era
        // executavel (execucao esta sendo ADICIONADA agora). RWX->RX ou
        // RX->RWX (ja executavel antes e depois) nao dispara aqui.
        BOOLEAN oldWasExecutable = SHV_IS_EXECUTABLE(*OldProtect);

        if (!oldWasExecutable && PidIsMonitored(targetPid))
        {
            PCHAR targetName = PsGetProcessImageFileName(targetProc);
            PCHAR callerName = PsGetProcessImageFileName(PsGetCurrentProcess());
            UINT64 callerPid = (UINT64)(ULONG_PTR)PsGetCurrentProcessId();

            ShvLog("[MEMPROT] ZwProtectVirtualMemory ADICIONOU EXECUCAO: alvo=%s (PID=%llu) "
                   "caller=%s (PID=%llu) base=%p size=0x%zX oldProtect=0x%08X newProtect=0x%08X status=0x%08X\n",
                   targetName ? targetName : "?", targetPid,
                   callerName ? callerName : "?", callerPid,
                   BaseAddress ? *BaseAddress : NULL,
                   RegionSize ? *RegionSize : 0,
                   *OldProtect, NewProtect, status);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[MEMPROT] ZwProtectVirtualMemory ADICIONOU EXECUCAO: alvo=%s (PID=%llu) "
                       "caller=%s (PID=%llu) base=%p size=0x%zX oldProtect=0x%08X newProtect=0x%08X status=0x%08X\n",
                       targetName ? targetName : "?", targetPid,
                       callerName ? callerName : "?", callerPid,
                       BaseAddress ? *BaseAddress : NULL,
                       RegionSize ? *RegionSize : 0,
                       *OldProtect, NewProtect, status);
        }
    }

    if (haveTarget) ObDereferenceObject(targetProc);

    return status;
}

// ============================================================
// API publica
// ============================================================
NTSTATUS
ShvMemProtectHooksInit (
    VOID
    )
{
    NTSTATUS status;
    PVOID    origFunc;

    HpvMemProtectResolveApis();

    status = HpvHookFuncByName(L"ZwAllocateVirtualMemory", HpvZwAllocateVirtualMemoryHook, &origFunc);
    if (NT_SUCCESS(status))
    {
        g_OrigZwAllocateVirtualMemory = (PfnZwAllocateVirtualMemory)origFunc;
        ShvLog("[MEMPROT] ZwAllocateVirtualMemory shadow hook OK (trampoline=%p)\n", origFunc);
    }
    else
    {
        ShvLog("[MEMPROT] HpvHookFuncByName(ZwAllocateVirtualMemory) falhou: 0x%08X (nao fatal)\n", status);
    }

    status = HpvHookFuncByName(L"ZwProtectVirtualMemory", HpvZwProtectVirtualMemoryHook, &origFunc);
    if (NT_SUCCESS(status))
    {
        g_OrigZwProtectVirtualMemory = (PfnZwProtectVirtualMemory)origFunc;
        ShvLog("[MEMPROT] ZwProtectVirtualMemory shadow hook OK (trampoline=%p)\n", origFunc);
    }
    else
    {
        ShvLog("[MEMPROT] HpvHookFuncByName(ZwProtectVirtualMemory) falhou: 0x%08X (nao fatal)\n", status);
    }

    // Nao-fatal: cada hook e independente, perder um so reduz a cobertura
    // do monitoramento, nao afeta o resto do driver.
    return STATUS_SUCCESS;
}

VOID
ShvMemProtectHooksUninit (
    VOID
    )
{
    struct {
        PCWSTR Name;
        PVOID* OrigFunc;
    } hooks[] = {
        { L"ZwAllocateVirtualMemory", (PVOID*)&g_OrigZwAllocateVirtualMemory },
        { L"ZwProtectVirtualMemory",  (PVOID*)&g_OrigZwProtectVirtualMemory  },
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
            ShvLog("[MEMPROT] %ws hook removido\n", hooks[i].Name);
        }
    }
}

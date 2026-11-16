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
#include <intrin.h>
#include <stdarg.h>
#include "..\shv_x.h"
#include "..\shv_dbg.h"
#include "..\shvhooks.h"
#pragma warning(disable:4221)
#pragma warning(disable:4204)
#pragma warning(disable:4996)  // ExAllocatePoolWithTag deprecated em WDK recente

#include "shvos_internal.h"
#include "thread_utils.h"

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
volatile LONG   g_DriverUnloading = 0;

// ============================================================
// IOCTL Dispatcher
// ============================================================

//
// ZwQuerySystemInformation -- nao importado automaticamente pelo ntifs.h.
// Resolvida DINAMICAMENTE (MmGetSystemRoutineAddress em DriverEntry, ver
// HpvResolveOptionalApis) em vez de linkada estaticamente: um import
// estatico nao resolvido pelo ntoskrnl.exe da build do Windows em uso
// IMPEDE O DRIVER DE CARREGAR (STATUS_PROCEDURE_NOT_FOUND no "sc start",
// sem nenhum log, porque o DriverEntry nunca chega a rodar). Resolvendo em
// runtime, se a API nao existir nessa build o driver ainda carrega
// normalmente -- so os comandos que dependem dela falham (logado).
//
typedef enum _SYSTEM_INFORMATION_CLASS_SHV
{
    SystemProcessInformation  = 5,
    SystemModuleInformation   = 11
} SYSTEM_INFORMATION_CLASS_SHV;

typedef NTSTATUS (*PFN_ZwQuerySystemInformation)(
    _In_      ULONG  SystemInformationClass,
    _Out_opt_ PVOID  SystemInformation,
    _In_      ULONG  SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );
static PFN_ZwQuerySystemInformation g_pZwQuerySystemInformation = NULL;

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
    ULONG_PTR      UniqueProcessKey;
    SIZE_T         PeakVirtualSize;
    SIZE_T         VirtualSize;
    ULONG          PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
    SIZE_T         PrivatePageCount;
    LARGE_INTEGER  ReadOperationCount;
    LARGE_INTEGER  WriteOperationCount;
    LARGE_INTEGER  OtherOperationCount;
    LARGE_INTEGER  ReadTransferCount;
    LARGE_INTEGER  WriteTransferCount;
    LARGE_INTEGER  OtherTransferCount;
    // Threads[NumberOfThreads] (SYSTEM_THREAD_INFORMATION_SHV) comeca logo
    // apos este struct -- por isso os campos acima (desde UniqueProcessKey)
    // precisam bater exatamente com o layout real do SO, senao o offset do
    // array de threads sai errado. Usado por SHV_CMD_LIST_PROCESS_THREADS.
} SYSTEM_PROCESS_INFORMATION_SHV, *PSYSTEM_PROCESS_INFORMATION_SHV;

typedef struct _SYSTEM_THREAD_INFORMATION_SHV
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;
    CLIENT_ID     ClientId;
    KPRIORITY     Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    ULONG         ThreadState;
    ULONG         WaitReason;
} SYSTEM_THREAD_INFORMATION_SHV, *PSYSTEM_THREAD_INFORMATION_SHV;

// Offset de KPROCESS.DirectoryTableBase dentro de EPROCESS no x64 Win10.
// EPROCESS comeca com KPROCESS; Pcb.DirectoryTableBase esta em +0x28.
#define EPROCESS_DIR_TABLE_BASE_OFFSET 0x28

// CR3 do processo System, usado como HOST_CR3 da VMCS (ver ShvOsGetSystemCr3
// em shv.h) -- cacheado na primeira chamada; PsInitialSystemProcess e
// exportada pelo ntoskrnl e declarada publicamente (ntddk.h), diferente das
// outras APIs hand-declared neste arquivo.
NTKERNELAPI PEPROCESS PsInitialSystemProcess;
static UINT64 g_SystemCr3 = 0;

// Offset de EPROCESS.UserDirectoryTableBase -- o CR3 usado em ring-3 quando
// KPTI/KVA-shadow (mitigacao Meltdown) esta ativo; DIFERENTE do CR3 "kernel"
// acima (ver [[feedback_cr3_filter_broke_usermode]] na memoria do projeto:
// eventos EPT disparados por acesso DIRETO em usermode carregam este CR3, nao
// o de DirectoryTableBase, entao "Causador"/"Destino" na GUI nao resolviam o
// processo para esses eventos sem isso).
//
// ATENCAO: ao contrario de DirectoryTableBase (estavel desde o x64 original),
// este offset MUDA entre builds do Windows (o campo so existe desde a
// mitigacao de Meltdown, ~jan/2018) e NAO foi verificado ao vivo neste
// binario -- 0x388 e o valor publicamente documentado para builds 19041
// (Windows 10 2004/20H1), que bate com o OS_VERSION visto nos dumps de BSOD
// desta VM. Se "UserDirBase" aparecer sempre 0 ou com lixo na GUI, confirme
// no WinDbg: `dt nt!_EPROCESS UserDirectoryTableBase` (ou ache o offset via
// `dt nt!_EPROCESS` inteiro) e ajuste esta constante.
#define EPROCESS_USER_DIR_TABLE_BASE_OFFSET 0x388

//
// PEB / PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY (usermode) -- layout x64 estavel
// desde Windows Vista, usados so pelos campos do inicio (Ldr dentro do PEB,
// InLoadOrderModuleList dentro do PEB_LDR_DATA, DllBase/SizeOfImage/
// BaseDllName dentro do LDR_DATA_TABLE_ENTRY). Nao declarados nos headers
// publicos da WDK (PsGetProcessPeb retorna PPEB opaco) -- usados por
// SHV_CMD_LIST_PROCESS_MODULES pra enumerar os modulos (EXE+DLLs) de um
// processo via kernel (lendo a propria PEB do processo, apos attach), em vez
// de depender de handle usermode (CreateToolhelp32Snapshot/OpenProcess), que
// falha contra processos protegidos (PPL).
//
typedef struct _HPV_LDR_DATA_TABLE_ENTRY_USER
{
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} HPV_LDR_DATA_TABLE_ENTRY_USER, *PHPV_LDR_DATA_TABLE_ENTRY_USER;

typedef struct _HPV_PEB_LDR_DATA
{
    ULONG      Length;
    BOOLEAN    Initialized;
    UCHAR      Padding[3];
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} HPV_PEB_LDR_DATA, *PHPV_PEB_LDR_DATA;

typedef struct _HPV_PEB
{
    BOOLEAN           InheritedAddressSpace;
    BOOLEAN           ReadImageFileExecOptions;
    BOOLEAN           BeingDebugged;
    BOOLEAN           BitField;
    UCHAR             Padding0[4];
    PVOID             Mutant;
    PVOID             ImageBaseAddress;
    PHPV_PEB_LDR_DATA Ldr;
} HPV_PEB, *PHPV_PEB;

// PsGetProcessPeb -- exportada pelo ntoskrnl desde Vista, mas nao declarada
// nos headers publicos da WDK (retorna PPEB opaco); retorno tratado aqui como
// PVOID e convertido pra HPV_PEB* acima. Resolvida dinamicamente (mesmo
// motivo de ZwQuerySystemInformation acima).
typedef PVOID (*PFN_PsGetProcessPeb)(_In_ PEPROCESS Process);
static PFN_PsGetProcessPeb g_pPsGetProcessPeb = NULL;

//
// Equivalentes 32-bit das structs acima, usados SO pra processos WOW64 (app
// 32-bit rodando em Windows x64) -- a PEB NATIVA (64-bit, PsGetProcessPeb)
// de um processo WOW64 tem Ldr vazio/nao-representativo; os modulos de
// verdade (todas as DLLs 32-bit carregadas) ficam na PEB32, achada via
// PsGetProcessWow64Process. Ponteiros aqui sao ULONG (32-bit) porque e como
// o layout da PEB32 realmente e (WOW64 ainda roda no mesmo espaco de
// enderecamento do processo, mapeado abaixo de 4GB, entao zero-extend de
// ULONG pra UINT64/ponteiro da um endereco valido).
//
typedef struct _HPV_LIST_ENTRY32
{
    ULONG Flink;
    ULONG Blink;
} HPV_LIST_ENTRY32;

typedef struct _HPV_UNICODE_STRING32
{
    USHORT Length;
    USHORT MaximumLength;
    ULONG  Buffer;
} HPV_UNICODE_STRING32;

typedef struct _HPV_LDR_DATA_TABLE_ENTRY32
{
    HPV_LIST_ENTRY32     InLoadOrderLinks;
    HPV_LIST_ENTRY32     InMemoryOrderLinks;
    HPV_LIST_ENTRY32     InInitializationOrderLinks;
    ULONG                DllBase;
    ULONG                EntryPoint;
    ULONG                SizeOfImage;
    HPV_UNICODE_STRING32 FullDllName;
    HPV_UNICODE_STRING32 BaseDllName;
} HPV_LDR_DATA_TABLE_ENTRY32, *PHPV_LDR_DATA_TABLE_ENTRY32;

typedef struct _HPV_PEB_LDR_DATA32
{
    ULONG            Length;
    UCHAR            Initialized;
    UCHAR            Padding[3];
    ULONG            SsHandle;
    HPV_LIST_ENTRY32 InLoadOrderModuleList;
    HPV_LIST_ENTRY32 InMemoryOrderModuleList;
    HPV_LIST_ENTRY32 InInitializationOrderModuleList;
} HPV_PEB_LDR_DATA32, *PHPV_PEB_LDR_DATA32;

typedef struct _HPV_PEB32
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG Mutant;
    ULONG ImageBaseAddress;
    ULONG Ldr;              // ponteiro (32-bit) pra HPV_PEB_LDR_DATA32
} HPV_PEB32, *PHPV_PEB32;

// PsGetProcessWow64Process -- exportada pelo ntoskrnl, retorna a PEB32 (NULL
// se o processo for nativo x64, nao-NULL se for WOW64). Igual PsGetProcessPeb,
// nao declarada nos headers publicos. Resolvida dinamicamente.
typedef PVOID (*PFN_PsGetProcessWow64Process)(_In_ PEPROCESS Process);
static PFN_PsGetProcessWow64Process g_pPsGetProcessWow64Process = NULL;

//
// ZwQueryVirtualMemory (e MEMORY_BASIC_INFORMATION/MemoryBasicInformation) JA
// sao declaradas por ntifs.h, diferente das outras APIs hand-declared neste
// arquivo. Usada por SHV_CMD_LIST_PROCESS_MEMORY com o pseudo-handle
// HPV_CURRENT_PROCESS (-1) ENQUANTO anexado (KeStackAttachProcess) ao
// processo alvo: pseudo-handle nao passa por nenhum access check de handle,
// entao funciona mesmo contra processos protegidos (PPL) -- diferente de
// VirtualQueryEx em usermode, que precisa de um HANDLE de verdade via
// OpenProcess (negado pro PPL).
//
#define HPV_CURRENT_PROCESS ((HANDLE)(LONG_PTR)-1)

//
// ZwSuspendThread/ZwResumeThread e PsGetContextThread -- exportadas pelo
// ntoskrnl (verificado via dumpbin /exports no .lib do WDK), mas nao
// declaradas nos headers publicos (igual PsGetProcessPeb/PsGetProcessWow64Process
// acima). Usadas por SHV_CMD_THREAD_SUSPEND/RESUME/GET_CONTEXT: o handle da
// thread e aberto via ObOpenObjectByPointer(..., KernelMode, ...) a partir do
// PETHREAD achado por PsLookupThreadByThreadId -- caminho kernel-mode, sem
// handle usermode (OpenThread), entao funciona mesmo contra processos
// protegidos (PPL). ZwTerminateThread NAO e exportada pro kernel (verificado
// na mesma lista) -- terminar uma thread arbitraria fica pra depois (precisa
// de outra tecnica, tipo APC). Resolvidas dinamicamente.
//
typedef NTSTATUS (*PFN_ZwSuspendThread)(
    _In_      HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );
typedef NTSTATUS (*PFN_ZwResumeThread)(
    _In_      HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );
typedef NTSTATUS (*PFN_PsGetContextThread)(
    _In_    PETHREAD Thread,
    _Inout_ PCONTEXT ThreadContext,
    _In_    KPROCESSOR_MODE Mode
    );
static PFN_ZwSuspendThread    g_pZwSuspendThread    = NULL;
static PFN_ZwResumeThread     g_pZwResumeThread     = NULL;
static PFN_PsGetContextThread g_pPsGetContextThread = NULL;

// PsSuspendProcess/PsResumeProcess -- unica alternativa de "freeze" que
// sobrou depois de checar o .lib do WDK (nao existe PsSuspendThread/
// PsResumeThread nem KeSuspendThread/KeResumeThread com esses nomes;
// ZwSuspendThread/ZwResumeThread existem no .lib mas nao foram encontradas
// na build real da VM de teste, ver [[fixes]]). Suspende/resume o PROCESSO
// INTEIRO (todas as threads), nao so uma -- por isso so e usada como
// fallback de ULTIMO RECURSO em GET_CONTEXT (congela por um instante curtinho
// so pra ler o contexto de forma confiavel), nunca como substituto real de
// SHV_CMD_THREAD_SUSPEND/RESUME (que suspenderiam uma thread so -- suspender
// o processo inteiro ali seria um efeito colateral inesperado pro usuario).
typedef NTSTATUS (*PFN_PsSuspendProcess)(_In_ PEPROCESS Process);
typedef NTSTATUS (*PFN_PsResumeProcess)(_In_ PEPROCESS Process);
static PFN_PsSuspendProcess g_pPsSuspendProcess = NULL;
static PFN_PsResumeProcess  g_pPsResumeProcess  = NULL;

//
// PsSuspendThread/PsResumeThread (as funcoes INTERNAS de verdade, nao os
// wrappers Zw*) -- nao exportadas por nome (confirmado: nao aparecem no
// .lib do WDK como export, por isso MmGetSystemRoutineAddress nunca ia
// achar), mas existem no binario e sao achaveis por pattern scan, igual
// PspExitProcess em hpv_policy_hooks.c. Assinaturas fornecidas pelo usuario
// (confirmadas via disassembly contra o ntoskrnl.exe real da VM de teste).
// Tomam o PETHREAD diretamente (sem handle nenhum), por isso sao preferidas
// sobre ZwSuspendThread/ZwResumeThread (que precisam de handle E nao foram
// encontradas nessa build via MmGetSystemRoutineAddress -- ver [[fixes]]).
//
typedef NTSTATUS (*PFN_PsSuspendThread)(_In_ PETHREAD Thread, _Out_opt_ PULONG PreviousSuspendCount);
typedef NTSTATUS (*PFN_PsResumeThread)(_In_ PETHREAD Thread, _Out_opt_ PULONG PreviousSuspendCount);
static PFN_PsSuspendThread g_pPsSuspendThread = NULL;
static PFN_PsResumeThread  g_pPsResumeThread  = NULL;

static const UINT8 kPsSuspendThreadPattern[] =
    "\x48\x89\x54\x24\x00\x48\x89\x4C\x24\x00\x53\x56\x57\x41\x56\x41\x57";
static const CHAR* kPsSuspendThreadMask = "xxxx?xxxx?xxxxxxx";

static const UINT8 kPsResumeThreadPattern[] =
    "\x48\x89\x5C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x00\x48\x8B\xDA\x48\x8B\xF9\xE8\x00\x00\x00\x00\x65\x48\x8B\x14\x25";
static const CHAR* kPsResumeThreadMask = "xxxx?xxxx?xxxx?xxxxxxx????xxxxx";

//
// Resolve as APIs por nome (nao garantidas em todo build do Windows) via
// MmGetSystemRoutineAddress -- chamada uma vez em DriverEntry, loga cada
// uma (ok ou "nao encontrada nesta build"). Ponteiro NULL = comando que
// depende dela retorna SHVD_STATUS_ERR_UNSUPPORTED em vez de travar/crashar.
// No final, tambem tenta achar PsSuspendThread/PsResumeThread por pattern
// scan (nao-exportadas, nao resolviveis por nome).
//
static VOID
HpvResolveOptionalApis (
    VOID
    )
{
    struct {
        PCWSTR  Name;
        PVOID*  Target;
    } apis[] = {
        { L"ZwQuerySystemInformation", (PVOID*)&g_pZwQuerySystemInformation },
        { L"PsGetProcessPeb",          (PVOID*)&g_pPsGetProcessPeb          },
        { L"PsGetProcessWow64Process", (PVOID*)&g_pPsGetProcessWow64Process },
        { L"ZwSuspendThread",          (PVOID*)&g_pZwSuspendThread          },
        { L"ZwResumeThread",           (PVOID*)&g_pZwResumeThread           },
        { L"PsGetContextThread",       (PVOID*)&g_pPsGetContextThread       },
        { L"PsSuspendProcess",         (PVOID*)&g_pPsSuspendProcess         },
        { L"PsResumeProcess",          (PVOID*)&g_pPsResumeProcess          },
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(apis); i++)
    {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, apis[i].Name);
        *apis[i].Target = MmGetSystemRoutineAddress(&name);

        ShvLog("[SHV] API opcional %ws: %s\n", apis[i].Name,
               *apis[i].Target ? "OK" : "NAO ENCONTRADA nesta build do Windows");
    }

    {
        UINT64 modBase = 0;
        SIZE_T modSize = 0;

        if (!HpvFindNtoskrnlModule(&modBase, &modSize))
        {
            ShvLog("[SHV] PsSuspendThread/PsResumeThread: nao achou o modulo ntoskrnl.exe (pattern scan pulado)\n");
        }
        else
        {
            UINT64 va;

            va = HpvFindPattern(modBase, modSize, kPsSuspendThreadPattern, kPsSuspendThreadMask);
            g_pPsSuspendThread = (PFN_PsSuspendThread)(ULONG_PTR)va;
            ShvLog("[SHV] API opcional PsSuspendThread (pattern scan): %s\n",
                   va ? "OK" : "NAO ENCONTRADA nesta build do Windows");
            if (va) ShvLog("[SHV]   PsSuspendThread va=%p\n", (PVOID)(ULONG_PTR)va);

            va = HpvFindPattern(modBase, modSize, kPsResumeThreadPattern, kPsResumeThreadMask);
            g_pPsResumeThread = (PFN_PsResumeThread)(ULONG_PTR)va;
            ShvLog("[SHV] API opcional PsResumeThread (pattern scan): %s\n",
                   va ? "OK" : "NAO ENCONTRADA nesta build do Windows");
            if (va) ShvLog("[SHV]   PsResumeThread va=%p\n", (PVOID)(ULONG_PTR)va);
        }
    }
}

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

//
// Chamado pelo hook de PspExitProcess (hpv_policy_hooks.c) quando um processo
// com EPT hook(s) ativo(s) esta terminando. Remove da tabela global (shvvmxhv.c)
// todo hook pertencente a esse PID e libera o MDL/paginas travadas de cada um
// (ShvHookTakeMdl + MmUnlockPages + IoFreeMdl) ANTES do EPROCESS ser destruido
// -- sem isso, MmProbeAndLockPages (SHV_CMD_HOOK_EPT) deixa paginas travadas
// quando o processo some sem passar por SHV_CMD_UNHOOK_EPT, causando o
// bugcheck PROCESS_HAS_LOCKED_PAGES (0xCB).
//
VOID
ShvCleanupExitedProcess (
    _In_ UINT64 Pid
    )
{
    UINT64 removedPhys[SHV_HOOK_MAX_ENTRIES];
    UINT32 count, i;

    if (Pid == 0)
        return;

    count = ShvHookRemoveByPid(Pid, removedPhys, SHV_HOOK_MAX_ENTRIES);
    if (count == 0)
        return;

    for (i = 0; i < count; i++)
    {
        PMDL mdl = ShvHookTakeMdl(removedPhys[i]);
        if (mdl != NULL)
        {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
        }
    }

    // Garante que todo CPU para de tentar restringir essas paginas (mesma
    // razao do force-sync em SHV_CMD_HOOK_EPT/UNHOOK_EPT -- ver fix "leitura
    // nao capturada" em memory/fixes.md).
    ShvOsForceAllCpuVmExit();

    ShvLog("[POLICY] PspExitProcess: PID=%llu terminou com %u EPT hook(s) ativo(s) -- removidos/MDL liberado automaticamente\n",
           Pid, count);
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

    if (InterlockedCompareExchange(&g_DriverUnloading, 0, 0) != 0)
    {
        Irp->IoStatus.Status      = STATUS_DEVICE_REMOVED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DEVICE_REMOVED;
    }

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

        // RangeSize (campo "Range" da GUI) e em BYTES -- so afeta quantas paginas
        // precisam ser EPT-hookadas (pageCountTotal); o filtro fino por VA exato
        // (ByteLen, abaixo) e quem decide se um acesso dentro da(s) pagina(s)
        // hookada(s) realmente conta como hit.
        {
        UINT64 pageCountTotal = (vaEnd - vaBase) / PAGE_SIZE;
        UINT64 byteLen        = req.Hook.RangeSize ? req.Hook.RangeSize : 1;
        if (pageCountTotal == 0) pageCountTotal = 1;

        if (req.Hook.Pid == 0)
        {
            // Kernel: paginas nao-paginadas; traduz cada pagina do range, mas
            // instala UMA SO entrada na tabela (na PRIMEIRA pagina fisica valida)
            // com RangeSize = numero de paginas. ShvVmxEptApplyHooks/RearmHook/
            // HandleEptViolation (shvvmxhv.c) ja sabem varrer as N paginas de UMA
            // entrada via SHV_HOOK_PAGE_IN_RANGE -- NAO criar uma entrada por
            // pagina aqui, ou paginas do meio do range acabam cobertas por DUAS
            // entradas sobrepostas (cada uma pensando que e o inicio de um range
            // de N paginas), causando HitCount/evento DUPLICADO/TRIPLICADO para
            // o mesmo acesso real (bug encontrado via teste do usuario).
            UINT64 va;
            UINT64 basePa = 0;
            for (va = vaBase; va < vaEnd; va += PAGE_SIZE)
            {
                PHYSICAL_ADDRESS pa;
                __try { pa = MmGetPhysicalAddress((PVOID)(ULONG_PTR)va); }
                __except (EXCEPTION_EXECUTE_HANDLER) { pa.QuadPart = 0; }
                if ((pa.QuadPart & ~0xFFFULL) != 0)
                {
                    if (basePa == 0)
                    {
                        basePa = pa.QuadPart & ~0xFFFULL;
                        ShvHookInstall(basePa, req.Hook.HookType,
                                       req.Hook.VirtAddr, 0, pageCountTotal, byteLen);
                    }
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

            // Itera PFNs so pra travar/contar; UMA SO entrada vai pra tabela
            // (na primeira pagina) -- mesma razao do ramo kernel acima: uma
            // entrada por pagina com RangeSize>1 faz paginas do meio do range
            // casarem em DUAS entradas sobrepostas, duplicando/triplicando o
            // evento/HitCount pro mesmo acesso real.
            pfnArray  = MmGetMdlPfnArray(mdl);
            pageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(vaBase, regionBytes);
            for (i = 0; i < pageCount; i++)
            {
                UINT64 gpa = (UINT64)pfnArray[i] << PAGE_SHIFT;
                if (gpa != 0)
                {
                    if (firstPa == 0)
                    {
                        firstPa = gpa;
                        ShvHookInstall(gpa, req.Hook.HookType,
                                       req.Hook.VirtAddr,
                                       req.Hook.Pid,
                                       pageCountTotal,
                                       byteLen);
                    }
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
        }

        // ShvHookInstall so atualiza a tabela global (ShvHookVersion++); cada CPU
        // so aplica a mudanca ao PROPRIO EPT de forma lazy, no topo do proximo
        // VM-exit que ele tomar (ver ShvVmxHandleExit). Se o core que vai fazer a
        // leitura de teste ficar sem tomar nenhum VM-exit entre o install e a
        // leitura (comum em cores ociosos/pouco usados), ele ainda esta rodando
        // com o EPT antigo (sem o hook) e a leitura passa batido, sem violation.
        // Forca TODOS os CPUs a tomar um VM-exit (CPUID) agora, sincronamente,
        // pra garantir que o hook ja esta ativo em todo mundo antes do IOCTL
        // retornar pro usermode.
        if (hooked) ShvOsForceAllCpuVmExit();

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
            ShvOsForceAllCpuVmExit();
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
            ShvOsForceAllCpuVmExit();
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

        if (g_pZwQuerySystemInformation == NULL)
        {
            resp->Status = SHVD_STATUS_ERR_UNSUPPORTED;
            break;
        }

        for (tries = 0; tries < 4; tries++)
        {
            if (sysInfo) ExFreePoolWithTag(sysInfo, 'vhSP');
            sysInfo = ExAllocatePoolWithTag(PagedPool, bufSize, 'vhSP');
            if (sysInfo == NULL)
            {
                resp->Status = SHVD_STATUS_ERR_NOMEM;
                break;
            }
            qStatus = g_pZwQuerySystemInformation(SystemProcessInformation,
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
                        pe->DirBase     = *(UINT64*)((UINT8*)proc + EPROCESS_DIR_TABLE_BASE_OFFSET);
                        pe->UserDirBase = *(UINT64*)((UINT8*)proc + EPROCESS_USER_DIR_TABLE_BASE_OFFSET);
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
        PVOID  sysInfo;

        if (g_pZwQuerySystemInformation == NULL)
        {
            resp->Status = SHVD_STATUS_ERR_UNSUPPORTED;
            break;
        }

        sysInfo = ExAllocatePoolWithTag(PagedPool, bufSize, 'vhSM');
        if (sysInfo == NULL)
        {
            resp->Status = SHVD_STATUS_ERR_NOMEM;
            break;
        }

        {
            NTSTATUS qStatus = g_pZwQuerySystemInformation(SystemModuleInformation,
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

    case SHV_CMD_LIST_PROCESS_MODULES:
    {
        UINT64     pid = req.ListProcModules.Pid;
        PEPROCESS  process;
        KAPC_STATE apcState;

        if (pid == 0)
        {
            resp->Status = SHVD_STATUS_ERR_INVALID;
            break;
        }

        if (g_pPsGetProcessPeb == NULL || g_pPsGetProcessWow64Process == NULL)
        {
            resp->Status = SHVD_STATUS_ERR_UNSUPPORTED;
            break;
        }

        if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process)))
        {
            resp->Status = SHVD_STATUS_ERR_ACCESS;
            break;
        }

        // Le a PEB/Ldr do PROPRIO processo alvo (kernel-mode, apos attach) em
        // vez de abrir handle via usermode (CreateToolhelp32Snapshot/
        // OpenProcess) -- funciona mesmo contra processos protegidos (PPL),
        // que negam PROCESS_QUERY_INFORMATION pra chamadores usermode.
        KeStackAttachProcess(process, &apcState);

        __try
        {
            // Processo WOW64 (app 32-bit em Windows x64): a PEB NATIVA
            // (PsGetProcessPeb) tem Ldr vazio/nao-representativo pros modulos
            // de verdade -- as DLLs 32-bit de verdade estao na PEB32, achada
            // via PsGetProcessWow64Process. Tenta esse caminho primeiro.
            PVOID wow64Peb = g_pPsGetProcessWow64Process(process);

            if (wow64Peb != NULL)
            {
                PHPV_PEB32 peb32 = (PHPV_PEB32)wow64Peb;

                if (peb32->Ldr == 0)
                {
                    resp->Status = SHVD_STATUS_ERR_ACCESS;
                }
                else
                {
                    PHPV_PEB_LDR_DATA32 ldr32   = (PHPV_PEB_LDR_DATA32)(ULONG_PTR)peb32->Ldr;
                    ULONG               headVa  = peb32->Ldr +
                                                    (ULONG)FIELD_OFFSET(HPV_PEB_LDR_DATA32, InLoadOrderModuleList);
                    ULONG               curVa   = ldr32->InLoadOrderModuleList.Flink;
                    UINT32              count      = 0;
                    UINT32              maxEntries = SHV_MAX_READ_SIZE / sizeof(SHV_MODULE_ENTRY);

                    while (curVa != headVa && curVa != 0 && count < maxEntries)
                    {
                        PHPV_LDR_DATA_TABLE_ENTRY32 mod32 = (PHPV_LDR_DATA_TABLE_ENTRY32)(ULONG_PTR)curVa;
                        PSHV_MODULE_ENTRY            me    = &resp->Modules[count];

                        RtlZeroMemory(me, sizeof(*me));
                        me->Base = (unsigned long long)mod32->DllBase;
                        me->Size = (unsigned long long)mod32->SizeOfImage;

                        if (mod32->BaseDllName.Buffer != 0 && mod32->BaseDllName.Length > 0)
                        {
                            PWCHAR nameBuf   = (PWCHAR)(ULONG_PTR)mod32->BaseDllName.Buffer;
                            ULONG  nameChars = mod32->BaseDllName.Length / sizeof(WCHAR);
                            ULONG  i;
                            if (nameChars >= SHV_MOD_NAME_LEN) nameChars = SHV_MOD_NAME_LEN - 1;
                            for (i = 0; i < nameChars; i++)
                                me->Name[i] = (char)nameBuf[i];
                        }

                        count++;
                        curVa = mod32->InLoadOrderLinks.Flink;
                    }

                    resp->Count  = count;
                    resp->Status = SHVD_STATUS_OK;
                }
            }
            else
            {
                // Processo nativo x64: PEB normal.
                PHPV_PEB peb = (PHPV_PEB)g_pPsGetProcessPeb(process);

                if (peb == NULL || peb->Ldr == NULL)
                {
                    resp->Status = SHVD_STATUS_ERR_ACCESS;
                }
                else
                {
                    PHPV_PEB_LDR_DATA ldr      = peb->Ldr;
                    PLIST_ENTRY       listHead = &ldr->InLoadOrderModuleList;
                    PLIST_ENTRY        entry;
                    UINT32             count      = 0;
                    UINT32             maxEntries = SHV_MAX_READ_SIZE / sizeof(SHV_MODULE_ENTRY);

                    for (entry = listHead->Flink;
                         entry != listHead && count < maxEntries;
                         entry = entry->Flink)
                    {
                        PHPV_LDR_DATA_TABLE_ENTRY_USER mod =
                            CONTAINING_RECORD(entry, HPV_LDR_DATA_TABLE_ENTRY_USER, InLoadOrderLinks);
                        PSHV_MODULE_ENTRY me = &resp->Modules[count];

                        RtlZeroMemory(me, sizeof(*me));
                        me->Base = (unsigned long long)(ULONG_PTR)mod->DllBase;
                        me->Size = (unsigned long long)mod->SizeOfImage;

                        if (mod->BaseDllName.Buffer != NULL && mod->BaseDllName.Length > 0)
                        {
                            ULONG nameChars = mod->BaseDllName.Length / sizeof(WCHAR);
                            ULONG i;
                            if (nameChars >= SHV_MOD_NAME_LEN) nameChars = SHV_MOD_NAME_LEN - 1;
                            for (i = 0; i < nameChars; i++)
                                me->Name[i] = (char)mod->BaseDllName.Buffer[i];
                        }

                        count++;
                    }

                    resp->Count  = count;
                    resp->Status = SHVD_STATUS_OK;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            resp->Status = SHVD_STATUS_ERR_ACCESS;
        }

        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
        break;
    }

    case SHV_CMD_LIST_PROCESS_THREADS:
    {
        UINT64   pid     = req.ProcFilter.Pid;
        ULONG    bufSize = 0x80000;
        PVOID    sysInfo = NULL;
        NTSTATUS qStatus = STATUS_UNSUCCESSFUL;
        UINT32   tries;

        if (pid == 0)
        {
            resp->Status = SHVD_STATUS_ERR_INVALID;
            break;
        }

        if (g_pZwQuerySystemInformation == NULL)
        {
            resp->Status = SHVD_STATUS_ERR_UNSUPPORTED;
            break;
        }

        // Mesma tecnica de SHV_CMD_LIST_PROCS (ZwQuerySystemInformation),
        // filtrando pelo PID -- nao precisa de handle pro processo, entao
        // funciona mesmo contra processos protegidos (PPL). O array de
        // threads (SYSTEM_THREAD_INFORMATION_SHV[NumberOfThreads]) vem logo
        // depois de cada SYSTEM_PROCESS_INFORMATION_SHV na mesma alocacao.
        for (tries = 0; tries < 4; tries++)
        {
            if (sysInfo) ExFreePoolWithTag(sysInfo, 'vhST');
            sysInfo = ExAllocatePoolWithTag(PagedPool, bufSize, 'vhST');
            if (sysInfo == NULL)
            {
                resp->Status = SHVD_STATUS_ERR_NOMEM;
                break;
            }
            qStatus = g_pZwQuerySystemInformation(SystemProcessInformation,
                                                  sysInfo, bufSize, NULL);
            if (qStatus != STATUS_INFO_LENGTH_MISMATCH)
                break;
            bufSize *= 2;
        }

        if (sysInfo == NULL)
            break;

        if (!NT_SUCCESS(qStatus))
        {
            ExFreePoolWithTag(sysInfo, 'vhST');
            resp->Status = SHVD_STATUS_ERR_ACCESS;
            break;
        }

        {
            PSYSTEM_PROCESS_INFORMATION_SHV entry =
                (PSYSTEM_PROCESS_INFORMATION_SHV)sysInfo;
            BOOLEAN found = FALSE;

            for (;;)
            {
                if ((UINT64)(ULONG_PTR)entry->UniqueProcessId == pid)
                {
                    PSYSTEM_THREAD_INFORMATION_SHV threads =
                        (PSYSTEM_THREAD_INFORMATION_SHV)
                        ((PUCHAR)entry + sizeof(SYSTEM_PROCESS_INFORMATION_SHV));
                    UINT32 count      = 0;
                    UINT32 maxEntries = SHV_MAX_READ_SIZE / sizeof(SHV_THREAD_ENTRY);
                    ULONG  i;

                    for (i = 0; i < entry->NumberOfThreads && count < maxEntries; i++)
                    {
                        PSHV_THREAD_ENTRY te = &resp->Threads[count];
                        te->Tid          = (unsigned long long)(ULONG_PTR)threads[i].ClientId.UniqueThread;
                        te->StartAddress = (unsigned long long)(ULONG_PTR)threads[i].StartAddress;

                        // Endereco do objeto PETHREAD no kernel, so pra
                        // exibicao (igual coluna "Object" do Process Hacker)
                        // -- SYSTEM_THREAD_INFORMATION nao traz o ponteiro
                        // direto, resolve via PsLookupThreadByThreadId e
                        // solta a referencia logo em seguida (so queremos o
                        // valor do endereco, nao manter a thread referenciada).
                        te->Object = 0;
                        {
                            PETHREAD teThread;
                            if (NT_SUCCESS(PsLookupThreadByThreadId(
                                    threads[i].ClientId.UniqueThread, &teThread)))
                            {
                                te->Object = (unsigned long long)(ULONG_PTR)teThread;
                                ObDereferenceObject(teThread);
                            }
                        }

                        count++;
                    }

                    resp->Count  = count;
                    resp->Status = SHVD_STATUS_OK;
                    found = TRUE;
                    break;
                }

                if (entry->NextEntryOffset == 0)
                    break;
                entry = (PSYSTEM_PROCESS_INFORMATION_SHV)
                        ((ULONG_PTR)entry + entry->NextEntryOffset);
            }

            if (!found)
                resp->Status = SHVD_STATUS_ERR_NOTFOUND;
        }

        ExFreePoolWithTag(sysInfo, 'vhST');
        break;
    }

    case SHV_CMD_LIST_PROCESS_MEMORY:
    {
        UINT64     pid       = req.ListProcMemory.Pid;
        UINT64     startAddr = req.ListProcMemory.StartAddr;
        PEPROCESS  process;
        KAPC_STATE apcState;

        if (pid == 0)
        {
            resp->Status = SHVD_STATUS_ERR_INVALID;
            break;
        }

        if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process)))
        {
            resp->Status = SHVD_STATUS_ERR_ACCESS;
            break;
        }

        // Anexa no processo alvo e consulta com o pseudo-handle "processo
        // atual" (-1) -- sem HANDLE de verdade, sem access check, funciona
        // mesmo contra processos protegidos (PPL). Mesmo loop sequencial de
        // VirtualQueryEx em usermode, so que de dentro do kernel.
        KeStackAttachProcess(process, &apcState);

        __try
        {
            MEMORY_BASIC_INFORMATION mbi;
            UINT64 addr       = startAddr; // continuacao: GUI reenvia o Base+Size
                                            // da ultima regiao recebida quando o
                                            // buffer enche (ver ShvBackend::
                                            // ListProcessMemory) -- o buffer do
                                            // IOCTL (SHV_MAX_READ_SIZE) so cabe
                                            // ~585 entradas de uma vez, bem menos
                                            // que o total de VADs de processos
                                            // "grandes" (ver [[fixes]]).
            UINT32 count      = 0;
            UINT32 maxEntries = SHV_MAX_READ_SIZE / sizeof(SHV_MEMREGION_ENTRY);

            while (count < maxEntries)
            {
                SIZE_T   retLen  = 0;
                NTSTATUS qStatus = ZwQueryVirtualMemory(
                    HPV_CURRENT_PROCESS, (PVOID)(ULONG_PTR)addr, MemoryBasicInformation,
                    &mbi, sizeof(mbi), &retLen);
                if (!NT_SUCCESS(qStatus))
                    break;

                {
                    PSHV_MEMREGION_ENTRY re = &resp->MemRegions[count];
                    re->Base    = (unsigned long long)(ULONG_PTR)mbi.BaseAddress;
                    re->Size    = (unsigned long long)mbi.RegionSize;
                    re->Protect = mbi.Protect ? mbi.Protect : mbi.AllocationProtect;
                    re->State   = mbi.State;
                    re->Type    = mbi.Type;
                    count++;
                }

                {
                    UINT64 next = (UINT64)(ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
                    if (next <= addr) break; // nao avancou -- evita loop infinito
                    addr = next;
                }
            }

            resp->Count  = count;
            resp->Status = SHVD_STATUS_OK;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            resp->Status = SHVD_STATUS_ERR_ACCESS;
        }

        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
        break;
    }

    case SHV_CMD_THREAD_SUSPEND:
    case SHV_CMD_THREAD_RESUME:
    {
        UINT64   tid      = req.ThreadCtl.Tid;
        PETHREAD thread   = NULL;
        HANDLE   hThread  = NULL;
        NTSTATUS tcStatus;

        if (tid == 0)
        {
            resp->Status = SHVD_STATUS_ERR_INVALID;
            break;
        }

        // Preferencia: PsSuspendThread/PsResumeThread achadas por pattern
        // scan (pegam o PETHREAD direto, sem handle nenhum) -- so cai pro
        // par Zw* (que precisa de handle, e nao foi encontrado nessa build
        // via MmGetSystemRoutineAddress de qualquer forma, ver [[fixes]]) se
        // o pattern scan nao achou.
        if (g_pPsSuspendThread != NULL && g_pPsResumeThread != NULL)
        {
            tcStatus = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)tid, &thread);
            if (!NT_SUCCESS(tcStatus))
            {
                resp->Status = SHVD_STATUS_ERR_ACCESS;
                break;
            }

            tcStatus = (req.Command == SHV_CMD_THREAD_SUSPEND)
                ? g_pPsSuspendThread(thread, NULL)
                : g_pPsResumeThread(thread, NULL);

            ObDereferenceObject(thread);
            resp->Status = NT_SUCCESS(tcStatus) ? SHVD_STATUS_OK : SHVD_STATUS_ERR_ACCESS;
            break;
        }

        if (g_pZwSuspendThread == NULL || g_pZwResumeThread == NULL)
        {
            resp->Status = SHVD_STATUS_ERR_UNSUPPORTED;
            break;
        }

        tcStatus = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)tid, &thread);
        if (!NT_SUCCESS(tcStatus))
        {
            resp->Status = SHVD_STATUS_ERR_ACCESS;
            break;
        }

        // Handle kernel-mode (sem OpenThread usermode) -- funciona mesmo
        // contra processos protegidos (PPL).
        tcStatus = ObOpenObjectByPointer(thread, OBJ_KERNEL_HANDLE, NULL,
                                         THREAD_SUSPEND_RESUME, NULL,
                                         KernelMode, &hThread);
        if (NT_SUCCESS(tcStatus))
        {
            tcStatus = (req.Command == SHV_CMD_THREAD_SUSPEND)
                ? g_pZwSuspendThread(hThread, NULL)
                : g_pZwResumeThread(hThread, NULL);
            ZwClose(hThread);
        }

        ObDereferenceObject(thread);
        resp->Status = NT_SUCCESS(tcStatus) ? SHVD_STATUS_OK : SHVD_STATUS_ERR_ACCESS;
        break;
    }

    case SHV_CMD_THREAD_GET_CONTEXT:
    {
        UINT64    tid               = req.ThreadCtl.Tid;
        PETHREAD  thread            = NULL;
        HANDLE    hThread           = NULL;
        PEPROCESS procSuspended     = NULL;
        BOOLEAN   psThreadSuspended = FALSE;
        BOOLEAN   canSuspend;
        NTSTATUS  gcStatus;

        if (tid == 0)
        {
            resp->Status = SHVD_STATUS_ERR_INVALID;
            break;
        }

        // So PsGetContextThread e obrigatoria. As demais sao best-effort,
        // em ordem de preferencia -- cada uma so "congela" o alvo com um
        // efeito colateral maior (ou exigencia maior) que a anterior:
        //   1) PsSuspendThread/PsResumeThread (pattern scan): so a thread
        //      alvo, sem handle nenhum -- a melhor opcao quando achada.
        //   2) ZwSuspendThread/ZwResumeThread: so a thread alvo, mas precisa
        //      de handle (ObOpenObjectByPointer).
        //   3) PsSuspendProcess/PsResumeProcess: o PROCESSO INTEIRO (todas
        //      as threads) -- so usado aqui, por um instante curtinho, como
        //      ultimo recurso pra ler o contexto de forma confiavel. NUNCA
        //      usado pros comandos SHV_CMD_THREAD_SUSPEND/RESUME dedicados
        //      (la seria um efeito colateral inesperado: o usuario pediu
        //      suspender uma thread, nao o processo inteiro).
        //   4) Nenhuma das tres: le sem congelar nada, em loop com retry
        //      (PsGetContextThread so e seguro quando a thread NAO esta
        //      rodando no instante exato da chamada -- ver [[fixes]]).
        if (g_pPsGetContextThread == NULL)
        {
            resp->Status = SHVD_STATUS_ERR_UNSUPPORTED;
            break;
        }
        canSuspend = (g_pZwSuspendThread != NULL && g_pZwResumeThread != NULL);

        gcStatus = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)tid, &thread);
        if (!NT_SUCCESS(gcStatus))
        {
            resp->Status = SHVD_STATUS_ERR_ACCESS;
            break;
        }

        if (g_pPsSuspendThread != NULL && g_pPsResumeThread != NULL)
        {
            if (NT_SUCCESS(g_pPsSuspendThread(thread, NULL)))
                psThreadSuspended = TRUE;
            else
                ShvLog("[SHV-IOCTL] GET_CONTEXT Tid=%llu: PsSuspendThread (pattern scan) falhou -- segue sem suspender\n", tid);
        }
        else if (canSuspend)
        {
            gcStatus = ObOpenObjectByPointer(thread, OBJ_KERNEL_HANDLE, NULL,
                                             THREAD_SUSPEND_RESUME, NULL,
                                             KernelMode, &hThread);
            if (NT_SUCCESS(gcStatus))
                g_pZwSuspendThread(hThread, NULL);
            else
            {
                ShvLog("[SHV-IOCTL] GET_CONTEXT Tid=%llu: ObOpenObjectByPointer(THREAD_SUSPEND_RESUME) falhou 0x%08X -- segue sem suspender\n",
                       tid, gcStatus);
                hThread = NULL; // segue sem suspender
            }
        }

        if (!psThreadSuspended && hThread == NULL &&
            g_pPsSuspendProcess != NULL && g_pPsResumeProcess != NULL)
        {
            PEPROCESS owner = PsGetThreadProcess(thread);
            if (NT_SUCCESS(g_pPsSuspendProcess(owner)))
                procSuspended = owner;
            else
                ShvLog("[SHV-IOCTL] GET_CONTEXT Tid=%llu: PsSuspendProcess falhou -- segue sem congelar\n", tid);
        }

        // Anexa no processo DONO da thread antes de ler o contexto -- mesmo
        // a thread kernel-stack/trap-frame sendo visivel independente do
        // processo corrente, chamadas internas do PsGetContextThread (estado
        // de FPU/XSAVE, validacoes ligadas ao KPROCESS atual) podem depender
        // de estar no contexto certo. Sem isso, a funcao vinha falhando com
        // STATUS_UNSUCCESSFUL mesmo com a thread/processo congelados.
        {
            PEPROCESS  owner = PsGetThreadProcess(thread);
            KAPC_STATE apcState;
            KeStackAttachProcess(owner, &apcState);

        __try
        {
            CONTEXT ctx = { 0 };
            UINT32  attempt;
            // Thread suspensa via ZwSuspendThread (hThread != NULL): e
            // sincrono de verdade, 1 tentativa basta. Processo congelado via
            // PsSuspendProcess (procSuspended != NULL): a suspensao de cada
            // thread normalmente e via APC, que so e entregue no proximo
            // ponto de checagem -- PsGetContextThread falha com
            // STATUS_UNSUCCESSFUL se pegar a thread ainda "Running" bem no
            // instante logo depois do PsSuspendProcess retornar, entao da
            // uns retries curtos tambem (bem menos que o caso sem suspensao
            // nenhuma). Sem suspensao nenhuma: mais tentativas, mesma logica.
            UINT32  maxAttempts = (psThreadSuspended || hThread != NULL) ? 1 : (procSuspended != NULL ? 8 : 20);

            gcStatus = STATUS_UNSUCCESSFUL;
            for (attempt = 0; attempt < maxAttempts; attempt++)
            {
                RtlZeroMemory(&ctx, sizeof(ctx));
                ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

                // Mode aqui NAO escolhe "contexto de usermode vs kernel" --
                // diz se o BUFFER DE SAIDA (&ctx) esta em memoria de usermode
                // ou kernel, pra decidir se faz ProbeForWrite nele. ctx e
                // local na pilha do KERNEL (deste driver), entao tem que ser
                // KernelMode -- com UserMode, o probe falha pra qualquer
                // endereco de kernel (era a causa do STATUS_ACCESS_VIOLATION
                // visto antes). A funcao ainda devolve os registradores de
                // USERMODE do alvo (o trap frame salvo), independente desse
                // parametro.
                gcStatus = g_pPsGetContextThread(thread, &ctx, KernelMode);
                if (NT_SUCCESS(gcStatus))
                    break;

                if (!psThreadSuspended && hThread == NULL)
                {
                    LARGE_INTEGER delay;
                    delay.QuadPart = -1000; // 100us, relativo (negativo)
                    KeDelayExecutionThread(KernelMode, FALSE, &delay);
                }
            }

            if (NT_SUCCESS(gcStatus))
            {
                resp->ThreadContext.Rip = ctx.Rip;
                resp->ThreadContext.Rsp = ctx.Rsp;
                resp->ThreadContext.Rbp = ctx.Rbp;
                resp->Status = SHVD_STATUS_OK;
            }
            else
            {
                ShvLog("[SHV-IOCTL] GET_CONTEXT Tid=%llu: PsGetContextThread(KernelMode) falhou 0x%08X apos %u tentativa(s) (psThreadSuspended=%d, canSuspend=%d, suspendeu=%d, procSuspended=%d)\n",
                       tid, gcStatus, maxAttempts, psThreadSuspended, canSuspend, hThread != NULL, procSuspended != NULL);
                resp->Status = SHVD_STATUS_ERR_ACCESS;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            NTSTATUS excCode = GetExceptionCode();
            ShvLog("[SHV-IOCTL] GET_CONTEXT Tid=%llu: excecao 0x%08X ao chamar PsGetContextThread (psThreadSuspended=%d, canSuspend=%d, suspendeu=%d, procSuspended=%d)\n",
                   tid, excCode, psThreadSuspended, canSuspend, hThread != NULL, procSuspended != NULL);
            resp->Status = SHVD_STATUS_ERR_ACCESS;
        }

            KeUnstackDetachProcess(&apcState);
        }

        if (psThreadSuspended)
            g_pPsResumeThread(thread, NULL);

        if (procSuspended != NULL)
            g_pPsResumeProcess(procSuspended);

        if (hThread != NULL)
        {
            g_pZwResumeThread(hThread, NULL);
            ZwClose(hThread);
        }
        ObDereferenceObject(thread);
        break;
    }

    case SHV_CMD_THREAD_GET_STACK:
    {
        UINT64   tid    = req.ThreadCtl.Tid;
        PETHREAD thread = NULL;
        HPV_THREAD_STACK_CAPTURE capture;
        NTSTATUS gsStatus;

        if (tid == 0)
        {
            resp->Status = SHVD_STATUS_ERR_INVALID;
            break;
        }

        gsStatus = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)tid, &thread);
        if (!NT_SUCCESS(gsStatus))
        {
            resp->Status = SHVD_STATUS_ERR_ACCESS;
            break;
        }

        // APC especial de kernel (nt/thread_utils.c) -- roda no contexto da
        // propria thread alvo, funciona mesmo contra processos protegidos
        // (PPL), diferente de PsGetContextThread (ver [[fixes]]: achado via
        // decompilacao do ntoskrnl.exe real, com a ajuda do usuario e do
        // IDA Pro MCP, que PspGetContextThreadInternal falha com
        // STATUS_UNSUCCESSFUL mesmo com a thread suspensa de verdade).
        gsStatus = HpvCaptureThreadStack(thread, &capture);
        ObDereferenceObject(thread);

        if (!NT_SUCCESS(gsStatus))
        {
            ShvLog("[SHV-IOCTL] GET_STACK Tid=%llu: HpvCaptureThreadStack falhou 0x%08X\n",
                   tid, gsStatus);
            resp->Status = (gsStatus == STATUS_NOT_SUPPORTED)
                ? SHVD_STATUS_ERR_UNSUPPORTED
                : SHVD_STATUS_ERR_ACCESS;
            break;
        }

        {
            ULONG i;
            ULONG frameCount = min(capture.FrameCount, SHV_STACK_MAX_FRAMES);

            RtlZeroMemory(&resp->ThreadStack, sizeof(resp->ThreadStack));
            resp->ThreadStack.Rip        = capture.Rip;
            resp->ThreadStack.Rsp        = capture.Rsp;
            resp->ThreadStack.Rbp        = capture.Rbp;
            resp->ThreadStack.FrameCount = frameCount;
            for (i = 0; i < frameCount; i++)
                resp->ThreadStack.Frames[i] = capture.Frames[i];
        }

        resp->Status = SHVD_STATUS_OK;
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

    case SHV_CMD_SET_STACK_FILTER:
        ShvSetStackFilterEnabled((UINT8)req.ProcFilter.Pid);
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
                // Atualiza a metadata exibida (Offset/Len/Bytes) pro ultimo
                // patch aplicado nesse slot -- faltava aqui, entao reaplicar
                // um patch num shadow ja existente nunca atualizava o que a
                // GUI mostra em Filtros->Hook Shadow.
                g_ShadowPages[i].Offset   = offset;
                g_ShadowPages[i].PatchLen = patchLen;
                RtlCopyMemory(g_ShadowPages[i].PatchBytes, req.Shadow.PatchBytes, patchLen);
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
        else
        {
            ShvOsForceAllCpuVmExit();
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
                    ShvOsForceAllCpuVmExit();
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
                UINT32 j;
                RtlZeroMemory(shi, sizeof(*shi));
                shi->GpaPage  = g_ShadowPages[i].Gpa;
                shi->Offset   = g_ShadowPages[i].Offset;
                shi->PatchLen = g_ShadowPages[i].PatchLen;
                shi->FuncVa   = 0;

                // g_ShadowPages nao guarda a VA original -- so a GPA (pagina).
                // Quem sabe a VA de verdade e g_SyscallHooks[] (hooks de
                // funcao via HpvHookFuncByVa, ex. NtOpenProcess), entao acha
                // por correspondencia de GPA (pagina) pra nao devolver sempre
                // FuncVa=0 pra esses casos -- era por isso que a coluna "VA"
                // em Filtros->Hook Shadow nunca aparecia preenchida na GUI.
                for (j = 0; j < SHV_SYSCALL_HOOK_MAX; j++)
                {
                    if (g_SyscallHooks[j].InUse &&
                        (g_SyscallHooks[j].FuncGpa & ~0xFFFULL) == g_ShadowPages[i].Gpa)
                    {
                        shi->FuncVa = (UINT64)(ULONG_PTR)g_SyscallHooks[j].FuncVa;
                        break;
                    }
                }

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

UINT64
ShvOsGetSystemCr3 (
    VOID
    )
{
    // Cacheado -- DirectoryTableBase do processo System nao muda durante a
    // vida do SO, entao so precisa ler uma vez (ver comentario completo em
    // shv.h, ShvOsGetSystemCr3).
    if (g_SystemCr3 == 0)
    {
        g_SystemCr3 = *(UINT64*)((UINT8*)PsInitialSystemProcess + EPROCESS_DIR_TABLE_BASE_OFFSET);
    }
    return g_SystemCr3;
}

UINT8
ShvOsIsAddressValid (
    _In_ PVOID Va
    )
{
    //
    // MmIsAddressValid e documentada como segura em qualquer IRQL (so
    // consulta a PTE correspondente, nao bloqueia e nao causa fault).
    //
    return MmIsAddressValid(Va) ? 1 : 0;
}

UINT8
ShvOsReadPhysical (
    _In_  UINT64  Pa,
    _Out_ UINT64* OutValue
    )
{
    MM_COPY_ADDRESS addr;
    SIZE_T          bytesRead = 0;
    NTSTATUS        status;

    *OutValue = 0;

    addr.PhysicalAddress.QuadPart = (LONGLONG)Pa;
    status = MmCopyMemory(OutValue, addr, sizeof(UINT64),
                          MM_COPY_MEMORY_PHYSICAL, &bytesRead);

    if (!NT_SUCCESS(status) || bytesRead != sizeof(UINT64))
    {
        *OutValue = 0;
        return 0;
    }

    return 1;
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

static VOID
ShvForceVmExitDpcRoutine (
    _In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    INT32 info[4];

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    //
    // CPUID causa VM-exit; ShvVmxHandleExit reaplica ShvHookTable (+ INVEPT
    // local) para este CPU no topo da funcao, antes do switch de ExitReason,
    // caso EptHookVersion esteja desatualizado -- ver shvvmxhv.c.
    //
    // NAO chamar ShvVmxCleanup aqui: essa rotina so faz sentido apos o iretq
    // usado no caminho de VMXOFF (unload). Fora desse contexto ela corrompe
    // DS/FS.base (troca para o seletor do TEB usermode), quebrando o tratamento
    // de excecao do kernel e disparando INT3 em KeCheckStackAndTargetAddress.
    //
    __cpuid(info, 0);

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

VOID
ShvOsForceAllCpuVmExit (
    VOID
    )
{
    KeGenericCallDpc(ShvForceVmExitDpcRoutine, NULL);
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

    //
    // Block new IOCTLs immediately so no IOCTL races during teardown
    //
    InterlockedExchange(&g_DriverUnloading, 1);

    // Remove symbolic link to block new device opens -- so existe se
    // DriverEntry conseguiu criar o device (DriverObject valido e
    // IoCreateDevice/IoCreateSymbolicLink deram certo).
    if (g_ShvDeviceObject != NULL)
        IoDeleteSymbolicLink(&symLink);

    //
    // Uninit process filters (ObRegisterCallbacks) -- waits for in-flight callbacks
    //
    ShvLog("[SHV] Removendo filtros de processo...\n");
    ShvHooksUninit();

    //
    // Remove EPT shadow policy hooks (from hook table; lazy per-vCPU EPT update pending)
    //
    ShvLog("[SHV] Removendo hooks de politica EPT...\n");
    ShvPolicyHooksUninit();

    //
    // Release user-mode MDLs and clear normal EPT hooks before VMXOFF
    //
    ShvLog("[SHV] Liberando MDLs e hooks EPT...\n");
    ShvHookReleaseMdls();
    ShvHookRemoveAll();

    //
    // Restore Beep dispatch table
    //
    ShvLog("[SHV] Restaurando Beep dispatch...\n");
    ShvBeepHijackTeardown();

    //
    // Unregister the power callback
    //
    ExUnregisterCallback(g_PowerCallbackRegistration);

    //
    // VMXOFF on all CPUs -- after this, EPT does not exist and shadow pages
    // can no longer execute; the trampoline pool is now safe to free.
    //
    ShvLog("[SHV] Descarregando hipervisor VMX (ShvUnload)...\n");
    ShvUnload();

    //
    // Libera TODAS as shadow pages ainda ativas (incluindo patches manuais
    // via SHV_CMD_HOOK_SHADOW que o usuario nao desinstalou antes do
    // unload) -- precisa ser DEPOIS de ShvUnload() pelo mesmo motivo do
    // trampoline pool abaixo (ver comentario em HpvShadowPagesReleaseAll).
    //
    ShvLog("[SHV] Liberando shadow pages orfas...\n");
    HpvShadowPagesReleaseAll();

    //
    // Free trampoline pool AFTER VMXOFF: EPT is gone, shadow pages cannot
    // execute, so no CPU can jump into the trampoline any more.
    //
    ShvLog("[SHV] Liberando trampoline pool...\n");
    HpvTrampolinePoolFree();

    //
    // Delete device object last, after full teardown
    //
    if (g_ShvDeviceObject != NULL)
    {
        IoDeleteDevice(g_ShvDeviceObject);
        g_ShvDeviceObject = NULL;
    }

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
    BOOLEAN haveDevice = FALSE; // DriverObject valido E IoCreateDevice/IoCreateSymbolicLink deram certo

    UNREFERENCED_PARAMETER(RegistryPath);

    //
    // Verificacao simples dos ponteiros recebidos -- nao rejeita a carga
    // (o driver continua funcionando sem a parte que dependeria do ponteiro
    // nulo), so evita dereferenciar o que nao pode ser usado:
    //   - RegistryPath: nao e usado por este driver de qualquer forma
    //     (UNREFERENCED_PARAMETER acima) -- NULL aqui nao muda nada.
    //   - DriverObject: usado por DriverUnload/MajorFunction[]/IoCreateDevice
    //     mais abaixo -- se for NULL, pula so essa parte (sem interface
    //     IOCTL nem DriverUnload automatico nessa carga), mas o resto
    //     (ShvLoad do hipervisor, hooks de politica, etc.) continua normal.
    //
    // Resolve APIs opcionais (nao garantidas em toda build do Windows) ANTES
    // de mais nada -- se alguma faltar, o log abaixo diz exatamente qual,
    // em vez do driver falhar silenciosamente no "sc start" (STATUS_
    // PROCEDURE_NOT_FOUND) sem nenhum diagnostico.
    //
    HpvResolveOptionalApis();
    HpvThreadUtilsResolveApis();

    if (DriverObject != NULL)
    {
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
        if (NT_SUCCESS(status))
        {
            status = IoCreateSymbolicLink(&symLink, &devName);
            if (NT_SUCCESS(status))
            {
                haveDevice = TRUE;
            }
            else
            {
                ShvLog("[SHV] IoCreateSymbolicLink falhou: 0x%08X -- seguindo sem interface IOCTL\n", status);
                IoDeleteDevice(g_ShvDeviceObject);
                g_ShvDeviceObject = NULL;
            }
        }
        else
        {
            ShvLog("[SHV] IoCreateDevice falhou: 0x%08X -- seguindo sem interface IOCTL\n", status);
        }
    }
    else
    {
        ShvLog("[SHV] DriverObject NULL -- pulando DriverUnload/MajorFunction[]/IoCreateDevice "
               "(sem interface IOCTL nem unload automatico nessa carga)\n");
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
        if (haveDevice)
        {
            IoDeleteSymbolicLink(&symLink);
            IoDeleteDevice(g_ShvDeviceObject);
            g_ShvDeviceObject = NULL;
        }
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
        if (haveDevice)
        {
            IoDeleteSymbolicLink(&symLink);
            IoDeleteDevice(g_ShvDeviceObject);
            g_ShvDeviceObject = NULL;
        }
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
        // VMX/EPT nunca chegaram a rodar neste ponto, entao e seguro liberar
        // direto (sem a ordenacao pos-VMXOFF exigida no DriverUnload) --
        // sem isso, os 4KB do trampoline pool vazavam ate reboot sempre que
        // o Beep hijack falhasse (ver memory/allocations.md).
        HpvTrampolinePoolFree();
        ExUnregisterCallback(g_PowerCallbackRegistration);
        if (haveDevice)
        {
            IoDeleteSymbolicLink(&symLink);
            IoDeleteDevice(g_ShvDeviceObject);
            g_ShvDeviceObject = NULL;
        }
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
        // ShvLoad falhou antes de VMLAUNCH ter sucesso em qualquer CPU (ou
        // desfez tudo ao detectar falha) -- nenhuma CPU chegou a rodar com
        // EPT ativo, entao e seguro liberar o trampoline pool direto aqui.
        HpvTrampolinePoolFree();
        ShvBeepHijackTeardown();
        ExUnregisterCallback(g_PowerCallbackRegistration);
        if (haveDevice)
        {
            IoDeleteSymbolicLink(&symLink);
            IoDeleteDevice(g_ShvDeviceObject);
            g_ShvDeviceObject = NULL;
        }
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


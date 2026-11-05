/*++

Module Name:

    shv_dbg.h

Abstract:

    Interface de debugging do SimpleVisor.
    Compartilhado entre kernel (shv.sys) e usermode (shv_monitor.exe).
    Independente de transporte: IOCTL hoje, CPUID shared memory no UEFI.

--*/

#pragma once
#pragma warning(disable: 4201)  // nonstandard: nameless struct/union

//
// IOCTL interface (transporte atual: DeviceIoControl)
// No futuro UEFI esse transporte sera substituido por CPUID + shared memory,
// mas as estruturas SHV_REQUEST / SHV_RESPONSE permanecem iguais.
//
#ifndef CTL_CODE
#define FILE_DEVICE_UNKNOWN     0x00000022
#define METHOD_BUFFERED         0
#define FILE_ANY_ACCESS         0
#define CTL_CODE(dev,func,meth,acc) \
    (((dev)<<16)|((acc)<<14)|((func)<<2)|(meth))
#endif

#define SHV_DEVICE_NAME         L"\\Device\\SimpleVisor"
#define SHV_DEVICE_LINK         L"\\DosDevices\\SimpleVisor"
#define SHV_DEVICE_WIN32        L"\\\\.\\SimpleVisor"
#define SHV_IOCTL_SUBMIT        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, \
                                         METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Comandos disponíveis
//
#define SHV_CMD_HOOK_EPT           1   // instala EPT hook (VA)
#define SHV_CMD_UNHOOK_EPT         2   // remove EPT hook (VA)
#define SHV_CMD_TRANSLATE_VA       3   // traduz VA -> PA (kernel ou processo)
#define SHV_CMD_READ_PHYS          4   // le bytes da memoria fisica
#define SHV_CMD_LIST_PROCS         5   // lista processos rodando
#define SHV_CMD_LIST_MODULES       6   // lista modulos do kernel
#define SHV_CMD_UNHOOK_ALL         7   // remove todos os EPT hooks
#define SHV_CMD_HOOK_SHADOW        8   // instala shadow hook (nao implementado)
#define SHV_CMD_UNHOOK_SHADOW      9   // remove shadow hook (nao implementado)
#define SHV_CMD_BEEP_SHADOW_SETUP  10  // upgrade beep hijack para EPT shadow (nao implementado)
#define SHV_CMD_LIST_SYSCALL_HOOKS 11  // lista syscall hooks (nao implementado)
#define SHV_CMD_NTOP_PROTECT       12  // adiciona PID a lista de protegidos
#define SHV_CMD_NTOP_UNPROTECT     13  // remove PID da lista de protegidos
#define SHV_CMD_NTOP_MONITOR       14  // adiciona PID a lista de monitorados
#define SHV_CMD_NTOP_UNMONITOR     15  // remove PID da lista de monitorados
#define SHV_CMD_NTOP_LIST          16  // lista todos os filtros
#define SHV_CMD_READ_VIRT          17  // le bytes da memoria virtual de um processo
#define SHV_CMD_NTOP_PROTECT_NAME  18  // adiciona nome a lista de protegidos
#define SHV_CMD_NTOP_UNPROTECT_NAME 19 // remove nome da lista de protegidos
#define SHV_CMD_NTOP_MONITOR_NAME  20  // adiciona nome a lista de monitorados
#define SHV_CMD_NTOP_UNMONITOR_NAME 21 // remove nome da lista de monitorados
#define SHV_CMD_LIST_SHADOW_PATCHES 22 // lista shadow patches (nao implementado)
#define SHV_CMD_CLEAR_EVENTS       23  // limpa ring buffer de eventos
#define SHV_CMD_LIST_EPT_HOOKS     24  // lista EPT hooks instalados

//
// Tipos de hook EPT (bitmask)
//
#define SHV_HOOK_EXEC           0x01  // captura execucao (Execute=0 no EPT)
#define SHV_HOOK_WRITE          0x02  // captura escrita  (Write=0 no EPT)
#define SHV_HOOK_READ           0x04  // captura leitura  (Read=0, Write=0 no EPT)

//
// Status de resposta (prefixo SHVD_ para evitar conflito com SHV_STATUS_* de shv_x.h)
//
#define SHVD_STATUS_OK           0
#define SHVD_STATUS_ERR_FULL     1   // tabela de hooks cheia
#define SHVD_STATUS_ERR_NOTFOUND 2   // hook nao encontrado para remover
#define SHVD_STATUS_ERR_NOMEM    3   // sem memoria para split de pagina
#define SHVD_STATUS_ERR_INVALID  4   // parametros invalidos
#define SHVD_STATUS_ERR_ACCESS   5   // acesso negado / pagina invalida

#define SHV_MAX_READ_SIZE       16384
#define SHV_SHADOW_PATCH_MAX    32
#define SHV_PROC_NAME_LEN       64
#define SHV_MOD_NAME_LEN        128

#pragma pack(push, 1)

//
// Estrutura de entrada enviada pelo usermode ao driver.
// Layout identico ao SHV_REQUEST do shv_client.h.
//
typedef struct _SHV_REQUEST
{
    unsigned int Command;
    union
    {
        struct
        {
            unsigned long long VirtAddr;   // VA a hookear
            unsigned char      HookType;   // SHV_HOOK_EXEC | SHV_HOOK_WRITE
            unsigned long long RangeSize;  // numero de paginas (default 1)
            unsigned long long Pid;        // PID do processo alvo (0 = kernel)
        } Hook;

        struct
        {
            unsigned long long VirtAddr;   // VA do hook a remover
            unsigned long long Pid;        // PID (0 = kernel VA)
        } Unhook;

        struct
        {
            unsigned long long VirtAddr;
            unsigned long long Pid;        // 0 = kernel
        } Translate;

        struct
        {
            unsigned long long PhysAddr;
            unsigned int       Size;       // max SHV_MAX_READ_SIZE
        } ReadPhys;

        struct
        {
            unsigned long long Gpa;
            unsigned int       PatchOffset;
            unsigned int       PatchLen;
            unsigned char      PatchBytes[SHV_SHADOW_PATCH_MAX];
        } Shadow;

        struct
        {
            unsigned long long Pid;
        } ProcFilter;

        struct
        {
            unsigned long long VirtAddr;
            unsigned int       Size;
            unsigned long long Pid;
        } ReadVirt;

        struct
        {
            char Name[SHV_PROC_NAME_LEN];
        } NameFilter;
    };
} SHV_REQUEST, *PSHV_REQUEST;

#define SHV_FILTER_TYPE_PROTECT    1
#define SHV_FILTER_TYPE_MONITOR    2

//
// Entrada de filtro (processo protegido ou monitorado).
//
typedef struct _SHV_PROC_FILTER_ENTRY
{
    unsigned long long Pid;
    char               Name[SHV_PROC_NAME_LEN];
    unsigned char      Type;    // 1=protegido 2=monitorado
    unsigned char      ByName;  // 1=filtro por nome, 0=por PID
    unsigned char      Pad[2];
} SHV_PROC_FILTER_ENTRY, *PSHV_PROC_FILTER_ENTRY;

//
// Entrada de lista de processos
//
typedef struct _SHV_PROC_ENTRY
{
    unsigned long long Pid;
    unsigned long long DirBase;            // CR3 do processo
    char               Name[SHV_PROC_NAME_LEN];
} SHV_PROC_ENTRY, *PSHV_PROC_ENTRY;

//
// Entrada de lista de modulos
//
typedef struct _SHV_MODULE_ENTRY
{
    unsigned long long Base;
    unsigned long long Size;
    char               Name[SHV_MOD_NAME_LEN];
} SHV_MODULE_ENTRY, *PSHV_MODULE_ENTRY;

//
// Informacao de um EPT hook instalado (retornada por SHV_CMD_LIST_EPT_HOOKS).
//
typedef struct _SHV_EPT_HOOK_INFO
{
    unsigned long long PhysAddr;
    unsigned long long VirtAddr;
    unsigned long long Pid;
    unsigned long long HitCount;
    unsigned long long RangeStart;
    unsigned long long RangeSize;
    unsigned char      Type;
    unsigned char      Pad[7];
} SHV_EPT_HOOK_INFO, *PSHV_EPT_HOOK_INFO;

//
// Informacao de um syscall hook via shadow page + trampolim
// (retornada por SHV_CMD_LIST_SYSCALL_HOOKS).
//
typedef struct _SHV_HOOK_INFO
{
    unsigned int       SyscallIndex;
    unsigned int       DisplacedSize;
    unsigned long long HookFuncVa;
    unsigned long long TrampolineVa;
    unsigned long long FuncGpa;
    unsigned long long FuncVa;
} SHV_HOOK_INFO, *PSHV_HOOK_INFO;

//
// Informacao de um shadow patch instalado via EPT split page
// (retornada por SHV_CMD_LIST_SHADOW_PATCHES).
//
typedef struct _SHV_SHADOW_HOOK_INFO
{
    unsigned long long GpaPage;
    unsigned int       Offset;
    unsigned int       PatchLen;
    unsigned char      PatchBytes[SHV_SHADOW_PATCH_MAX];
    unsigned long long FuncVa;
} SHV_SHADOW_HOOK_INFO, *PSHV_SHADOW_HOOK_INFO;

//
// Estrutura de resposta do driver para o usermode.
// O campo Data e interpretado de acordo com o comando.
// Layout identico ao SHV_RESPONSE do shv_client.h.
//
typedef struct _SHV_RESPONSE
{
    unsigned int Status;   // SHVD_STATUS_*
    unsigned int Count;    // para comandos de lista: numero de entradas
    union
    {
        unsigned long long  PhysAddr;            // Translate
        unsigned char       Data[SHV_MAX_READ_SIZE]; // ReadPhys / ReadVirt
        SHV_PROC_ENTRY      Procs[SHV_MAX_READ_SIZE / sizeof(SHV_PROC_ENTRY)];
        SHV_MODULE_ENTRY    Modules[SHV_MAX_READ_SIZE / sizeof(SHV_MODULE_ENTRY)];
        SHV_PROC_FILTER_ENTRY Filters[SHV_MAX_READ_SIZE / sizeof(SHV_PROC_FILTER_ENTRY)];
        SHV_EPT_HOOK_INFO    EptHookInfos[SHV_MAX_READ_SIZE / sizeof(SHV_EPT_HOOK_INFO)];
        SHV_HOOK_INFO        HookInfos[SHV_MAX_READ_SIZE / sizeof(SHV_HOOK_INFO)];
        SHV_SHADOW_HOOK_INFO ShadowHookInfos[SHV_MAX_READ_SIZE / sizeof(SHV_SHADOW_HOOK_INFO)];
    };
} SHV_RESPONSE, *PSHV_RESPONSE;

#pragma pack(pop)

//
// Tipos internos do motor de shadow hooks -- definidos fora do pack(1) pois
// sao estruturas internas do kernel, nao parte do protocolo IOCTL.
// Incluidos em shv_dbg.h para serem acessiveis tanto de shvvmxhv.c (VMX
// root mode) quanto de nt/hpv_hooks.c (NT mode).
//

#define SHV_SHADOW_MAX          8
#define SHV_TRAMPOLINE_SLOT_SIZE 64
#define SHV_TRAMPOLINE_MAX      64
#define SHV_SYSCALL_HOOK_MAX    32

#pragma warning(disable: 4201)

typedef struct _SHV_SHADOW_PAGE_RECORD
{
    unsigned long long Gpa;
    unsigned long long ShadowPa;
    void*              ShadowVa;
    unsigned int       RefCount;
    unsigned int       Offset;
    unsigned int       PatchLen;
    unsigned char      PatchBytes[SHV_SHADOW_PATCH_MAX];
} SHV_SHADOW_PAGE_RECORD, *PSHV_SHADOW_PAGE_RECORD;

typedef struct _SHV_SYSCALL_HOOK_ENTRY
{
    unsigned int  SyscallIndex;
    unsigned int  DisplacedSize;
    void*         HookFunc;
    unsigned char* Trampoline;
    unsigned long long FuncGpa;
    void*         FuncVa;
    unsigned char InUse;
    unsigned char IsInlinePatch;
} SHV_SYSCALL_HOOK_ENTRY, *PSHV_SYSCALL_HOOK_ENTRY;

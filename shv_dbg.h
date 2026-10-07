/*++

Module Name:

    shv_dbg.h

Abstract:

    Interface de debugging do SimpleVisor.
    Compartilhado entre kernel (shv.sys) e usermode (shv_monitor.exe).
    Independente de transporte: IOCTL hoje, CPUID shared memory no UEFI.

--*/

#pragma once

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
#define SHV_CMD_HOOK_EPT        1   // instala EPT hook em um PA
#define SHV_CMD_UNHOOK_EPT      2   // remove EPT hook de um PA
#define SHV_CMD_TRANSLATE_VA    3   // traduz VA -> PA (kernel ou processo)
#define SHV_CMD_READ_PHYS       4   // le bytes da memoria fisica
#define SHV_CMD_LIST_PROCS      5   // lista processos rodando
#define SHV_CMD_LIST_MODULES    6   // lista modulos do kernel

//
// Tipos de hook EPT (bitmask)
//
#define SHV_HOOK_EXEC           0x01  // captura execucao (Execute=0 no EPT)
#define SHV_HOOK_WRITE          0x02  // captura escrita  (Write=0 no EPT)

//
// Status de resposta (prefixo SHVD_ para evitar conflito com SHV_STATUS_* de shv_x.h)
//
#define SHVD_STATUS_OK           0
#define SHVD_STATUS_ERR_FULL     1   // tabela de hooks cheia
#define SHVD_STATUS_ERR_NOTFOUND 2   // hook nao encontrado para remover
#define SHVD_STATUS_ERR_NOMEM    3   // sem memoria para split de pagina
#define SHVD_STATUS_ERR_INVALID  4   // parametros invalidos
#define SHVD_STATUS_ERR_ACCESS   5   // acesso negado / pagina invalida

#define SHV_MAX_READ_SIZE       3072
#define SHV_PROC_NAME_LEN       64
#define SHV_MOD_NAME_LEN        128

#pragma pack(push, 1)

//
// Estrutura de entrada enviada pelo usermode ao driver.
//
typedef struct _SHV_REQUEST
{
    unsigned int Command;
    union
    {
        struct
        {
            unsigned long long PhysAddr;
            unsigned char      HookType;   // SHV_HOOK_EXEC | SHV_HOOK_WRITE
        } Hook;

        struct
        {
            unsigned long long PhysAddr;
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
    };
} SHV_REQUEST, *PSHV_REQUEST;

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
// Estrutura de resposta do driver para o usermode.
// O campo Data e interpretado de acordo com o comando.
//
typedef struct _SHV_RESPONSE
{
    unsigned int Status;   // SHV_STATUS_*
    unsigned int Count;    // para comandos de lista: numero de entradas
    union
    {
        unsigned long long  PhysAddr;            // Translate
        unsigned char       Data[SHV_MAX_READ_SIZE]; // ReadPhys / raw
        SHV_PROC_ENTRY      Procs[SHV_MAX_READ_SIZE / sizeof(SHV_PROC_ENTRY)];
        SHV_MODULE_ENTRY    Modules[SHV_MAX_READ_SIZE / sizeof(SHV_MODULE_ENTRY)];
    };
} SHV_RESPONSE, *PSHV_RESPONSE;

#pragma pack(pop)

/*++

Module Name:

    shv_client.h

Abstract:

    SimpleVisor client library -- comunicacao usermode com o hypervisor.
    Auto-contido: nao depende de shv_comm.h nem shv_dbg.h.
    Suporta dois modos de comunicacao selecionados via SHV_COMM_MODE:
      SHV_COMM_DEVICE      (0) -- CreateFile \\.\SimpleVisor + DeviceIoControl
      SHV_COMM_BEEP_HIJACK (1) -- NtCreateFile \Device\Beep  + DeviceIoControl

    Uso basico:
        ShvClient shv;
        if (!ShvClient::IsHypervisorPresent()) { ... }
        if (!shv.Open()) { ... }
        shv.Protect(pid);
        shv.Close();

--*/

#pragma once

#include <windows.h>
#include <intrin.h>
#include <stdint.h>

// ============================================================
// Modo de comunicacao
// ============================================================
#define SHV_COMM_DEVICE       0
#define SHV_COMM_BEEP_HIJACK  1
#ifndef SHV_COMM_MODE
#define SHV_COMM_MODE         1   // default: Beep hijack (nao requer admin para symlink)
#endif

// ============================================================
// Protocolo CPUID
// ============================================================
#define SHV_CPUID_LEAF              0x80000042u
#define SHV_EVENT_RING_SIZE         256

#define SHV_QUERY_PRESENCE          0
#define SHV_QUERY_LSTAR_READS       1
#define SHV_QUERY_LSTAR_WRITES      2
#define SHV_QUERY_EXIT_COUNT        3
#define SHV_QUERY_LAST_LSTAR        4
#define SHV_QUERY_HOOK_HITS         5
#define SHV_QUERY_EPT_CAPS          6
#define SHV_QUERY_EVENT_INFO        10
#define SHV_QUERY_EVENT_BASE        11
#define SHV_QUERY_EVENT_EXT_BASE    (SHV_QUERY_EVENT_BASE + SHV_EVENT_RING_SIZE)
#define SHV_QUERY_EVENT_EXT2_BASE   (SHV_QUERY_EVENT_BASE + 2 * SHV_EVENT_RING_SIZE)
#define SHV_QUERY_EVENT_EXT3_BASE   (SHV_QUERY_EVENT_BASE + 3 * SHV_EVENT_RING_SIZE)
#define SHV_QUERY_EVENT_EXT4_BASE   (SHV_QUERY_EVENT_BASE + 4 * SHV_EVENT_RING_SIZE)
#define SHV_QUERY_EVENT_EXT5_BASE   (SHV_QUERY_EVENT_BASE + 5 * SHV_EVENT_RING_SIZE)
#define SHV_QUERY_EVENT_EXT6_BASE   (SHV_QUERY_EVENT_BASE + 6 * SHV_EVENT_RING_SIZE)
#define SHV_QUERY_EVENT_EXT7_BASE   (SHV_QUERY_EVENT_BASE + 7 * SHV_EVENT_RING_SIZE)
#define SHV_QUERY_EVENT_EXT8_BASE   (SHV_QUERY_EVENT_BASE + 8 * SHV_EVENT_RING_SIZE)
#define SHV_EVENT_STACK_FRAMES      8

#define SHV_EVENT_LSTAR_READ        1
#define SHV_EVENT_LSTAR_WRITE       2
#define SHV_EVENT_EPT_EXEC          3
#define SHV_EVENT_EPT_WRITE         4
#define SHV_EVENT_EPT_READ          5

// ============================================================
// IOCTL interface
// ============================================================
#ifndef CTL_CODE
#define FILE_DEVICE_UNKNOWN 0x00000022
#define METHOD_BUFFERED     0
#define FILE_ANY_ACCESS     0
#define CTL_CODE(dev,func,meth,acc) (((dev)<<16)|((acc)<<14)|((func)<<2)|(meth))
#endif

#define SHV_DEVICE_WIN32        L"\\\\.\\SimpleVisor"
#define SHV_IOCTL_SUBMIT        CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)

// Comandos IOCTL
#define SHV_CMD_HOOK_EPT           1
#define SHV_CMD_UNHOOK_EPT         2
#define SHV_CMD_TRANSLATE_VA       3
#define SHV_CMD_READ_PHYS          4
#define SHV_CMD_LIST_PROCS         5
#define SHV_CMD_LIST_MODULES       6
#define SHV_CMD_UNHOOK_ALL         7
#define SHV_CMD_HOOK_SHADOW        8
#define SHV_CMD_UNHOOK_SHADOW      9
#define SHV_CMD_BEEP_SHADOW_SETUP  10
#define SHV_CMD_LIST_SYSCALL_HOOKS 11
#define SHV_CMD_NTOP_PROTECT       12
#define SHV_CMD_NTOP_UNPROTECT     13
#define SHV_CMD_NTOP_MONITOR       14
#define SHV_CMD_NTOP_UNMONITOR     15
#define SHV_CMD_NTOP_LIST           16
#define SHV_CMD_READ_VIRT           17
#define SHV_CMD_NTOP_PROTECT_NAME   18
#define SHV_CMD_NTOP_UNPROTECT_NAME 19
#define SHV_CMD_NTOP_MONITOR_NAME   20
#define SHV_CMD_NTOP_UNMONITOR_NAME 21
#define SHV_CMD_LIST_SHADOW_PATCHES 22
#define SHV_CMD_CLEAR_EVENTS        23
#define SHV_CMD_LIST_EPT_HOOKS      24

// Status de resposta
#define SHVD_STATUS_OK             0
#define SHVD_STATUS_ERR_FULL       1
#define SHVD_STATUS_ERR_NOTFOUND   2
#define SHVD_STATUS_ERR_NOMEM      3
#define SHVD_STATUS_ERR_INVALID    4
#define SHVD_STATUS_ERR_ACCESS     5

// Tipos de EPT hook (bitmask)
#define SHV_HOOK_EXEC              0x01
#define SHV_HOOK_WRITE             0x02
#define SHV_HOOK_READ              0x04

// Tipos de filtro de processo
#define SHV_FILTER_TYPE_PROTECT    1
#define SHV_FILTER_TYPE_MONITOR    2

// Limites
#define SHV_HOOKS_MAX_PROCS        32
#define SHV_SHADOW_PATCH_MAX       32
#define SHV_MAX_READ_SIZE          16384
#define SHV_PROC_NAME_LEN          64
#define SHV_MOD_NAME_LEN           128

// ============================================================
// Estruturas de protocolo (packed, espelhando o kernel)
// ============================================================
#pragma pack(push, 1)

typedef struct {
    unsigned long long VirtAddr;
    unsigned char      HookType;
    unsigned long long RangeSize;
    unsigned long long Pid;
} SHV_HOOK_ARGS;

typedef struct {
    unsigned long long VirtAddr;
    unsigned long long Pid;   // 0 = kernel VA; >0 = PID do processo
} SHV_UNHOOK_ARGS;

typedef struct {
    unsigned long long VirtAddr;
    unsigned long long Pid;
} SHV_TRANSLATE_ARGS;

typedef struct {
    unsigned long long PhysAddr;
    unsigned int       Size;
} SHV_READPHYS_ARGS;

typedef struct {
    unsigned long long VirtAddr;
    unsigned int       Size;
    unsigned long long Pid;
} SHV_READVIRT_ARGS;

typedef struct {
    unsigned long long Gpa;
    unsigned int       PatchOffset;
    unsigned int       PatchLen;
    unsigned char      PatchBytes[SHV_SHADOW_PATCH_MAX];
} SHV_SHADOW_ARGS;

typedef struct {
    unsigned long long Pid;
} SHV_PROCFILTER_ARGS;

typedef struct {
    char Name[SHV_PROC_NAME_LEN];
} SHV_NAMEFILTER_ARGS;

typedef struct {
    unsigned int Command;
    union {
        SHV_HOOK_ARGS        Hook;
        SHV_UNHOOK_ARGS      Unhook;
        SHV_TRANSLATE_ARGS   Translate;
        SHV_READPHYS_ARGS    ReadPhys;
        SHV_SHADOW_ARGS      Shadow;
        SHV_PROCFILTER_ARGS  ProcFilter;
        SHV_READVIRT_ARGS    ReadVirt;
        SHV_NAMEFILTER_ARGS  NameFilter;
    };
} SHV_REQUEST;

typedef struct {
    unsigned long long Pid;
    unsigned long long DirBase;
    char               Name[SHV_PROC_NAME_LEN];
} SHV_PROC_ENTRY;

typedef struct {
    unsigned long long Base;
    unsigned long long Size;
    char               Name[SHV_MOD_NAME_LEN];
} SHV_MODULE_ENTRY;

typedef struct {
    unsigned int       SyscallIndex;
    unsigned int       DisplacedSize;
    unsigned long long HookFuncVa;
    unsigned long long TrampolineVa;
    unsigned long long FuncGpa;
    unsigned long long FuncVa;
} SHV_HOOK_INFO;

typedef struct {
    unsigned long long GpaPage;
    unsigned int       Offset;
    unsigned int       PatchLen;
    unsigned char      PatchBytes[SHV_SHADOW_PATCH_MAX];
    unsigned long long FuncVa;
} SHV_SHADOW_HOOK_INFO;

typedef struct {
    unsigned long long PhysAddr;
    unsigned long long VirtAddr;
    unsigned long long Pid;
    unsigned long long HitCount;
    unsigned long long RangeStart;
    unsigned long long RangeSize;
    unsigned char      Type;
    unsigned char      Pad[7];
} SHV_EPT_HOOK_INFO;

typedef struct {
    unsigned long long Pid;
    char               Name[SHV_PROC_NAME_LEN];
    unsigned char      Type;
    unsigned char      ByName;
    unsigned char      Pad[2];
} SHV_PROC_FILTER_ENTRY;

typedef struct {
    unsigned int Status;
    unsigned int Count;
    union {
        unsigned long long    PhysAddr;
        unsigned char         Data[SHV_MAX_READ_SIZE];
        SHV_PROC_ENTRY        Procs[SHV_MAX_READ_SIZE / sizeof(SHV_PROC_ENTRY)];
        SHV_MODULE_ENTRY      Modules[SHV_MAX_READ_SIZE / sizeof(SHV_MODULE_ENTRY)];
        SHV_HOOK_INFO         HookInfos[SHV_MAX_READ_SIZE / sizeof(SHV_HOOK_INFO)];
        SHV_PROC_FILTER_ENTRY Filters[SHV_MAX_READ_SIZE / sizeof(SHV_PROC_FILTER_ENTRY)];
        SHV_SHADOW_HOOK_INFO  ShadowHookInfos[SHV_MAX_READ_SIZE / sizeof(SHV_SHADOW_HOOK_INFO)];
        SHV_EPT_HOOK_INFO     EptHookInfos[SHV_MAX_READ_SIZE / sizeof(SHV_EPT_HOOK_INFO)];
    };
} SHV_RESPONSE;

#pragma pack(pop)

// ============================================================
// Entrada de evento do ring buffer (decodificada, nao packed)
// ============================================================
struct ShvEventEntry {
    uint32_t seqNum;
    uint8_t  type;       // SHV_EVENT_*
    uint8_t  cpu;
    uint64_t value;      // GuestRIP (EPT) ou valor MSR (LSTAR)
    uint64_t returnAddr; // [RSP] no momento do evento (caller return addr)
    uint64_t aux;        // GPA para EPT write; GuestRIP para LSTAR
    uint64_t cr3;        // GUEST_CR3 -- identifica o processo
    uint64_t timestamp;  // hora do fault: 100ns desde 1601 (Windows FILETIME)
    uint64_t linearAddr; // GUEST_LINEAR_ADDRESS: VA do acesso que causou o fault (0 se nao disponivel)
    uint64_t stack[SHV_EVENT_STACK_FRAMES]; // RSP[0..7] no momento do fault (0 = nao disponivel)
};

// ============================================================
// ShvClient -- classe principal de comunicacao
// ============================================================
class ShvClient
{
public:
    ShvClient();
    ~ShvClient();

    // Abre o canal de comunicacao com o hypervisor.
    // Deve ser chamado antes de qualquer comando IOCTL.
    bool Open();

    // Fecha o canal de comunicacao.
    void Close();

    // Retorna true se o canal esta aberto.
    bool IsOpen() const;

    // --------------------------------------------------------
    // Consultas CPUID (nao requerem Open; qualquer processo)
    // --------------------------------------------------------

    // Retorna true se o SimpleVisor esta ativo.
    // outCpu: CPU logica onde o CPUID foi executado.
    // outVer: versao do hypervisor.
    static bool IsHypervisorPresent(int* outCpu = nullptr, int* outVer = nullptr);

    // Le um contador CPUID pelo sub-leaf (SHV_QUERY_*).
    static uint64_t QueryCounter(int subLeaf);

    // Preenche totalEvents e ringSize a partir do sub-leaf SHV_QUERY_EVENT_INFO.
    static bool QueryEventInfo(uint32_t* totalEvents, uint32_t* ringSize);

    // Le um slot do ring buffer de eventos (slot 0..SHV_EVENT_RING_SIZE-1).
    static ShvEventEntry ReadEvent(int slot);

    // --------------------------------------------------------
    // Comandos IOCTL (requerem Open bem-sucedido)
    // --------------------------------------------------------

    // Instala EPT hook em va.
    // hookType: bitmask SHV_HOOK_EXEC | SHV_HOOK_WRITE | SHV_HOOK_READ.
    // rangeSize: numero de paginas monitoradas (default 1).
    // pid: CR3 do processo alvo (0 = qualquer).
    bool HookEpt(uint64_t va, uint8_t hookType,
                 uint64_t rangeSize = 1, uint64_t pid = 0);

    // Remove EPT hook instalado em va.  pid=0 para VA de kernel.
    bool UnhookEpt(uint64_t va, uint64_t pid = 0);

    // Remove todos os EPT hooks instalados.
    bool UnhookAll();

    // Traduz VA do processo pid para PA.
    // pid = 0: usa o processo do chamador.
    bool TranslateVa(uint64_t va, uint64_t pid, uint64_t* outPa);

    // Le size bytes a partir de pa (endereco fisico).
    // outBuf deve ter pelo menos size bytes (max SHV_MAX_READ_SIZE).
    // outCount (opcional): bytes efetivamente lidos.
    bool ReadPhys(uint64_t pa, uint32_t size,
                  void* outBuf, uint32_t* outCount = nullptr);

    // Le size bytes a partir de va no processo pid.
    // pid = 0: processo do chamador.
    bool ReadVirt(uint64_t va, uint32_t size, uint64_t pid,
                  void* outBuf, uint32_t* outCount = nullptr);

    // Lista processos ativos. out deve ter capacidade para maxCount entradas.
    // outCount: numero de entradas preenchidas.
    bool ListProcs(SHV_PROC_ENTRY* out, uint32_t maxCount, uint32_t* outCount);

    // Lista modulos do processo pid. pid = 0: processo do chamador.
    bool ListModules(SHV_MODULE_ENTRY* out, uint32_t maxCount, uint32_t* outCount);

    // Lista syscall hooks instalados.
    bool ListSyscallHooks(SHV_HOOK_INFO* out, uint32_t maxCount, uint32_t* outCount);

    // Lista shadow hooks instalados no kernel (startup + IOCTL).
    bool ListShadowPatches(SHV_SHADOW_HOOK_INFO* out, uint32_t maxCount, uint32_t* outCount);

    // Zera o ring buffer de eventos no kernel e reseta o contador.
    bool ClearEvents();

    // Lista EPT hooks instalados via IOCTL.
    bool ListEptHooks(SHV_EPT_HOOK_INFO* out, uint32_t maxCount, uint32_t* outCount);

    // Lista filtros de processo (protect/monitor) ativos.
    bool ListFilters(SHV_PROC_FILTER_ENTRY* out, uint32_t maxCount, uint32_t* outCount);

    // Adiciona pid a lista de processos protegidos (bloqueia NtOpenProcess).
    bool Protect(uint64_t pid);

    // Remove pid da lista de processos protegidos.
    bool Unprotect(uint64_t pid);

    // Adiciona pid a lista de processos monitorados (loga acessos).
    bool Monitor(uint64_t pid);

    // Remove pid da lista de processos monitorados.
    bool Unmonitor(uint64_t pid);

    // Adiciona nome de processo a lista de protegidos (case-insensitive).
    bool ProtectName(const char* name);

    // Remove nome de processo da lista de protegidos.
    bool UnprotectName(const char* name);

    // Adiciona nome de processo a lista de monitorados.
    bool MonitorName(const char* name);

    // Remove nome de processo da lista de monitorados.
    bool UnmonitorName(const char* name);

    // Instala shadow page manual em gpa com patch em offset.
    // bytes/len: sequencia de bytes a aplicar (max SHV_SHADOW_PATCH_MAX).
    bool ShadowPatch(uint64_t gpa, uint32_t offset,
                     const uint8_t* bytes, uint32_t len);

    // Remove shadow page em gpa.
    bool Unshadow(uint64_t gpa);

    // Configura shadow hook automatico no handler IRP do device Beep.
    // outGpa (opcional): GPA onde a shadow page foi instalada.
    bool BeepShadowSetup(uint64_t* outGpa = nullptr);

    // --------------------------------------------------------
    // Acesso a ultima resposta bruta
    // --------------------------------------------------------

    const SHV_RESPONSE& LastResponse() const { return m_resp; }
    uint32_t            LastStatus()   const { return m_resp.Status; }

    // Converte status para string legivel.
    static const char* StatusString(uint32_t status);

private:
    bool Submit(const SHV_REQUEST& req);

    HANDLE      m_device;
    SHV_RESPONSE m_resp;
};

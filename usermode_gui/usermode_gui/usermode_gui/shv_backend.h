/*++

Module Name:

    shv_backend.h

Abstract:

    Backend do monitor: estado compartilhado entre os tabs, thread de polling
    e wrappers de comando sobre o ShvClient.

--*/

#pragma once
#include <windows.h>
#include <vector>
#include <deque>
#include <string>
#include "../../../shv_client/shv_client.h"

// ============================================================
// Constantes
// ============================================================
static constexpr int  kEventHistoryMax  = 20000;
static constexpr DWORD kPollIntervalMs  = 1000;

// ============================================================
// Estruturas de estado
// ============================================================

struct ShvEventRecord {
    uint32_t seqNum;
    uint8_t  type;        // SHV_EVENT_*
    uint8_t  cpu;
    uint64_t value;       // GuestRIP (EPT) ou MSR value (LSTAR)
    uint64_t returnAddr;
    uint64_t aux;
    uint64_t cr3;
    uint64_t timestamp;   // 100ns desde 1601 (Windows FILETIME, do kernel)
    uint64_t linearAddr;  // VA do acesso que causou o fault (GUEST_LINEAR_ADDRESS; 0 se indisponivel)
    uint64_t stack[SHV_EVENT_STACK_FRAMES]; // RSP[0..7] no momento do fault (0 = nao capturado)
    DWORD    tickMs;      // GetTickCount() local quando recebido
};

struct ShvStats {
    bool     present;
    int      cpu;
    int      version;
    uint64_t exitCount;
    uint64_t hookHits;
    uint64_t lstarReads;
    uint64_t lstarWrites;
    uint64_t lastLstar;
    bool     eptExecOnly;
    uint32_t totalEvents;
    uint64_t copyVmHits;   // total de chamadas interceptadas em MmCopyVirtualMemory
};

struct ShvEptHookEntry {
    uint64_t va;
    uint64_t pa;      // GPA (page-aligned); 0 se nao resolvido
    uint8_t  type;    // SHV_HOOK_EXEC | SHV_HOOK_WRITE | SHV_HOOK_READ
    uint64_t range;
    uint64_t pid;
};

// Uma FUNCAO hookeada dentro de uma shadow page -- offset/len/bytes sao
// POR FUNCAO (cada uma tem seu proprio patch de 12 bytes no seu proprio
// offset dentro da pagina de 4KB compartilhada), nao da pagina como um todo.
struct ShvShadowFuncEntry {
    uint64_t va;   // 0 = shadow patch manual sem funcao nomeada associada
                   // (aba Memoria->Shadow Patch, modo cru por GPA).
    uint32_t offset;
    uint32_t len;
    uint8_t  bytes[SHV_SHADOW_PATCH_MAX];
};

struct ShvShadowEntry {
    uint64_t gpa;
    uint64_t va;   // PRIMEIRA funcao (funcs[0].va, ou 0 se nenhuma) -- mantido
                   // por compatibilidade com o lookup de modulo/CR3 existente.
    uint64_t cr3;  // DirBase do processo dono de "va" (0 = desconhecido/kernel).
    std::vector<ShvShadowFuncEntry> funcs; // TODAS as funcoes hookeadas que
                                // compartilham esta pagina (RefCount > 1 no
                                // kernel, ex. ZwOpenKey/ZwOpenKeyEx vizinhas no
                                // binario), cada uma com seu PROPRIO offset/
                                // bytes -- nao os mesmos bytes repetidos pra
                                // todas (ver memory/fixes.md).
};

struct ShvState {
    ShvStats                           stats;
    std::vector<SHV_HOOK_INFO>         syscallHooks;
    std::vector<SHV_PROC_FILTER_ENTRY> filters;
    std::vector<SHV_PROC_ENTRY>        procs;
    std::vector<SHV_MODULE_ENTRY>      kernelModules;  // SHV_CMD_LIST_MODULES
    std::deque<ShvEventRecord>         events;
    DWORD                              lastRefreshMs;
    std::vector<ShvEptHookEntry>       eptHooks;
    std::vector<ShvShadowEntry>        shadowPatches;   // patches instalados pela GUI (IOCTL cru)
    std::vector<ShvShadowEntry>        kernelShadows;   // hooks instalados no startup do driver
    std::deque<SHV_REGISTRY_EVENT>     registryEvents;  // SHV_CMD_LIST_REGISTRY_EVENTS (acumulado localmente por SeqNum)
    uint64_t                           lastRegistrySeqSeen = 0;
};

// ============================================================
// ShvBackend
// ============================================================
class ShvBackend {
public:
    ShvBackend();
    ~ShvBackend();

    // Conexao
    void Connect();
    void Disconnect();
    bool IsConnected() const;

    // Lock/Unlock ao redor de leituras de State()
    void              Lock();
    void              Unlock();
    const ShvState&   State() const { return m_state; }

    // Atualiza todos os dados imediatamente (chamado pela UI)
    void RefreshAll();

    // Resultado de comando
    struct CmdResult {
        bool     ok;
        uint32_t status;  // SHVD_STATUS_*
    };

    // Comandos IOCTL
    CmdResult HookEpt(uint64_t va, uint8_t type, uint64_t range, uint64_t pid);
    CmdResult UnhookEpt(uint64_t va);
    CmdResult UnhookAll();
    CmdResult TranslateVa(uint64_t va, uint64_t pid, uint64_t* outPa);
    CmdResult ReadPhys(uint64_t pa, uint32_t size, void* buf, uint32_t* outCount);
    CmdResult ReadVirt(uint64_t va, uint32_t size, uint64_t pid, void* buf, uint32_t* outCount);
    // Modulos (EXE+DLLs) do processo pid, lidos pelo kernel via PEB (funciona
    // mesmo contra processos protegidos/PPL, ao contrario de Toolhelp32 em usermode).
    CmdResult ListProcessModules(uint64_t pid, std::vector<SHV_MODULE_ENTRY>& out);
    // Threads (tid+startaddr) e regioes de memoria de um processo, lidas pelo
    // kernel (ZwQuerySystemInformation / ZwQueryVirtualMemory anexado) --
    // funcionam mesmo contra processos protegidos (PPL).
    CmdResult ListProcessThreads(uint64_t pid, std::vector<SHV_THREAD_ENTRY>& out);
    CmdResult ListProcessMemory(uint64_t pid, std::vector<SHV_MEMREGION_ENTRY>& out);
    // Suspende/resume uma thread via handle kernel-mode (funciona com PPL).
    CmdResult SuspendThread(uint64_t tid);
    CmdResult ResumeThread(uint64_t tid);
    // Rip/Rsp/Rbp de uma thread (suspende, le contexto, resume) -- usado pra
    // sementear um stack walk sem handle usermode.
    CmdResult GetThreadContext(uint64_t tid, SHV_THREAD_CONTEXT* out);
    // Stack de kernel via APC especial (funciona com PPL) -- ver ShvClient::GetThreadStack.
    CmdResult GetThreadStack(uint64_t tid, SHV_THREAD_STACK* out);
    CmdResult Protect(uint64_t pid);
    CmdResult Unprotect(uint64_t pid);
    CmdResult Monitor(uint64_t pid);
    CmdResult Unmonitor(uint64_t pid);
    CmdResult ProtectName(const char* name);
    CmdResult UnprotectName(const char* name);
    CmdResult MonitorName(const char* name);
    CmdResult UnmonitorName(const char* name);
    // va/cr3 (opcionais, default 0): quando o chamador ja sabe a VA e o CR3
    // (DirBase) do processo dono dela -- ficam gravados localmente so pra
    // exibicao na aba Filtros->Hook Shadow (o protocolo IOCTL em si continua
    // baseado em GPA; o kernel nao guarda VA nenhuma).
    CmdResult ShadowPatch(uint64_t gpa, uint32_t offset, const uint8_t* bytes, uint32_t len,
                          uint64_t va = 0, uint64_t cr3 = 0);
    CmdResult Unshadow(uint64_t gpa);
    CmdResult BeepShadowSetup(uint64_t* outGpa);
    // Downgrade de volta pro hijack de tabela -- usar isto pra "desligar" o
    // Beep Shadow (ex. checkbox na GUI), NAO backend.Unshadow() com a GPA
    // do beep: aquele so remove o redirecionamento sem recolocar nada no
    // lugar, perdendo a comunicacao com o hypervisor pelo canal Beep.
    CmdResult BeepShadowRemove();
    CmdResult ClearEvents();
    CmdResult SetStackFilter(bool enabled);
    CmdResult ListEptHooks();
    // Zera o ring buffer de eventos de registro no kernel E o acumulado local.
    CmdResult ClearRegistryEvents();

    // Linha de status (ultima operacao)
    const std::string& StatusMsg()     const { return m_statusMsg;     }
    bool               StatusIsError() const { return m_statusIsError; }
    void               ClearStatus()         { m_statusMsg.clear();    }

private:
    void PostStatus(bool isError, const char* fmt, ...);

    static DWORD WINAPI PollThread(LPVOID param);
    void PollLoop();
    void PollOnce();

    ShvClient        m_client;
    ShvState         m_state;
    CRITICAL_SECTION m_cs;
    HANDLE           m_pollThread;
    volatile bool    m_running;
    uint32_t         m_lastSeqSeen;  // apenas pelo poll thread
    std::string      m_statusMsg;
    bool             m_statusIsError;
};

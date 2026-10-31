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
static constexpr int  kEventHistoryMax  = 2000;
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
};

struct ShvEptHookEntry {
    uint64_t va;
    uint64_t pa;      // GPA (page-aligned); 0 se nao resolvido
    uint8_t  type;    // SHV_HOOK_EXEC | SHV_HOOK_WRITE | SHV_HOOK_READ
    uint64_t range;
    uint64_t pid;
};

struct ShvShadowEntry {
    uint64_t gpa;
    uint32_t offset;
    uint32_t len;
    uint8_t  bytes[SHV_SHADOW_PATCH_MAX];
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
    CmdResult Protect(uint64_t pid);
    CmdResult Unprotect(uint64_t pid);
    CmdResult Monitor(uint64_t pid);
    CmdResult Unmonitor(uint64_t pid);
    CmdResult ProtectName(const char* name);
    CmdResult UnprotectName(const char* name);
    CmdResult MonitorName(const char* name);
    CmdResult UnmonitorName(const char* name);
    CmdResult ShadowPatch(uint64_t gpa, uint32_t offset, const uint8_t* bytes, uint32_t len);
    CmdResult Unshadow(uint64_t gpa);
    CmdResult BeepShadowSetup(uint64_t* outGpa);
    CmdResult ClearEvents();
    CmdResult ListEptHooks();

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

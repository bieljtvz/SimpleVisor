/*++

Module Name:

    shv_backend.cpp

Abstract:

    Implementacao do ShvBackend: thread de polling, refresh e comandos.

--*/

#include "shv_backend.h"
#include <intrin.h>
#include <stdarg.h>
#include <stdio.h>
#include <algorithm>

// ============================================================
// Construtor / Destrutor
// ============================================================

ShvBackend::ShvBackend()
    : m_running(false)
    , m_pollThread(NULL)
    , m_lastSeqSeen(0)
    , m_statusIsError(false)
{
    InitializeCriticalSection(&m_cs);
    m_state = {};
}

ShvBackend::~ShvBackend()
{
    Disconnect();
    DeleteCriticalSection(&m_cs);
}

// ============================================================
// Conexao
// ============================================================

void ShvBackend::Connect()
{
    if (m_client.IsOpen()) return;

    if (!m_client.Open())
    {
        PostStatus(true, "Falha ao abrir dispositivo (erro %lu)", GetLastError());
        return;
    }

    m_running    = true;
    m_pollThread = CreateThread(NULL, 0, PollThread, this, 0, NULL);
    PostStatus(false, "Conectado ao hypervisor");
}

void ShvBackend::Disconnect()
{
    m_running = false;
    if (m_pollThread)
    {
        WaitForSingleObject(m_pollThread, 3000);
        CloseHandle(m_pollThread);
        m_pollThread = NULL;
    }
    m_client.Close();
}

bool ShvBackend::IsConnected() const
{
    return m_client.IsOpen();
}

void ShvBackend::Lock()   { EnterCriticalSection(&m_cs); }
void ShvBackend::Unlock() { LeaveCriticalSection(&m_cs); }

// ============================================================
// Refresh
// ============================================================

void ShvBackend::RefreshAll()
{
    Lock();
    PollOnce();
    Unlock();
}

DWORD WINAPI ShvBackend::PollThread(LPVOID param)
{
    static_cast<ShvBackend*>(param)->PollLoop();
    return 0;
}

void ShvBackend::PollLoop()
{
    while (m_running)
    {
        Lock();
        PollOnce();
        Unlock();
        Sleep(kPollIntervalMs);
    }
}

// Deve ser chamado com m_cs adquirido
void ShvBackend::PollOnce()
{
    // --- Stats (CPUID, sem IOCTL) ---
    {
        ShvStats s = {};
        s.present     = ShvClient::IsHypervisorPresent(&s.cpu, &s.version);
        s.exitCount   = ShvClient::QueryCounter(SHV_QUERY_EXIT_COUNT);
        s.hookHits    = ShvClient::QueryCounter(SHV_QUERY_HOOK_HITS);
        s.lstarReads  = ShvClient::QueryCounter(SHV_QUERY_LSTAR_READS);
        s.lstarWrites = ShvClient::QueryCounter(SHV_QUERY_LSTAR_WRITES);
        s.lastLstar   = ShvClient::QueryCounter(SHV_QUERY_LAST_LSTAR);

        int r[4];
        __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_EPT_CAPS);
        s.eptExecOnly = (r[0] & 1) != 0;

        uint32_t total = 0;
        ShvClient::QueryEventInfo(&total, nullptr);
        s.totalEvents = total;

        m_state.stats         = s;
        m_state.lastRefreshMs = GetTickCount();
    }

    if (!m_client.IsOpen()) return;

    // --- EPT hooks (repopula apos restart da GUI) ---
    {
        static SHV_EPT_HOOK_INFO buf[SHV_MAX_READ_SIZE / sizeof(SHV_EPT_HOOK_INFO)];
        uint32_t n = 0;
        if (m_client.ListEptHooks(buf, _countof(buf), &n))
        {
            m_state.eptHooks.clear();
            for (uint32_t i = 0; i < n; i++)
            {
                if (buf[i].Type & (SHV_HOOK_EXEC | SHV_HOOK_WRITE | SHV_HOOK_READ))
                {
                    ShvEptHookEntry e = {};
                    e.va    = buf[i].VirtAddr;
                    e.pa    = buf[i].PhysAddr;
                    e.type  = buf[i].Type;
                    e.range = buf[i].RangeSize;
                    e.pid   = buf[i].Pid;
                    m_state.eptHooks.push_back(e);
                }
            }
        }
    }

    // --- Syscall hooks ---
    {
        static SHV_HOOK_INFO buf[SHV_MAX_READ_SIZE / sizeof(SHV_HOOK_INFO)];
        uint32_t n = 0;
        if (m_client.ListSyscallHooks(buf, _countof(buf), &n))
            m_state.syscallHooks.assign(buf, buf + n);
    }

    // --- Filtros de processo ---
    {
        static SHV_PROC_FILTER_ENTRY buf[SHV_MAX_READ_SIZE / sizeof(SHV_PROC_FILTER_ENTRY)];
        uint32_t n = 0;
        if (m_client.ListFilters(buf, _countof(buf), &n))
            m_state.filters.assign(buf, buf + n);
    }

    // --- Processos ---
    {
        static SHV_PROC_ENTRY buf[SHV_MAX_READ_SIZE / sizeof(SHV_PROC_ENTRY)];
        uint32_t n = 0;
        if (m_client.ListProcs(buf, _countof(buf), &n))
            m_state.procs.assign(buf, buf + n);
    }

    // --- Modulos do kernel ---
    {
        static SHV_MODULE_ENTRY buf[SHV_MAX_READ_SIZE / sizeof(SHV_MODULE_ENTRY)];
        uint32_t n = 0;
        if (m_client.ListModules(buf, _countof(buf), &n))
            m_state.kernelModules.assign(buf, buf + n);
    }

    // --- Shadow hooks do kernel (startup) ---
    {
        static SHV_SHADOW_HOOK_INFO buf[SHV_MAX_READ_SIZE / sizeof(SHV_SHADOW_HOOK_INFO)];
        uint32_t n = 0;
        if (m_client.ListShadowPatches(buf, _countof(buf), &n))
        {
            m_state.kernelShadows.clear();
            for (uint32_t i = 0; i < n; i++)
            {
                ShvShadowEntry e = {};
                e.gpa    = buf[i].GpaPage;
                e.offset = buf[i].Offset;
                e.len    = (buf[i].PatchLen < SHV_SHADOW_PATCH_MAX)
                               ? buf[i].PatchLen : SHV_SHADOW_PATCH_MAX;
                memcpy(e.bytes, buf[i].PatchBytes, e.len);
                m_state.kernelShadows.push_back(e);
            }
        }
    }

    // --- Eventos do ring buffer ---
    {
        uint32_t total = 0, ringSize = 0;
        ShvClient::QueryEventInfo(&total, &ringSize);

        if (total != m_lastSeqSeen)
        {
            int slots = (int)min(ringSize, (uint32_t)SHV_EVENT_RING_SIZE);
            ShvEventRecord newEvs[SHV_EVENT_RING_SIZE];
            int newCount = 0;

            for (int i = 0; i < slots; i++)
            {
                ShvEventEntry e = ShvClient::ReadEvent(i);
                if (e.seqNum == 0 || e.seqNum <= m_lastSeqSeen) continue;
                ShvEventRecord& r = newEvs[newCount++];
                r.seqNum     = e.seqNum;
                r.type       = e.type;
                r.cpu        = e.cpu;
                r.value      = e.value;
                r.returnAddr = e.returnAddr;
                r.aux        = e.aux;
                r.cr3        = e.cr3;
                r.timestamp  = e.timestamp;
                r.linearAddr = e.linearAddr;
                for (int si = 0; si < SHV_EVENT_STACK_FRAMES; si++)
                    r.stack[si] = e.stack[si];
                r.tickMs     = GetTickCount();
            }

            // Ordena por seqNum crescente
            std::sort(newEvs, newEvs + newCount,
                [](const ShvEventRecord& a, const ShvEventRecord& b) {
                    return a.seqNum < b.seqNum;
                });

            for (int i = 0; i < newCount; i++)
            {
                m_state.events.push_back(newEvs[i]);
                if (m_lastSeqSeen < newEvs[i].seqNum)
                    m_lastSeqSeen = newEvs[i].seqNum;
            }
            while ((int)m_state.events.size() > kEventHistoryMax)
                m_state.events.pop_front();
        }
    }
}

// ============================================================
// Comandos IOCTL
// ============================================================

#define CMD_WRAP(call, okMsg, errMsg, ...)                           \
    Lock();                                                          \
    bool _ok = (call);                                               \
    uint32_t _st = m_client.LastStatus();                            \
    if (_ok) PostStatus(false, okMsg, ##__VA_ARGS__);                \
    else     PostStatus(true,  errMsg, ShvClient::StatusString(_st));\
    Unlock();                                                        \
    return { _ok, _st }

ShvBackend::CmdResult ShvBackend::HookEpt(uint64_t va, uint8_t type,
                                          uint64_t range, uint64_t pid)
{
    Lock();
    bool _ok = m_client.HookEpt(va, type, range, pid);
    uint32_t _st = m_client.LastStatus();
    if (_ok)
    {
        PostStatus(false, "EPT hook instalado em 0x%llX", va);
        bool found = false;
        for (auto& h : m_state.eptHooks)
            if (h.va == va) { h.type = type; h.range = range; h.pid = pid; found = true; break; }
        if (!found) m_state.eptHooks.push_back({ va, 0, type, range, pid });
    }
    else PostStatus(true, "HookEpt falhou: %s", ShvClient::StatusString(_st));
    Unlock();
    return { _ok, _st };
}

ShvBackend::CmdResult ShvBackend::UnhookEpt(uint64_t va)
{
    Lock();
    // Recupera o PID associado a este VA para que o driver possa fazer o
    // process-attach e traduzir o VA user-mode para PA corretamente.
    uint64_t pid = 0;
    for (const auto& h : m_state.eptHooks)
        if (h.va == va) { pid = h.pid; break; }

    bool _ok = m_client.UnhookEpt(va, pid);
    uint32_t _st = m_client.LastStatus();
    if (_ok)
    {
        PostStatus(false, "EPT hook removido em 0x%llX", va);
        auto& h = m_state.eptHooks;
        h.erase(std::remove_if(h.begin(), h.end(),
            [va](const ShvEptHookEntry& e) { return e.va == va; }), h.end());
    }
    else PostStatus(true, "UnhookEpt falhou: %s", ShvClient::StatusString(_st));
    Unlock();
    return { _ok, _st };
}

ShvBackend::CmdResult ShvBackend::UnhookAll()
{
    Lock();
    bool _ok = m_client.UnhookAll();
    uint32_t _st = m_client.LastStatus();
    if (_ok) { PostStatus(false, "Todos os hooks removidos"); m_state.eptHooks.clear(); }
    else       PostStatus(true, "UnhookAll falhou: %s", ShvClient::StatusString(_st));
    Unlock();
    return { _ok, _st };
}

ShvBackend::CmdResult ShvBackend::TranslateVa(uint64_t va, uint64_t pid,
                                              uint64_t* outPa)
{
    Lock();
    bool _ok = m_client.TranslateVa(va, pid, outPa);
    uint32_t _st = m_client.LastStatus();
    if (!_ok) PostStatus(true, "TranslateVa falhou: %s", ShvClient::StatusString(_st));
    Unlock();
    return { _ok, _st };
}

ShvBackend::CmdResult ShvBackend::ReadPhys(uint64_t pa, uint32_t size,
                                           void* buf, uint32_t* outCount)
{
    Lock();
    bool _ok = m_client.ReadPhys(pa, size, buf, outCount);
    uint32_t _st = m_client.LastStatus();
    if (!_ok) PostStatus(true, "ReadPhys falhou: %s", ShvClient::StatusString(_st));
    Unlock();
    return { _ok, _st };
}

ShvBackend::CmdResult ShvBackend::ReadVirt(uint64_t va, uint32_t size,
                                           uint64_t pid, void* buf,
                                           uint32_t* outCount)
{
    Lock();
    bool _ok = m_client.ReadVirt(va, size, pid, buf, outCount);
    uint32_t _st = m_client.LastStatus();
    if (!_ok) PostStatus(true, "ReadVirt falhou: %s", ShvClient::StatusString(_st));
    Unlock();
    return { _ok, _st };
}

ShvBackend::CmdResult ShvBackend::Protect(uint64_t pid)
{
    CMD_WRAP(m_client.Protect(pid),
             "PID %llu protegido", "Protect falhou: %s", pid);
}

ShvBackend::CmdResult ShvBackend::Unprotect(uint64_t pid)
{
    CMD_WRAP(m_client.Unprotect(pid),
             "PID %llu desprotegido", "Unprotect falhou: %s", pid);
}

ShvBackend::CmdResult ShvBackend::Monitor(uint64_t pid)
{
    CMD_WRAP(m_client.Monitor(pid),
             "PID %llu monitorado", "Monitor falhou: %s", pid);
}

ShvBackend::CmdResult ShvBackend::Unmonitor(uint64_t pid)
{
    CMD_WRAP(m_client.Unmonitor(pid),
             "PID %llu sem monitor", "Unmonitor falhou: %s", pid);
}

ShvBackend::CmdResult ShvBackend::ProtectName(const char* name)
{
    CMD_WRAP(m_client.ProtectName(name),
             "Nome '%s' protegido", "ProtectName falhou: %s", name);
}

ShvBackend::CmdResult ShvBackend::UnprotectName(const char* name)
{
    CMD_WRAP(m_client.UnprotectName(name),
             "Nome '%s' desprotegido", "UnprotectName falhou: %s", name);
}

ShvBackend::CmdResult ShvBackend::MonitorName(const char* name)
{
    CMD_WRAP(m_client.MonitorName(name),
             "Nome '%s' monitorado", "MonitorName falhou: %s", name);
}

ShvBackend::CmdResult ShvBackend::UnmonitorName(const char* name)
{
    CMD_WRAP(m_client.UnmonitorName(name),
             "Nome '%s' sem monitor", "UnmonitorName falhou: %s", name);
}

ShvBackend::CmdResult ShvBackend::ShadowPatch(uint64_t gpa, uint32_t offset,
                                              const uint8_t* bytes, uint32_t len)
{
    Lock();
    bool _ok = m_client.ShadowPatch(gpa, offset, bytes, len);
    uint32_t _st = m_client.LastStatus();
    if (_ok)
    {
        PostStatus(false, "Shadow patch GPA 0x%llX+0x%X (%u bytes)", gpa, offset, len);
        bool found = false;
        for (auto& s : m_state.shadowPatches)
        {
            if (s.gpa == gpa)
            {
                s.offset = offset; s.len = len;
                memcpy(s.bytes, bytes, min(len, (uint32_t)SHV_SHADOW_PATCH_MAX));
                found = true; break;
            }
        }
        if (!found)
        {
            ShvShadowEntry e = {};
            e.gpa = gpa; e.offset = offset;
            e.len = min(len, (uint32_t)SHV_SHADOW_PATCH_MAX);
            memcpy(e.bytes, bytes, e.len);
            m_state.shadowPatches.push_back(e);
        }
    }
    else PostStatus(true, "ShadowPatch falhou: %s", ShvClient::StatusString(_st));
    Unlock();
    return { _ok, _st };
}

ShvBackend::CmdResult ShvBackend::Unshadow(uint64_t gpa)
{
    Lock();
    bool _ok = m_client.Unshadow(gpa);
    uint32_t _st = m_client.LastStatus();
    if (_ok)
    {
        PostStatus(false, "Shadow removido GPA 0x%llX", gpa);
        auto& p = m_state.shadowPatches;
        p.erase(std::remove_if(p.begin(), p.end(),
            [gpa](const ShvShadowEntry& s) { return s.gpa == gpa; }), p.end());
    }
    else PostStatus(true, "Unshadow falhou: %s", ShvClient::StatusString(_st));
    Unlock();
    return { _ok, _st };
}

ShvBackend::CmdResult ShvBackend::ClearEvents()
{
    Lock();
    bool _ok = m_client.ClearEvents();
    uint32_t _st = m_client.LastStatus();
    if (_ok)
    {
        m_state.events.clear();
        m_lastSeqSeen = 0;
        PostStatus(false, "Historico de eventos limpo");
    }
    else PostStatus(true, "ClearEvents falhou: %s", ShvClient::StatusString(_st));
    Unlock();
    return { _ok, _st };
}

ShvBackend::CmdResult ShvBackend::ListEptHooks()
{
    Lock();
    static SHV_EPT_HOOK_INFO buf[SHV_MAX_READ_SIZE / sizeof(SHV_EPT_HOOK_INFO)];
    uint32_t n = 0;
    bool _ok = m_client.ListEptHooks(buf, _countof(buf), &n);
    uint32_t _st = m_client.LastStatus();
    if (_ok)
    {
        m_state.eptHooks.clear();
        for (uint32_t i = 0; i < n; i++)
        {
            if (buf[i].Type & (SHV_HOOK_EXEC | SHV_HOOK_WRITE | SHV_HOOK_READ))
            {
                ShvEptHookEntry e = {};
                e.va    = buf[i].VirtAddr;
                e.pa    = buf[i].PhysAddr;
                e.type  = buf[i].Type;
                e.range = buf[i].RangeSize;
                e.pid   = buf[i].Pid;
                m_state.eptHooks.push_back(e);
            }
        }
    }
    else PostStatus(true, "ListEptHooks falhou: %s", ShvClient::StatusString(_st));
    Unlock();
    return { _ok, _st };
}

ShvBackend::CmdResult ShvBackend::BeepShadowSetup(uint64_t* outGpa)
{
    Lock();
    bool _ok = m_client.BeepShadowSetup(outGpa);
    uint32_t _st = m_client.LastStatus();
    if (_ok) PostStatus(false, "Beep shadow OK, GPA=0x%llX", outGpa ? *outGpa : 0);
    else     PostStatus(true,  "BeepShadowSetup falhou: %s", ShvClient::StatusString(_st));
    Unlock();
    return { _ok, _st };
}

// ============================================================
// Utilitario
// ============================================================

void ShvBackend::PostStatus(bool isError, const char* fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    m_statusMsg    = buf;
    m_statusIsError = isError;
}

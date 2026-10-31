/*++

Module Name:

    shv_client.cpp

Abstract:

    Implementacao da biblioteca de comunicacao com o SimpleVisor.

--*/

#include "shv_client.h"
#include <winternl.h>   // OBJECT_ATTRIBUTES, IO_STATUS_BLOCK
#include <string.h>

// ============================================================
// ShvClient -- construtor / destrutor
// ============================================================

ShvClient::ShvClient()
    : m_device(INVALID_HANDLE_VALUE)
    , m_resp{}
{
}

ShvClient::~ShvClient()
{
    Close();
}

// ============================================================
// Conexao
// ============================================================

#if SHV_COMM_MODE == SHV_COMM_BEEP_HIJACK

bool ShvClient::Open()
{
    if (m_device != INVALID_HANDLE_VALUE)
        return true;

    typedef VOID    (NTAPI* pfnRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
    typedef NTSTATUS (*pfnNtCreateFile)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
        PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto fnRtlInit     = (pfnRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
    auto fnNtCreateFile = (pfnNtCreateFile)        GetProcAddress(ntdll, "NtCreateFile");
    if (!fnRtlInit || !fnNtCreateFile)
        return false;

    UNICODE_STRING devName;
    fnRtlInit(&devName, L"\\Device\\Beep");

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &devName, 0, NULL, NULL);

    IO_STATUS_BLOCK ioStatus = {};
    NTSTATUS st = fnNtCreateFile(
        &m_device,
        FILE_ALL_ACCESS,
        &objAttr,
        &ioStatus,
        NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        0, NULL, 0);

    if (!NT_SUCCESS(st) || m_device == INVALID_HANDLE_VALUE)
    {
        m_device = INVALID_HANDLE_VALUE;
        return false;
    }
    return true;
}

#else // SHV_COMM_DEVICE

bool ShvClient::Open()
{
    if (m_device != INVALID_HANDLE_VALUE)
        return true;

    m_device = CreateFileW(SHV_DEVICE_WIN32,
                           GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    return m_device != INVALID_HANDLE_VALUE;
}

#endif // SHV_COMM_MODE

void ShvClient::Close()
{
    if (m_device != INVALID_HANDLE_VALUE)
    {
        CloseHandle(m_device);
        m_device = INVALID_HANDLE_VALUE;
    }
}

bool ShvClient::IsOpen() const
{
    return m_device != INVALID_HANDLE_VALUE;
}

// ============================================================
// Helpers privados
// ============================================================

bool ShvClient::Submit(const SHV_REQUEST& req)
{
    if (m_device == INVALID_HANDLE_VALUE)
        return false;

    m_resp = {};
    DWORD returned = 0;
    return DeviceIoControl(m_device,
                           SHV_IOCTL_SUBMIT,
                           (LPVOID)&req, sizeof(req),
                           &m_resp, sizeof(m_resp),
                           &returned, NULL) != FALSE;
}

// ============================================================
// Consultas CPUID (estaticas)
// ============================================================

bool ShvClient::IsHypervisorPresent(int* outCpu, int* outVer)
{
    int r[4];
    __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_PRESENCE);
    if (r[0] != (int)SHV_CPUID_LEAF)
        return false;
    if (outCpu) *outCpu = r[1];
    if (outVer) *outVer = r[2];
    return true;
}

uint64_t ShvClient::QueryCounter(int subLeaf)
{
    int r[4];
    __cpuidex(r, SHV_CPUID_LEAF, subLeaf);
    return ((uint64_t)(uint32_t)r[1] << 32) | (uint32_t)r[0];
}

bool ShvClient::QueryEventInfo(uint32_t* totalEvents, uint32_t* ringSize)
{
    int r[4];
    __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_EVENT_INFO);
    if (totalEvents) *totalEvents = (uint32_t)r[0];
    if (ringSize)    *ringSize    = (uint32_t)r[1];
    return true;
}

ShvEventEntry ShvClient::ReadEvent(int slot)
{
    int r[4];
    ShvEventEntry e = {};

    // Base: SeqNum, Value, Type, CPU
    __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_EVENT_BASE + slot);
    e.seqNum = (uint32_t)r[0];
    e.value  = ((uint64_t)(uint32_t)r[2] << 32) | (uint32_t)r[1];
    e.type   = (uint8_t)((r[3] >> 8) & 0xFF);
    e.cpu    = (uint8_t)(r[3] & 0xFF);

    // Extendida: ReturnAddr, Aux
    __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_EVENT_EXT_BASE + slot);
    e.returnAddr = ((uint64_t)(uint32_t)r[1] << 32) | (uint32_t)r[0];
    e.aux        = ((uint64_t)(uint32_t)r[3] << 32) | (uint32_t)r[2];

    // Extendida 2: CR3
    __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_EVENT_EXT2_BASE + slot);
    e.cr3 = ((uint64_t)(uint32_t)r[1] << 32) | (uint32_t)r[0];

    // Extendida 3: Timestamp (100ns desde 1601)
    __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_EVENT_EXT3_BASE + slot);
    e.timestamp = ((uint64_t)(uint32_t)r[1] << 32) | (uint32_t)r[0];

    // Extendida 4: GUEST_LINEAR_ADDRESS (VA do acesso que causou o fault)
    __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_EVENT_EXT4_BASE + slot);
    e.linearAddr = ((uint64_t)(uint32_t)r[1] << 32) | (uint32_t)r[0];

    // Extendidas 5-8: stack frames RSP[0..7] (pares de UINT64 por CPUID)
    __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_EVENT_EXT5_BASE + slot);
    e.stack[0] = ((uint64_t)(uint32_t)r[1] << 32) | (uint32_t)r[0];
    e.stack[1] = ((uint64_t)(uint32_t)r[3] << 32) | (uint32_t)r[2];

    __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_EVENT_EXT6_BASE + slot);
    e.stack[2] = ((uint64_t)(uint32_t)r[1] << 32) | (uint32_t)r[0];
    e.stack[3] = ((uint64_t)(uint32_t)r[3] << 32) | (uint32_t)r[2];

    __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_EVENT_EXT7_BASE + slot);
    e.stack[4] = ((uint64_t)(uint32_t)r[1] << 32) | (uint32_t)r[0];
    e.stack[5] = ((uint64_t)(uint32_t)r[3] << 32) | (uint32_t)r[2];

    __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_EVENT_EXT8_BASE + slot);
    e.stack[6] = ((uint64_t)(uint32_t)r[1] << 32) | (uint32_t)r[0];
    e.stack[7] = ((uint64_t)(uint32_t)r[3] << 32) | (uint32_t)r[2];

    return e;
}

bool ShvClient::ClearEvents()
{
    SHV_REQUEST req = {};
    req.Command = SHV_CMD_CLEAR_EVENTS;
    return Submit(req) && m_resp.Status == SHVD_STATUS_OK;
}

bool ShvClient::ListEptHooks(SHV_EPT_HOOK_INFO* out, uint32_t maxCount, uint32_t* outCount)
{
    if (!out || maxCount == 0) return false;

    SHV_REQUEST req = {};
    req.Command = SHV_CMD_LIST_EPT_HOOKS;

    if (!Submit(req) || m_resp.Status != SHVD_STATUS_OK)
        return false;

    uint32_t n = m_resp.Count;
    if (n > maxCount) n = maxCount;
    memcpy(out, m_resp.EptHookInfos, n * sizeof(SHV_EPT_HOOK_INFO));
    if (outCount) *outCount = n;
    return true;
}

// ============================================================
// Comandos IOCTL
// ============================================================

bool ShvClient::HookEpt(uint64_t va, uint8_t hookType,
                        uint64_t rangeSize, uint64_t pid)
{
    SHV_REQUEST req = {};
    req.Command           = SHV_CMD_HOOK_EPT;
    req.Hook.VirtAddr     = va;
    req.Hook.HookType     = hookType;
    req.Hook.RangeSize    = rangeSize;
    req.Hook.Pid          = pid;
    return Submit(req) && m_resp.Status == SHVD_STATUS_OK;
}

bool ShvClient::UnhookEpt(uint64_t va, uint64_t pid)
{
    SHV_REQUEST req = {};
    req.Command         = SHV_CMD_UNHOOK_EPT;
    req.Unhook.VirtAddr = va;
    req.Unhook.Pid      = pid;
    return Submit(req) && m_resp.Status == SHVD_STATUS_OK;
}

bool ShvClient::UnhookAll()
{
    SHV_REQUEST req = {};
    req.Command = SHV_CMD_UNHOOK_ALL;
    return Submit(req) && m_resp.Status == SHVD_STATUS_OK;
}

bool ShvClient::TranslateVa(uint64_t va, uint64_t pid, uint64_t* outPa)
{
    SHV_REQUEST req = {};
    req.Command              = SHV_CMD_TRANSLATE_VA;
    req.Translate.VirtAddr   = va;
    req.Translate.Pid        = pid;

    if (!Submit(req) || m_resp.Status != SHVD_STATUS_OK)
        return false;

    if (outPa) *outPa = m_resp.PhysAddr;
    return true;
}

bool ShvClient::ReadPhys(uint64_t pa, uint32_t size,
                         void* outBuf, uint32_t* outCount)
{
    if (!outBuf || size == 0 || size > SHV_MAX_READ_SIZE)
        return false;

    SHV_REQUEST req = {};
    req.Command            = SHV_CMD_READ_PHYS;
    req.ReadPhys.PhysAddr  = pa;
    req.ReadPhys.Size      = size;

    if (!Submit(req) || m_resp.Status != SHVD_STATUS_OK)
        return false;

    uint32_t bytes = m_resp.Count < size ? m_resp.Count : size;
    memcpy(outBuf, m_resp.Data, bytes);
    if (outCount) *outCount = bytes;
    return true;
}

bool ShvClient::ReadVirt(uint64_t va, uint32_t size, uint64_t pid,
                         void* outBuf, uint32_t* outCount)
{
    if (!outBuf || size == 0 || size > SHV_MAX_READ_SIZE)
        return false;

    SHV_REQUEST req = {};
    req.Command            = SHV_CMD_READ_VIRT;
    req.ReadVirt.VirtAddr  = va;
    req.ReadVirt.Size      = size;
    req.ReadVirt.Pid       = pid;

    if (!Submit(req) || m_resp.Status != SHVD_STATUS_OK)
        return false;

    uint32_t bytes = m_resp.Count < size ? m_resp.Count : size;
    memcpy(outBuf, m_resp.Data, bytes);
    if (outCount) *outCount = bytes;
    return true;
}

bool ShvClient::ListProcs(SHV_PROC_ENTRY* out, uint32_t maxCount, uint32_t* outCount)
{
    if (!out || maxCount == 0) return false;

    SHV_REQUEST req = {};
    req.Command = SHV_CMD_LIST_PROCS;

    if (!Submit(req) || m_resp.Status != SHVD_STATUS_OK)
        return false;

    uint32_t n = m_resp.Count;
    if (n > maxCount) n = maxCount;
    memcpy(out, m_resp.Procs, n * sizeof(SHV_PROC_ENTRY));
    if (outCount) *outCount = n;
    return true;
}

bool ShvClient::ListModules(SHV_MODULE_ENTRY* out, uint32_t maxCount, uint32_t* outCount)
{
    if (!out || maxCount == 0) return false;

    SHV_REQUEST req = {};
    req.Command = SHV_CMD_LIST_MODULES;

    if (!Submit(req) || m_resp.Status != SHVD_STATUS_OK)
        return false;

    uint32_t n = m_resp.Count;
    if (n > maxCount) n = maxCount;
    memcpy(out, m_resp.Modules, n * sizeof(SHV_MODULE_ENTRY));
    if (outCount) *outCount = n;
    return true;
}

bool ShvClient::ListSyscallHooks(SHV_HOOK_INFO* out, uint32_t maxCount, uint32_t* outCount)
{
    if (!out || maxCount == 0) return false;

    SHV_REQUEST req = {};
    req.Command = SHV_CMD_LIST_SYSCALL_HOOKS;

    if (!Submit(req) || m_resp.Status != SHVD_STATUS_OK)
        return false;

    uint32_t n = m_resp.Count;
    if (n > maxCount) n = maxCount;
    memcpy(out, m_resp.HookInfos, n * sizeof(SHV_HOOK_INFO));
    if (outCount) *outCount = n;
    return true;
}

bool ShvClient::ListShadowPatches(SHV_SHADOW_HOOK_INFO* out, uint32_t maxCount, uint32_t* outCount)
{
    if (!out || maxCount == 0) return false;

    SHV_REQUEST req = {};
    req.Command = SHV_CMD_LIST_SHADOW_PATCHES;

    if (!Submit(req) || m_resp.Status != SHVD_STATUS_OK)
        return false;

    uint32_t n = m_resp.Count;
    if (n > maxCount) n = maxCount;
    memcpy(out, m_resp.ShadowHookInfos, n * sizeof(SHV_SHADOW_HOOK_INFO));
    if (outCount) *outCount = n;
    return true;
}

bool ShvClient::ListFilters(SHV_PROC_FILTER_ENTRY* out, uint32_t maxCount, uint32_t* outCount)
{
    if (!out || maxCount == 0) return false;

    SHV_REQUEST req = {};
    req.Command = SHV_CMD_NTOP_LIST;

    if (!Submit(req) || m_resp.Status != SHVD_STATUS_OK)
        return false;

    uint32_t n = m_resp.Count;
    if (n > maxCount) n = maxCount;
    memcpy(out, m_resp.Filters, n * sizeof(SHV_PROC_FILTER_ENTRY));
    if (outCount) *outCount = n;
    return true;
}

bool ShvClient::Protect(uint64_t pid)
{
    SHV_REQUEST req = {};
    req.Command        = SHV_CMD_NTOP_PROTECT;
    req.ProcFilter.Pid = pid;
    return Submit(req) && m_resp.Status == SHVD_STATUS_OK;
}

bool ShvClient::Unprotect(uint64_t pid)
{
    SHV_REQUEST req = {};
    req.Command        = SHV_CMD_NTOP_UNPROTECT;
    req.ProcFilter.Pid = pid;
    return Submit(req) && m_resp.Status == SHVD_STATUS_OK;
}

bool ShvClient::Monitor(uint64_t pid)
{
    SHV_REQUEST req = {};
    req.Command        = SHV_CMD_NTOP_MONITOR;
    req.ProcFilter.Pid = pid;
    return Submit(req) && m_resp.Status == SHVD_STATUS_OK;
}

bool ShvClient::Unmonitor(uint64_t pid)
{
    SHV_REQUEST req = {};
    req.Command        = SHV_CMD_NTOP_UNMONITOR;
    req.ProcFilter.Pid = pid;
    return Submit(req) && m_resp.Status == SHVD_STATUS_OK;
}

bool ShvClient::ProtectName(const char* name)
{
    SHV_REQUEST req = {};
    req.Command = SHV_CMD_NTOP_PROTECT_NAME;
    if (name) strncpy_s(req.NameFilter.Name, sizeof(req.NameFilter.Name), name, _TRUNCATE);
    return Submit(req) && m_resp.Status == SHVD_STATUS_OK;
}

bool ShvClient::UnprotectName(const char* name)
{
    SHV_REQUEST req = {};
    req.Command = SHV_CMD_NTOP_UNPROTECT_NAME;
    if (name) strncpy_s(req.NameFilter.Name, sizeof(req.NameFilter.Name), name, _TRUNCATE);
    return Submit(req) && m_resp.Status == SHVD_STATUS_OK;
}

bool ShvClient::MonitorName(const char* name)
{
    SHV_REQUEST req = {};
    req.Command = SHV_CMD_NTOP_MONITOR_NAME;
    if (name) strncpy_s(req.NameFilter.Name, sizeof(req.NameFilter.Name), name, _TRUNCATE);
    return Submit(req) && m_resp.Status == SHVD_STATUS_OK;
}

bool ShvClient::UnmonitorName(const char* name)
{
    SHV_REQUEST req = {};
    req.Command = SHV_CMD_NTOP_UNMONITOR_NAME;
    if (name) strncpy_s(req.NameFilter.Name, sizeof(req.NameFilter.Name), name, _TRUNCATE);
    return Submit(req) && m_resp.Status == SHVD_STATUS_OK;
}

bool ShvClient::ShadowPatch(uint64_t gpa, uint32_t offset,
                            const uint8_t* bytes, uint32_t len)
{
    if (!bytes || len == 0 || len > SHV_SHADOW_PATCH_MAX)
        return false;

    SHV_REQUEST req = {};
    req.Command              = SHV_CMD_HOOK_SHADOW;
    req.Shadow.Gpa           = gpa & ~0xFFFULL;
    req.Shadow.PatchOffset   = offset;
    req.Shadow.PatchLen      = len;
    memcpy(req.Shadow.PatchBytes, bytes, len);
    return Submit(req) && m_resp.Status == SHVD_STATUS_OK;
}

bool ShvClient::Unshadow(uint64_t gpa)
{
    SHV_REQUEST req = {};
    req.Command         = SHV_CMD_UNHOOK_SHADOW;
    req.Unhook.VirtAddr = gpa & ~0xFFFULL;  // campo reutilizado como GPA
    return Submit(req) && m_resp.Status == SHVD_STATUS_OK;
}

bool ShvClient::BeepShadowSetup(uint64_t* outGpa)
{
    SHV_REQUEST req = {};
    req.Command = SHV_CMD_BEEP_SHADOW_SETUP;

    if (!Submit(req) || m_resp.Status != SHVD_STATUS_OK)
        return false;

    if (outGpa) *outGpa = m_resp.PhysAddr;
    return true;
}

// ============================================================
// Utilitario
// ============================================================

const char* ShvClient::StatusString(uint32_t status)
{
    switch (status)
    {
        case SHVD_STATUS_OK:           return "OK";
        case SHVD_STATUS_ERR_FULL:     return "ERR_FULL";
        case SHVD_STATUS_ERR_NOTFOUND: return "ERR_NOTFOUND";
        case SHVD_STATUS_ERR_NOMEM:    return "ERR_NOMEM";
        case SHVD_STATUS_ERR_INVALID:  return "ERR_INVALID";
        case SHVD_STATUS_ERR_ACCESS:   return "ERR_ACCESS";
        default:                       return "ERR_UNKNOWN";
    }
}

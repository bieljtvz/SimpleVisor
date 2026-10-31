/*++

Module Name:

    tab_procs.cpp

Abstract:

    Tab 4: Lista de processos com modulos (Toolhelp32), estado de
           protecao/monitor do hypervisor e acoes rapidas.

--*/

#include "tab_procs.h"
#include "tab_memory.h"
#include "imgui/imgui.h"
#include <tlhelp32.h>
#include <shellapi.h>
#include <dbghelp.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <string>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "dbghelp.lib")

// ── PE dump de memoria para disco ────────────────────────────────────────────
// Le headers + sections via ReadVirt e reconstroi o PE no layout de arquivo.
// Fallback para dump raw sequencial se o cabecalho nao for um PE valido.
static void DumpPeFromMemory(ShvBackend& backend,
                              uint64_t    base,
                              uint64_t    modSize,
                              uint64_t    pid,
                              const char* procName,
                              uint64_t    procPid,
                              const char* modName)
{
    // ── Diretorio de saida: <exedir>\<procname>_<pid>\ ────────────────────
    char exeDir[MAX_PATH] = "";
    GetModuleFileNameA(NULL, exeDir, sizeof(exeDir));
    char* sl = strrchr(exeDir, '\\');
    if (sl) *(sl + 1) = '\0';

    char outDir[MAX_PATH];
    snprintf(outDir, sizeof(outDir), "%s%s_%llu", exeDir, procName, procPid);
    CreateDirectoryA(outDir, nullptr);

    char fpath[MAX_PATH];
    snprintf(fpath, sizeof(fpath), "%s\\dump_%s.bin", outDir, modName);

    // ── Tenta reconstrucao PE por sections ────────────────────────────────
    static uint8_t hdrBuf[0x1000];
    uint32_t hdrGot = 0;
    {
        uint32_t toRead = (uint32_t)min(modSize, (uint64_t)sizeof(hdrBuf));
        backend.ReadVirt(base, toRead, pid, hdrBuf, &hdrGot);
    }

    bool peOk = false;
    if (hdrGot >= sizeof(IMAGE_DOS_HEADER))
    {
        auto* dos = (IMAGE_DOS_HEADER*)hdrBuf;
        DWORD ntOff = dos->e_lfanew;
        if (dos->e_magic == IMAGE_DOS_SIGNATURE &&
            ntOff + 4 + sizeof(IMAGE_FILE_HEADER) + 2 <= hdrGot)
        {
            DWORD sig = *(DWORD*)(hdrBuf + ntOff);
            if (sig == IMAGE_NT_SIGNATURE)
            {
                auto* fh   = (IMAGE_FILE_HEADER*)(hdrBuf + ntOff + 4);
                WORD  szOpt = fh->SizeOfOptionalHeader;
                WORD  nSec  = fh->NumberOfSections;
                WORD  magic = *(WORD*)(hdrBuf + ntOff + 4 + sizeof(IMAGE_FILE_HEADER));
                DWORD hdrSize = 0;

                if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    auto* opt = (IMAGE_OPTIONAL_HEADER64*)
                        (hdrBuf + ntOff + 4 + sizeof(IMAGE_FILE_HEADER));
                    hdrSize = opt->SizeOfHeaders;
                }
                else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                {
                    auto* opt = (IMAGE_OPTIONAL_HEADER32*)
                        (hdrBuf + ntOff + 4 + sizeof(IMAGE_FILE_HEADER));
                    hdrSize = opt->SizeOfHeaders;
                }

                if (hdrSize > 0 && hdrSize <= 0x4000 && nSec <= 96)
                {
                    auto* secs = (IMAGE_SECTION_HEADER*)
                        (hdrBuf + ntOff + 4 + sizeof(IMAGE_FILE_HEADER) + szOpt);

                    FILE* fp = nullptr;
                    fopen_s(&fp, fpath, "wb");
                    if (fp)
                    {
                        // Headers completos (ate hdrSize)
                        static uint8_t hdrFull[0x4000];
                        uint32_t got2 = 0;
                        uint32_t rsz  = (uint32_t)min((uint64_t)sizeof(hdrFull),
                                                      (uint64_t)hdrSize);
                        backend.ReadVirt(base, rsz, pid, hdrFull, &got2);
                        fwrite(hdrFull, 1, got2, fp);
                        for (DWORD p = got2; p < hdrSize; p++) fputc(0, fp);

                        // Cada secao no offset PointerToRawData
                        static uint8_t secChunk[SHV_MAX_READ_SIZE];
                        for (WORD si = 0; si < nSec; si++)
                        {
                            DWORD va     = secs[si].VirtualAddress;
                            DWORD vsz    = secs[si].Misc.VirtualSize;
                            DWORD rawOff = secs[si].PointerToRawData;
                            if (va == 0 || vsz == 0 || rawOff == 0) continue;

                            _fseeki64(fp, rawOff, SEEK_SET);
                            uint64_t off = 0;
                            while (off < vsz)
                            {
                                uint32_t chunk = (uint32_t)min(
                                    (uint64_t)vsz - off,
                                    (uint64_t)SHV_MAX_READ_SIZE);
                                uint32_t got3 = 0;
                                backend.ReadVirt(base + va + off, chunk,
                                                 pid, secChunk, &got3);
                                if (got3 > 0)
                                {
                                    fwrite(secChunk, 1, got3, fp);
                                    off += got3;
                                }
                                else
                                {
                                    // secao inacessivel: preenche zeros
                                    memset(secChunk, 0, chunk);
                                    fwrite(secChunk, 1, chunk, fp);
                                    off += chunk;
                                }
                            }
                        }
                        fclose(fp);
                        peOk = true;
                    }
                }
            }
        }
    }

    if (!peOk)
    {
        // Fallback: dump raw sequencial
        FILE* fp = nullptr;
        fopen_s(&fp, fpath, "wb");
        if (fp)
        {
            static uint8_t rawChunk[SHV_MAX_READ_SIZE];
            uint64_t total = min(modSize, 64ull << 20);
            uint64_t off   = 0;
            while (off < total)
            {
                uint32_t sz  = (uint32_t)min(total - off, (uint64_t)SHV_MAX_READ_SIZE);
                uint32_t got = 0;
                backend.ReadVirt(base + off, sz, pid, rawChunk, &got);
                if (got == 0) break;
                fwrite(rawChunk, 1, got, fp);
                off += got;
            }
            fclose(fp);
        }
    }
}

// ── Thread fetch ─────────────────────────────────────────────────────────────
typedef NTSTATUS(WINAPI* PNtQIT)(HANDLE, ULONG, PVOID, ULONG, PULONG);

struct ThreadInfo {
    uint64_t tid;
    uint64_t startAddr;
};

static std::vector<ThreadInfo> FetchThreads(DWORD pid)
{
    static PNtQIT NtQIT = (PNtQIT)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");

    std::vector<ThreadInfo> result;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return result;

    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(snap, &te))
    {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            ThreadInfo t = {};
            t.tid = te.th32ThreadID;
            if (NtQIT)
            {
                HANDLE h = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (h)
                {
                    ULONG64 sa = 0;
                    NtQIT(h, 9, &sa, sizeof(sa), nullptr); // ThreadQuerySetWin32StartAddress
                    t.startAddr = (uint64_t)sa;
                    CloseHandle(h);
                }
            }
            result.push_back(t);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return result;
}

// ── Stack walk ───────────────────────────────────────────────────────────────
struct StackFrame {
    uint64_t rip;
    uint64_t rsp;
    char     symbol[256];
};

static std::vector<StackFrame> WalkThreadStack(DWORD pid, DWORD tid)
{
    std::vector<StackFrame> frames;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                FALSE, pid);
    if (!hProc) return frames;

    HANDLE hThread = OpenThread(
        THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
        FALSE, tid);
    if (!hThread) { CloseHandle(hProc); return frames; }

    SuspendThread(hThread);
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    bool ctxOk = GetThreadContext(hThread, &ctx) != 0;
    ResumeThread(hThread);

    if (!ctxOk) { CloseHandle(hThread); CloseHandle(hProc); return frames; }

    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    SymInitialize(hProc, nullptr, TRUE);

    STACKFRAME64 sf   = {};
    sf.AddrPC.Offset    = ctx.Rip;
    sf.AddrPC.Mode      = AddrModeFlat;
    sf.AddrFrame.Offset = ctx.Rbp;
    sf.AddrFrame.Mode   = AddrModeFlat;
    sf.AddrStack.Offset = ctx.Rsp;
    sf.AddrStack.Mode   = AddrModeFlat;

    CONTEXT ctxCopy = ctx;
    for (int i = 0; i < 128; i++)
    {
        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProc, hThread,
                         &sf, &ctxCopy, nullptr,
                         SymFunctionTableAccess64, SymGetModuleBase64, nullptr))
            break;
        if (sf.AddrPC.Offset == 0) break;

        StackFrame f = {};
        f.rip = sf.AddrPC.Offset;
        f.rsp = sf.AddrStack.Offset;

        char symBuf[sizeof(SYMBOL_INFO) + 512] = {};
        SYMBOL_INFO* sym = (SYMBOL_INFO*)symBuf;
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen   = 512;
        DWORD64 disp = 0;

        if (SymFromAddr(hProc, f.rip, &disp, sym) && sym->Name[0])
        {
            if (disp)
                snprintf(f.symbol, sizeof(f.symbol), "%s+0x%llX", sym->Name, (unsigned long long)disp);
            else
                snprintf(f.symbol, sizeof(f.symbol), "%s", sym->Name);
        }
        else
        {
            IMAGEHLP_MODULE64 mod = {};
            mod.SizeOfStruct = sizeof(mod);
            if (SymGetModuleInfo64(hProc, f.rip, &mod))
                snprintf(f.symbol, sizeof(f.symbol), "%s+0x%llX",
                         mod.ModuleName[0] ? mod.ModuleName : "?",
                         (unsigned long long)(f.rip - mod.BaseOfImage));
            else
                snprintf(f.symbol, sizeof(f.symbol), "0x%016llX", (unsigned long long)f.rip);
        }

        frames.push_back(f);
    }

    SymCleanup(hProc);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return frames;
}

// ── Memory region fetch ───────────────────────────────────────────────────────
struct ModuleInfo {
    uint64_t base;
    uint64_t size;
    char     name[128];
    char     path[MAX_PATH];
};

struct MemRegion {
    uint64_t base;
    uint64_t size;
    DWORD    protect;
    DWORD    state;
    DWORD    type;
    char     module[64];
};

static const char* ProtectStr(DWORD prot)
{
    switch (prot & 0xFF)
    {
    case PAGE_NOACCESS:           return "---";
    case PAGE_READONLY:           return "R--";
    case PAGE_READWRITE:          return "RW-";
    case PAGE_WRITECOPY:          return "RC-";
    case PAGE_EXECUTE:            return "--X";
    case PAGE_EXECUTE_READ:       return "R-X";
    case PAGE_EXECUTE_READWRITE:  return "RWX";
    case PAGE_EXECUTE_WRITECOPY:  return "RCX";
    default:                      return "   ";
    }
}

static const char* StateStr(DWORD state)
{
    switch (state)
    {
    case MEM_COMMIT:  return "Commit";
    case MEM_RESERVE: return "Reserve";
    case MEM_FREE:    return "Free";
    default:          return "?";
    }
}

static const char* TypeStr(DWORD type)
{
    switch (type)
    {
    case MEM_IMAGE:   return "Image";
    case MEM_MAPPED:  return "Mapped";
    case MEM_PRIVATE: return "Private";
    default:          return "---";
    }
}

static std::vector<MemRegion> FetchMemRegions(DWORD pid,
                                               const std::vector<ModuleInfo>& mods)
{
    std::vector<MemRegion> result;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return result;

    MEMORY_BASIC_INFORMATION mbi = {};
    uintptr_t addr = 0;
    while (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        MemRegion r = {};
        r.base    = (uint64_t)(uintptr_t)mbi.BaseAddress;
        r.size    = (uint64_t)mbi.RegionSize;
        r.protect = mbi.Protect ? mbi.Protect : mbi.AllocationProtect;
        r.state   = mbi.State;
        r.type    = mbi.Type;
        for (const auto& m : mods)
        {
            if (r.base >= m.base && r.base < m.base + m.size)
            {
                snprintf(r.module, sizeof(r.module), "%s", m.name);
                break;
            }
        }
        result.push_back(r);
        uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }
    CloseHandle(hProc);
    return result;
}

static const ImVec4 kColorOk      = { 0.20f, 0.90f, 0.40f, 1.0f };
static const ImVec4 kColorWarn    = { 1.00f, 0.75f, 0.00f, 1.0f };
static const ImVec4 kColorErr     = { 1.00f, 0.30f, 0.20f, 1.0f };
static const ImVec4 kColorDim     = { 0.55f, 0.55f, 0.55f, 1.0f };
static const ImVec4 kColorProtect = { 1.00f, 0.60f, 0.00f, 1.0f };
static const ImVec4 kColorMonitor = { 0.40f, 0.90f, 1.00f, 1.0f };

// Usa CreateToolhelp32Snapshot para listar modulos de um PID usermode
static std::vector<ModuleInfo> FetchModules(DWORD pid)
{
    std::vector<ModuleInfo> result;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return result;

    MODULEENTRY32W me = {};
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me))
    {
        do {
            ModuleInfo m = {};
            m.base = (uint64_t)(uintptr_t)me.modBaseAddr;
            m.size = (uint64_t)me.modBaseSize;
            WideCharToMultiByte(CP_UTF8, 0, me.szModule,  -1, m.name, (int)sizeof(m.name), nullptr, nullptr);
            WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, m.path, (int)sizeof(m.path), nullptr, nullptr);
            result.push_back(m);
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return result;
}

void RenderTabProcs(ShvBackend& backend)
{
    static char                  s_search[64]   = "";
    static int                   s_selIdx        = -1;
    static uint64_t              s_selPid        = 0;
    static char                  s_selName[128] = "";
    static std::vector<ModuleInfo>  s_modules;
    static std::vector<ThreadInfo>  s_threads;
    static uint64_t                 s_ctxTid      = 0;
    static std::vector<MemRegion>   s_memRegions;
    static bool                     s_memLoaded   = false;
    static bool                     s_showFree    = false;
    static char                     s_pidInput[16] = "";
    static std::vector<StackFrame>  s_stackFrames;
    static bool                     s_stackPopupPending   = false;
    static bool                     s_terminatePending    = false;
    static bool                     s_eptHookPending      = false;
    static uint64_t                 s_eptHookBase         = 0;
    static uint64_t                 s_eptHookSize         = 0;

    // ── Barra superior ────────────────────────────────────────────────────────
    if (ImGui::Button("Atualizar"))
    {
        backend.RefreshAll();
        s_selIdx = -1;
        s_modules.clear();
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200);
    ImGui::InputText("Buscar##pr", s_search, sizeof(s_search));
    ImGui::SameLine(0, 30);
    ImGui::TextDisabled("Selecione um processo para ver modulos / acoes");

    ImGui::Spacing();

    // ── Layout dividido: lista de processos | painel direito ─────────────────
    float listWidth = 460.0f;
    ImGui::BeginChild("proc_list", ImVec2(listWidth, 0), true);

    backend.Lock();
    const auto& procs   = backend.State().procs;
    const auto& filters = backend.State().filters;

    if (ImGui::BeginTable("procs_tbl", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("PID",     ImGuiTableColumnFlags_WidthFixed, 55.0f);
        ImGui::TableSetupColumn("DirBase", ImGuiTableColumnFlags_WidthFixed, 135.0f);
        ImGui::TableSetupColumn("Flags",   ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Nome",    ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (int i = 0; i < (int)procs.size(); i++)
        {
            const auto& p = procs[i];

            // Filtro de busca
            if (s_search[0] && !strstr(p.Name, s_search)) continue;

            // Verifica flags de protecao/monitor
            bool isProtected = false, isMonitored = false;
            for (const auto& f : filters)
            {
                if (f.Pid == p.Pid)
                {
                    if (f.Type == SHV_FILTER_TYPE_PROTECT) isProtected = true;
                    if (f.Type == SHV_FILTER_TYPE_MONITOR) isMonitored = true;
                }
            }

            ImGui::TableNextRow();
            bool selected = (s_selIdx == i);
            ImGui::TableNextColumn();
            ImGui::PushID(i);
            if (ImGui::Selectable("", selected,
                    ImGuiSelectableFlags_SpanAllColumns |
                    ImGuiSelectableFlags_AllowItemOverlap,
                    ImVec2(0, 0)))
            {
                if (s_selIdx != i)
                {
                    s_selIdx     = i;
                    s_selPid     = p.Pid;
                    strncpy_s(s_selName, p.Name, _TRUNCATE);
                    s_modules    = FetchModules((DWORD)p.Pid);
                    s_threads    = FetchThreads((DWORD)p.Pid);
                    s_memRegions.clear();
                    s_memLoaded  = false;
                    snprintf(s_pidInput, sizeof(s_pidInput), "%llu", p.Pid);
                }
            }
            ImGui::PopID();
            ImGui::SameLine(0, 0);
            ImGui::Text("%llu", p.Pid);

            ImGui::TableNextColumn();
            ImGui::Text("0x%016llX", p.DirBase);

            ImGui::TableNextColumn();
            if (isProtected)
            {
                ImGui::PushStyleColor(ImGuiCol_Text, kColorProtect);
                ImGui::TextUnformatted("P");
                ImGui::PopStyleColor();
                if (isMonitored) ImGui::SameLine(0, 2);
            }
            if (isMonitored)
            {
                ImGui::PushStyleColor(ImGuiCol_Text, kColorMonitor);
                ImGui::TextUnformatted("M");
                ImGui::PopStyleColor();
            }

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(p.Name);
        }
        ImGui::EndTable();
    }
    backend.Unlock();
    ImGui::EndChild();

    ImGui::SameLine();

    // ── Painel direito ────────────────────────────────────────────────────────
    ImGui::BeginChild("proc_detail", ImVec2(0, 0), true);

    if (s_selIdx >= 0)
    {
        backend.Lock();
        bool valid = (s_selIdx < (int)backend.State().procs.size());
        bool isProtected = false, isMonitored = false;
        if (valid)
        {
            const auto& p = backend.State().procs[s_selIdx];
            ImGui::Text("Processo: %s  (PID %llu)", p.Name, p.Pid);
            ImGui::Text("DirBase: 0x%016llX", p.DirBase);
            for (const auto& f : backend.State().filters)
            {
                bool match = f.ByName ? (_stricmp(f.Name, p.Name) == 0)
                                      : (f.Pid == p.Pid);
                if (match)
                {
                    if (f.Type == SHV_FILTER_TYPE_PROTECT) isProtected = true;
                    if (f.Type == SHV_FILTER_TYPE_MONITOR) isMonitored = true;
                }
            }
        }
        backend.Unlock();

        ImGui::Separator();

        ImGui::SetNextItemWidth(100);
        ImGui::InputText("PID##act", s_pidInput, sizeof(s_pidInput));
        uint64_t actPid = strtoull(s_pidInput, nullptr, 10);

        ImGui::Spacing();

        bool chkProt = isProtected;
        ImGui::PushID("chkProt");
        ImGui::PushStyleColor(ImGuiCol_CheckMark, kColorProtect);
        if (ImGui::Checkbox("Protegido", &chkProt))
        {
            if (chkProt) backend.Protect(actPid);
            else         backend.Unprotect(actPid);
        }
        ImGui::PopStyleColor();
        ImGui::PopID();

        ImGui::SameLine(0, 24);

        bool chkMon = isMonitored;
        ImGui::PushID("chkMon");
        ImGui::PushStyleColor(ImGuiCol_CheckMark, kColorMonitor);
        if (ImGui::Checkbox("Monitorado", &chkMon))
        {
            if (chkMon) backend.Monitor(actPid);
            else        backend.Unmonitor(actPid);
        }
        ImGui::PopStyleColor();
        ImGui::PopID();

        ImGui::SameLine(0, 40);

        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.65f, 0.10f, 0.10f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.80f, 0.15f, 0.15f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.50f, 0.05f, 0.05f, 1.0f));
        if (ImGui::Button("Terminar Processo"))
            s_terminatePending = true;
        ImGui::PopStyleColor(3);

        ImGui::Spacing();
        ImGui::Separator();

        if (ImGui::BeginTabBar("proc_tabs"))
        {
            // ── Modules ──────────────────────────────────────────────────────
            if (ImGui::BeginTabItem("Modules"))
            {
                if (ImGui::Button("Recarregar"))
                    s_modules = FetchModules((DWORD)s_selPid);
                ImGui::SameLine();
                ImGui::TextDisabled("(%zu)", s_modules.size());
                ImGui::Spacing();

                if (!s_modules.empty() &&
                    ImGui::BeginTable("mod_tbl", 3,
                        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                        ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit,
                        ImVec2(0, 0)))
                {
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableSetupColumn("Base",    ImGuiTableColumnFlags_WidthFixed,  145.0f);
                    ImGui::TableSetupColumn("Tamanho", ImGuiTableColumnFlags_WidthFixed,   90.0f);
                    ImGui::TableSetupColumn("Nome",    ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();

                    for (int mi = 0; mi < (int)s_modules.size(); mi++)
                    {
                        const ModuleInfo& m = s_modules[mi];
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        ImGui::PushID(mi);
                        ImGui::Selectable("", false,
                            ImGuiSelectableFlags_SpanAllColumns |
                            ImGuiSelectableFlags_AllowItemOverlap,
                            ImVec2(0, 0));
                        if (ImGui::IsItemHovered())
                            ImGui::SetTooltip("%s\n(clique direito para acoes)", m.path);
                        if (ImGui::BeginPopupContextItem("mod_ctx"))
                        {
                            if (ImGui::MenuItem("Copy Info"))
                            {
                                char cb[640];
                                snprintf(cb, sizeof(cb),
                                    "Nome: %s\nBase: 0x%016llX\nTamanho: 0x%llX (%llu KB)\nPath: %s",
                                    m.name, m.base, m.size, m.size / 1024, m.path);
                                ImGui::SetClipboardText(cb);
                            }
                            if (ImGui::MenuItem("Dump"))
                                DumpPeFromMemory(backend, m.base, m.size,
                                                 s_selPid, s_selName, s_selPid, m.name);
                            if (ImGui::MenuItem("Explorer File") && m.path[0])
                            {
                                char arg[MAX_PATH + 12];
                                snprintf(arg, sizeof(arg), "/select,\"%s\"", m.path);
                                ShellExecuteA(nullptr, "open", "explorer.exe",
                                    arg, nullptr, SW_SHOW);
                            }
                            if (ImGui::MenuItem("View Memory"))
                                TabMemoryNavigateTo(m.base, s_selPid);
                            ImGui::EndPopup();
                        }
                        ImGui::PopID();
                        ImGui::SameLine(0, 0);
                        ImGui::Text("0x%016llX", m.base);
                        ImGui::TableNextColumn();
                        ImGui::Text("0x%08llX", m.size);
                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted(m.name);
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            // ── Threads ───────────────────────────────────────────────────────
            if (ImGui::BeginTabItem("Threads"))
            {
                if (ImGui::Button("Recarregar"))
                    s_threads = FetchThreads((DWORD)s_selPid);
                ImGui::SameLine();
                ImGui::TextDisabled("(%zu)", s_threads.size());
                ImGui::Spacing();

                if (!s_threads.empty() &&
                    ImGui::BeginTable("thr_tbl", 3,
                        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                        ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit,
                        ImVec2(0, 0)))
                {
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableSetupColumn("TID",          ImGuiTableColumnFlags_WidthFixed,  72.0f);
                    ImGui::TableSetupColumn("Start Addr",   ImGuiTableColumnFlags_WidthFixed, 145.0f);
                    ImGui::TableSetupColumn("ThreadObject", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();

                    for (int ti = 0; ti < (int)s_threads.size(); ti++)
                    {
                        const ThreadInfo& t = s_threads[ti];
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        ImGui::PushID(ti);
                        ImGui::Selectable("", false,
                            ImGuiSelectableFlags_SpanAllColumns |
                            ImGuiSelectableFlags_AllowItemOverlap,
                            ImVec2(0, 0));
                        if (ImGui::IsItemClicked(ImGuiMouseButton_Right))
                            s_ctxTid = t.tid;
                        if (ImGui::BeginPopupContextItem("thr_ctx"))
                        {
                            if (ImGui::MenuItem("Suspend"))
                            {
                                HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, (DWORD)s_ctxTid);
                                if (h) { SuspendThread(h); CloseHandle(h); }
                            }
                            if (ImGui::MenuItem("Resume"))
                            {
                                HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, (DWORD)s_ctxTid);
                                if (h) { ResumeThread(h); CloseHandle(h); }
                            }
                            ImGui::Separator();
                            if (ImGui::MenuItem("Terminate"))
                            {
                                HANDLE h = OpenThread(THREAD_TERMINATE, FALSE, (DWORD)s_ctxTid);
                                if (h) { TerminateThread(h, 0); CloseHandle(h); }
                            }
                            ImGui::Separator();
                            if (ImGui::MenuItem("View Stack"))
                            {
                                s_stackFrames       = WalkThreadStack((DWORD)s_selPid, (DWORD)s_ctxTid);
                                s_stackPopupPending = true;
                            }
                            ImGui::EndPopup();
                        }
                        ImGui::PopID();
                        ImGui::SameLine(0, 0);
                        ImGui::Text("%llu", t.tid);
                        ImGui::TableNextColumn();
                        if (t.startAddr)
                            ImGui::Text("0x%016llX", t.startAddr);
                        else
                            ImGui::TextDisabled("---");
                        ImGui::TableNextColumn();
                        ImGui::TextDisabled("--- (futura impl.)");
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            // ── Memory ────────────────────────────────────────────────────────
            if (ImGui::BeginTabItem("Memory"))
            {
                if (ImGui::Button("Carregar"))
                {
                    s_memRegions = FetchMemRegions((DWORD)s_selPid, s_modules);
                    s_memLoaded  = true;
                }
                ImGui::SameLine();
                ImGui::TextDisabled("(%zu regioes)", s_memRegions.size());
                ImGui::SameLine(0, 16);
                ImGui::Checkbox("Mostrar livre", &s_showFree);
                ImGui::Spacing();

                if (s_memLoaded &&
                    ImGui::BeginTable("memr_tbl", 6,
                        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                        ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit,
                        ImVec2(0, 0)))
                {
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableSetupColumn("Endereco", ImGuiTableColumnFlags_WidthFixed, 145.0f);
                    ImGui::TableSetupColumn("Tamanho",  ImGuiTableColumnFlags_WidthFixed,  80.0f);
                    ImGui::TableSetupColumn("Prot",     ImGuiTableColumnFlags_WidthFixed,  38.0f);
                    ImGui::TableSetupColumn("State",    ImGuiTableColumnFlags_WidthFixed,  58.0f);
                    ImGui::TableSetupColumn("Tipo",     ImGuiTableColumnFlags_WidthFixed,  54.0f);
                    ImGui::TableSetupColumn("Modulo",   ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();

                    for (int ri = 0; ri < (int)s_memRegions.size(); ri++)
                    {
                        const MemRegion& r = s_memRegions[ri];
                        if (!s_showFree && r.state == MEM_FREE) continue;

                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        ImGui::PushID(ri);
                        ImGui::Selectable("", false,
                            ImGuiSelectableFlags_SpanAllColumns |
                            ImGuiSelectableFlags_AllowItemOverlap,
                            ImVec2(0, 0));
                        if (r.state != MEM_FREE && ImGui::BeginPopupContextItem("memr_ctx"))
                        {
                            if (ImGui::MenuItem("View Memory"))
                                TabMemoryNavigateTo(r.base, s_selPid);
                            ImGui::Separator();
                            // EPT hook exige pagina fisica presente; apenas MEM_COMMIT garante isso
                            if (r.state == MEM_COMMIT && ImGui::MenuItem("Adicionar EPT Hook"))
                            {
                                s_eptHookBase    = r.base;
                                s_eptHookSize    = r.size;
                                s_eptHookPending = true;
                            }
                            if (r.state != MEM_COMMIT)
                            {
                                ImGui::BeginDisabled();
                                ImGui::MenuItem("Adicionar EPT Hook (Reserve - sem PA)");
                                ImGui::EndDisabled();
                            }
                            ImGui::EndPopup();
                        }
                        ImGui::PopID();
                        ImGui::SameLine(0, 0);

                        bool isExec = (r.protect & 0xF0) != 0;
                        ImVec4 addrCol = (r.state == MEM_FREE) ? kColorDim
                                       : isExec                ? kColorWarn
                                       : ImGui::GetStyleColorVec4(ImGuiCol_Text);
                        ImGui::PushStyleColor(ImGuiCol_Text, addrCol);
                        ImGui::Text("0x%016llX", r.base);
                        ImGui::PopStyleColor();

                        ImGui::TableNextColumn();
                        if (r.size >= 1024 * 1024)
                            ImGui::Text("%.1f MB", r.size / (1024.0 * 1024.0));
                        else if (r.size >= 1024)
                            ImGui::Text("%.0f KB", r.size / 1024.0);
                        else
                            ImGui::Text("%llu B", r.size);

                        ImGui::TableNextColumn();
                        if (r.state != MEM_FREE)
                        {
                            if (isExec) ImGui::PushStyleColor(ImGuiCol_Text, kColorWarn);
                            ImGui::TextUnformatted(ProtectStr(r.protect));
                            if (isExec) ImGui::PopStyleColor();
                        }

                        ImGui::TableNextColumn();
                        if (r.state == MEM_FREE)
                        {
                            ImGui::PushStyleColor(ImGuiCol_Text, kColorDim);
                            ImGui::TextUnformatted("Free");
                            ImGui::PopStyleColor();
                        }
                        else
                            ImGui::TextUnformatted(StateStr(r.state));

                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted(TypeStr(r.type));

                        ImGui::TableNextColumn();
                        if (r.module[0]) ImGui::TextUnformatted(r.module);
                    }
                    ImGui::EndTable();
                }
                else if (!s_memLoaded)
                {
                    ImGui::Spacing();
                    ImGui::PushStyleColor(ImGuiCol_Text, kColorDim);
                    ImGui::TextUnformatted("  Clique em Carregar para listar as regioes.");
                    ImGui::PopStyleColor();
                }
                ImGui::EndTabItem();
            }

            ImGui::EndTabBar();
        }
    }
    else
    {
        ImGui::PushStyleColor(ImGuiCol_Text, kColorDim);
        ImGui::TextUnformatted("\n  Selecione um processo na lista.");
        ImGui::PopStyleColor();
    }

    // ── Stack popup ───────────────────────────────────────────────────────────
    if (s_stackPopupPending)
    {
        ImGui::OpenPopup("Stack##swpopup");
        s_stackPopupPending = false;
    }
    ImGui::SetNextWindowSize(ImVec2(820, 460), ImGuiCond_Appearing);
    if (ImGui::BeginPopupModal("Stack##swpopup", nullptr,
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize))
    {
        static uint64_t s_swCtxRip = 0;

        ImGui::TextDisabled("TID %llu  —  %zu frames", s_ctxTid, s_stackFrames.size());
        ImGui::SameLine(0, 20);
        if (ImGui::SmallButton("Fechar")) ImGui::CloseCurrentPopup();
        ImGui::Separator();

        if (ImGui::BeginTable("sw_tbl", 4,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit,
                ImVec2(0, 0)))
        {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("#",              ImGuiTableColumnFlags_WidthFixed,  30.0f);
            ImGui::TableSetupColumn("RIP",            ImGuiTableColumnFlags_WidthFixed, 145.0f);
            ImGui::TableSetupColumn("RSP",            ImGuiTableColumnFlags_WidthFixed, 145.0f);
            ImGui::TableSetupColumn("Simbolo / Modulo+Offset", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            for (int fi = 0; fi < (int)s_stackFrames.size(); fi++)
            {
                const StackFrame& f = s_stackFrames[fi];
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(fi);
                ImGui::Selectable("", false,
                    ImGuiSelectableFlags_SpanAllColumns |
                    ImGuiSelectableFlags_AllowItemOverlap,
                    ImVec2(0, 0));
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right))
                    s_swCtxRip = f.rip;
                if (ImGui::BeginPopupContextItem("sw_ctx"))
                {
                    if (ImGui::MenuItem("View Memory (RIP)"))
                    {
                        TabMemoryNavigateTo(s_swCtxRip, s_selPid);
                        ImGui::CloseCurrentPopup();
                    }
                    if (ImGui::MenuItem("View Memory (RSP)"))
                    {
                        TabMemoryNavigateTo(f.rsp, s_selPid);
                        ImGui::CloseCurrentPopup();
                    }
                    ImGui::EndPopup();
                }
                ImGui::PopID();
                ImGui::SameLine(0, 0);
                ImGui::Text("%d", fi);

                ImGui::TableNextColumn();
                ImGui::Text("0x%016llX", (unsigned long long)f.rip);

                ImGui::TableNextColumn();
                if (f.rsp)
                    ImGui::Text("0x%016llX", (unsigned long long)f.rsp);
                else
                    ImGui::TextDisabled("---");

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(f.symbol);
            }

            if (s_stackFrames.empty())
            {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TableSetColumnIndex(0);
                ImGui::PushStyleColor(ImGuiCol_Text, kColorDim);
                ImGui::TextUnformatted("Sem frames — thread pode estar em kernel mode ou sem permissao.");
                ImGui::PopStyleColor();
            }

            ImGui::EndTable();
        }
        ImGui::EndPopup();
    }

    // ── Modal: confirmacao de Terminar Processo ───────────────────────────────
    if (s_terminatePending)
    {
        ImGui::OpenPopup("Terminar##killpopup");
        s_terminatePending = false;
    }
    ImGui::SetNextWindowSize(ImVec2(420, 130), ImGuiCond_Appearing);
    if (ImGui::BeginPopupModal("Terminar##killpopup", nullptr,
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize))
    {
        ImGui::Spacing();
        ImGui::PushStyleColor(ImGuiCol_Text, kColorErr);
        ImGui::Text("Terminar  %s  (PID %llu)?", s_selName, s_selPid);
        ImGui::PopStyleColor();
        ImGui::TextDisabled("Esta acao nao pode ser desfeita.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.65f, 0.10f, 0.10f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.80f, 0.15f, 0.15f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.50f, 0.05f, 0.05f, 1.0f));
        if (ImGui::Button("Confirmar", ImVec2(120, 0)))
        {
            HANDLE hKill = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)s_selPid);
            if (hKill)
            {
                TerminateProcess(hKill, 1);
                CloseHandle(hKill);
            }
            backend.RefreshAll();
            s_selIdx  = -1;
            s_modules.clear();
            s_threads.clear();
            s_memRegions.clear();
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopStyleColor(3);

        ImGui::SameLine(0, 16);
        if (ImGui::Button("Cancelar", ImVec2(90, 0)))
            ImGui::CloseCurrentPopup();

        ImGui::EndPopup();
    }

    // ── Modal: instalar EPT hook em regiao de memoria ─────────────────────────
    if (s_eptHookPending)
    {
        ImGui::OpenPopup("EPT Hook##eptpopup");
        s_eptHookPending = false;
    }
    ImGui::SetNextWindowSize(ImVec2(400, 210), ImGuiCond_Appearing);
    if (ImGui::BeginPopupModal("EPT Hook##eptpopup", nullptr,
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize))
    {
        static bool s_eptExec  = true;
        static bool s_eptWrite = false;
        static bool s_eptRead  = false;

        ImGui::Spacing();
        ImGui::TextDisabled("Endereco:"); ImGui::SameLine();
        ImGui::Text("0x%016llX", (unsigned long long)s_eptHookBase);
        ImGui::TextDisabled("Tamanho: "); ImGui::SameLine();
        if (s_eptHookSize >= 1024 * 1024)
            ImGui::Text("%.1f MB  (%llu bytes)", s_eptHookSize / (1024.0 * 1024.0), (unsigned long long)s_eptHookSize);
        else if (s_eptHookSize >= 1024)
            ImGui::Text("%.0f KB  (%llu bytes)", s_eptHookSize / 1024.0, (unsigned long long)s_eptHookSize);
        else
            ImGui::Text("%llu bytes", (unsigned long long)s_eptHookSize);
        ImGui::TextDisabled("PID:      "); ImGui::SameLine();
        ImGui::Text("%llu  (%s)", (unsigned long long)s_selPid, s_selName);

        ImGui::Spacing();
        ImGui::Text("Permissoes a monitorar:");
        ImGui::SameLine(0, 12);
        ImGui::PushStyleColor(ImGuiCol_CheckMark, kColorWarn);
        ImGui::Checkbox("Exec##ept",  &s_eptExec);
        ImGui::PopStyleColor();
        ImGui::SameLine(0, 16);
        ImGui::Checkbox("Write##ept", &s_eptWrite);
        ImGui::SameLine(0, 16);
        ImGui::Checkbox("Read##ept",  &s_eptRead);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        bool anySelected = s_eptExec || s_eptWrite || s_eptRead;
        if (!anySelected)
        {
            ImGui::PushStyleColor(ImGuiCol_Text, kColorErr);
            ImGui::TextUnformatted("  Selecione ao menos uma permissao.");
            ImGui::PopStyleColor();
        }
        else
        {
            if (ImGui::Button("Instalar##ept", ImVec2(100, 0)))
            {
                uint8_t hookType = (s_eptExec  ? SHV_HOOK_EXEC  : 0)
                                 | (s_eptWrite ? SHV_HOOK_WRITE : 0)
                                 | (s_eptRead  ? SHV_HOOK_READ  : 0);
                auto res = backend.HookEpt(s_eptHookBase, hookType, s_eptHookSize, s_selPid);
                if (res.ok) backend.RefreshAll();  // atualiza procs/modules imediatamente
                ImGui::CloseCurrentPopup();
            }
            ImGui::SameLine(0, 16);
        }
        if (ImGui::Button("Cancelar##ept", ImVec2(90, 0)))
            ImGui::CloseCurrentPopup();

        ImGui::EndPopup();
    }

    ImGui::EndChild();
}

/*++

Module Name:

    tab_events.cpp

Abstract:

    Tab 2: Monitor de eventos do ring buffer, dividido em sub-abas:
      LSTAR    -- eventos MSR LSTAR (futura implementacao)
      EPT      -- eventos de hook EPT (exec/write/read)
      Syscalls -- monitoramento de syscalls (futura implementacao)
      Others   -- outros eventos (futura implementacao)

--*/

#include "tab_events.h"
#include "shv_config.h"
#include "imgui/imgui.h"
#include <stdio.h>
#include <vector>
#include <unordered_map>
#include <tlhelp32.h>

// ── Metadados de tipo de evento ──────────────────────────────────────────────

static const ImVec4 kEvColors[] = {
    { 0.55f, 0.55f, 0.55f, 1.0f },  // 0 = desconhecido
    { 0.40f, 0.80f, 1.00f, 1.0f },  // 1 = LSTAR_READ   azul
    { 0.90f, 0.70f, 0.00f, 1.0f },  // 2 = LSTAR_WRITE  amarelo
    { 0.20f, 0.90f, 0.40f, 1.0f },  // 3 = EPT_EXEC     verde
    { 1.00f, 0.50f, 0.10f, 1.0f },  // 4 = EPT_WRITE    laranja
    { 1.00f, 0.25f, 0.20f, 1.0f },  // 5 = EPT_READ     vermelho
};

static const char* kEvNames[] = {
    "???", "LSTAR_READ", "LSTAR_WRITE", "EPT_EXEC", "EPT_WRITE", "EPT_READ"
};

static inline ImVec4 EventColor(uint8_t type)
{
    return (type < 6) ? kEvColors[type] : kEvColors[0];
}

static inline const char* EventName(uint8_t type)
{
    return (type < 6) ? kEvNames[type] : "???";
}

// ── Helpers ──────────────────────────────────────────────────────────────────

static const char* ProcNameByCr3(const std::vector<SHV_PROC_ENTRY>& procs, uint64_t cr3)
{
    if (cr3 == 0) return nullptr;
    for (const auto& p : procs)
        if (p.DirBase == cr3) return p.Name;
    return nullptr;
}

static const char* ModuleBaseName(const char* name)
{
    const char* last = name;
    for (const char* p = name; *p; p++)
        if (*p == '\\' || *p == '/') last = p + 1;
    return last;
}

static const char* ModuleNameByVa(const std::vector<SHV_MODULE_ENTRY>& mods, uint64_t va)
{
    if (va == 0) return nullptr;
    for (const auto& m : mods)
        if (va >= m.Base && va < m.Base + m.Size) return ModuleBaseName(m.Name);
    return nullptr;
}

static const char* kEptColNames[] = {
    "Hora", "Seq", "CPU", "Tipo", "Causador", "Destino",
    "RIP/Value", "RetAddr", "Aux/GPA", "VA Fault", "CR3"
};

// Evento selecionado na tabela (para exibir stack trace).
// Compartilhado entre RenderEventTable e RenderTabEvents.
static ShvEventRecord s_selectedEvent   = {};
static bool           s_hasSelected     = false;

static bool FindModuleForVa(const std::vector<SHV_MODULE_ENTRY>& mods, uint64_t va,
                              const char** outName, uint64_t* outBase)
{
    for (const auto& m : mods)
    {
        if (va >= m.Base && va < m.Base + m.Size)
        {
            *outName = ModuleBaseName(m.Name);
            *outBase = m.Base;
            return true;
        }
    }
    return false;
}

static void RenderAddrCell(uint64_t va,
                            const std::vector<SHV_MODULE_ENTRY>& kernMods,
                            const std::vector<SHV_MODULE_ENTRY>* procMods,
                            bool showModOff)
{
    if (va == 0) { ImGui::TextDisabled("---"); return; }

    if (showModOff)
    {
        const char* name; uint64_t base;
        if (FindModuleForVa(kernMods, va, &name, &base))
        {
            ImGui::Text("%s+0x%llX", name, (unsigned long long)(va - base));
            return;
        }
        if (procMods && FindModuleForVa(*procMods, va, &name, &base))
        {
            ImGui::Text("%s+0x%llX", name, (unsigned long long)(va - base));
            return;
        }
        // Nao resolvido: mostra endereco cru sem prefixo enganoso
        ImGui::Text("0x%016llX", (unsigned long long)va);
        return;
    }

    ImGui::Text("0x%016llX", (unsigned long long)va);
}

// ── Cache de modulos de processos user-mode ──────────────────────────────────

struct ProcModEntry {
    uint64_t cr3;
    std::vector<SHV_MODULE_ENTRY> mods;
};

static std::vector<ProcModEntry> s_procModCache;
static DWORD                     s_procModRefreshMs = 0;

static void RefreshProcModCache(const std::vector<SHV_PROC_ENTRY>& procs)
{
    DWORD now = GetTickCount();
    if (now - s_procModRefreshMs < 2000) return;
    s_procModRefreshMs = now;
    s_procModCache.clear();

    // Build name -> cr3 map (case-insensitive, first match wins)
    std::unordered_map<std::string, uint64_t> nameToCr3;
    for (const auto& p : procs)
    {
        std::string key(p.Name);
        for (char& c : key) c = (char)tolower((unsigned char)c);
        nameToCr3.emplace(key, p.DirBase);
    }

    HANDLE psnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (psnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(psnap, &pe)) { CloseHandle(psnap); return; }

    do
    {
        char nameA[MAX_PATH] = {};
        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, nameA, sizeof(nameA), nullptr, nullptr);
        std::string key(nameA);
        for (char& c : key) c = (char)tolower((unsigned char)c);

        auto it = nameToCr3.find(key);
        if (it == nameToCr3.end()) continue;

        HANDLE msnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe.th32ProcessID);
        if (msnap == INVALID_HANDLE_VALUE) continue;

        ProcModEntry entry;
        entry.cr3 = it->second;

        MODULEENTRY32W me = {};
        me.dwSize = sizeof(me);
        if (Module32FirstW(msnap, &me))
        {
            do
            {
                SHV_MODULE_ENTRY mod = {};
                mod.Base = (uint64_t)(ULONG_PTR)me.modBaseAddr;
                mod.Size = me.modBaseSize;
                WideCharToMultiByte(CP_ACP, 0, me.szExePath, -1,
                                    mod.Name, sizeof(mod.Name), nullptr, nullptr);
                entry.mods.push_back(mod);
            } while (Module32NextW(msnap, &me));
        }
        CloseHandle(msnap);
        s_procModCache.push_back(std::move(entry));

    } while (Process32NextW(psnap, &pe));

    CloseHandle(psnap);
}

static const std::vector<SHV_MODULE_ENTRY>* ProcModsByCr3(uint64_t cr3)
{
    if (cr3 == 0) return nullptr;
    for (const auto& e : s_procModCache)
        if (e.cr3 == cr3) return &e.mods;
    return nullptr;
}

static void RenderPlaceholder(const char* label)
{
    float avail = ImGui::GetContentRegionAvail().y;
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + avail * 0.35f);
    ImGui::SetCursorPosX(
        ImGui::GetCursorPosX() +
        (ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize(label).x) * 0.5f);
    ImGui::TextDisabled("%s", label);
}

// Tabela de eventos filtrada por um conjunto de tipos permitidos.
// typeMask: bitmask 1<<type para tipos a exibir (ex.: (1<<3)|(1<<4)|(1<<5) = EPT).
static void RenderEventTable(ShvBackend& backend,
                             uint32_t    typeMask,
                             bool        autoScroll,
                             bool        paused,
                             char*       addrFilter,
                             size_t      addrFilterSz,
                             uint32_t&   lastSeenSeq,
                             const std::vector<SHV_PROC_ENTRY>&   procs,
                             const std::vector<SHV_MODULE_ENTRY>& modules)
{
    ImGui::SetNextItemWidth(170);
    ImGui::InputText("RIP/Addr##filt", addrFilter, addrFilterSz);
    ImGui::SameLine(0, 12);
    if (ImGui::Button("Limpar historico"))
        backend.ClearEvents();
    ImGui::SameLine(0, 12);
    ImGui::Checkbox("Show Mod&Off", &g_cfg.evtShowModOff);
    ImGui::SameLine(0, 12);
    if (ImGui::Button("Colunas"))
        ImGui::OpenPopup("col_sel_popup");
    if (ImGui::BeginPopup("col_sel_popup"))
    {
        for (int ci = 0; ci < 11; ci++)
            ImGui::Checkbox(kEptColNames[ci], &g_cfg.evtColVis[ci]);
        ImGui::EndPopup();
    }
    ImGui::Spacing();

    // Reserva espaco para o painel de stack (140px) na parte inferior.
    float stackPanelH = 140.0f;
    ImVec2 tableSize = ImVec2(0.0f, ImGui::GetContentRegionAvail().y - stackPanelH - 28.0f);
    if (ImGui::BeginTable("ev_tbl", 11,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX |
            ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_Hideable,
            tableSize))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Hora",      ImGuiTableColumnFlags_WidthFixed,   85.0f);
        ImGui::TableSetupColumn("Seq",       ImGuiTableColumnFlags_WidthFixed,   55.0f);
        ImGui::TableSetupColumn("CPU",       ImGuiTableColumnFlags_WidthFixed,   30.0f);
        ImGui::TableSetupColumn("Tipo",      ImGuiTableColumnFlags_WidthFixed,   90.0f);
        ImGui::TableSetupColumn("Causador",  ImGuiTableColumnFlags_WidthFixed,  120.0f);
        ImGui::TableSetupColumn("Destino",   ImGuiTableColumnFlags_WidthFixed,  130.0f);
        ImGui::TableSetupColumn("RIP/Value", ImGuiTableColumnFlags_WidthFixed,  145.0f);
        ImGui::TableSetupColumn("RetAddr",   ImGuiTableColumnFlags_WidthFixed,  145.0f);
        ImGui::TableSetupColumn("Aux/GPA",   ImGuiTableColumnFlags_WidthFixed,  145.0f);
        ImGui::TableSetupColumn("VA Fault",  ImGuiTableColumnFlags_WidthFixed,  145.0f);
        ImGui::TableSetupColumn("CR3",       ImGuiTableColumnFlags_WidthFixed,  145.0f);
        for (int ci = 0; ci < 11; ci++)
            ImGui::TableSetColumnEnabled(ci, g_cfg.evtColVis[ci]);
        ImGui::TableHeadersRow();

        backend.Lock();
        const auto& events = backend.State().events;

        uint64_t addrVal  = 0;
        bool     useAddr  = (addrFilter[0] != '\0');
        if (useAddr)
            addrVal = strtoull(addrFilter, nullptr, 16);

        for (const auto& e : events)
        {
            uint8_t t = (e.type < 6) ? e.type : 0;
            if (!(typeMask & (1u << t))) continue;
            if (useAddr && e.value != addrVal) continue;

            bool isSelected = s_hasSelected && (s_selectedEvent.seqNum == e.seqNum);
            ImGui::TableNextRow(isSelected ? ImGuiTableRowFlags_None : ImGuiTableRowFlags_None);
            ImGui::TableSetColumnIndex(0);
            // Selectable invisivel sobre toda a linha
            char selId[24];
            snprintf(selId, sizeof(selId), "##sel%u", e.seqNum);
            if (ImGui::Selectable(selId, isSelected,
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowItemOverlap,
                    ImVec2(0, ImGui::GetTextLineHeightWithSpacing())))
            {
                s_selectedEvent = e;
                s_hasSelected   = true;
            }
            ImGui::SameLine();

            // Coluna Hora: converte FILETIME kernel -> hora local HH:MM:SS.mmm
            ImGui::TableNextColumn();
            if (e.timestamp != 0)
            {
                FILETIME ft, localFt;
                ft.dwLowDateTime  = (DWORD)(e.timestamp & 0xFFFFFFFFULL);
                ft.dwHighDateTime = (DWORD)(e.timestamp >> 32);
                SYSTEMTIME st = {};
                if (FileTimeToLocalFileTime(&ft, &localFt) &&
                    FileTimeToSystemTime(&localFt, &st))
                {
                    ImGui::Text("%02u:%02u:%02u.%03u",
                        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
                }
                else ImGui::TextDisabled("---");
            }
            else ImGui::TextDisabled("---");

            ImGui::TableNextColumn(); ImGui::Text("%u", e.seqNum);
            ImGui::TableNextColumn(); ImGui::Text("%u", e.cpu);
            ImGui::TableNextColumn();
            ImGui::PushStyleColor(ImGuiCol_Text, EventColor(e.type));
            ImGui::TextUnformatted(EventName(e.type));
            ImGui::PopStyleColor();

            // Causador: processo que estava executando quando o fault ocorreu (via CR3)
            ImGui::TableNextColumn();
            {
                const char* srcName = ProcNameByCr3(procs, e.cr3);
                if (srcName)
                    ImGui::TextUnformatted(srcName);
                else if (e.cr3 != 0)
                    ImGui::TextDisabled("nao identificado");
                else
                    ImGui::TextDisabled("---");
            }

            // Destino: modulo/driver dona do RIP faultado
            ImGui::TableNextColumn();
            {
                const char* dstMod = ModuleNameByVa(modules, e.value);
                if (dstMod)
                {
                    ImGui::TextUnformatted(dstMod);
                }
                else if (e.value != 0)
                {
                    if (e.value >= 0xFFFF800000000000ULL)
                        ImGui::TextDisabled("kernel");
                    else
                        ImGui::TextDisabled("nao identificado");
                }
                else
                {
                    ImGui::TextDisabled("---");
                }
            }

            {
                const auto* pm = ProcModsByCr3(e.cr3);
                ImGui::TableNextColumn(); RenderAddrCell(e.value,      modules, pm, g_cfg.evtShowModOff);
                ImGui::TableNextColumn(); RenderAddrCell(e.returnAddr, modules, pm, g_cfg.evtShowModOff);
                ImGui::TableNextColumn();
                if (e.aux) ImGui::Text("0x%016llX", (unsigned long long)e.aux);
                else       ImGui::TextDisabled("---");
                ImGui::TableNextColumn(); RenderAddrCell(e.linearAddr, modules, pm, g_cfg.evtShowModOff);
            }
            ImGui::TableNextColumn(); ImGui::Text("0x%016llX", e.cr3);
        }

        // Scroll para o final somente quando novos eventos chegarem
        // e o checkbox de auto-scroll estiver ativo.
        {
            uint32_t newestSeq = events.empty() ? 0 : events.back().seqNum;
            if (autoScroll && !paused && newestSeq != lastSeenSeq)
            {
                ImGui::SetScrollHereY(1.0f);
                lastSeenSeq = newestSeq;
            }
        }

        backend.Unlock();
        ImGui::EndTable();
    }

    // ── Painel de stack trace ──────────────────────────────────────────────────
    ImGui::Spacing();
    ImGui::Separator();
    if (s_hasSelected)
    {
        const auto* pm = ProcModsByCr3(s_selectedEvent.cr3);
        ImGui::Text("Stack  seq=%u  %s", s_selectedEvent.seqNum, EventName(s_selectedEvent.type));
        ImGui::SameLine(0, 16);
        if (ImGui::SmallButton("x##clrsel")) { s_hasSelected = false; }
        ImGui::Spacing();
        for (int fi = 0; fi < SHV_EVENT_STACK_FRAMES; fi++)
        {
            uint64_t frame = s_selectedEvent.stack[fi];
            ImGui::Text("  [%d]", fi);
            ImGui::SameLine(55);
            RenderAddrCell(frame, modules, pm, g_cfg.evtShowModOff);
        }
    }
    else
    {
        ImGui::TextDisabled("Clique numa linha para ver a stack trace");
    }
}

// ── Ponto de entrada ─────────────────────────────────────────────────────────

void RenderTabEvents(ShvBackend& backend)
{
    static bool     s_autoScroll    = true;
    static bool     s_paused        = false;
    static char     s_addrEpt[32]   = "";
    static char     s_addrLstar[32] = "";
    static uint32_t s_lastSeqEpt    = 0;

    // Snapshot de lookup tables (uma vez por frame, fora do lock da tabela)
    std::vector<SHV_PROC_ENTRY>   s_procs;
    std::vector<SHV_MODULE_ENTRY> s_modules;
    backend.Lock();
    s_procs   = backend.State().procs;
    s_modules = backend.State().kernelModules;
    backend.Unlock();

    // Atualiza cache de modulos user-mode por processo (throttlado a cada 2s)
    RefreshProcModCache(s_procs);

    // Controles globais
    ImGui::Checkbox("Auto-scroll p/ novos", &s_autoScroll); ImGui::SameLine();
    ImGui::Checkbox("Pausar",               &s_paused);

    // Rodape com contadores (antes das abas para nao sumir ao trocar)
    backend.Lock();
    uint32_t total = backend.State().stats.totalEvents;
    size_t   hist  = backend.State().events.size();
    backend.Unlock();

    ImGui::SameLine(0, 30);
    ImGui::TextDisabled("Historico: %zu   Total HV: %u   Ring: %d",
                        hist, total, SHV_EVENT_RING_SIZE);

    ImGui::Spacing();

    if (!ImGui::BeginTabBar("ev_subtabs"))
        return;

    // ── LSTAR ─────────────────────────────────────────────────────────────────
    if (ImGui::BeginTabItem("LSTAR"))
    {
        RenderPlaceholder("Monitoramento LSTAR - futura implementacao");
        ImGui::EndTabItem();
    }

    // ── EPT ───────────────────────────────────────────────────────────────────
    if (ImGui::BeginTabItem("EPT"))
    {
        // tipos 3=EPT_EXEC, 4=EPT_WRITE, 5=EPT_READ
        const uint32_t kEptMask = (1u << 3) | (1u << 4) | (1u << 5);
        RenderEventTable(backend, kEptMask,
                         s_autoScroll, s_paused,
                         s_addrEpt, sizeof(s_addrEpt),
                         s_lastSeqEpt,
                         s_procs, s_modules);
        ImGui::EndTabItem();
    }

    // ── Syscalls ──────────────────────────────────────────────────────────────
    if (ImGui::BeginTabItem("Syscalls"))
    {
        RenderPlaceholder("Monitoramento de Syscalls - futura implementacao");
        ImGui::EndTabItem();
    }

    // ── Others ────────────────────────────────────────────────────────────────
    if (ImGui::BeginTabItem("Others"))
    {
        RenderPlaceholder("Outros eventos - futura implementacao");
        ImGui::EndTabItem();
    }

    ImGui::EndTabBar();
}

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
#include <string.h>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <utility>
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

// Compara contra DirBase (CR3 "kernel") E UserDirBase (CR3 "user", usado em
// ring-3 quando KPTI/KVA-shadow esta ativo) -- um acesso usermode direto
// (ex.: memcpy no proprio processo) carrega o CR3 "user" no evento, que NAO
// bate com DirBase sozinho. Ver [[feedback_cr3_filter_broke_usermode]].
static const char* ProcNameByCr3(const std::vector<SHV_PROC_ENTRY>& procs, uint64_t cr3)
{
    if (cr3 == 0) return nullptr;
    for (const auto& p : procs)
        if (p.DirBase == cr3 || (p.UserDirBase != 0 && p.UserDirBase == cr3))
            return p.Name;
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

// Monta o texto de uma celula de endereco (modulo+offset ou hex cru) sem
// desenhar nada -- usado tanto pelo RenderAddrCell "antigo" (stack panel)
// quanto pela tabela principal, que precisa da string pronta pra alimentar
// RenderCopyableCell (medida de largura + menu de copiar).
static std::string FormatAddrCell(uint64_t va,
                                   const std::vector<SHV_MODULE_ENTRY>& kernMods,
                                   const std::vector<SHV_MODULE_ENTRY>* procMods,
                                   bool showModOff,
                                   bool* outDisabled)
{
    *outDisabled = false;
    char buf[160];

    if (va == 0) { *outDisabled = true; return "---"; }

    if (showModOff)
    {
        const char* name; uint64_t base;
        if (FindModuleForVa(kernMods, va, &name, &base))
        {
            snprintf(buf, sizeof(buf), "%s+0x%llX", name, (unsigned long long)(va - base));
            return buf;
        }
        if (procMods && FindModuleForVa(*procMods, va, &name, &base))
        {
            snprintf(buf, sizeof(buf), "%s+0x%llX", name, (unsigned long long)(va - base));
            return buf;
        }
        // Nao resolvido: mostra endereco cru sem prefixo enganoso
        snprintf(buf, sizeof(buf), "0x%016llX", (unsigned long long)va);
        return buf;
    }

    snprintf(buf, sizeof(buf), "0x%016llX", (unsigned long long)va);
    return buf;
}

static void RenderAddrCell(uint64_t va,
                            const std::vector<SHV_MODULE_ENTRY>& kernMods,
                            const std::vector<SHV_MODULE_ENTRY>* procMods,
                            bool showModOff)
{
    bool disabled = false;
    std::string s = FormatAddrCell(va, kernMods, procMods, showModOff, &disabled);
    if (disabled) ImGui::TextDisabled("%s", s.c_str());
    else           ImGui::Text("%s", s.c_str());
}

// Desenha (se ci == selCol) o Selectable invisivel que cobre a linha inteira
// (ImGuiSelectableFlags_SpanAllColumns), usado pra selecionar o evento ao
// clicar em qualquer parte da linha. PRECISA ser desenhado na primeira coluna
// VISIVEL da tabela (selCol), nao sempre na coluna 0 ("Hora") -- se "Hora"
// estiver desabilitada via "Colunas", TableNextColumn() pra ela retorna uma
// celula de largura zero/oculta, e um Selectable desenhado ali nao recebe
// clique nenhum (bug relatado: so dava pra selecionar a linha com "Hora"
// ativa). selCol e calculado uma vez por frame (primeira coluna com
// g_cfg.evtColVis[ci]==true), antes do loop de linhas.
static bool PlaceRowSelectableIfOwned(int selCol, int ci, bool isSelected)
{
    if (ci != selCol) return false;
    bool clicked = ImGui::Selectable("", isSelected,
            ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowItemOverlap,
            ImVec2(0, 0));
    ImGui::SameLine(0, 0);
    return clicked;
}

// Desenha o texto de uma celula "copiavel": clique direito abre um menu de
// contexto com "Copiar" (copia o texto exato da celula pra area de
// transferencia via ImGui::SetClipboardText). Tambem atualiza *widthSlot com
// a largura em pixels do texto, usado pelo auto-fit de largura de coluna
// (ver s_colWidth/RenderEventTable) -- o chamador deve envolver cada celula
// num ImGui::PushID/PopID exclusivo (linha+coluna) pra o popup de contexto
// nao colidir entre celulas.
static void RenderCopyableCell(float* widthSlot, const char* text,
                                const ImVec4* color = nullptr, bool disabled = false)
{
    if (color) ImGui::PushStyleColor(ImGuiCol_Text, *color);
    if (disabled) ImGui::TextDisabled("%s", text);
    else           ImGui::TextUnformatted(text);
    if (color) ImGui::PopStyleColor();

    float w = ImGui::CalcTextSize(text).x;
    if (w > *widthSlot) *widthSlot = w;

    if (ImGui::BeginPopupContextItem("cellctx"))
    {
        if (ImGui::Selectable("Copiar"))
            ImGui::SetClipboardText(text);
        ImGui::EndPopup();
    }
}

// ── Cache de modulos de processos user-mode ──────────────────────────────────

struct ProcModEntry {
    uint64_t cr3;       // DirBase (CR3 "kernel")
    uint64_t userCr3;    // UserDirBase (CR3 "user", eventos de acesso direto usermode)
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

    // Build name -> (cr3, userCr3) map (case-insensitive, first match wins)
    std::unordered_map<std::string, std::pair<uint64_t, uint64_t>> nameToCr3;
    for (const auto& p : procs)
    {
        std::string key(p.Name);
        for (char& c : key) c = (char)tolower((unsigned char)c);
        nameToCr3.emplace(key, std::make_pair(p.DirBase, p.UserDirBase));
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
        entry.cr3     = it->second.first;
        entry.userCr3 = it->second.second;

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
        if (e.cr3 == cr3 || (e.userCr3 != 0 && e.userCr3 == cr3))
            return &e.mods;
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
                             const std::vector<SHV_MODULE_ENTRY>& modules,
                             bool        showStackFilterToggle = false)
{
    // Filtro de call-site do stack walk heuristico (ShvLooksLikeCallSite no
    // hypervisor) -- so exibido na aba EPT, onde o stack walk e usado. Estado
    // local (nao persiste entre sessoes): reflete o default do kernel
    // (ShvStackWalkDebugNoFilter=0 == filtro ligado).
    static bool s_stackFilterEnabled = true;
    if (showStackFilterToggle)
    {
        if (ImGui::Checkbox("Filtro call-site (stack)", &s_stackFilterEnabled))
            backend.SetStackFilter(s_stackFilterEnabled);
        ImGui::SameLine(0, 12);
    }
    ImGui::SetNextItemWidth(170);
    ImGui::InputText("RIP/Addr##filt", addrFilter, addrFilterSz);
    ImGui::SameLine(0, 12);
    if (ImGui::Button("Limpar historico"))
        backend.ClearEvents();
    ImGui::SameLine(0, 12);
    static bool s_ignoreDuplicates = false;
    ImGui::Checkbox("Ignorar Duplicados", &s_ignoreDuplicates);
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

    // Largura de cada coluna, auto-ajustada ao conteudo mais largo ja visto
    // (medido quadro a quadro em colWNext abaixo e aplicado no proximo
    // TableSetupColumn -- atraso de 1 frame, padrao usual pra "auto-fit" em
    // ImGui modo imediato). Comeca nos valores fixos originais; nunca encolhe
    // abaixo da largura do proprio label do cabecalho.
    static float s_colWidth[11] = { 85, 55, 30, 90, 120, 130, 145, 145, 145, 145, 145 };
    float colWNext[11];
    for (int ci = 0; ci < 11; ci++)
        colWNext[ci] = ImGui::CalcTextSize(kEptColNames[ci]).x + 16.0f;

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
        for (int ci = 0; ci < 11; ci++)
            ImGui::TableSetupColumn(kEptColNames[ci], ImGuiTableColumnFlags_WidthFixed, s_colWidth[ci]);
        for (int ci = 0; ci < 11; ci++)
            ImGui::TableSetColumnEnabled(ci, g_cfg.evtColVis[ci]);
        ImGui::TableHeadersRow();

        // Primeira coluna visivel -- e onde o Selectable de selecao de linha
        // (SpanAllColumns) precisa ser desenhado neste frame (ver
        // PlaceRowSelectableIfOwned acima).
        int selCol = 0;
        for (int ci = 0; ci < 11; ci++)
        {
            if (g_cfg.evtColVis[ci]) { selCol = ci; break; }
        }

        backend.Lock();
        const auto& events = backend.State().events;

        uint64_t addrVal  = 0;
        bool     useAddr  = (addrFilter[0] != '\0');
        if (useAddr)
            addrVal = strtoull(addrFilter, nullptr, 16);

        // "Ignorar Duplicados": compara cada linha contra TODAS as ja vistas
        // nesta mesma renderizacao (nao so a anterior), pela assinatura
        // Tipo+RIP/Value+RetAddr+Aux+CR3+VA Fault (ignora SeqNum/Timestamp/
        // tickMs, que sempre diferem mesmo pra retries da mesma leitura
        // real -- ver fix "1 leitura gerando 1-3 eventos" em memory/fixes.md).
        // Hash set em vez de O(n^2) pra nao travar com historico grande.
        std::unordered_set<uint64_t> seenSignatures;
        auto DedupSignature = [](const ShvEventRecord& ev) -> uint64_t
        {
            uint64_t h = ev.type;
            h = h * 1099511628211ULL ^ ev.value;
            h = h * 1099511628211ULL ^ ev.returnAddr;
            h = h * 1099511628211ULL ^ ev.aux;
            h = h * 1099511628211ULL ^ ev.cr3;
            h = h * 1099511628211ULL ^ ev.linearAddr;
            return h;
        };

        for (const auto& e : events)
        {
            uint8_t t = (e.type < 6) ? e.type : 0;
            if (!(typeMask & (1u << t))) continue;
            if (useAddr && e.value != addrVal) continue;
            if (s_ignoreDuplicates)
            {
                uint64_t sig = DedupSignature(e);
                if (!seenSignatures.insert(sig).second) continue;
            }

            bool isSelected = s_hasSelected && (s_selectedEvent.seqNum == e.seqNum);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            // Todas as celulas da linha (inclusive o Selectable abaixo) ficam
            // dentro deste PushID(seqNum) -- cada RenderCopyableCell faz seu
            // proprio PushID(coluna) por dentro, entao a dupla (seqNum, coluna)
            // da um ID unico pro menu de contexto "Copiar" de cada celula.
            ImGui::PushID((int)e.seqNum);

            if (PlaceRowSelectableIfOwned(selCol, 0, isSelected))
            {
                s_selectedEvent = e;
                s_hasSelected   = true;
            }

            // Coluna Hora: converte FILETIME kernel -> hora local HH:MM:SS.mmm.
            // Fica na MESMA coluna 0 onde o Selectable acima foi desenhado
            // (via TableNextColumn(), nao TableSetColumnIndex+SameLine com
            // espacamento) -- nao chamar outro TableNextColumn() aqui.
            {
                char horaBuf[32] = "---";
                if (e.timestamp != 0)
                {
                    FILETIME ft, localFt;
                    ft.dwLowDateTime  = (DWORD)(e.timestamp & 0xFFFFFFFFULL);
                    ft.dwHighDateTime = (DWORD)(e.timestamp >> 32);
                    SYSTEMTIME st = {};
                    if (FileTimeToLocalFileTime(&ft, &localFt) &&
                        FileTimeToSystemTime(&localFt, &st))
                    {
                        snprintf(horaBuf, sizeof(horaBuf), "%02u:%02u:%02u.%03u",
                            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
                    }
                }
                ImGui::PushID(0);
                RenderCopyableCell(&colWNext[0], horaBuf, nullptr, horaBuf[0] == '-');
                ImGui::PopID();
            }

            ImGui::TableNextColumn();
            if (PlaceRowSelectableIfOwned(selCol, 1, isSelected)) { s_selectedEvent = e; s_hasSelected = true; }
            {
                char buf[16];
                snprintf(buf, sizeof(buf), "%u", e.seqNum);
                ImGui::PushID(1);
                RenderCopyableCell(&colWNext[1], buf);
                ImGui::PopID();
            }
            ImGui::TableNextColumn();
            if (PlaceRowSelectableIfOwned(selCol, 2, isSelected)) { s_selectedEvent = e; s_hasSelected = true; }
            {
                char buf[16];
                snprintf(buf, sizeof(buf), "%u", e.cpu);
                ImGui::PushID(2);
                RenderCopyableCell(&colWNext[2], buf);
                ImGui::PopID();
            }
            ImGui::TableNextColumn();
            if (PlaceRowSelectableIfOwned(selCol, 3, isSelected)) { s_selectedEvent = e; s_hasSelected = true; }
            {
                ImVec4 col = EventColor(e.type);
                ImGui::PushID(3);
                RenderCopyableCell(&colWNext[3], EventName(e.type), &col);
                ImGui::PopID();
            }

            // Causador: processo que estava executando quando o fault ocorreu (via CR3)
            ImGui::TableNextColumn();
            if (PlaceRowSelectableIfOwned(selCol, 4, isSelected)) { s_selectedEvent = e; s_hasSelected = true; }
            {
                const char* srcName = ProcNameByCr3(procs, e.cr3);
                const char* text = srcName ? srcName : (e.cr3 != 0 ? "nao identificado" : "---");
                ImGui::PushID(4);
                RenderCopyableCell(&colWNext[4], text, nullptr, srcName == nullptr);
                ImGui::PopID();
            }

            // Destino: modulo/driver dona do RIP faultado. Verifica modulos do
            // kernel primeiro; se nao achar e o evento tiver CR3 de um processo
            // conhecido, verifica tambem os modulos user-mode daquele processo
            // (necessario para hooks instalados em codigo usermode, nao so em
            // drivers/ntoskrnl).
            ImGui::TableNextColumn();
            if (PlaceRowSelectableIfOwned(selCol, 5, isSelected)) { s_selectedEvent = e; s_hasSelected = true; }
            {
                const auto* pm = ProcModsByCr3(e.cr3);
                const char* dstMod = ModuleNameByVa(modules, e.value);
                if (!dstMod && pm)
                    dstMod = ModuleNameByVa(*pm, e.value);

                const char* text;
                bool disabled = false;
                if (dstMod)
                {
                    text = dstMod;
                }
                else if (e.value != 0)
                {
                    disabled = true;
                    text = (e.value >= 0xFFFF800000000000ULL) ? "kernel" : "nao identificado";
                }
                else
                {
                    disabled = true;
                    text = "---";
                }
                ImGui::PushID(5);
                RenderCopyableCell(&colWNext[5], text, nullptr, disabled);
                ImGui::PopID();
            }

            {
                const auto* pm = ProcModsByCr3(e.cr3);
                bool disabled;
                std::string s;

                ImGui::TableNextColumn();
                if (PlaceRowSelectableIfOwned(selCol, 6, isSelected)) { s_selectedEvent = e; s_hasSelected = true; }
                disabled = false;
                s = FormatAddrCell(e.value, modules, pm, g_cfg.evtShowModOff, &disabled);
                ImGui::PushID(6);
                RenderCopyableCell(&colWNext[6], s.c_str(), nullptr, disabled);
                ImGui::PopID();

                ImGui::TableNextColumn();
                if (PlaceRowSelectableIfOwned(selCol, 7, isSelected)) { s_selectedEvent = e; s_hasSelected = true; }
                disabled = false;
                s = FormatAddrCell(e.returnAddr, modules, pm, g_cfg.evtShowModOff, &disabled);
                ImGui::PushID(7);
                RenderCopyableCell(&colWNext[7], s.c_str(), nullptr, disabled);
                ImGui::PopID();

                ImGui::TableNextColumn();
                if (PlaceRowSelectableIfOwned(selCol, 8, isSelected)) { s_selectedEvent = e; s_hasSelected = true; }
                char auxBuf[32];
                bool auxDisabled = (e.aux == 0);
                if (auxDisabled) snprintf(auxBuf, sizeof(auxBuf), "---");
                else              snprintf(auxBuf, sizeof(auxBuf), "0x%016llX", (unsigned long long)e.aux);
                ImGui::PushID(8);
                RenderCopyableCell(&colWNext[8], auxBuf, nullptr, auxDisabled);
                ImGui::PopID();

                ImGui::TableNextColumn();
                if (PlaceRowSelectableIfOwned(selCol, 9, isSelected)) { s_selectedEvent = e; s_hasSelected = true; }
                disabled = false;
                s = FormatAddrCell(e.linearAddr, modules, pm, g_cfg.evtShowModOff, &disabled);
                ImGui::PushID(9);
                RenderCopyableCell(&colWNext[9], s.c_str(), nullptr, disabled);
                ImGui::PopID();
            }

            ImGui::TableNextColumn();
            if (PlaceRowSelectableIfOwned(selCol, 10, isSelected)) { s_selectedEvent = e; s_hasSelected = true; }
            {
                char buf[32];
                snprintf(buf, sizeof(buf), "0x%016llX", (unsigned long long)e.cr3);
                ImGui::PushID(10);
                RenderCopyableCell(&colWNext[10], buf);
                ImGui::PopID();
            }

            ImGui::PopID(); // seqNum
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

        // Aplica a largura medida neste frame pra o proximo TableSetupColumn
        // (auto-fit com 1 frame de atraso -- ver comentario acima de s_colWidth).
        for (int ci = 0; ci < 11; ci++)
            s_colWidth[ci] = colWNext[ci];
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

// ── Syscalls: eventos de acesso a registro de processos MONITORADOS ─────────
// (ZwOpenKey/ZwOpenKeyEx/ZwCreateKey/ZwQueryKey, via shadow hook em
// nt/hpv_registry_hooks.c -- ver SHV_CMD_LIST_REGISTRY_EVENTS).

static const char* RegOpName(unsigned char op)
{
    switch (op)
    {
        case SHV_REGOP_OPENKEY:   return "OpenKey";
        case SHV_REGOP_OPENKEYEX: return "OpenKeyEx";
        case SHV_REGOP_CREATEKEY: return "CreateKey";
        case SHV_REGOP_QUERYKEY:  return "QueryKey";
        default:                  return "?";
    }
}

static void RenderRegistryEventsTable(ShvBackend& backend)
{
    static char     s_pathFilter[128] = "";
    static uint64_t s_lastSeenSeq     = 0;
    static bool     s_autoScroll      = true;

    ImGui::Checkbox("Auto-scroll p/ novos##reg", &s_autoScroll);
    ImGui::SameLine(0, 12);
    ImGui::SetNextItemWidth(260);
    ImGui::InputText("Filtro caminho##reg", s_pathFilter, sizeof(s_pathFilter));
    ImGui::SameLine(0, 12);
    if (ImGui::Button("Limpar##reg"))
        backend.ClearRegistryEvents();

    backend.Lock();
    size_t hist = backend.State().registryEvents.size();
    backend.Unlock();
    ImGui::SameLine(0, 20);
    ImGui::TextDisabled("Historico: %zu", hist);

    ImGui::Spacing();

    if (ImGui::BeginTable("reg_tbl", 6,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX |
            ImGuiTableFlags_SizingFixedFit,
            ImVec2(0.0f, ImGui::GetContentRegionAvail().y)))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Seq",     ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("PID",     ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableSetupColumn("Processo",ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("Operacao",ImGuiTableColumnFlags_WidthFixed, 90);
        ImGui::TableSetupColumn("Status",  ImGuiTableColumnFlags_WidthFixed, 110);
        ImGui::TableSetupColumn("Caminho da chave", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        bool useFilter = (s_pathFilter[0] != '\0');

        backend.Lock();
        const auto& evs = backend.State().registryEvents;
        for (const auto& e : evs)
        {
            if (useFilter && !strstr(e.KeyPath, s_pathFilter))
                continue;

            ImGui::TableNextRow();
            ImGui::PushID((int)(e.SeqNum & 0x7FFFFFFF));

            ImGui::TableNextColumn();
            ImGui::Text("%llu", (unsigned long long)e.SeqNum);

            ImGui::TableNextColumn();
            ImGui::Text("%llu", (unsigned long long)e.Pid);

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(e.ProcessName[0] ? e.ProcessName : "?");

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(RegOpName(e.Operation));

            ImGui::TableNextColumn();
            if (e.Status == 0)
                ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.4f, 1.0f), "0x%08X", (unsigned int)e.Status);
            else
                ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.1f, 1.0f), "0x%08X", (unsigned int)e.Status);

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(e.KeyPath[0] ? e.KeyPath : "---");

            ImGui::PopID();
        }

        if (s_autoScroll)
        {
            uint64_t newestSeq = evs.empty() ? 0 : evs.back().SeqNum;
            if (newestSeq != s_lastSeenSeq)
            {
                ImGui::SetScrollHereY(1.0f);
                s_lastSeenSeq = newestSeq;
            }
        }

        backend.Unlock();
        ImGui::EndTable();
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
                         s_procs, s_modules,
                         /*showStackFilterToggle=*/true);
        ImGui::EndTabItem();
    }

    // ── Syscalls ──────────────────────────────────────────────────────────────
    // Monitoramento de acesso a registro (ZwOpenKey/ZwOpenKeyEx/ZwCreateKey/
    // ZwQueryKey) dos processos MONITORADOS -- ver nt/hpv_registry_hooks.c.
    if (ImGui::BeginTabItem("Syscalls"))
    {
        RenderRegistryEventsTable(backend);
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

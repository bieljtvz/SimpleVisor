/*++

Module Name:

    tab_filters.cpp

Abstract:

    Tab Filtros: sub-abas Processos, Hook EPT, Hook Shadow Patch.
    Processos: gestao de listas de processos protegidos e monitorados.
    Hook EPT / Hook Shadow Patch: lista de hooks ativos com acao de remocao.

--*/

#include "tab_filters.h"
#include "imgui/imgui.h"
#include <stdio.h>
#include <string.h>
#include <vector>

static const ImVec4 kColorProtect = { 1.00f, 0.60f, 0.00f, 1.0f };
static const ImVec4 kColorMonitor = { 0.30f, 0.85f, 1.00f, 1.0f };
static const ImVec4 kColorByName  = { 0.60f, 1.00f, 0.40f, 1.0f };
static const ImVec4 kColorByPid   = { 1.00f, 0.80f, 0.30f, 1.0f };
static const ImVec4 kColorDim     = { 0.55f, 0.55f, 0.55f, 1.0f };
static const ImVec4 kColorOk      = { 0.20f, 0.90f, 0.40f, 1.0f };
static const ImVec4 kColorWarn    = { 1.00f, 0.75f, 0.00f, 1.0f };

static void RenderFilterPanel(
    const char*                          childId,
    const char*                          title,
    const ImVec4&                        titleColor,
    const char*                          tableId,
    std::vector<SHV_PROC_FILTER_ENTRY>&  entries,
    const char*                          nameInputId,
    char*                                nameInputBuf,
    int                                  nameInputLen,
    const char*                          pidInputId,
    char*                                pidInputBuf,
    int                                  pidInputLen,
    const char*                          addNameBtnId,
    const char*                          addPidBtnId,
    ShvBackend&                          backend,
    bool                                 isProtect
)
{
    ImGui::BeginChild(childId, ImVec2(0, 0), true);

    ImGui::PushStyleColor(ImGuiCol_Text, titleColor);
    ImGui::TextUnformatted(title);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::TextDisabled("(%zu)", entries.size());
    ImGui::Separator();

    if (ImGui::BeginTable(tableId, 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
            ImVec2(0, -90.0f)))
    {
        ImGui::TableSetupColumn("Tipo",  ImGuiTableColumnFlags_WidthFixed,  46.0f);
        ImGui::TableSetupColumn("PID",   ImGuiTableColumnFlags_WidthFixed,  58.0f);
        ImGui::TableSetupColumn("Nome",  ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("##rm",  ImGuiTableColumnFlags_WidthFixed,  24.0f);
        ImGui::TableHeadersRow();

        for (int i = 0; i < (int)entries.size(); i++)
        {
            const auto& f = entries[i];
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            if (f.ByName)
            {
                ImGui::PushStyleColor(ImGuiCol_Text, kColorByName);
                ImGui::TextUnformatted("[N]");
                ImGui::PopStyleColor();
            }
            else
            {
                ImGui::PushStyleColor(ImGuiCol_Text, kColorByPid);
                ImGui::TextUnformatted("[P]");
                ImGui::PopStyleColor();
            }

            ImGui::TableNextColumn();
            if (f.ByName) ImGui::TextDisabled("---");
            else          ImGui::Text("%llu", f.Pid);

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(f.Name[0] ? f.Name : "<unknown>");

            ImGui::TableNextColumn();
            char lbl[32]; snprintf(lbl, sizeof(lbl), "X##%s%d", childId, i);
            if (ImGui::SmallButton(lbl))
            {
                if (f.ByName)
                {
                    if (isProtect) backend.UnprotectName(f.Name);
                    else           backend.UnmonitorName(f.Name);
                }
                else
                {
                    if (isProtect) backend.Unprotect(f.Pid);
                    else           backend.Unmonitor(f.Pid);
                }
            }
        }
        ImGui::EndTable();
    }

    ImGui::Separator();

    ImGui::SetNextItemWidth(-70.0f);
    ImGui::InputText(nameInputId, nameInputBuf, nameInputLen);
    ImGui::SameLine();
    if (ImGui::Button(addNameBtnId) && nameInputBuf[0])
    {
        if (isProtect) backend.ProtectName(nameInputBuf);
        else           backend.MonitorName(nameInputBuf);
        nameInputBuf[0] = '\0';
        backend.RefreshAll();
    }

    ImGui::SetNextItemWidth(-70.0f);
    ImGui::InputText(pidInputId, pidInputBuf, pidInputLen);
    ImGui::SameLine();
    if (ImGui::Button(addPidBtnId) && pidInputBuf[0])
    {
        uint64_t pid = strtoull(pidInputBuf, nullptr, 10);
        if (pid)
        {
            if (isProtect) backend.Protect(pid);
            else           backend.Monitor(pid);
        }
        pidInputBuf[0] = '\0';
        backend.RefreshAll();
    }

    ImGui::EndChild();
}

// Formata bitmask de tipo EPT em string "XWR"
static void HookTypeName(uint8_t type, char* buf, int len)
{
    buf[0] = '\0';
    if (type & SHV_HOOK_EXEC)  strcat_s(buf, len, "X");
    if (type & SHV_HOOK_WRITE) strcat_s(buf, len, "W");
    if (type & SHV_HOOK_READ)  strcat_s(buf, len, "R");
    if (!buf[0]) strcpy_s(buf, len, "---");
}

void RenderTabFilters(ShvBackend& backend)
{
    static char s_protName[SHV_PROC_NAME_LEN] = "";
    static char s_protPid[16]                 = "";
    static char s_monName[SHV_PROC_NAME_LEN]  = "";
    static char s_monPid[16]                  = "";

    if (!ImGui::BeginTabBar("flt_tabs")) return;

    // ── Processos ─────────────────────────────────────────────────────────────
    if (ImGui::BeginTabItem("Processos"))
    {
        std::vector<SHV_PROC_FILTER_ENTRY> protected_, monitored;
        backend.Lock();
        for (const auto& f : backend.State().filters)
        {
            if (f.Type == SHV_FILTER_TYPE_PROTECT) protected_.push_back(f);
            else                                   monitored.push_back(f);
        }
        backend.Unlock();

        if (ImGui::Button("Atualizar"))
            backend.RefreshAll();
        ImGui::SameLine(0, 20);
        ImGui::TextDisabled("Protegidos: %zu  |  Monitorados: %zu",
            protected_.size(), monitored.size());
        ImGui::Spacing();

        float halfW = (ImGui::GetContentRegionAvail().x - 8.0f) / 2.0f;

        ImGui::BeginChild("fp_wrap", ImVec2(halfW, 0), false);
        RenderFilterPanel(
            "fp", "Protegidos", kColorProtect, "prot_tbl", protected_,
            "Nome##pn", s_protName, (int)sizeof(s_protName),
            "PID##pp",  s_protPid,  (int)sizeof(s_protPid),
            "Add Nome##pn", "Add PID##pp",
            backend, true
        );
        ImGui::EndChild();

        ImGui::SameLine();

        ImGui::BeginChild("fm_wrap", ImVec2(0, 0), false);
        RenderFilterPanel(
            "fm", "Monitorados", kColorMonitor, "mon_tbl", monitored,
            "Nome##mn", s_monName, (int)sizeof(s_monName),
            "PID##mp",  s_monPid,  (int)sizeof(s_monPid),
            "Add Nome##mn", "Add PID##mp",
            backend, false
        );
        ImGui::EndChild();

        ImGui::EndTabItem();
    }

    // ── Hook EPT ──────────────────────────────────────────────────────────────
    if (ImGui::BeginTabItem("Hook EPT"))
    {
        std::vector<ShvEptHookEntry> hooks;
        std::vector<SHV_PROC_ENTRY>  procs;
        backend.Lock();
        hooks = backend.State().eptHooks;
        procs = backend.State().procs;
        backend.Unlock();

        ImGui::TextDisabled("%zu hook(s) ativos", hooks.size());
        ImGui::SameLine(0, 16);
        if (ImGui::SmallButton("Remover Todos##ept") && !hooks.empty())
            backend.UnhookAll();
        ImGui::Spacing();

        static uint64_t s_ctxVa = 0;

        if (ImGui::BeginTable("ept_tbl", 7,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX |
                ImGuiTableFlags_SizingFixedFit,
                ImVec2(0, 0)))
        {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("VA",       ImGuiTableColumnFlags_WidthFixed, 145.0f);
            ImGui::TableSetupColumn("PA",       ImGuiTableColumnFlags_WidthFixed, 145.0f);
            ImGui::TableSetupColumn("Tipo",     ImGuiTableColumnFlags_WidthFixed,  38.0f);
            ImGui::TableSetupColumn("Range",    ImGuiTableColumnFlags_WidthFixed,  52.0f);
            ImGui::TableSetupColumn("PID",      ImGuiTableColumnFlags_WidthFixed,  70.0f);
            ImGui::TableSetupColumn("Processo", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("##act",    ImGuiTableColumnFlags_WidthFixed,  24.0f);
            ImGui::TableHeadersRow();

            for (int i = 0; i < (int)hooks.size(); i++)
            {
                const ShvEptHookEntry& h = hooks[i];
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(i);
                ImGui::Selectable("", false,
                    ImGuiSelectableFlags_SpanAllColumns |
                    ImGuiSelectableFlags_AllowItemOverlap,
                    ImVec2(0, 0));
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right))
                    s_ctxVa = h.va;
                if (ImGui::BeginPopupContextItem("ept_ctx"))
                {
                    if (ImGui::MenuItem("Remover Hook"))
                        backend.UnhookEpt(s_ctxVa);
                    ImGui::EndPopup();
                }
                ImGui::PopID();
                ImGui::SameLine(0, 0);

                bool isExec = (h.type & SHV_HOOK_EXEC) != 0;
                ImGui::PushStyleColor(ImGuiCol_Text, isExec ? kColorWarn : kColorOk);
                ImGui::Text("0x%016llX", (unsigned long long)h.va);
                ImGui::PopStyleColor();

                ImGui::TableNextColumn();
                if (h.pa)
                    ImGui::Text("0x%016llX", (unsigned long long)h.pa);
                else
                    ImGui::TextDisabled("---");

                ImGui::TableNextColumn();
                char typeBuf[8]; HookTypeName(h.type, typeBuf, sizeof(typeBuf));
                ImGui::PushStyleColor(ImGuiCol_Text, isExec ? kColorWarn : kColorOk);
                ImGui::TextUnformatted(typeBuf);
                ImGui::PopStyleColor();

                ImGui::TableNextColumn();
                ImGui::Text("%llu", (unsigned long long)h.range);

                ImGui::TableNextColumn();
                if (h.pid) ImGui::Text("%llu", (unsigned long long)h.pid);
                else       ImGui::TextDisabled("qualquer");

                ImGui::TableNextColumn();
                if (h.pid == 0)
                {
                    ImGui::TextDisabled("kernel");
                }
                else
                {
                    const char* procName = nullptr;
                    for (const auto& p : procs)
                        if ((uint64_t)p.Pid == h.pid) { procName = p.Name; break; }
                    if (procName) ImGui::TextUnformatted(procName);
                    else          ImGui::TextDisabled("---");
                }

                ImGui::TableNextColumn();
                char rmLbl[16]; snprintf(rmLbl, sizeof(rmLbl), "X##e%d", i);
                if (ImGui::SmallButton(rmLbl))
                    backend.UnhookEpt(h.va);
            }

            if (hooks.empty())
            {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushStyleColor(ImGuiCol_Text, kColorDim);
                ImGui::TextUnformatted("Nenhum EPT hook instalado.");
                ImGui::PopStyleColor();
            }

            ImGui::EndTable();
        }
        ImGui::EndTabItem();
    }

    // ── Hook Shadow Patch ─────────────────────────────────────────────────────
    if (ImGui::BeginTabItem("Hook Shadow"))
    {
        // Lista unica a partir do poll (kernelShadows) -- e sempre o estado
        // real e completo do kernel (g_ShadowPages[]), ja enriquecido com
        // VA/CR3 quando conhecidos (ver merge em ShvBackend::Refresh). Usar
        // tambem m_state.shadowPatches aqui so causava linhas duplicadas pra
        // cada shadow instalado pela propria GUI (uma copia local "[U]" e
        // outra vinda do poll "[K]", mesma GPA, mesmos bytes).
        std::vector<ShvShadowEntry>   shadows;
        std::vector<SHV_MODULE_ENTRY> kernMods;
        backend.Lock();
        shadows  = backend.State().kernelShadows;
        kernMods = backend.State().kernelModules;
        backend.Unlock();

        // Uma linha por FUNCAO hookeada, nao por pagina -- uma pagina com
        // varias funcoes compartilhando ela (RefCount > 1 no kernel, ex.
        // ZwOpenKey/ZwOpenKeyEx vizinhas no binario) gera uma linha pra cada
        // uma, CADA UMA com seu proprio Offset/Len/Bytes (vem de
        // ShvShadowFuncEntry, nao mais os mesmos bytes da pagina repetidos
        // pra todas -- ver memory/fixes.md). GPA e CR3 sao da pagina (iguais
        // pra todas as linhas que compartilham ela).
        struct ShadowRow { int pageIdx; int funcIdx; };
        std::vector<ShadowRow> rows;
        for (int i = 0; i < (int)shadows.size(); i++)
        {
            const ShvShadowEntry& p = shadows[i];
            if (p.funcs.empty())
                rows.push_back({ i, -1 });
            else
                for (int f = 0; f < (int)p.funcs.size(); f++)
                    rows.push_back({ i, f });
        }

        ImGui::TextDisabled("%zu funcao(oes) hookeada(s) em %zu pagina(s) de shadow",
                            rows.size(), shadows.size());
        ImGui::Spacing();

        static uint64_t s_selGpa    = 0;
        static bool     s_hasSel    = false;

        ImGui::BeginDisabled(!s_hasSel);
        if (ImGui::Button("Remover Shadow selecionado"))
        {
            backend.Unshadow(s_selGpa);
            s_hasSel = false;
        }
        ImGui::EndDisabled();
        if (s_hasSel)
        {
            ImGui::SameLine(0, 12);
            ImGui::TextDisabled("GPA selecionada: 0x%016llX", (unsigned long long)s_selGpa);
        }
        ImGui::Spacing();

        if (ImGui::BeginTable("shd_tbl", 7,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit,
                ImVec2(0, 0)))
        {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("GPA",    ImGuiTableColumnFlags_WidthFixed, 145.0f);
            ImGui::TableSetupColumn("VA",      ImGuiTableColumnFlags_WidthFixed, 145.0f);
            ImGui::TableSetupColumn("Modulo",  ImGuiTableColumnFlags_WidthFixed, 130.0f);
            ImGui::TableSetupColumn("CR3",     ImGuiTableColumnFlags_WidthFixed, 145.0f);
            ImGui::TableSetupColumn("Offset",  ImGuiTableColumnFlags_WidthFixed,  60.0f);
            ImGui::TableSetupColumn("Len",     ImGuiTableColumnFlags_WidthFixed,  36.0f);
            ImGui::TableSetupColumn("Bytes",   ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            auto ModNameForVa = [&](uint64_t va) -> const char* {
                for (const auto& m : kernMods)
                    if (va >= m.Base && va < m.Base + m.Size)
                    {
                        const char* base = strrchr(m.Name, '\\');
                        return base ? base + 1 : m.Name;
                    }
                return nullptr;
            };

            static const ShvShadowFuncEntry kEmptyFunc = {};

            for (int i = 0; i < (int)rows.size(); i++)
            {
                const ShadowRow&          r  = rows[i];
                const ShvShadowEntry&     p  = shadows[r.pageIdx];
                const ShvShadowFuncEntry& fn = (r.funcIdx >= 0) ? p.funcs[r.funcIdx] : kEmptyFunc;
                bool isSelected = s_hasSel && (s_selGpa == p.gpa);
                ImGui::TableNextRow();
                ImGui::PushID(i);

                ImGui::TableNextColumn();
                if (ImGui::Selectable("", isSelected,
                        ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowItemOverlap,
                        ImVec2(0, 0)))
                {
                    s_selGpa = p.gpa;
                    s_hasSel = true;
                }
                if (ImGui::BeginPopupContextItem("shd_ctx"))
                {
                    // Remove a pagina inteira -- se outras funcoes ainda
                    // compartilham ela, HpvUnhookFuncByVa decrementa o
                    // RefCount em vez de liberar (ver nt/hpv_hooks.c);
                    // so some da lista quando a ultima for removida.
                    if (ImGui::MenuItem("Remover Shadow (pagina inteira)"))
                        backend.Unshadow(p.gpa);
                    ImGui::EndPopup();
                }
                ImGui::SameLine(0, 0);
                ImGui::Text("0x%016llX", (unsigned long long)p.gpa);

                ImGui::TableNextColumn();
                if (fn.va != 0) ImGui::Text("0x%016llX", (unsigned long long)fn.va);
                else             ImGui::TextDisabled("---");

                ImGui::TableNextColumn();
                {
                    const char* modName = fn.va != 0 ? ModNameForVa(fn.va) : nullptr;
                    if (modName) ImGui::TextUnformatted(modName);
                    else          ImGui::TextDisabled("---");
                }

                ImGui::TableNextColumn();
                if (p.cr3 != 0) ImGui::Text("0x%016llX", (unsigned long long)p.cr3);
                else             ImGui::TextDisabled("kernel");

                ImGui::TableNextColumn();
                ImGui::Text("0x%X", fn.offset);

                ImGui::TableNextColumn();
                ImGui::Text("%u", fn.len);

                ImGui::TableNextColumn();
                {
                    char hexBuf[SHV_SHADOW_PATCH_MAX * 3 + 1];
                    char* q = hexBuf;
                    for (uint32_t b = 0; b < fn.len && b < SHV_SHADOW_PATCH_MAX; b++)
                        q += snprintf(q, 4, "%02X ", fn.bytes[b]);
                    if (q > hexBuf) *(q - 1) = '\0';
                    ImGui::PushStyleColor(ImGuiCol_Text, kColorWarn);
                    ImGui::TextUnformatted(hexBuf);
                    ImGui::PopStyleColor();
                }

                ImGui::PopID();
            }

            if (rows.empty())
            {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushStyleColor(ImGuiCol_Text, kColorDim);
                ImGui::TextUnformatted("Nenhum shadow patch instalado.");
                ImGui::PopStyleColor();
            }

            ImGui::EndTable();
        }
        ImGui::EndTabItem();
    }

    ImGui::EndTabBar();
}

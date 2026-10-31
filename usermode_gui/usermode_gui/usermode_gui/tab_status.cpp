/*++

Module Name:

    tab_status.cpp

Abstract:

    Tab 1: Status geral do hypervisor — contadores, syscall hooks, filtros.

--*/

#include "tab_status.h"
#include "imgui/imgui.h"
#include <stdio.h>

static const ImVec4 kColorOk    = { 0.20f, 0.90f, 0.40f, 1.0f };
static const ImVec4 kColorWarn  = { 1.00f, 0.75f, 0.00f, 1.0f };
static const ImVec4 kColorErr   = { 1.00f, 0.30f, 0.20f, 1.0f };
static const ImVec4 kColorDim   = { 0.55f, 0.55f, 0.55f, 1.0f };
static const ImVec4 kColorBlue  = { 0.40f, 0.80f, 1.00f, 1.0f };

static void SectionHeader(const char* label)
{
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, kColorBlue);
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();
    ImGui::Separator();
}

static void LabelValue(const char* label, const char* fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::PushStyleColor(ImGuiCol_Text, kColorDim);
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();
    ImGui::TableSetColumnIndex(1);
    ImGui::TextUnformatted(buf);
}

void RenderTabStatus(ShvBackend& backend)
{
    backend.Lock();
    const ShvState& st = backend.State();

    // ── Hypervisor ──────────────────────────────────────────────────────────
    SectionHeader("Hypervisor");

    if (ImGui::BeginTable("hv_tbl", 2, ImGuiTableFlags_SizingFixedFit))
    {
        ImGui::TableSetupColumn("Campo", ImGuiTableColumnFlags_WidthFixed, 160.0f);
        ImGui::TableSetupColumn("Valor", ImGuiTableColumnFlags_WidthStretch);

        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        ImGui::PushStyleColor(ImGuiCol_Text, kColorDim);
        ImGui::TextUnformatted("Presente");
        ImGui::PopStyleColor();
        ImGui::TableSetColumnIndex(1);
        if (st.stats.present)
        {
            ImGui::PushStyleColor(ImGuiCol_Text, kColorOk);
            ImGui::TextUnformatted("SIM");
            ImGui::PopStyleColor();
        }
        else
        {
            ImGui::PushStyleColor(ImGuiCol_Text, kColorErr);
            ImGui::TextUnformatted("NAO DETECTADO");
            ImGui::PopStyleColor();
        }

        LabelValue("CPU Logica",      "%d",          st.stats.cpu);
        LabelValue("Versao",          "%d",          st.stats.version);
        LabelValue("VM-Exits",        "%llu",        st.stats.exitCount);
        LabelValue("EPT Hook Hits",   "%llu",        st.stats.hookHits);
        LabelValue("LSTAR Reads",     "%llu",        st.stats.lstarReads);
        LabelValue("LSTAR Writes",    "%llu",        st.stats.lstarWrites);
        LabelValue("LSTAR Atual",     "0x%016llX",   st.stats.lastLstar);
        LabelValue("Eventos (total)", "%u",           st.stats.totalEvents);

        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        ImGui::PushStyleColor(ImGuiCol_Text, kColorDim);
        ImGui::TextUnformatted("Execute-only EPT");
        ImGui::PopStyleColor();
        ImGui::TableSetColumnIndex(1);
        ImGui::PushStyleColor(ImGuiCol_Text, st.stats.eptExecOnly ? kColorOk : kColorWarn);
        ImGui::TextUnformatted(st.stats.eptExecOnly ? "Suportado" : "Nao suportado");
        ImGui::PopStyleColor();

        ImGui::EndTable();
    }

    // ── Syscall Hooks ────────────────────────────────────────────────────────
    char hookLabel[64];
    snprintf(hookLabel, sizeof(hookLabel), "Syscall Hooks (%zu)###hooks",
             st.syscallHooks.size());
    SectionHeader(hookLabel);

    if (st.syscallHooks.empty())
    {
        ImGui::PushStyleColor(ImGuiCol_Text, kColorDim);
        ImGui::TextUnformatted("  (nenhum hook instalado)");
        ImGui::PopStyleColor();
    }
    else if (ImGui::BeginTable("hook_tbl", 6,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_ScrollY,
                ImVec2(0.0f, 140.0f)))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Index",      ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Disp",       ImGuiTableColumnFlags_WidthFixed, 40.0f);
        ImGui::TableSetupColumn("FuncVA",     ImGuiTableColumnFlags_WidthFixed, 145.0f);
        ImGui::TableSetupColumn("HookFunc",   ImGuiTableColumnFlags_WidthFixed, 145.0f);
        ImGui::TableSetupColumn("Trampoline", ImGuiTableColumnFlags_WidthFixed, 145.0f);
        ImGui::TableSetupColumn("FuncGPA",    ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto& h : st.syscallHooks)
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("0x%04X",      h.SyscallIndex);
            ImGui::TableNextColumn(); ImGui::Text("%u",          h.DisplacedSize);
            ImGui::TableNextColumn(); ImGui::Text("0x%016llX",   h.FuncVa);
            ImGui::TableNextColumn(); ImGui::Text("0x%016llX",   h.HookFuncVa);
            ImGui::TableNextColumn(); ImGui::Text("0x%016llX",   h.TrampolineVa);
            ImGui::TableNextColumn(); ImGui::Text("0x%016llX",   h.FuncGpa);
        }
        ImGui::EndTable();
    }

    // ── Filtros de Processo ─────────────────────────────────────────────────
    char filterLabel[64];
    snprintf(filterLabel, sizeof(filterLabel), "Filtros de Processo (%zu)###filters",
             st.filters.size());
    SectionHeader(filterLabel);

    if (st.filters.empty())
    {
        ImGui::PushStyleColor(ImGuiCol_Text, kColorDim);
        ImGui::TextUnformatted("  (nenhum filtro ativo)");
        ImGui::PopStyleColor();
    }
    else if (ImGui::BeginTable("filter_tbl", 3,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_SizingFixedFit,
                ImVec2(0.0f, 120.0f)))
    {
        ImGui::TableSetupColumn("Tipo", ImGuiTableColumnFlags_WidthFixed,   90.0f);
        ImGui::TableSetupColumn("PID",  ImGuiTableColumnFlags_WidthFixed,   70.0f);
        ImGui::TableSetupColumn("Nome", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto& f : st.filters)
        {
            bool isProtect = (f.Type == SHV_FILTER_TYPE_PROTECT);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushStyleColor(ImGuiCol_Text,
                isProtect ? kColorWarn : kColorOk);
            ImGui::TextUnformatted(isProtect ? "[PROTECT]" : "[MONITOR]");
            ImGui::PopStyleColor();
            ImGui::TableNextColumn(); ImGui::Text("%llu",  f.Pid);
            ImGui::TableNextColumn(); ImGui::TextUnformatted(
                f.Name[0] ? f.Name : "<unknown>");
        }
        ImGui::EndTable();
    }

    // ── Rodape de refresh ────────────────────────────────────────────────────
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, kColorDim);
    ImGui::Text("Atualizado ha %lu ms   [Refresh: automatico 1s]",
                GetTickCount() - st.lastRefreshMs);
    ImGui::PopStyleColor();

    backend.Unlock();

    if (ImGui::Button("Atualizar agora"))
        backend.RefreshAll();
}

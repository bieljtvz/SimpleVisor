/*++

Module Name:

    tab_drivers.cpp

Abstract:

    Tab 5: Lista de drivers do kernel — combina PsLoadedModuleList (via
           hypervisor) com EnumDeviceDrivers (psapi) para enriquecer paths.

--*/

#include "tab_drivers.h"
#include "imgui/imgui.h"
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <string>

#pragma comment(lib, "psapi.lib")

static const ImVec4 kColorDim  = { 0.55f, 0.55f, 0.55f, 1.0f };
static const ImVec4 kColorHead = { 0.40f, 0.80f, 1.00f, 1.0f };

struct DriverInfo {
    uint64_t    base;
    uint64_t    size;
    char        name[128];
    char        path[MAX_PATH];   // de EnumDeviceDrivers, quando disponivel
};

// Busca path via psapi dado o endereço base
static void FillPsapiPath(DriverInfo& d)
{
    static LPVOID s_psDrivers[2048];
    static int    s_psCount = 0;
    static bool   s_psFetched = false;

    if (!s_psFetched)
    {
        DWORD cb = 0;
        EnumDeviceDrivers(s_psDrivers, sizeof(s_psDrivers), &cb);
        s_psCount = (int)(cb / sizeof(LPVOID));
        s_psFetched = true;
    }

    for (int i = 0; i < s_psCount; i++)
    {
        if ((uint64_t)(uintptr_t)s_psDrivers[i] == d.base)
        {
            GetDeviceDriverFileNameA(s_psDrivers[i], d.path, sizeof(d.path));
            break;
        }
    }
}

// Lista todos os drivers usando EnumDeviceDrivers como fonte primaria
// e enriquece com dados do hypervisor (SHV_MODULE_ENTRY) quando disponivel
static std::vector<DriverInfo> BuildDriverList(ShvBackend& backend)
{
    std::vector<DriverInfo> result;

    // Fonte 1: psapi EnumDeviceDrivers
    static LPVOID drvBases[2048];
    DWORD cb = 0;
    if (!EnumDeviceDrivers(drvBases, sizeof(drvBases), &cb)) return result;
    int n = (int)(cb / sizeof(LPVOID));

    for (int i = 0; i < n; i++)
    {
        DriverInfo d = {};
        d.base = (uint64_t)(uintptr_t)drvBases[i];
        GetDeviceDriverBaseNameA(drvBases[i], d.name, sizeof(d.name));
        GetDeviceDriverFileNameA(drvBases[i], d.path, sizeof(d.path));
        result.push_back(d);
    }

    // Fonte 2: hypervisor ListModules (enriquece com tamanho real)
    backend.Lock();
    const auto& hvMods = backend.State().kernelModules;
    for (auto& d : result)
    {
        for (const auto& hm : hvMods)
        {
            if (hm.Base == d.base)
            {
                d.size = hm.Size;
                if (d.name[0] == '\0')
                    strncpy_s(d.name, hm.Name, _TRUNCATE);
                break;
            }
        }
    }
    // Adiciona entradas que so existem na lista do hypervisor
    for (const auto& hm : hvMods)
    {
        bool found = false;
        for (const auto& d : result)
            if (d.base == hm.Base) { found = true; break; }
        if (!found)
        {
            DriverInfo d = {};
            d.base = hm.Base;
            d.size = hm.Size;
            strncpy_s(d.name, hm.Name, _TRUNCATE);
            result.push_back(d);
        }
    }
    backend.Unlock();

    return result;
}

void RenderTabDrivers(ShvBackend& backend)
{
    static char                    s_search[64] = "";
    static std::vector<DriverInfo> s_drivers;
    static int                     s_selIdx  = -1;
    static bool                    s_loaded  = false;

    // ── Barra superior ────────────────────────────────────────────────────────
    if (ImGui::Button("Atualizar") || !s_loaded)
    {
        s_drivers = BuildDriverList(backend);
        s_selIdx  = -1;
        s_loaded  = true;
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220);
    ImGui::InputText("Buscar##drv", s_search, sizeof(s_search));
    ImGui::SameLine();
    ImGui::TextDisabled("(%zu drivers)", s_drivers.size());

    ImGui::Spacing();

    // ── Layout: lista | detalhes ──────────────────────────────────────────────
    float listW = 500.0f;
    ImGui::BeginChild("drv_list", ImVec2(listW, 0), true);

    if (ImGui::BeginTable("drv_tbl", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Base",     ImGuiTableColumnFlags_WidthFixed, 145.0f);
        ImGui::TableSetupColumn("Tamanho",  ImGuiTableColumnFlags_WidthFixed,  90.0f);
        ImGui::TableSetupColumn("Nome",     ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (int i = 0; i < (int)s_drivers.size(); i++)
        {
            const DriverInfo& d = s_drivers[i];
            if (s_search[0] && !strstr(d.name, s_search) && !strstr(d.path, s_search))
                continue;

            ImGui::TableNextRow();
            bool selected = (s_selIdx == i);

            ImGui::TableNextColumn();
            ImGui::PushID(i);
            if (ImGui::Selectable("", selected,
                    ImGuiSelectableFlags_SpanAllColumns |
                    ImGuiSelectableFlags_AllowItemOverlap))
                s_selIdx = i;
            ImGui::PopID();
            ImGui::SameLine(0, 0);
            ImGui::Text("0x%016llX", d.base);

            ImGui::TableNextColumn();
            if (d.size) ImGui::Text("0x%llX", d.size);
            else        ImGui::TextDisabled("---");

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(d.name[0] ? d.name : "<sem nome>");
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    ImGui::SameLine();

    // ── Painel de detalhes ────────────────────────────────────────────────────
    ImGui::BeginChild("drv_detail", ImVec2(0, 0), true);

    if (s_selIdx >= 0 && s_selIdx < (int)s_drivers.size())
    {
        const DriverInfo& d = s_drivers[s_selIdx];

        ImGui::PushStyleColor(ImGuiCol_Text, kColorHead);
        ImGui::TextUnformatted(d.name[0] ? d.name : "<sem nome>");
        ImGui::PopStyleColor();
        ImGui::Separator();

        auto row = [](const char* lbl, const char* val) {
            ImGui::PushStyleColor(ImGuiCol_Text, kColorDim);
            ImGui::Text("%-14s", lbl);
            ImGui::PopStyleColor();
            ImGui::SameLine();
            ImGui::TextUnformatted(val);
        };

        char tmp[64];
        snprintf(tmp, sizeof(tmp), "0x%016llX", d.base);   row("Base",    tmp);
        if (d.size) snprintf(tmp, sizeof(tmp), "0x%llX (%llu KB)", d.size, d.size / 1024);
        else        snprintf(tmp, sizeof(tmp), "---");
        row("Tamanho", tmp);

        ImGui::Spacing();
        ImGui::PushStyleColor(ImGuiCol_Text, kColorDim);
        ImGui::TextUnformatted("Path:");
        ImGui::PopStyleColor();
        ImGui::TextWrapped("%s", d.path[0] ? d.path : "<desconhecido>");

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Botoes de acao do hypervisor
        ImGui::TextUnformatted("EPT Hook na base do driver:");
        ImGui::SameLine();

        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.35f, 0.15f, 1.0f));
        if (ImGui::Button("Exec Hook##dv"))
            backend.HookEpt(d.base, SHV_HOOK_EXEC, 1, 0);
        ImGui::SameLine();
        if (ImGui::Button("Write Hook##dv"))
            backend.HookEpt(d.base, SHV_HOOK_WRITE, 1, 0);
        ImGui::SameLine();
        if (ImGui::Button("Remover Hook##dv"))
            backend.UnhookEpt(d.base);
        ImGui::PopStyleColor();

        ImGui::Spacing();
        if (ImGui::Button("Copiar Base"))
        {
            char cb[32]; snprintf(cb, sizeof(cb), "0x%016llX", d.base);
            ImGui::SetClipboardText(cb);
        }
        ImGui::SameLine();
        if (ImGui::Button("Copiar Path"))
            ImGui::SetClipboardText(d.path);
    }
    else
    {
        ImGui::PushStyleColor(ImGuiCol_Text, kColorDim);
        ImGui::TextUnformatted("\n  Selecione um driver na lista.");
        ImGui::PopStyleColor();
    }

    ImGui::EndChild();
}

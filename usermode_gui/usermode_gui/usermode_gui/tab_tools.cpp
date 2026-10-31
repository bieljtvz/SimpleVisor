/*++

Module Name:

    tab_tools.cpp

Abstract:

    Tab 6: Ferramentas rapidas — protecao/monitor, dump de memoria para
           arquivo e comandos gerais do hypervisor.

--*/

#include "tab_tools.h"
#include "imgui/imgui.h"
#include <stdio.h>
#include <string.h>

static const ImVec4 kColorOk      = { 0.20f, 0.90f, 0.40f, 1.0f };
static const ImVec4 kColorWarn    = { 1.00f, 0.75f, 0.00f, 1.0f };
static const ImVec4 kColorErr     = { 1.00f, 0.30f, 0.20f, 1.0f };
static const ImVec4 kColorHead    = { 0.40f, 0.80f, 1.00f, 1.0f };

static void SectionHeader(const char* label)
{
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, kColorHead);
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();
    ImGui::Separator();
}

// Salva buffer em arquivo; retorna true em sucesso
static bool DumpToFile(const char* path, const void* data, DWORD size)
{
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    WriteFile(f, data, size, &written, NULL);
    CloseHandle(f);
    return (written == size);
}

void RenderTabTools(ShvBackend& backend)
{
    // ── Protecao rapida ────────────────────────────────────────────────────────
    SectionHeader("Protecao / Monitor Rapido");

    {
        static char s_pidStr[16] = "";
        ImGui::SetNextItemWidth(120);
        ImGui::InputText("PID##tl", s_pidStr, sizeof(s_pidStr));
        uint64_t pid = strtoull(s_pidStr, nullptr, 10);
        ImGui::SameLine(0, 12);

        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.5f, 0.28f, 0.0f, 1.0f));
        if (ImGui::Button("Proteger"))   backend.Protect(pid);
        ImGui::SameLine();
        if (ImGui::Button("Desproteger")) backend.Unprotect(pid);
        ImGui::PopStyleColor();

        ImGui::SameLine(0, 16);

        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.28f, 0.50f, 1.0f));
        if (ImGui::Button("Monitorar"))     backend.Monitor(pid);
        ImGui::SameLine();
        if (ImGui::Button("Parar Monitor")) backend.Unmonitor(pid);
        ImGui::PopStyleColor();
    }

    // ── Dump de memoria para arquivo ──────────────────────────────────────────
    SectionHeader("Dump de Memoria para Arquivo");

    {
        static char   s_addrStr[32]  = "";
        static char   s_sizeStr[16]  = "4096";
        static char   s_pidStr[16]   = "0";
        static char   s_fileStr[260] = "dump.bin";
        static int    s_mode         = 1;   // 0=fisica 1=virtual
        static char   s_lastMsg[128] = "";
        static bool   s_lastOk       = true;

        ImGui::RadioButton("Fisica##dm",  &s_mode, 0); ImGui::SameLine();
        ImGui::RadioButton("Virtual##dm", &s_mode, 1);

        ImGui::SetNextItemWidth(200); ImGui::InputText("Endereco##dm", s_addrStr, sizeof(s_addrStr));
        ImGui::SameLine();
        ImGui::SetNextItemWidth(90);  ImGui::InputText("Tamanho##dm", s_sizeStr, sizeof(s_sizeStr));
        if (s_mode == 1)
        {
            ImGui::SameLine();
            ImGui::SetNextItemWidth(80);
            ImGui::InputText("PID##dm", s_pidStr, sizeof(s_pidStr));
        }
        ImGui::SetNextItemWidth(350); ImGui::InputText("Arquivo##dm", s_fileStr, sizeof(s_fileStr));
        ImGui::SameLine();
        if (ImGui::Button("Dump"))
        {
            uint64_t addr = strtoull(s_addrStr, nullptr, 16);
            uint32_t sz   = (uint32_t)strtoul(s_sizeStr, nullptr, 10);
            uint64_t pid  = strtoull(s_pidStr, nullptr, 10);
            if (sz > SHV_MAX_READ_SIZE) sz = SHV_MAX_READ_SIZE;

            static uint8_t buf[SHV_MAX_READ_SIZE];
            uint32_t got = 0;
            ShvBackend::CmdResult r;

            if (s_mode == 0) r = backend.ReadPhys(addr, sz, buf, &got);
            else             r = backend.ReadVirt(addr, sz, pid, buf, &got);

            if (r.ok && got > 0)
            {
                bool saved = DumpToFile(s_fileStr, buf, got);
                s_lastOk = saved;
                if (saved)
                    snprintf(s_lastMsg, sizeof(s_lastMsg), "Salvo: %u bytes em %s", got, s_fileStr);
                else
                    snprintf(s_lastMsg, sizeof(s_lastMsg), "Falha ao salvar arquivo");
            }
            else
            {
                s_lastOk = false;
                snprintf(s_lastMsg, sizeof(s_lastMsg), "Falha na leitura: %s",
                         ShvClient::StatusString(r.status));
            }
        }

        if (s_lastMsg[0])
        {
            ImGui::PushStyleColor(ImGuiCol_Text, s_lastOk ? kColorOk : kColorErr);
            ImGui::Text("  %s", s_lastMsg);
            ImGui::PopStyleColor();
        }
    }

    // ── Comandos gerais ───────────────────────────────────────────────────────
    SectionHeader("Comandos Gerais");

    {
        static char s_gpaResult[64] = "";
        static bool s_beepOk = false;

        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.5f, 0.10f, 0.10f, 1.0f));
        if (ImGui::Button("Remover Todos os Hooks"))
        {
            backend.UnhookAll();
        }
        ImGui::PopStyleColor();
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Remove todos os EPT hooks instalados");

        ImGui::SameLine(0, 16);

        if (ImGui::Button("Beep Shadow Setup"))
        {
            uint64_t gpa = 0;
            auto r = backend.BeepShadowSetup(&gpa);
            s_beepOk = r.ok;
            if (r.ok) snprintf(s_gpaResult, sizeof(s_gpaResult), "GPA=0x%llX", gpa);
            else      snprintf(s_gpaResult, sizeof(s_gpaResult), "Falhou");
        }
        if (s_gpaResult[0])
        {
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Text, s_beepOk ? kColorOk : kColorErr);
            ImGui::TextUnformatted(s_gpaResult);
            ImGui::PopStyleColor();
        }

        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.10f, 0.30f, 0.50f, 1.0f));
        if (ImGui::Button("Reconectar"))
        {
            backend.Disconnect();
            backend.Connect();
        }
        ImGui::PopStyleColor();
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Fecha e reabre o canal de comunicacao");
    }

    // ── Listas rapidas de filtros ─────────────────────────────────────────────
    SectionHeader("Filtros Ativos (resumo)");

    {
        backend.Lock();
        const auto& filters = backend.State().filters;
        if (filters.empty())
        {
            ImGui::TextDisabled("  (nenhum filtro ativo)");
        }
        for (const auto& f : filters)
        {
            bool prot = (f.Type == SHV_FILTER_TYPE_PROTECT);
            ImGui::PushStyleColor(ImGuiCol_Text, prot ? kColorWarn : kColorOk);
            ImGui::Text("  %-10s  PID %llu  %s",
                        prot ? "[PROTECT]" : "[MONITOR]",
                        f.Pid,
                        f.Name[0] ? f.Name : "<unknown>");
            ImGui::PopStyleColor();

            ImGui::SameLine(0, 12);
            char rmLabel[32];
            snprintf(rmLabel, sizeof(rmLabel), "X##rm%llu%u", f.Pid, f.Type);
            if (ImGui::SmallButton(rmLabel))
            {
                uint64_t pid = f.Pid;
                uint8_t  tp  = f.Type;
                backend.Unlock();
                if (tp == SHV_FILTER_TYPE_PROTECT) backend.Unprotect(pid);
                else                               backend.Unmonitor(pid);
                backend.Lock();
            }
        }
        backend.Unlock();
    }
}

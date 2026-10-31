/*++

Module Name:

    tab_memory.cpp

Abstract:

    Tab 3: Ferramentas de memoria — traducao VA→PA, leitura com hex editor
           nativo (imgui_hex), shadow patch e EPT hooks.

--*/

#include "tab_memory.h"
#include "imgui/imgui.h"
#include "imgui/imgui_hexview/imgui_hex.h"
#include <stdio.h>
#include <string.h>

static const ImVec4 kColorOk   = { 0.20f, 0.90f, 0.40f, 1.0f };
static const ImVec4 kColorErr  = { 1.00f, 0.30f, 0.20f, 1.0f };

// ── Inter-tab navigation state ────────────────────────────────────────────────
bool            g_memTabSelectPending = false;
static uint64_t s_readAddr            = 0;
static uint64_t s_readPid             = 0;
static bool     s_readAuto            = false;

void TabMemoryNavigateTo(uint64_t addr, uint64_t pid)
{
    s_readAddr            = addr;
    s_readPid             = pid;
    s_readAuto            = true;
    g_memTabSelectPending = true;
}

// Converte string hex (ex: "FF2500") para bytes; retorna numero de bytes
static int HexStringToBytes(const char* s, uint8_t* out, int maxLen)
{
    int n = 0;
    while (*s && *(s + 1) && n < maxLen)
    {
        char pair[3] = { s[0], s[1], 0 };
        out[n++] = (uint8_t)strtoul(pair, nullptr, 16);
        s += 2;
        while (*s == ' ') s++;
    }
    return n;
}

void RenderTabMemory(ShvBackend& backend)
{
    if (!ImGui::BeginTabBar("mem_tabs")) return;

    // ── Traducao VA ───────────────────────────────────────────────────────────
    if (ImGui::BeginTabItem("Trad. VA"))
    {
        ImGui::Spacing();
        {
            static char s_vaStr[32]  = "";
            static char s_pidStr[16] = "0";
            static char s_paStr[32]  = "";
            static bool s_ok         = true;

            ImGui::SetNextItemWidth(200); ImGui::InputText("VA##tr", s_vaStr, sizeof(s_vaStr));
            ImGui::SameLine();
            ImGui::SetNextItemWidth(80);  ImGui::InputText("PID##tr", s_pidStr, sizeof(s_pidStr));
            ImGui::SameLine();
            if (ImGui::Button("Traduzir"))
            {
                uint64_t va  = strtoull(s_vaStr,  nullptr, 16);
                uint64_t pid = strtoull(s_pidStr, nullptr, 10);
                uint64_t pa  = 0;
                auto r = backend.TranslateVa(va, pid, &pa);
                s_ok = r.ok;
                if (r.ok) snprintf(s_paStr, sizeof(s_paStr), "0x%016llX", pa);
                else      snprintf(s_paStr, sizeof(s_paStr), "ERRO: %s",
                                   ShvClient::StatusString(r.status));
            }
            if (s_paStr[0])
            {
                ImGui::SameLine();
                ImGui::PushStyleColor(ImGuiCol_Text, s_ok ? kColorOk : kColorErr);
                ImGui::Text("PA = %s", s_paStr);
                ImGui::PopStyleColor();
            }
        }
        ImGui::EndTabItem();
    }

    // ── Leitura ───────────────────────────────────────────────────────────────
    {
        ImGuiTabItemFlags lFlags = s_readAuto ? ImGuiTabItemFlags_SetSelected : 0;
        if (ImGui::BeginTabItem("Leitura", nullptr, lFlags))
        {
            ImGui::Spacing();
            {
                static char     s_addrStr[32] = "";
                static char     s_sizeStr[16] = "256";
                static char     s_pidStr[16]  = "0";
                static int      s_mode        = 1;   // 0=fisica 1=virtual
                static uint8_t  s_buf[SHV_MAX_READ_SIZE] = {};
                static uint32_t s_bufSize     = 0;
                static uint64_t s_baseAddr    = 0;
                static ImGuiHexEditorState s_hexState = {};

                // Consume inter-tab navigation: pre-fill + auto-read 256 bytes
                if (s_readAuto)
                {
                    snprintf(s_addrStr, sizeof(s_addrStr), "%llX", s_readAddr);
                    snprintf(s_sizeStr, sizeof(s_sizeStr), "256");
                    snprintf(s_pidStr,  sizeof(s_pidStr),  "%llu", s_readPid);
                    s_mode = 1;

                    uint32_t got = 0;
                    ShvBackend::CmdResult r = backend.ReadVirt(
                        s_readAddr, 256, s_readPid, s_buf, &got);
                    if (r.ok && got > 0)
                    {
                        s_bufSize              = got;
                        s_baseAddr             = s_readAddr;
                        s_hexState.Bytes       = s_buf;
                        s_hexState.MaxBytes    = (int)got;
                        s_hexState.ReadOnly    = true;
                        s_hexState.ShowAscii   = true;
                        s_hexState.ShowAddress = true;
                        s_hexState.Separators  = 8;
                    }
                    else { s_bufSize = 0; }

                    s_readAuto = false;
                    s_readAddr = 0;
                    s_readPid  = 0;
                }

                ImGui::RadioButton("Fisica",  &s_mode, 0); ImGui::SameLine();
                ImGui::RadioButton("Virtual", &s_mode, 1); ImGui::SameLine(0, 16);
                ImGui::SetNextItemWidth(200); ImGui::InputText("Endereco##rd", s_addrStr, sizeof(s_addrStr));
                ImGui::SameLine();
                ImGui::SetNextItemWidth(70);  ImGui::InputText("Tam##rd", s_sizeStr, sizeof(s_sizeStr));
                if (s_mode == 1)
                {
                    ImGui::SameLine();
                    ImGui::SetNextItemWidth(70);
                    ImGui::InputText("PID##rd", s_pidStr, sizeof(s_pidStr));
                }
                ImGui::SameLine();
                if (ImGui::Button("Ler"))
                {
                    uint64_t addr = strtoull(s_addrStr, nullptr, 16);
                    uint32_t sz   = (uint32_t)strtoul(s_sizeStr, nullptr, 10);
                    uint64_t pid  = strtoull(s_pidStr,  nullptr, 10);
                    if (sz > SHV_MAX_READ_SIZE) sz = SHV_MAX_READ_SIZE;

                    uint32_t got = 0;
                    ShvBackend::CmdResult r;
                    if (s_mode == 0) r = backend.ReadPhys(addr, sz, s_buf, &got);
                    else             r = backend.ReadVirt(addr, sz, pid, s_buf, &got);

                    if (r.ok && got > 0)
                    {
                        s_bufSize              = got;
                        s_baseAddr             = addr;
                        s_hexState.Bytes       = s_buf;
                        s_hexState.MaxBytes    = (int)got;
                        s_hexState.ReadOnly    = true;
                        s_hexState.ShowAscii   = true;
                        s_hexState.ShowAddress = true;
                        s_hexState.Separators  = 8;
                    }
                    else { s_bufSize = 0; }
                }

                if (s_bufSize > 0)
                {
                    ImGui::SameLine(0, 16);
                    ImGui::TextDisabled("%u bytes @ 0x%llX", s_bufSize, s_baseAddr);
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Copiar hex"))
                    {
                        static char hexClip[SHV_MAX_READ_SIZE * 3 + 1];
                        char* p = hexClip;
                        for (uint32_t i = 0; i < s_bufSize && (p - hexClip) < (int)sizeof(hexClip) - 3; i++)
                            p += snprintf(p, 4, "%02X ", s_buf[i]);
                        ImGui::SetClipboardText(hexClip);
                    }
                }

                if (s_bufSize > 0)
                {
                    ImGui::Spacing();
                    ImVec2 hexSize(0.0f, 200.0f);
                    if (ImGui::BeginHexEditor("##hexview", &s_hexState, hexSize))
                        ImGui::EndHexEditor();
                }
            }
            ImGui::EndTabItem();
        }
    }

    // ── Shadow Patch ──────────────────────────────────────────────────────────
    if (ImGui::BeginTabItem("Shadow Patch"))
    {
        ImGui::Spacing();
        {
            static char s_gpaStr[32]   = "";
            static char s_offStr[16]   = "0";
            static char s_bytesStr[80] = "";

            ImGui::SetNextItemWidth(200); ImGui::InputText("GPA (hex)##sh", s_gpaStr, sizeof(s_gpaStr));
            ImGui::SameLine();
            ImGui::SetNextItemWidth(80);  ImGui::InputText("Offset##sh", s_offStr, sizeof(s_offStr));
            ImGui::SetNextItemWidth(360);
            ImGui::InputText("Bytes hex (sem espaco, ex: FF2500)##sh",
                             s_bytesStr, sizeof(s_bytesStr));
            ImGui::SameLine();
            if (ImGui::Button("Aplicar##sh"))
            {
                uint64_t gpa    = strtoull(s_gpaStr,  nullptr, 16);
                uint32_t offset = (uint32_t)strtoul(s_offStr, nullptr, 16);
                uint8_t  bytes[SHV_SHADOW_PATCH_MAX];
                int      len = HexStringToBytes(s_bytesStr, bytes, SHV_SHADOW_PATCH_MAX);
                if (len > 0) backend.ShadowPatch(gpa, offset, bytes, (uint32_t)len);
            }
            ImGui::SameLine();
            if (ImGui::Button("Remover##sh"))
                backend.Unshadow(strtoull(s_gpaStr, nullptr, 16));
            ImGui::SameLine();
            if (ImGui::Button("Beep Shadow Setup"))
            {
                uint64_t gpa = 0;
                backend.BeepShadowSetup(&gpa);
            }
        }
        ImGui::EndTabItem();
    }

    // ── EPT Hook ──────────────────────────────────────────────────────────────
    if (ImGui::BeginTabItem("EPT Hook"))
    {
        ImGui::Spacing();
        {
            static char s_vaStr[32]    = "";
            static char s_pidStr[16]   = "0";
            static char s_rangeStr[16] = "1";
            static bool s_exec  = true;
            static bool s_write = false;
            static bool s_read  = false;

            ImGui::SetNextItemWidth(200); ImGui::InputText("VA##ep", s_vaStr, sizeof(s_vaStr));
            ImGui::SameLine();
            ImGui::SetNextItemWidth(70);  ImGui::InputText("PID##ep", s_pidStr, sizeof(s_pidStr));
            ImGui::SameLine();
            ImGui::SetNextItemWidth(60);  ImGui::InputText("Range##ep", s_rangeStr, sizeof(s_rangeStr));
            ImGui::SameLine(0, 16);
            ImGui::Checkbox("Exec##ep",  &s_exec);  ImGui::SameLine();
            ImGui::Checkbox("Write##ep", &s_write); ImGui::SameLine();
            ImGui::Checkbox("Read##ep",  &s_read);  ImGui::SameLine(0, 16);

            if (ImGui::Button("Instalar##ep"))
            {
                uint8_t type = (s_exec  ? SHV_HOOK_EXEC  : 0)
                             | (s_write ? SHV_HOOK_WRITE : 0)
                             | (s_read  ? SHV_HOOK_READ  : 0);
                if (type)
                {
                    auto res = backend.HookEpt(strtoull(s_vaStr, nullptr, 16), type,
                                               strtoull(s_rangeStr, nullptr, 10),
                                               strtoull(s_pidStr, nullptr, 10));
                    if (res.ok) backend.RefreshAll();
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Remover##ep"))
                backend.UnhookEpt(strtoull(s_vaStr, nullptr, 16));
            ImGui::SameLine();
            if (ImGui::Button("Remover Todos##ep"))
                backend.UnhookAll();
        }
        ImGui::EndTabItem();
    }

    ImGui::EndTabBar();
}

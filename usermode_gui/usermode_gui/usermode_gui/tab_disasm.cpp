/*++

Module Name:

    tab_disasm.cpp

Abstract:

    Desmontador de instrucoes x86-64 (Zydis) usado dentro da aba
    Memoria->Leitura: recebe o mesmo buffer ja lido por ReadVirt/ReadPhys
    (sem leitura propria) e renderiza como tabela endereco/bytes/instrucao.

    Resolucao de simbolo (modulo+offset): um hook no formatter do Zydis
    (ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS) intercepta todo endereco
    absoluto impresso (operando de memoria sem base/index, ex. "lea rcx,
    [0x40000000]", e alvos de call/jmp) e, se o endereco cair dentro de um
    modulo conhecido (kernel ou, se um PID foi informado, as DLLs desse
    processo), imprime "modulo+0xOFFSET" em vez do hex cru.

    Modulos do processo vem do KERNEL via IOCTL (ShvBackend::ListProcessModules
    -> SHV_CMD_LIST_PROCESS_MODULES -> driver le a PEB do processo alvo apos
    attach), nao de CreateToolhelp32Snapshot em usermode -- assim funciona
    mesmo contra processos protegidos (PPL), que negam
    PROCESS_QUERY_INFORMATION pra um chamador usermode comum.

--*/

#include "tab_disasm.h"
#include "imgui/imgui.h"
#include <Zydis/Zydis.h>
#include <stdio.h>
#include <string.h>

static const ImVec4 kColorDim = { 0.55f, 0.55f, 0.55f, 1.0f };

struct DisasmLine
{
    uint64_t Address;
    uint8_t  Length;
    uint8_t  Bytes[ZYDIS_MAX_INSTRUCTION_LENGTH];
    char     Text[128];
};

// ── Modulos do processo (DLLs), com cache curto por PID ───────────────────────
// Evita um IOCTL a cada frame enquanto o checkbox de desmontar fica ligado --
// mesmo esquema de refresh (2s) usado em tab_events.cpp.
struct ProcModCache
{
    uint64_t                      Pid       = 0;
    DWORD                         RefreshMs = 0;
    std::vector<SHV_MODULE_ENTRY> Mods;
};
static ProcModCache s_procModCache;

static const std::vector<SHV_MODULE_ENTRY>& GetProcessModules(uint64_t pid, ShvBackend& backend)
{
    static const std::vector<SHV_MODULE_ENTRY> kEmpty;
    if (pid == 0) return kEmpty;

    DWORD now = GetTickCount();
    if (s_procModCache.Pid == pid && (now - s_procModCache.RefreshMs) < 2000)
        return s_procModCache.Mods;

    s_procModCache.Pid       = pid;
    s_procModCache.RefreshMs = now;
    backend.ListProcessModules(pid, s_procModCache.Mods); // limpa e preenche; vazio se falhar
    return s_procModCache.Mods;
}

static const char* ModuleBaseName(const char* name)
{
    const char* last = name;
    for (const char* p = name; *p; p++)
        if (*p == '\\' || *p == '/') last = p + 1;
    return last;
}

static bool FindModuleForAddr(const std::vector<SHV_MODULE_ENTRY>& mods, uint64_t addr,
                               const char** outName, uint64_t* outBase)
{
    for (const auto& m : mods)
    {
        if (addr >= m.Base && addr < m.Base + m.Size)
        {
            *outName = ModuleBaseName(m.Name);
            *outBase = m.Base;
            return true;
        }
    }
    return false;
}

// ── Hook do formatter: endereco absoluto -> "modulo+offset" quando resolvido ──
// Contexto (lista de modulos da chamada atual) fica num ponteiro estatico --
// desmontagem roda só na thread de render do ImGui, sem reentrancia.
static const std::vector<SHV_MODULE_ENTRY>* s_symKernMods = nullptr;
static const std::vector<SHV_MODULE_ENTRY>* s_symProcMods = nullptr;
static ZydisFormatterFunc                   s_defaultPrintAddressAbs = nullptr;

static ZyanStatus ZydisPrintAddressAbsHook(const ZydisFormatter* formatter,
                                            ZydisFormatterBuffer* buffer,
                                            ZydisFormatterContext* context)
{
    ZyanU64 address = 0;
    ZyanStatus calcStatus = ZydisCalcAbsoluteAddress(
        context->instruction, context->operand, context->runtime_address, &address);

    if (ZYAN_SUCCESS(calcStatus))
    {
        const char* name  = nullptr;
        uint64_t    base  = 0;
        bool        found = (s_symKernMods && FindModuleForAddr(*s_symKernMods, address, &name, &base))
                          || (s_symProcMods && FindModuleForAddr(*s_symProcMods, address, &name, &base));

        if (found)
        {
            ZyanString* str;
            ZYAN_CHECK(ZydisFormatterBufferGetString(buffer, &str));

            uint64_t off = address - base;
            char text[128];
            if (off) snprintf(text, sizeof(text), "%s+0x%llX", name, (unsigned long long)off);
            else     snprintf(text, sizeof(text), "%s", name);

            ZyanStringView view;
            ZYAN_CHECK(ZyanStringViewInsideBuffer(&view, text));
            return ZyanStringAppend(str, &view);
        }
    }

    // Nao resolvido: cai pro comportamento padrao do Zydis (hex cru)
    return s_defaultPrintAddressAbs(formatter, buffer, context);
}

// Desmonta sequencialmente todo o buffer [base, base+size) em instrucoes;
// bytes que nao formam instrucao valida viram uma linha "db" de 1 byte, pra
// nao travar o avanco do desmontador.
static void DisassembleBuffer(const uint8_t* buf, uint32_t size, uint64_t base,
                               const std::vector<SHV_MODULE_ENTRY>& kernMods,
                               const std::vector<SHV_MODULE_ENTRY>& procMods,
                               std::vector<DisasmLine>& out)
{
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    // ZydisFormatterSetHook e in/out: entra com o novo hook, sai com o
    // anterior (o default interno do Zydis, numa formatter recem-inicializada)
    // -- guardamos esse default uma vez so, pra usar de fallback no hook.
    {
        ZydisFormatterFunc hook = (ZydisFormatterFunc)&ZydisPrintAddressAbsHook;
        ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS,
                               (const void**)&hook);
        if (!s_defaultPrintAddressAbs)
            s_defaultPrintAddressAbs = hook;
    }

    s_symKernMods = &kernMods;
    s_symProcMods = &procMods;

    out.clear();
    uint32_t offset = 0;
    while (offset < size)
    {
        ZydisDecodedInstruction instr;
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];

        ZyanStatus status = ZydisDecoderDecodeFull(
            &decoder, buf + offset, size - offset, &instr, ops);

        DisasmLine line = {};
        line.Address    = base + offset;

        if (ZYAN_SUCCESS(status))
        {
            line.Length = instr.length;
            memcpy(line.Bytes, buf + offset, instr.length);

            char text[128] = {};
            ZydisFormatterFormatInstruction(
                &formatter, &instr, ops, instr.operand_count_visible,
                text, sizeof(text), line.Address, nullptr);
            snprintf(line.Text, sizeof(line.Text), "%s", text);

            offset += instr.length;
        }
        else
        {
            line.Length   = 1;
            line.Bytes[0] = buf[offset];
            snprintf(line.Text, sizeof(line.Text), "db 0x%02X (invalido)", buf[offset]);
            offset += 1;
        }

        out.push_back(line);
    }

    s_symKernMods = nullptr;
    s_symProcMods = nullptr;
}

void RenderDisasmView(const uint8_t* Buf, uint32_t Size, uint64_t BaseAddr,
                      uint64_t Pid, const std::vector<SHV_MODULE_ENTRY>& KernMods,
                      ShvBackend& Backend)
{
    if (Size == 0) return;

    const std::vector<SHV_MODULE_ENTRY>& procMods = GetProcessModules(Pid, Backend);

    std::vector<DisasmLine> lines;
    DisassembleBuffer(Buf, Size, BaseAddr, KernMods, procMods, lines);

    ImGui::TextDisabled("%zu instrucoes", lines.size());
    ImGui::Spacing();

    // Altura 0 = estica ate o fim da janela/child pai (mesmo esquema das
    // outras abas que fazem BeginChild com ImVec2(0,0)).
    ImVec2 tableSize(0.0f, 0.0f);
    ImGui::BeginChild("##disasm_list", tableSize, true);

    if (ImGui::BeginTable("disasm_tbl", 3,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY))
    {
        ImGui::TableSetupColumn("Endereco",  ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableSetupColumn("Bytes",     ImGuiTableColumnFlags_WidthFixed, 230.0f);
        ImGui::TableSetupColumn("Instrucao", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto& ln : lines)
        {
            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%016llX", ln.Address);

            ImGui::TableSetColumnIndex(1);
            char hex[ZYDIS_MAX_INSTRUCTION_LENGTH * 3 + 1] = {};
            char* p = hex;
            for (int i = 0; i < ln.Length; i++)
                p += snprintf(p, 4, "%02X ", ln.Bytes[i]);
            ImGui::PushStyleColor(ImGuiCol_Text, kColorDim);
            ImGui::TextUnformatted(hex);
            ImGui::PopStyleColor();

            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(ln.Text);
        }

        ImGui::EndTable();
    }
    ImGui::EndChild();
}

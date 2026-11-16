#pragma once
#include <cstdint>
#include <vector>
#include "shv_backend.h"

// Desmonta [Buf, Buf+Size) (instrucoes x86-64) a partir de BaseAddr e
// renderiza como tabela ImGui (Endereco/Bytes/Instrucao). Usado dentro da
// aba Memoria->Leitura, junto com o hex editor, sobre o mesmo buffer ja lido.
//
// KernMods: lista de modulos do kernel (backend.State().kernelModules) --
// usada pra resolver endereco absoluto em operando (ex.: "lea rcx, [0x...]")
// para "modulo+offset" em vez do hex cru.
// Pid: processo cujos modulos (EXE+DLLs) tambem entram na resolucao, alem
// dos do kernel; 0 = so kernel. Modulos do processo sao obtidos via
// Backend.ListProcessModules (IOCTL -> kernel le a PEB do processo alvo),
// NAO via CreateToolhelp32Snapshot em usermode -- funciona mesmo contra
// processos protegidos (PPL), que negam handle de query pro usermode.
void RenderDisasmView(const uint8_t* Buf, uint32_t Size, uint64_t BaseAddr,
                      uint64_t Pid, const std::vector<SHV_MODULE_ENTRY>& KernMods,
                      ShvBackend& Backend);

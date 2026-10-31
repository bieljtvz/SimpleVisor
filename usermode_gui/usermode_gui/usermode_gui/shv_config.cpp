/*++

Module Name:

    shv_config.cpp

Abstract:

    Implementacao de CfgLoad / CfgSave usando Windows INI API
    (GetPrivateProfileInt / WritePrivateProfileString).
    Arquivo: shv_layout.ini no mesmo diretorio do executavel.

--*/

#include "shv_config.h"
#include <windows.h>
#include <string.h>

// Defaults
ShvConfig g_cfg = {
    false,   // evtShowModOff
    { true, true, true, true, true, true, true, true, true, true, true }
};

static const char* kSection = "events_ept";

static const char* kColKeys[SHV_CFG_EPT_COL_COUNT] = {
    "col_hora", "col_seq", "col_cpu", "col_tipo", "col_causador",
    "col_destino", "col_rip_value", "col_retaddr", "col_aux_gpa",
    "col_va_fault", "col_cr3"
};

// Monta caminho absoluto: <dir_exe>\shv_layout.ini
static void GetIniPath(char* buf, DWORD sz)
{
    GetModuleFileNameA(NULL, buf, sz);
    // Encontra o ultimo separador e trunca o nome do exe
    char* last = buf;
    for (char* p = buf; *p; p++)
        if (*p == '\\' || *p == '/') last = p;
    *last = '\0';
    strcat_s(buf, sz, "\\shv_layout.ini");
}

void CfgLoad()
{
    char path[MAX_PATH];
    GetIniPath(path, sizeof(path));

    g_cfg.evtShowModOff =
        GetPrivateProfileIntA(kSection, "show_mod_off", 0, path) != 0;

    for (int i = 0; i < SHV_CFG_EPT_COL_COUNT; i++)
        g_cfg.evtColVis[i] =
            GetPrivateProfileIntA(kSection, kColKeys[i], 1, path) != 0;
}

void CfgSave()
{
    char path[MAX_PATH];
    GetIniPath(path, sizeof(path));

    WritePrivateProfileStringA(kSection, "show_mod_off",
        g_cfg.evtShowModOff ? "1" : "0", path);

    for (int i = 0; i < SHV_CFG_EPT_COL_COUNT; i++)
        WritePrivateProfileStringA(kSection, kColKeys[i],
            g_cfg.evtColVis[i] ? "1" : "0", path);
}

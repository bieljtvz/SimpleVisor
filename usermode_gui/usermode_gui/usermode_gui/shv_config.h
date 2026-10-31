/*++

Module Name:

    shv_config.h

Abstract:

    Configuracao persistente da GUI: carregada na inicializacao,
    salva no fechamento. Arquivo: shv_layout.ini (mesmo diretorio do exe).

--*/

#pragma once

#define SHV_CFG_EPT_COL_COUNT 11

struct ShvConfig {
    // Tabela Eventos > EPT
    bool evtShowModOff;
    bool evtColVis[SHV_CFG_EPT_COL_COUNT];
};

// Instancia global -- lida por tab_events.cpp, salva em main.cpp
extern ShvConfig g_cfg;

// Carrega shv_layout.ini (falha silenciosa: usa defaults)
void CfgLoad();

// Salva shv_layout.ini
void CfgSave();

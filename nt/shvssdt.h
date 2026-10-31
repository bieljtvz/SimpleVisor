#pragma once
#include <ntifs.h>

// -----------------------------------------------------------------------
// SSDT (System Service Descriptor Table) utilities
// -----------------------------------------------------------------------

typedef struct _SYSTEM_SERVICE_TABLE
{
    PULONG  ServiceTableBase;
    PULONG  ServiceCounterTableBase;
    ULONG   NumberOfServices;
    PUCHAR  ParamTableBase;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

// Ponteiro para a SSDT resolvida em ShvSsdtInit().
extern PSYSTEM_SERVICE_TABLE g_KeServiceDescriptorTable;

// Localiza a SSDT varrendo o codigo de KiSystemCall64 (LSTAR).
// Deve ser chamada uma vez, em PASSIVE_LEVEL, antes das demais funcoes.
// Retorna TRUE se encontrou com sucesso.
BOOLEAN ShvSsdtInit(VOID);

// Retorna o VA atual da funcao de indice 'id' na SSDT.
// Requer ShvSsdtInit() chamado com sucesso antes.
ULONGLONG ShvSsdtGetFuncAddr(ULONG Id);

// Converte um VA de funcao de volta para o valor de offset da entrada SSDT.
ULONG ShvSsdtGetOffset(ULONGLONG FuncAddr);

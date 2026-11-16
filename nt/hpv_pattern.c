/*++

Module Name:

    hpv_pattern.c

Abstract:

    Busca de assinatura de bytes (pattern/signature scan) em memoria de
    kernel. Usado pra localizar funcoes internas do ntoskrnl.exe que NAO
    sao exportadas (MmGetSystemRoutineAddress nao resolve, ex.: PspExitProcess)
    -- diferente de HpvHookFuncByName (hpv_hooks.c), que so funciona pra funcoes exportadas.

  

Environment:

    Kernel mode, qualquer IRQL (so le memoria, nao faz nenhuma chamada de
    sistema) -- mas so e seguro chamar contra memoria que nao pode ser
    paginada ou liberada durante a busca (ex.: a secao .text de ntoskrnl.exe,
    sempre residente).

--*/

#include <ntifs.h>
#include <ntimage.h>

// Layout estavel desde Windows Vista/7 at Windows 11 (so usamos os campos
// no comeco da struct: InLoadOrderLinks, DllBase, SizeOfImage, BaseDllName).
// Nao declarada nos headers publicos da WDK.
typedef struct _HPV_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY      InLoadOrderLinks;
    PVOID           ExceptionTable;
    ULONG           ExceptionTableSize;
    PVOID           GpValue;
    PVOID           NonPagedDebugInfo;
    PVOID           DllBase;
    PVOID           EntryPoint;
    ULONG           SizeOfImage;
    UNICODE_STRING  FullDllName;
    UNICODE_STRING  BaseDllName;
} HPV_LDR_DATA_TABLE_ENTRY, *PHPV_LDR_DATA_TABLE_ENTRY;

//
// Acha a base e o tamanho da secao .text do ntoskrnl.exe carregado --
// necessario pra limitar o range de HpvFindPattern (as demais secoes podem
// nao estar residentes ou conter dados que gerariam falso-positivo).
//
// Tecnica: resolve PsLoadedModuleList (dado exportado, lista duplamente
// encadeada de todos os modulos carregados), percorre procurando a entrada
// cujo BaseDllName seja "ntoskrnl.exe", pega DllBase/SizeOfImage dali, e por
// fim faz parsing manual do PE (IMAGE_DOS_HEADER/IMAGE_NT_HEADERS/
// IMAGE_SECTION_HEADER) pra achar a secao chamada ".text". Se por algum
// motivo a secao nao for localizada, cai pra varrer o modulo inteiro
// (DllBase..DllBase+SizeOfImage) como fallback.
//
//
// So a parte de achar DllBase/SizeOfImage do ntoskrnl.exe via PsLoadedModuleList
// (sem parsing de PE) -- usada tanto por HpvFindNtoskrnlModule (modulo inteiro)
// quanto por HpvFindNtoskrnlTextSection (que ainda restringe pra secao .text).
//
static BOOLEAN
HpvFindNtoskrnlModuleBase (
    _Out_ PVOID* ModuleBase,
    _Out_ ULONG* ModuleSize
    )
{
    UNICODE_STRING             listName;
    PLIST_ENTRY                listHead;
    PLIST_ENTRY                entry;
    PHPV_LDR_DATA_TABLE_ENTRY  mod;
    UNICODE_STRING             targetName;

    *ModuleBase = NULL;
    *ModuleSize = 0;

    RtlInitUnicodeString(&listName, L"PsLoadedModuleList");
    listHead = (PLIST_ENTRY)MmGetSystemRoutineAddress(&listName);
    if (listHead == NULL)
        return FALSE;

    RtlInitUnicodeString(&targetName, L"ntoskrnl.exe");

    for (entry = listHead->Flink; entry != listHead; entry = entry->Flink)
    {
        mod = (PHPV_LDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(
                  entry, HPV_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (mod->BaseDllName.Buffer != NULL &&
            RtlEqualUnicodeString(&mod->BaseDllName, &targetName, TRUE))
        {
            *ModuleBase = mod->DllBase;
            *ModuleSize = mod->SizeOfImage;
            return TRUE;
        }
    }

    return FALSE;
}

//
// Acha a base e o tamanho do modulo ntoskrnl.exe INTEIRO (sem restringir a
// nenhuma secao especifica) -- usado quando a assinatura pode estar fora da
// secao .text (ex.: .rdata/.data por engano no scan, ou builds onde o layout
// de secoes difere), em vez de HpvFindNtoskrnlTextSection.
//
BOOLEAN
HpvFindNtoskrnlModule (
    _Out_ UINT64* Base,
    _Out_ SIZE_T* Size
    )
{
    PVOID moduleBase;
    ULONG moduleSize;

    *Base = 0;
    *Size = 0;

    if (!HpvFindNtoskrnlModuleBase(&moduleBase, &moduleSize))
        return FALSE;

    *Base = (UINT64)moduleBase;
    *Size = moduleSize;
    return TRUE;
}

BOOLEAN
HpvFindNtoskrnlTextSection (
    _Out_ UINT64* Base,
    _Out_ SIZE_T* Size
    )
{
    PVOID                      moduleBase;
    ULONG                      moduleSize;
    PIMAGE_DOS_HEADER          dos;
    PIMAGE_NT_HEADERS          nt;
    PIMAGE_SECTION_HEADER      sec;
    UINT16                     i;

    *Base = 0;
    *Size = 0;

    if (!HpvFindNtoskrnlModuleBase(&moduleBase, &moduleSize))
        return FALSE;

    dos = (PIMAGE_DOS_HEADER)moduleBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    nt = (PIMAGE_NT_HEADERS)((UINT8*)moduleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (sec[i].Name[0] == '.' && sec[i].Name[1] == 't' &&
            sec[i].Name[2] == 'e' && sec[i].Name[3] == 'x' &&
            sec[i].Name[4] == 't' && sec[i].Name[5] == '\0')
        {
            *Base = (UINT64)moduleBase + sec[i].VirtualAddress;
            *Size = sec[i].Misc.VirtualSize;
            return TRUE;
        }
    }

    // Fallback: secao .text nao encontrada no cabecalho PE -- varre o
    // modulo inteiro em vez de desistir.
    *Base = (UINT64)moduleBase;
    *Size = moduleSize;
    return TRUE;
}

//
// Compara UM offset: Data[i] == Mask[i] pra cada posicao onde MaskStr[i]=='x'.
// MaskStr[i] != 'x' (tipicamente '?') significa "nao importa o byte aqui".
// Retorna FALSE no primeiro byte que nao bate; TRUE se bateu tudo (ou a
// mascara for vazia).
//
static BOOLEAN
HpvPatternCompareAt (
    _In_reads_bytes_(1) const UINT8* Data,
    _In_reads_bytes_(1) const UINT8* Mask,
    _In_z_               const CHAR* MaskStr
    )
{
    for (; *MaskStr; ++MaskStr, ++Data, ++Mask)
    {
        if (*MaskStr == 'x' && *Data != *Mask)
            return FALSE;
    }

    return TRUE;
}

//
// Tamanho da mascara sem depender de strlen do CRT (driver kernel pode nao
// linkar a CRT completa) -- so conta caracteres ate o terminador nulo.
//
static SIZE_T
HpvMaskLength (
    _In_z_ const CHAR* MaskStr
    )
{
    SIZE_T len = 0;
    while (MaskStr[len] != '\0') len++;
    return len;
}

//
// Varre [Base, Base+Size) procurando o padrao Pattern/Mask (mesmo esquema
// descrito no cabecalho do arquivo). Retorna o endereco do PRIMEIRO byte que
// bate com a assinatura inteira, ou 0 se nao encontrar.
//
// Exemplo de uso (achar PspExitProcess, nao exportada, via assinatura):
//
//   UINT64 found = HpvFindPattern(
//       (UINT64)ntoskrnlBase, ntoskrnlTextSize,
//       (const UINT8*)"\x48\x89\x5C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x00\x48\x8B\xDA\x40\x8A\xF1",
//       "xxxx?xxxx?xxxx?xxxxxx");
//
UINT64
HpvFindPattern (
    _In_ UINT64       Base,
    _In_ SIZE_T       Size,
    _In_ const UINT8* Pattern,
    _In_z_ const CHAR* Mask
    )
{
    SIZE_T maskLen = HpvMaskLength(Mask);
    SIZE_T i;

    if (Base == 0 || Pattern == NULL || maskLen == 0 || Size < maskLen)
        return 0;

    for (i = 0; i <= Size - maskLen; i++)
    {
        if (HpvPatternCompareAt((const UINT8*)(Base + i), Pattern, Mask))
            return Base + i;
    }

    return 0;
}

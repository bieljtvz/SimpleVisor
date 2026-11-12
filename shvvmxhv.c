/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    shvvmxhv.c

Abstract:

    This module implements the Simple Hyper Visor itself.

Author:

    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

    Hypervisor mode only, IRQL MAX_IRQL

--*/

#include "shv.h"
#include "shv_comm.h"
#include "shv_dbg.h"

// Forward decl -- definida (FORCEINLINE) mais abaixo neste arquivo, mas
// usada por ShvHvPushEvent antes desse ponto.
uintptr_t FORCEINLINE ShvVmxRead(_In_ UINT32 VmcsFieldId);

//
// Contador de VM-exits. Incrementado a cada exit para confirmar que o
// handler esta sendo chamado. Leia com o WinDbg: dd shv!ShvExitCount
//
volatile UINT64 ShvExitCount = 0;
volatile UINT64 ShvLastExitReason = 0;

//
// Contadores de observacao do MSR LSTAR (modo passivo, sem hook de SYSCALL).
// O MSR bitmap forca um VM-exit a cada RDMSR/WRMSR no LSTAR.
//
// Leia no WinDbg:
//   dq shv!ShvLstarReadCount    <- quantas vezes RDMSR LSTAR foi executado
//   dq shv!ShvLstarWriteCount   <- quantas vezes WRMSR LSTAR foi executado
//   dq shv!ShvLastLstarValue    <- ultimo valor lido/escrito no LSTAR
//
volatile UINT64 ShvLstarReadCount  = 0;
volatile UINT64 ShvLstarWriteCount = 0;
volatile UINT64 ShvLastLstarValue  = 0;

//
// EPT execute hook legado: KiSystemCall64 instalado em ShvVmxLaunchOnVp.
// Mantido para compatibilidade com CPUID sub-leaf SHV_QUERY_HOOK_HITS.
//
volatile UINT64 ShvEptHookPhysical = 0;
volatile UINT64 ShvEptHookHitCount = 0;

// Definido em nt/hpv_policy_hooks.c (NT-side, PASSIVE_LEVEL) -- so um UINT64,
// sem dependencia de WDK, pode ser lido direto daqui pra expor via CPUID
// (SHV_QUERY_COPYVM_HITS).
extern volatile UINT64 ShvReadVirtualMemoryHookHitCount;

//
// Tabela de hooks EPT instalados pelo usermode via IOCTL.
// A versao (ShvHookVersion) e incrementada a cada install/remove.
// Cada CPU aplica a tabela lazily no proximo VM-exit quando detecta
// que sua copia local (VpData->EptHookVersion) esta desatualizada.
//
#define SHV_HOOK_MAX_ENTRIES    16

typedef struct _SHV_HOOK_ENTRY
{
    UINT64 PhysAddr;       // GPA alinhada a 4KB; 0 = slot livre
    UINT64 ShadowPhysAddr; // PA da shadow page; 0 = hook EPT normal
    UINT8  Type;           // SHV_HOOK_EXEC | SHV_HOOK_WRITE (para hooks normais)
    UINT64 HitCount;
    UINT64 VirtAddr;       // VA exato pedido pelo usuario (inicio do range de bytes)
    UINT64 Pid;            // PID do processo alvo (0 = kernel)
    UINT64 RangeSize;      // numero de PAGINAS hookadas neste bloco (p/ EPT, sempre >=1)
    UINT64 ByteLen;        // tamanho EXATO em bytes do range pedido (p/ filtro de VA
                           // na violacao -- EPT so pode restringir por pagina, mas o
                           // handler usa isto + VirtAddr pra so logar/contar hit quando
                           // GUEST_LINEAR_ADDRESS cai dentro de [VirtAddr, VirtAddr+ByteLen))
} SHV_HOOK_ENTRY;

static SHV_HOOK_ENTRY ShvHookTable[SHV_HOOK_MAX_ENTRIES];
volatile UINT64       ShvHookVersion = 0;

//
// Verifica se uma pagina (ja alinhada a 4KB) cai dentro do range de um hook
// de multiplas paginas. RangeSize==0 e tratado como 1 pagina (mesma
// convencao ja usada em ShvHookInstall/ShvListEptHooks). SEM esse cheque,
// ShvVmxEptApplyHooks/ShvVmxEptRearmHook/ShvVmxHandleEptViolation so
// enxergavam a PRIMEIRA pagina do range (comparacao exata PhysAddr==page) --
// um hook instalado com RangeSize>1 nunca de fato cobria as paginas depois
// da primeira, e o "Range" exibido na GUI ficava so cosmetico, sem efeito.
//
#define SHV_HOOK_PAGE_IN_RANGE(entryIdx, pg) \
    ((pg) >= ShvHookTable[entryIdx].PhysAddr && \
     (pg) < ShvHookTable[entryIdx].PhysAddr + \
            (ShvHookTable[entryIdx].RangeSize ? ShvHookTable[entryIdx].RangeSize : 1) * 0x1000ULL)

//
// Filtro fino por VA exato: a violacao de EPT sempre dispara pra pagina
// inteira (limitacao de hardware -- ver SHV_HOOK_PAGE_IN_RANGE acima), mas
// o usuario pode pedir um range de bytes bem menor (ex.: VA=0x40009,
// RangeSize(bytes)=1 -> so deve "contar hit"/logar evento quando o acesso
// real for exatamente em 0x40009, nao em qualquer lugar da pagina 0x40000).
// VirtAddr==0 (hook sem VA conhecido) desativa o filtro, sempre casa.
//
#define SHV_HOOK_VA_MATCH(entryIdx, va) \
    (ShvHookTable[entryIdx].VirtAddr == 0 || \
     ((va) >= ShvHookTable[entryIdx].VirtAddr && \
      (va) <  ShvHookTable[entryIdx].VirtAddr + \
              (ShvHookTable[entryIdx].ByteLen ? ShvHookTable[entryIdx].ByteLen : 1)))

UINT8 ShvEptExecuteOnlySupported = 0;

//
// Estado compartilhado entre shvvmxhv.c (EPT) e nt/hpv_hooks.c (NT-side).
// Exportados via shvos_internal.h.
//
SHV_SHADOW_PAGE_RECORD  g_ShadowPages[SHV_SHADOW_MAX];
void*                   g_TrampolinePool  = NULL;
UINT32                  g_TrampolineUsed  = 0;
SHV_SYSCALL_HOOK_ENTRY  g_SyscallHooks[SHV_SYSCALL_HOOK_MAX];

//
// Ring buffer de eventos: o hypervisor escreve aqui a cada interceptacao
// (RDMSR/WRMSR LSTAR, EPT violation). O usermode le via CPUID sub-leaf.
//
// Estrutura de uma entrada -- deve caber em 4 registradores CPUID (EAX/EBX/ECX/EDX):
//   EAX = SeqNum   (numero sequencial monotonicamente crescente)
//   EBX = Value.Lo (32 bits baixos do valor associado ao evento)
//   ECX = Value.Hi (32 bits altos)
//   EDX = (Type << 8) | CpuNumber
//
typedef struct _SHV_HV_EVENT
{
    UINT32 SeqNum;      // identificador sequencial
    UINT8  Type;        // SHV_EVENT_* de shv_comm.h
    UINT8  CpuNumber;   // qual processador logico gerou o evento
    UINT16 Reserved;
    UINT64 Value;       // GuestRIP para violacoes EPT; valor do MSR para LSTAR
    UINT64 ReturnAddr;  // [GUEST_RSP] para exec hooks; GuestRIP para write hooks
    UINT64 Aux;         // GPA para write hooks; GUEST_RIP para LSTAR events
    UINT64 Cr3;         // GUEST_CR3 no momento do evento -- identifica o
                         // processo que estava executando (usado pela GUI
                         // para resolver "Causador"/"CR3" e, via CR3, o
                         // modulo user-mode em "Destino"/RIP/RetAddr).
    UINT64 Timestamp;   // FILETIME (100ns desde 1601) no momento do evento --
                         // usado pela GUI na coluna "Hora".
    UINT64 LinearAddr;  // GUEST_LINEAR_ADDRESS -- VA do acesso que causou a
                         // violacao de EPT (so para eventos EPT_*; 0 para LSTAR).
                         // Usado pela GUI na coluna "VA Fault".
    UINT64 Stack[SHV_EVENT_STACK_FRAMES]; // Stack trace HEURISTICO (ver
                         // ShvCaptureStackHeuristic) -- nao e um unwind
                         // estruturado de verdade, so = 0 se nao capturado.
} SHV_HV_EVENT, *PSHV_HV_EVENT;

//
// KUSER_SHARED_DATA->SystemTime -- endereco fixo (nao afetado por KASLR,
// mapeado identico em todos os processos/modo kernel desde o XP) e sempre
// residente, entao e seguro ler diretamente em VMX root mode (interrupcoes
// desligadas) sem nenhuma chamada de SO. Layout (KSYSTEM_TIME, 12 bytes):
// LowPart (ULONG) @ +0x00, High1Time (LONG) @ +0x04, High2Time (LONG) @ +0x08.
// Os dois campos "High" sao escritos em sequencia nao-atomica pelo kernel
// real durante a atualizacao; o padrao High1/Low/High2 + retry detecta e
// descarta uma leitura tearing (mesmo truque usado por KeQuerySystemTime).
//
#define SHV_KUSER_SHARED_DATA       ((volatile UINT8*)0xFFFFF78000000000ULL)
#define SHV_KUSER_SYSTEMTIME_OFFSET 0x14

static UINT64
ShvReadSystemTime (
    VOID
    )
{
    volatile INT32*  high1 = (volatile INT32*)(SHV_KUSER_SHARED_DATA + SHV_KUSER_SYSTEMTIME_OFFSET + 4);
    volatile INT32*  high2 = (volatile INT32*)(SHV_KUSER_SHARED_DATA + SHV_KUSER_SYSTEMTIME_OFFSET + 8);
    volatile UINT32* low   = (volatile UINT32*)(SHV_KUSER_SHARED_DATA + SHV_KUSER_SYSTEMTIME_OFFSET);
    INT32  h1, h2;
    UINT32 lo;

    do
    {
        h1 = *high1;
        lo = *low;
        h2 = *high2;
    } while (h1 != h2);

    return ((UINT64)(UINT32)h1 << 32) | lo;
}

#define SHV_KERNEL_VA_MIN   0xFFFF800000000000ULL
#define SHV_PTE_PRESENT     0x1ULL
#define SHV_PTE_PS          0x80ULL
#define SHV_PTE_PHYS_MASK   0x000FFFFFFFFFF000ULL // bits 12-51, serve pra PML4E/PDPTE/PDE/PTE de 4KB

//
// Contadores de diagnostico do stack walk usermode -- leia no WinDbg com
// "dq shv!ShvStackWalk<Nome>" (mesmo padrao ja usado no projeto pra
// ShvPaToVaRejectCount/ShvPaToVaLastBadResult). Dizem exatamente em qual
// nivel da traducao PML4/PDPT/PD/PT as falhas estao acontecendo, sem
// precisar adicionar nada na GUI.
//
volatile UINT64 ShvStackWalkAttempts     = 0; // vezes que ShvCaptureStackHeuristic rodou com RSP usermode
volatile UINT64 ShvStackWalkSuccess      = 0; // traducoes de slot da pilha que deram certo (pelo menos 1 QWORD lido)
volatile UINT64 ShvStackWalkPml4Fail     = 0;
volatile UINT64 ShvStackWalkPdptFail     = 0;
volatile UINT64 ShvStackWalkPdFail       = 0;
volatile UINT64 ShvStackWalkPtFail       = 0;
volatile UINT64 ShvStackWalkFinalFail    = 0; // leitura fisica final (ShvOsReadPhysical) falhou
volatile UINT64 ShvStackWalkCallSiteReject = 0; // slot traduzido e valido, mas nao passou no filtro de call-site
volatile UINT64 ShvStackWalkLastCr3      = 0; // Cr3 usado na ULTIMA tentativa (kernel ou usermode)
volatile UINT64 ShvStackWalkLastGva      = 0; // GVA que estava sendo traduzido na ULTIMA falha

// Diagnostico fino do nivel PDPT (o que mais falhou no primeiro teste):
// distingue "nao conseguiu nem LER a PDPTE" (problema de ShvOsReadPhysical)
// de "leu certinho mas o bit Present era 0" (a propria entrada diz que nao
// esta mapeado). So preenchido quando o nivel PDPT falha.
volatile UINT64 ShvStackWalkPdptReadFail = 0; // ShvOsReadPhysical da PDPTE falhou (nao chegou nem a ler)
volatile UINT64 ShvStackWalkLastPml4Entry= 0; // valor cru da PML4E que levou a essa PDPTE
volatile UINT64 ShvStackWalkLastPdptPa   = 0; // endereco FISICO que tentamos ler pra PDPTE
volatile UINT64 ShvStackWalkLastPdptEntry= 0; // valor cru lido (0 se ShvOsReadPhysical falhou)

// Toggle de diagnostico -- escreva 1 AO VIVO via WinDbg, sem precisar
// recompilar/redeployar:
//   ed shv!ShvStackWalkDebugNoFilter 1
// Com isso ligado, ShvCaptureStackHeuristic para de filtrar por
// ShvLooksLikeCallSite e guarda os primeiros QWORDs traduzidos com sucesso
// da pilha usermode CRUS (so passando pelo filtro grosso de "parece um VA
// canonico de usermode"), pra inspecionar manualmente no WinDbg/GUI o que
// realmente esta la, sem depender do meu padrao de opcode estar certo.
volatile UINT8  ShvStackWalkDebugNoFilter = 0;

//
// Liga/desliga o filtro de call-site em runtime via IOCTL (SHV_CMD_SET_STACK_FILTER),
// pra poder comparar lado a lado no GUI sem precisar do WinDbg/`ed`. Enabled=1
// -> filtro ligado (ShvStackWalkDebugNoFilter=0); Enabled=0 -> filtro desligado
// (mostra tudo que parece um VA plausivel, sem checar call-site).
//
VOID
ShvSetStackFilterEnabled (
    _In_ UINT8 Enabled
    )
{
    ShvStackWalkDebugNoFilter = Enabled ? 0 : 1;
}

//
// Traduz um GVA de QUALQUER processo (identificado por Cr3) pro endereco
// FISICO correspondente, andando manualmente PML4->PDPT->PD->PT (4KB, 2MB ou
// 1GB). Cada nivel vira uma leitura fisica via ShvOsReadPhysical (MmCopyMemory
// com MM_COPY_MEMORY_PHYSICAL -- documentada como segura em IRQL <=
// DISPATCH_LEVEL) -- nunca um offset ou snapshot cacheado da tabela de
// paginas. Retorna 0 (sem escrever em *OutPa) se qualquer nivel nao estiver
// presente ou nao puder ser lido -- nunca "adivinha" um resultado.
//
// Devolve o endereco FISICO (nao um VA pra dereferenciar) de proposito: a
// primeira versao usava MmGetVirtualForPhysical pra obter um VA e
// dereferenciava direto, mas uma comparacao com leitura fisica real via
// WinDbg ("!dq") mostrou que esse VA podia devolver conteudo DIFERENTE do
// que estava realmente na memoria fisica (silenciosamente errado, sem
// travar nada -- pior que um bugcheck). MmCopyMemory(PHYSICAL) e o mecanismo
// que o proprio WinDbg usa pra leitura fisica; ler o QWORD final tambem
// passa por ele agora (ver ShvReadGvaWithCr3), nunca por um dereference direto.
//
static UINT8
ShvTranslateGvaWithCr3 (
    _In_  UINT64  Cr3,
    _In_  UINT64  Gva,
    _Out_ UINT64* OutPa
    )
{
    UINT64 entry;
    UINT64 pa;

    *OutPa = 0;
    ShvStackWalkLastCr3 = Cr3;
    ShvStackWalkLastGva = Gva;

    // PML4E
    pa = (Cr3 & SHV_PTE_PHYS_MASK) + ((Gva >> 39) & 0x1FF) * 8;
    if (!ShvOsReadPhysical(pa, &entry) || !(entry & SHV_PTE_PRESENT))
    {
        _InterlockedIncrement64((LONG64*)&ShvStackWalkPml4Fail);
        return 0;
    }
    ShvStackWalkLastPml4Entry = entry;

    // PDPTE
    pa = (entry & SHV_PTE_PHYS_MASK) + ((Gva >> 30) & 0x1FF) * 8;
    ShvStackWalkLastPdptPa = pa;
    {
        UINT8 readOk = ShvOsReadPhysical(pa, &entry);
        ShvStackWalkLastPdptEntry = readOk ? entry : 0;
        if (!readOk)
            _InterlockedIncrement64((LONG64*)&ShvStackWalkPdptReadFail);
        if (!readOk || !(entry & SHV_PTE_PRESENT))
        {
            _InterlockedIncrement64((LONG64*)&ShvStackWalkPdptFail);
            return 0;
        }
    }
    if (entry & SHV_PTE_PS)
    {
        // Pagina de 1GB: bits 30-51 da entrada sao a base fisica
        *OutPa = (entry & 0x000FFFFFC0000000ULL) + (Gva & 0x3FFFFFFFULL);
        _InterlockedIncrement64((LONG64*)&ShvStackWalkSuccess);
        return 1;
    }

    // PDE
    pa = (entry & SHV_PTE_PHYS_MASK) + ((Gva >> 21) & 0x1FF) * 8;
    if (!ShvOsReadPhysical(pa, &entry) || !(entry & SHV_PTE_PRESENT))
    {
        _InterlockedIncrement64((LONG64*)&ShvStackWalkPdFail);
        return 0;
    }
    if (entry & SHV_PTE_PS)
    {
        // Pagina de 2MB: bits 21-51 da entrada sao a base fisica
        *OutPa = (entry & 0x000FFFFFFFE00000ULL) + (Gva & 0x1FFFFFULL);
        _InterlockedIncrement64((LONG64*)&ShvStackWalkSuccess);
        return 1;
    }

    // PTE (pagina normal de 4KB)
    pa = (entry & SHV_PTE_PHYS_MASK) + ((Gva >> 12) & 0x1FF) * 8;
    if (!ShvOsReadPhysical(pa, &entry) || !(entry & SHV_PTE_PRESENT))
    {
        _InterlockedIncrement64((LONG64*)&ShvStackWalkPtFail);
        return 0;
    }

    *OutPa = (entry & SHV_PTE_PHYS_MASK) + (Gva & 0xFFFULL);
    _InterlockedIncrement64((LONG64*)&ShvStackWalkSuccess);
    return 1;
}

//
// Traduz Gva (via Cr3) e le o QWORD final -- sempre por ShvOsReadPhysical,
// nunca por dereference de um VA obtido separadamente (ver comentario acima
// em ShvTranslateGvaWithCr3 sobre por que isso importa).
//
static UINT8
ShvReadGvaWithCr3 (
    _In_  UINT64  Cr3,
    _In_  UINT64  Gva,
    _Out_ UINT64* OutValue
    )
{
    UINT64 pa;

    *OutValue = 0;

    if (!ShvTranslateGvaWithCr3(Cr3, Gva, &pa))
        return 0;

    if (!ShvOsReadPhysical(pa, OutValue))
    {
        _InterlockedIncrement64((LONG64*)&ShvStackWalkFinalFail);
        return 0;
    }

    return 1;
}

//
// Quantos QWORDs acima do RSP sao varridos procurando candidatos a endereco
// de retorno -- bem mais que SHV_EVENT_STACK_FRAMES, porque nem todo QWORD
// que esta fisicamente na pilha e um retorno de verdade (lixo de chamadas
// antigas, variaveis locais, etc.); o filtro de "call-site" em
// ShvLooksLikeCallSite e o que reduz esse ruido.
//
// 64 (512 bytes) se mostrou PEQUENO DEMAIS num teste real: comparando com
// "dps" do WinDbg (com simbolos, processo ainda vivo), a janela inteira de
// 64 QWORDs acima do RSP era quase so preenchimento de build debug
// (0xCCCCCCCC) -- nenhum endereco de retorno de verdade cabia ali. Frames de
// pilha sem otimizacao (padding, canario do /RTC, locals maiores) passam
// facil de 512 bytes. 512 QWORDs (4KB, ~1 pagina) da bem mais margem sem
// ficar arbitrariamente grande.
#define SHV_STACK_SCAN_WINDOW 512

//
// Verifica se os 8 bytes antes de Candidate terminam numa instrucao CALL
// plausivel -- call rel32 direto (E8 xx xx xx xx, 5 bytes) ou call r/m64
// indireto por registrador (FF /2, 2 ou 3 bytes com prefixo REX). E uma
// HEURISTICA (opcao 2 discutida com o usuario): nao cobre call por memoria
// com ModRM/SIB mais longos, mas pega os casos mais comuns sem precisar de
// um parser de instrucoes completo.
//
// Candidate pode ser kernel ou usermode (Cr3 so e usado no segundo caso).
// Rejeita (sem tentar ler nada) a rara janela que cruzaria uma fronteira de
// pagina de 4KB -- so os casos comuns (Candidate com pelo menos 8 bytes de
// folga desde o inicio da propria pagina) sao verificados; o resto conta
// como "nao parece call-site" (consistente com a natureza heuristica desta
// funcao -- pode pular um frame real ocasionalmente, nunca arrisca uma
// segunda traducao so pra cobrir esse caso raro).
//
// So le os bytes depois de confirmar residencia (direto via
// ShvOsIsAddressValid pra kernel, ou via ShvTranslateGvaWithCr3 pra
// usermode) -- Candidate vem de um valor QUALQUER lido da pilha, nao de um
// endereco confiavel por construcao; ler sem essa checagem e exatamente a
// classe de erro que ja causou bugchecks 0xD1 DISABLED_INTERRUPT_FAULT
// neste projeto (ver [[feedback_direct_map_single_offset_bugcheck]]).
//
static UINT8
ShvLooksLikeCallSite (
    _In_ UINT64 Cr3,
    _In_ UINT64 Candidate
    )
{
    UINT64 windowStart;
    UINT64 qword;
    UINT8* bytes;

    if (Candidate < 8 || (Candidate & 0xFFFULL) < 8)
        return 0;

    windowStart = Candidate - 8;

    if (windowStart >= SHV_KERNEL_VA_MIN)
    {
        // Enderecos de kernel: leitura direta continua segura (mapeados
        // identicos em qualquer CR3, sempre residentes para codigo carregado).
        if (!ShvOsIsAddressValid((VOID*)windowStart))
            return 0;
        qword = *(volatile UINT64*)windowStart;
    }
    else
    {
        if (!ShvReadGvaWithCr3(Cr3, windowStart, &qword))
            return 0;
    }

    bytes = (UINT8*)&qword;

    // CALL rel32: E8 cd (5 bytes, terminando exatamente em Candidate)
    if (bytes[3] == 0xE8)
        return 1;

    // CALL r/m64 indireto: FF /2 (ModRM.reg == 2, binario 010 -> mascara 0x38 == 0x10)
    if (bytes[6] == 0xFF && (bytes[7] & 0x38) == 0x10)
        return 1;

    // Mesma coisa com prefixo REX (necessario para registradores R8-R15)
    if (bytes[5] >= 0x40 && bytes[5] <= 0x4F &&
        bytes[6] == 0xFF && (bytes[7] & 0x38) == 0x10)
        return 1;

    // CALL indireto via IAT/ponteiro de funcao: FF 15 disp32 ("call qword ptr
    // [rip+disp32]", 6 bytes: ModRM=00/010/101=0x15, SEM SIB/base/index
    // variaveis). E o padrao mais comum pra chamar funcoes importadas
    // (CRT/API do Windows) em builds sem otimizacao -- faltava aqui e
    // explicava a maioria das rejeicoes no teste real (CallSiteReject alto,
    // zero frames aceitos apesar de Success alto).
    if (bytes[2] == 0xFF && bytes[3] == 0x15)
        return 1;

    return 0;
}

//
// Stack trace heuristico a partir de GuestRsp -- varre SHV_STACK_SCAN_WINDOW
// QWORDs acima do RSP e guarda em OutFrames (ate SHV_EVENT_STACK_FRAMES) os
// valores que: (1) sao um VA plausivel no mesmo "mundo" do RSP (kernel ou
// usermode -- nunca mistura os dois), (2) tem bit0==0 (alinhamento de
// instrucao), e (3) sao precedidos por algo que parece uma instrucao CALL
// (ShvLooksLikeCallSite). NAO e um unwind estruturado de verdade (sem usar
// .pdata/UNWIND_INFO) -- pode pular frames reais ou, raramente, aceitar um
// falso positivo; e a opcao 2 que foi discutida e escolhida (meio-termo
// entre o scan bruto e um unwinder completo).
//
// RSP de kernel: leitura direta (enderecos de kernel sao mapeados
// identicos em qualquer CR3, e o proprio RSP ja esta residente por
// definicao -- a CPU estava usando-o AGORA). RSP de usermode: cada slot e
// traduzido individualmente via ShvTranslateGvaWithCr3, usando o Cr3 do
// proprio evento (GUEST_CR3 -- o CR3 da thread que causou o evento, ou seja
// exatamente a pilha que queremos andar).
//
static VOID
ShvCaptureStackHeuristic (
    _In_ UINT64 Cr3,
    _In_ UINT64 GuestRsp,
    _Out_writes_(SHV_EVENT_STACK_FRAMES) UINT64* OutFrames
    )
{
    UINT32 i;
    UINT32 found = 0;
    UINT8  isKernel;

    for (i = 0; i < SHV_EVENT_STACK_FRAMES; i++)
        OutFrames[i] = 0;

    if ((GuestRsp & 0x7) != 0)
        return;

    isKernel = (GuestRsp >= SHV_KERNEL_VA_MIN) ? 1 : 0;

    if (!isKernel)
        _InterlockedIncrement64((LONG64*)&ShvStackWalkAttempts);

    for (i = 0; i < SHV_STACK_SCAN_WINDOW && found < SHV_EVENT_STACK_FRAMES; i++)
    {
        UINT64 slotGva = GuestRsp + (UINT64)i * 8;
        UINT64 value;

        if (isKernel)
        {
            if (!ShvOsIsAddressValid((VOID*)slotGva))
                break; // saiu da regiao residente da pilha
            value = *(volatile UINT64*)slotGva;
        }
        else
        {
            // slotGva e sempre 8-byte alinhado aqui, entao nunca cruza uma
            // fronteira de pagina de 4KB sozinho -- 1 traducao por slot basta.
            if (!ShvReadGvaWithCr3(Cr3, slotGva, &value))
                break;
        }

        if (isKernel)
        {
            if (value < SHV_KERNEL_VA_MIN || (value & 0x1) != 0)
                continue; // nao parece um VA de kernel/instrucao valido
        }
        else
        {
            // Teto real de um VA canonico de usermode (bits 47-63 devem ser
            // zero) -- nao so "< SHV_KERNEL_VA_MIN", que deixava passar lixo
            // nao-canonico (ex.: 0xCCCCCCCCCCCCCCCC, padrao classico de
            // memoria de pilha nao inicializada em build debug).
            if (value < 0x10000ULL || value >= 0x0000800000000000ULL || (value & 0x1) != 0)
                continue; // nao parece um VA de usermode/instrucao valido
        }

        if ((!isKernel && ShvStackWalkDebugNoFilter) || ShvLooksLikeCallSite(Cr3, value))
            OutFrames[found++] = value;
        else if (!isKernel)
            _InterlockedIncrement64((LONG64*)&ShvStackWalkCallSiteReject);
    }
}

static SHV_HV_EVENT ShvEventBuffer[SHV_EVENT_RING_SIZE];
volatile UINT64     ShvEventCount = 0; // total de eventos escritos (nunca decrementa)

//
// Adiciona um evento ao ring buffer de forma segura para multi-CPU.
// Usa InterlockedIncrement64 (instrucao LOCK XADD) que e segura em
// VMX root mode -- nao faz chamadas de sistema, apenas uma instrucao atomica.
//
static VOID
ShvHvPushEvent (
    _In_ UINT8  Type,
    _In_ UINT64 Value,
    _In_ UINT64 ReturnAddr,
    _In_ UINT64 Aux,
    _In_ UINT64 LinearAddr
    )
{
    LONG64   idx;
    UINT32   slot;
    PSHV_HV_EVENT ev;

    idx  = _InterlockedIncrement64((LONG64*)&ShvEventCount) - 1;
    slot = (UINT32)(idx % SHV_EVENT_RING_SIZE);
    ev   = &ShvEventBuffer[slot];

    ev->Type       = Type;
    ev->CpuNumber  = (UINT8)ShvOsGetCurrentProcessorNumber();
    ev->Reserved   = 0;
    ev->Value      = Value;
    ev->ReturnAddr = ReturnAddr;
    ev->Aux        = Aux;
    ev->Cr3        = ShvVmxRead(GUEST_CR3);
    ev->Timestamp  = ShvReadSystemTime();
    ev->LinearAddr = LinearAddr;
    ShvCaptureStackHeuristic(ev->Cr3, ShvVmxRead(GUEST_RSP), ev->Stack);
    _mm_sfence();
    ev->SeqNum     = (UINT32)(idx + 1);
}


//
// Instala um hook EPT na tabela global. Chamado pelo IOCTL handler (PASSIVE_LEVEL).
// Retorna SHVD_STATUS_OK ou SHVD_STATUS_ERR_FULL.
//
UINT32
ShvHookInstall (
    _In_ UINT64 PhysAddr,
    _In_ UINT8  HookType,
    _In_ UINT64 VirtAddr,
    _In_ UINT64 Pid,
    _In_ UINT64 RangeSize,
    _In_ UINT64 ByteLen
    )
{
    UINT32 i;
    UINT64 page = PhysAddr & ~0xFFFULL;

    // Atualiza entrada existente para esta pagina
    for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
    {
        if (ShvHookTable[i].PhysAddr == page)
        {
            ShvHookTable[i].Type     |= HookType;
            ShvHookTable[i].VirtAddr  = VirtAddr;
            ShvHookTable[i].Pid       = Pid;
            ShvHookTable[i].RangeSize = RangeSize ? RangeSize : 1;
            ShvHookTable[i].ByteLen   = ByteLen ? ByteLen : 1;
            _InterlockedIncrement64((LONG64*)&ShvHookVersion);
            return SHVD_STATUS_OK;
        }
    }

    // Slot livre
    for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
    {
        if (ShvHookTable[i].PhysAddr == 0)
        {
            ShvHookTable[i].PhysAddr  = page;
            ShvHookTable[i].Type      = HookType;
            ShvHookTable[i].HitCount  = 0;
            ShvHookTable[i].VirtAddr  = VirtAddr;
            ShvHookTable[i].Pid       = Pid;
            ShvHookTable[i].RangeSize = RangeSize ? RangeSize : 1;
            ShvHookTable[i].ByteLen   = ByteLen ? ByteLen : 1;
            _InterlockedIncrement64((LONG64*)&ShvHookVersion);
            return SHVD_STATUS_OK;
        }
    }

    return SHVD_STATUS_ERR_FULL;
}

//
// Remove um hook EPT da tabela global.
// Retorna SHVD_STATUS_OK ou SHVD_STATUS_ERR_NOTFOUND.
//
UINT32
ShvHookRemove (
    _In_ UINT64 PhysAddr
    )
{
    UINT32 i;
    UINT64 page = PhysAddr & ~0xFFFULL;

    for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
    {
        if (ShvHookTable[i].PhysAddr == page)
        {
            ShvHookTable[i].PhysAddr = 0;
            ShvHookTable[i].Type     = 0;
            ShvHookTable[i].HitCount = 0;
            _InterlockedIncrement64((LONG64*)&ShvHookVersion);
            return SHVD_STATUS_OK;
        }
    }

    return SHVD_STATUS_ERR_NOTFOUND;
}

//
// Remove todos os hooks EPT da tabela global.
// Chamado via IOCTL SHV_CMD_UNHOOK_ALL.
//
VOID
ShvHookRemoveAll (
    VOID
    )
{
    UINT32 i;
    for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
    {
        // Preserva shadow hooks (ShadowPhysAddr != 0) -- esses sao gerenciados
        // por ShvHookRemoveShadow, nao pelo UNHOOK_ALL de EPT hooks normais.
        if (ShvHookTable[i].ShadowPhysAddr != 0)
            continue;
        ShvHookTable[i].PhysAddr  = 0;
        ShvHookTable[i].Type      = 0;
        ShvHookTable[i].HitCount  = 0;
        ShvHookTable[i].VirtAddr  = 0;
        ShvHookTable[i].Pid       = 0;
        ShvHookTable[i].RangeSize = 0;
    }
    _InterlockedIncrement64((LONG64*)&ShvHookVersion);
}

//
// Instala um shadow hook: redireciona a GPA para a shadow page (execute-only).
// Chamado pelo NT-side (PASSIVE_LEVEL) depois de preparar a shadow page.
//
UINT32
ShvHookInstallShadow (
    _In_ UINT64 OriginalPhys,
    _In_ UINT64 ShadowPhys
    )
{
    UINT32 i;
    UINT64 page = OriginalPhys & ~0xFFFULL;

    for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
    {
        if (ShvHookTable[i].PhysAddr == page)
        {
            ShvHookTable[i].ShadowPhysAddr = ShadowPhys;
            _InterlockedIncrement64((LONG64*)&ShvHookVersion);
            return SHVD_STATUS_OK;
        }
    }

    for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
    {
        if (ShvHookTable[i].PhysAddr == 0)
        {
            ShvHookTable[i].PhysAddr       = page;
            ShvHookTable[i].ShadowPhysAddr = ShadowPhys;
            ShvHookTable[i].Type           = 0;
            ShvHookTable[i].HitCount       = 0;
            _InterlockedIncrement64((LONG64*)&ShvHookVersion);
            return SHVD_STATUS_OK;
        }
    }

    return SHVD_STATUS_ERR_FULL;
}

//
// Remove um shadow hook da tabela global.
//
// NAO zera PhysAddr: so desliga ShadowPhysAddr/Type e mantem a entrada com
// PhysAddr setado. Isso faz ShvVmxEptApplyHooks cair no ramo "else" (Type==0)
// na proxima vez que cada vCPU reaplicar a tabela, restaurando o PTE de EPT
// para a PA ORIGINAL com r=1,w=1,x=1 -- em vez de deixar o PTE apontando para
// a shadow page indefinidamente (ShvVmxEptApplyHooks ignora entradas com
// PhysAddr==0 via "continue", ou seja nunca desfaz o mapeamento antigo).
//
// Chamador (nt/hpv_hooks.c HpvUnhookFuncByVa) DEVE sincronizar todos os CPUs
// (forcar cada um a processar um VM-exit, reaplicando a tabela + INVEPT) antes
// de liberar a memoria fisica da shadow page, e so depois chamar
// ShvHookFreeSlot para liberar o slot da tabela. Sem essa restauracao previa,
// um CPU que ainda nao reaplicou a tabela continua com o EPT PTE apontando
// para a shadow page; se ela for liberada e reaproveitada por outra alocacao
// enquanto isso, esse CPU acaba executando memoria arbitraria -> bugcheck
// (observado como 0x139 KERNEL_SECURITY_CHECK_FAILURE / guard_icall_bugcheck).
//
// Retorna SHVD_STATUS_OK ou SHVD_STATUS_ERR_NOTFOUND.
//
UINT32
ShvHookRemoveShadow (
    _In_ UINT64 OriginalPhys
    )
{
    UINT32 i;
    UINT64 page = OriginalPhys & ~0xFFFULL;

    for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
    {
        if (ShvHookTable[i].PhysAddr == page &&
            ShvHookTable[i].ShadowPhysAddr != 0)
        {
            ShvHookTable[i].ShadowPhysAddr = 0;
            ShvHookTable[i].Type           = 0;
            ShvHookTable[i].HitCount       = 0;
            _InterlockedIncrement64((LONG64*)&ShvHookVersion);
            return SHVD_STATUS_OK;
        }
    }

    return SHVD_STATUS_ERR_NOTFOUND;
}

//
// Libera definitivamente o slot da tabela global apos ShvHookRemoveShadow +
// a sincronizacao de todos os CPUs ja terem restaurado o PTE para a PA
// original (ver comentario acima). Nao precisa incrementar ShvHookVersion:
// o PTE ja esta correto (r=1,w=1,x=1 -> identidade) desde a reaplicacao
// anterior; isso so libera o slot de SHV_HOOK_MAX_ENTRIES para reuso.
//
UINT32
ShvHookFreeSlot (
    _In_ UINT64 OriginalPhys
    )
{
    UINT32 i;
    UINT64 page = OriginalPhys & ~0xFFFULL;

    for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
    {
        if (ShvHookTable[i].PhysAddr == page &&
            ShvHookTable[i].ShadowPhysAddr == 0)
        {
            ShvHookTable[i].PhysAddr = 0;
            ShvHookTable[i].Type     = 0;
            ShvHookTable[i].HitCount = 0;
            return SHVD_STATUS_OK;
        }
    }

    return SHVD_STATUS_ERR_NOTFOUND;
}

//
// Limpa a tabela de restauracao de MTF em todos os VPs.
// Atualmente stub: o MtfRestorePhysical e zerado naturalmente pelo handler de MTF.
//
VOID
ShvVmxClearRestoreTables (
    VOID
    )
{
    // Noop: por-CPU MtfRestorePhysical e zerado pelo handler de MTF
}

//
// Limpa o ring buffer de eventos.
// Chamado via IOCTL SHV_CMD_CLEAR_EVENTS.
//
// IMPORTANTE: zera o CONTEUDO do buffer, nao so o contador. So resetar
// ShvEventCount para 0 deixava os slots antigos com SeqNum alto (da serie
// anterior) intactos; como a GUI tambem zera seu "ultimo SeqNum visto" ao
// limpar (para casar com o contador reiniciado), o proximo poll tratava
// TODOS os slots com SeqNum > 0 como "novos" e reexibia o historico antigo
// inteiro -- dando a impressao de que o botao "Limpar historico" nao fazia
// nada.
//
VOID
ShvClearEvents (
    VOID
    )
{
    __stosb((UINT8*)ShvEventBuffer, 0, sizeof(ShvEventBuffer));
    _InterlockedExchange64((LONG64*)&ShvEventCount, 0);
}

//
// Preenche OutBuffer com ate MaxCount entradas SHV_EPT_HOOK_INFO da tabela.
// Retorna o numero de entradas escritas.
// Chamado via IOCTL SHV_CMD_LIST_EPT_HOOKS.
//
UINT32
ShvListEptHooks (
    _Out_ VOID*  OutBuffer,
    _In_  UINT32 MaxCount,
    _In_  UINT32 EntrySize
    )
{
    UINT32 count = 0;
    UINT32 i;

    for (i = 0; i < SHV_HOOK_MAX_ENTRIES && count < MaxCount; i++)
    {
        if (ShvHookTable[i].PhysAddr != 0 && ShvHookTable[i].ShadowPhysAddr == 0)
        {
            PSHV_EPT_HOOK_INFO e = (PSHV_EPT_HOOK_INFO)((UINT8*)OutBuffer + count * EntrySize);
            __stosb((UINT8*)e, 0, EntrySize);
            e->PhysAddr  = ShvHookTable[i].PhysAddr;
            e->VirtAddr  = ShvHookTable[i].VirtAddr;
            e->Pid       = ShvHookTable[i].Pid;
            e->HitCount  = ShvHookTable[i].HitCount;
            e->RangeStart= ShvHookTable[i].PhysAddr;
            e->RangeSize = ShvHookTable[i].RangeSize ? ShvHookTable[i].RangeSize : 1;
            e->Type      = ShvHookTable[i].Type;
            count++;
        }
    }

    return count;
}

//
// Aplica todos os hooks da tabela global ao EPT deste CPU.
// Chamado quando VpData->EptHookVersion < ShvHookVersion.
// Roda em VMX root mode (nenhuma chamada de SO aqui).
//
static VOID
ShvVmxEptApplyHooks (
    _In_ PSHV_VP_DATA VpData
    )
{
    UINT32 i;

    for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
    {
        UINT64 basePa;
        UINT64 rangePages;
        UINT64 j;
        UINT8  type;
        UINT8  r, w, x;

        if (ShvHookTable[i].PhysAddr == 0)
        {
            continue;
        }

        basePa     = ShvHookTable[i].PhysAddr;
        type       = ShvHookTable[i].Type;
        // Hooks com shadow page nunca sao de multiplas paginas (shadow e
        // sempre 1 PFN so) -- so o hook normal itera o range inteiro.
        rangePages = (ShvHookTable[i].ShadowPhysAddr != 0) ? 1
                   : (ShvHookTable[i].RangeSize ? ShvHookTable[i].RangeSize : 1);

        for (j = 0; j < rangePages; j++)
        {
            UINT64 pa = basePa + j * 0x1000ULL;

            // Garante que a pagina grande foi dividida em 4KB PTEs
            ShvVmxEptSplitLargePage(VpData, pa);

            if (ShvHookTable[i].ShadowPhysAddr != 0)
            {
                // Shadow hook: EPT PTE aponta para shadow page, execute-only.
                // Leituras/escritas na GPA original causam violacao e servimos
                // a pagina original por 1 instrucao via MTF.
                ShvVmxEptSetPhysAndPerms(VpData, pa, ShvHookTable[i].ShadowPhysAddr,
                                         0, 0, 1);
            }
            else
            {
                // Hook normal (ou entrada de shadow hook ja removido, restaurando
                // identidade -- ver ShvHookRemoveShadow em shvvmxhv.c).
                //
                // NAO usar ShvVmxEptSetPermissions aqui: ela so altera os bits
                // Read/Write/Execute da PTE, sem tocar no PageFrameNumber. Se esta
                // entrada ERA um shadow hook (ShadowPhysAddr acabou de ser zerado
                // por ShvHookRemoveShadow), a PTE ainda aponta para o PFN da shadow
                // page -- usar SetPermissions deixaria a PTE com r=1,w=1,x=1
                // (totalmente acessivel) MAS ainda apontando para a shadow page.
                // Isso e exatamente o que causava o BSOD: ao liberar a shadow page
                // (MmFreeContiguousMemory), a PTE continuava "viva" referenciando
                // aquela memoria, que podia ser reaproveitada e executada por outro
                // CPU -> bugcheck 0x139 (confirmado via WinDbg: "u" na GPA ainda
                // mostrava o patch da shadow page mesmo apos "Shadow page liberada").
                //
                // ShvVmxEptSetPhysAndPerms(VpData, pa, pa, ...) forca o PFN de
                // volta para a PA ORIGINAL (identidade) -- seguro tambem para hooks
                // normais (nao-shadow), que sempre usam GPA==PA.
                r = (type & SHV_HOOK_READ)  ? 0 : 1;
                w = ((type & SHV_HOOK_WRITE) || (r == 0)) ? 0 : 1;
                x = (type & SHV_HOOK_EXEC)  ? 0 : 1;
                ShvVmxEptSetPhysAndPerms(VpData, pa, pa, r, w, x);
            }
        }
    }

    ShvVmxInveptLocal(VpData);
}

//
// Re-arma o hook na pagina indicada consultando tanto o hook legado
// (ShvEptHookPhysical) quanto a tabela de hooks.
// Chamado pelo handler de MTF apos o guest executar 1 instrucao.
//
static VOID
ShvVmxEptRearmHook (
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64       GuestPa
    )
{
    UINT32 i;
    UINT64 page = GuestPa & ~0xFFFULL;
    UINT8  r = 1, w = 1, x = 1;

    // Shadow hooks: restaura PTE para shadow PA, execute-only
    for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
    {
        if (ShvHookTable[i].PhysAddr == page &&
            ShvHookTable[i].ShadowPhysAddr != 0)
        {
            // Shadow hooks nunca sao multi-pagina (ver ShvVmxEptApplyHooks) --
            // comparacao exata continua certa aqui, nao precisa de range-check.
            ShvVmxEptSetPhysAndPerms(VpData, page, ShvHookTable[i].ShadowPhysAddr,
                                     0, 0, 1);
            ShvVmxInveptLocal(VpData);
            return;
        }
    }

    // Hook legado de KiSystemCall64
    if (page == ShvEptHookPhysical)
    {
        x = 0;
    }

    // Tabela de hooks do usermode (EPT normal) -- range-check (nao so a
    // primeira pagina), pra re-armar corretamente qualquer pagina de um hook
    // de multiplas paginas (RangeSize > 1).
    for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
    {
        if (ShvHookTable[i].PhysAddr != 0 &&
            ShvHookTable[i].ShadowPhysAddr == 0 &&
            SHV_HOOK_PAGE_IN_RANGE(i, page))
        {
            if (ShvHookTable[i].Type & SHV_HOOK_EXEC)  x = 0;
            if (ShvHookTable[i].Type & SHV_HOOK_WRITE) w = 0;
            if (ShvHookTable[i].Type & SHV_HOOK_READ)  { r = 0; w = 0; }
        }
    }

    // Mesma razao do ShvVmxEptApplyHooks acima: usar SetPhysAndPerms (nao
    // SetPermissions) garante que, se esta PTE vinha de um shadow hook ja
    // removido, o PFN tambem volte para a PA original (nao so os bits de
    // permissao).
    ShvVmxEptSetPhysAndPerms(VpData, page, page, r, w, x);
    ShvVmxInveptLocal(VpData);
}

DECLSPEC_NORETURN
VOID
ShvVmxResume (
    VOID
    )
{
    //
    // Issue a VMXRESUME. The reason that we've defined an entire function for
    // this sole instruction is both so that we can use it as the target of the
    // VMCS when re-entering the VM After a VM-Exit, as well as so that we can
    // decorate it with the DECLSPEC_NORETURN marker, which is not set on the
    // intrinsic (as it can fail in case of an error).
    //
    __vmx_vmresume();
}

uintptr_t
FORCEINLINE
ShvVmxRead (
    _In_ UINT32 VmcsFieldId
    )
{
    size_t FieldData;

    //
    // Because VMXREAD returns an error code, and not the data, it is painful
    // to use in most circumstances. This simple function simplifies it use.
    //
    __vmx_vmread(VmcsFieldId, &FieldData);
    return FieldData;
}

INT32
ShvVmxLaunch (
    VOID
    )
{
    INT32 failureCode;

    //
    // Launch the VMCS
    //
    __vmx_vmlaunch();

    //
    // If we got here, either VMCS setup failed in some way, or the launch
    // did not proceed as planned.
    //
    failureCode = (INT32)ShvVmxRead(VM_INSTRUCTION_ERROR);
    __vmx_off();

    //
    // Return the error back to the caller
    //
    return failureCode;
}

VOID
ShvVmxHandleInvd (
    VOID
    )
{
    //
    // This is the handler for the INVD instruction. Technically it may be more
    // correct to use __invd instead of __wbinvd, but that intrinsic doesn't
    // actually exist. Additionally, the Windows kernel (or HAL) don't contain
    // any example of INVD actually ever being used. Finally, Hyper-V itself
    // handles INVD by issuing WBINVD as well, so we'll just do that here too.
    //
    __wbinvd();
}

//
// A leaf SHV_CPUID_LEAF e o protocolo completo de sub-leaves estao definidos
// em shv_comm.h (incluido acima) para ser compartilhado com o usermode.

VOID
ShvVmxHandleCpuid (
    _In_ PSHV_VP_STATE VpState
    )
{
    INT32 cpu_info[4];

    //
    // Verificacao da sequencia magica de desligamento do hypervisor.
    // Quando RAX=0x41414141 e RCX=0x42424242 vindo de Ring 0 (kernel),
    // o hypervisor sinaliza que deve ser descarregado (ExitVm = TRUE).
    // Isso faz o ShvVmxEntryHandler executar o caminho de desligamento.
    //
    if ((VpState->VpRegs->Rax == 0x41414141) &&
        (VpState->VpRegs->Rcx == 0x42424242) &&
        ((ShvVmxRead(GUEST_CS_SELECTOR) & RPL_MASK) == DPL_SYSTEM))
    {
        VpState->ExitVm = TRUE;
        return;
    }

    //
    // Verifica se alguem esta consultando nossa leaf customizada.
    // Qualquer software (inclusive usermode) pode fazer isso com:
    //   int cpuInfo[4];
    //   __cpuid(cpuInfo, 0x53485600);
    // e verificar se cpuInfo[0] == 0x53485600 para saber se o SHV esta ativo.
    //
    if (VpState->VpRegs->Rax == SHV_CPUID_LEAF)
    {
        //
        // Leaf de comunicacao do SimpleVisor. O sub-leaf (ECX) determina
        // qual informacao e retornada. Veja shv_comm.h para a lista completa.
        // Nenhum desses casos passa o CPUID para o hardware -- as respostas
        // sao fabricadas inteiramente pelo hypervisor.
        //
        LARGE_INTEGER   counter;
        UINT32          subleaf = (UINT32)VpState->VpRegs->Rcx;
        PSHV_HV_EVENT   ev;

        // Zera os registradores de saida como default seguro
        VpState->VpRegs->Rax = 0;
        VpState->VpRegs->Rbx = 0;
        VpState->VpRegs->Rcx = 0;
        VpState->VpRegs->Rdx = 0;

        if (subleaf == SHV_QUERY_PRESENCE)
        {
            // EAX = assinatura (a propria leaf), EBX = cpu, ECX = versao
            VpState->VpRegs->Rax = SHV_CPUID_LEAF;
            VpState->VpRegs->Rbx = (UINT64)ShvOsGetCurrentProcessorNumber();
            VpState->VpRegs->Rcx = 1;
        }
        else if (subleaf == SHV_QUERY_LSTAR_READS)
        {
            counter.QuadPart     = ShvLstarReadCount;
            VpState->VpRegs->Rax = counter.LowPart;
            VpState->VpRegs->Rbx = counter.HighPart;
        }
        else if (subleaf == SHV_QUERY_LSTAR_WRITES)
        {
            counter.QuadPart     = ShvLstarWriteCount;
            VpState->VpRegs->Rax = counter.LowPart;
            VpState->VpRegs->Rbx = counter.HighPart;
        }
        else if (subleaf == SHV_QUERY_EXIT_COUNT)
        {
            counter.QuadPart     = ShvExitCount;
            VpState->VpRegs->Rax = counter.LowPart;
            VpState->VpRegs->Rbx = counter.HighPart;
        }
        else if (subleaf == SHV_QUERY_LAST_LSTAR)
        {
            counter.QuadPart     = ShvLastLstarValue;
            VpState->VpRegs->Rax = counter.LowPart;
            VpState->VpRegs->Rbx = counter.HighPart;
        }
        else if (subleaf == SHV_QUERY_HOOK_HITS)
        {
            counter.QuadPart     = ShvEptHookHitCount;
            VpState->VpRegs->Rax = counter.LowPart;
            VpState->VpRegs->Rbx = counter.HighPart;
        }
        else if (subleaf == SHV_QUERY_EVENT_INFO)
        {
            // EAX = total de eventos escritos (32 bits baixos),
            // EBX = tamanho do ring buffer
            counter.QuadPart     = ShvEventCount;
            VpState->VpRegs->Rax = counter.LowPart;
            VpState->VpRegs->Rbx = SHV_EVENT_RING_SIZE;
        }
        else if (subleaf >= SHV_QUERY_EVENT_BASE &&
                 subleaf <  SHV_QUERY_EVENT_BASE + SHV_EVENT_RING_SIZE)
        {
            // Parte base do evento: EAX=SeqNum, EBX=Value.Lo, ECX=Value.Hi, EDX=(Type<<8)|CpuNum
            // Value = GuestRIP para EPT; valor do MSR para LSTAR
            ev = &ShvEventBuffer[subleaf - SHV_QUERY_EVENT_BASE];
            counter.QuadPart     = ev->Value;
            VpState->VpRegs->Rax = ev->SeqNum;
            VpState->VpRegs->Rbx = counter.LowPart;
            VpState->VpRegs->Rcx = counter.HighPart;
            VpState->VpRegs->Rdx = ((UINT32)ev->Type << 8) | ev->CpuNumber;
        }
        else if (subleaf == SHV_QUERY_EPT_CAPS)
        {
            // EAX bit0 = execute-only EPT suportado pelo hardware
            VpState->VpRegs->Rax = ShvEptExecuteOnlySupported & 1u;
        }
        else if (subleaf == SHV_QUERY_COPYVM_HITS)
        {
            // ShvReadVirtualMemoryHookHitCount e um global NT-side comum
            // (nt/hpv_policy_hooks.c, atualizado em PASSIVE_LEVEL pelo hook de
            // MmCopyVirtualMemory) -- shvvmxhv.c so declara o extern e le o
            // valor, sem depender de nenhum header WDK (e so um UINT64).
            counter.QuadPart     = ShvReadVirtualMemoryHookHitCount;
            VpState->VpRegs->Rax = counter.LowPart;
            VpState->VpRegs->Rbx = counter.HighPart;
        }
        else if (subleaf >= SHV_QUERY_EVENT_EXT_BASE &&
                 subleaf <  SHV_QUERY_EVENT_EXT_BASE + SHV_EVENT_RING_SIZE)
        {
            // Parte extendida do mesmo slot: retorna ReturnAddr e Aux.
            // EAX=ReturnAddr.Lo, EBX=ReturnAddr.Hi, ECX=Aux.Lo, EDX=Aux.Hi
            LARGE_INTEGER aux;
            ev = &ShvEventBuffer[subleaf - SHV_QUERY_EVENT_EXT_BASE];
            counter.QuadPart     = ev->ReturnAddr;
            aux.QuadPart         = ev->Aux;
            VpState->VpRegs->Rax = counter.LowPart;
            VpState->VpRegs->Rbx = counter.HighPart;
            VpState->VpRegs->Rcx = aux.LowPart;
            VpState->VpRegs->Rdx = aux.HighPart;
        }
        else if (subleaf >= SHV_QUERY_EVENT_EXT2_BASE &&
                 subleaf <  SHV_QUERY_EVENT_EXT2_BASE + SHV_EVENT_RING_SIZE)
        {
            // Terceira parte do mesmo slot: GUEST_CR3 do evento.
            // EAX=Cr3.Lo, EBX=Cr3.Hi
            LARGE_INTEGER cr3;
            ev = &ShvEventBuffer[subleaf - SHV_QUERY_EVENT_EXT2_BASE];
            cr3.QuadPart         = ev->Cr3;
            VpState->VpRegs->Rax = cr3.LowPart;
            VpState->VpRegs->Rbx = cr3.HighPart;
        }
        else if (subleaf >= SHV_QUERY_EVENT_EXT3_BASE &&
                 subleaf <  SHV_QUERY_EVENT_EXT3_BASE + SHV_EVENT_RING_SIZE)
        {
            // Quarta parte do mesmo slot: Timestamp (FILETIME) do evento.
            // EAX=Timestamp.Lo, EBX=Timestamp.Hi
            LARGE_INTEGER ts;
            ev = &ShvEventBuffer[subleaf - SHV_QUERY_EVENT_EXT3_BASE];
            ts.QuadPart          = ev->Timestamp;
            VpState->VpRegs->Rax = ts.LowPart;
            VpState->VpRegs->Rbx = ts.HighPart;
        }
        else if (subleaf >= SHV_QUERY_EVENT_EXT4_BASE &&
                 subleaf <  SHV_QUERY_EVENT_EXT4_BASE + SHV_EVENT_RING_SIZE)
        {
            // Quinta parte do mesmo slot: GUEST_LINEAR_ADDRESS (VA Fault) do evento.
            // EAX=LinearAddr.Lo, EBX=LinearAddr.Hi
            LARGE_INTEGER la;
            ev = &ShvEventBuffer[subleaf - SHV_QUERY_EVENT_EXT4_BASE];
            la.QuadPart          = ev->LinearAddr;
            VpState->VpRegs->Rax = la.LowPart;
            VpState->VpRegs->Rbx = la.HighPart;
        }
        else if (subleaf >= SHV_QUERY_EVENT_EXT5_BASE &&
                 subleaf <  SHV_QUERY_EVENT_EXT12_BASE + SHV_EVENT_RING_SIZE)
        {
            // Stack trace heuristico: EXT5..EXT12, 2 frames por sub-leaf.
            // EAX/EBX = Stack[2*N], ECX/EDX = Stack[2*N+1]
            LARGE_INTEGER f0, f1;
            UINT32 group = (subleaf - SHV_QUERY_EVENT_EXT5_BASE) / SHV_EVENT_RING_SIZE;
            UINT32 slot  = (subleaf - SHV_QUERY_EVENT_EXT5_BASE) % SHV_EVENT_RING_SIZE;

            ev = &ShvEventBuffer[slot];
            f0.QuadPart = ev->Stack[group * 2];
            f1.QuadPart = ev->Stack[group * 2 + 1];
            VpState->VpRegs->Rax = f0.LowPart;
            VpState->VpRegs->Rbx = f0.HighPart;
            VpState->VpRegs->Rcx = f1.LowPart;
            VpState->VpRegs->Rdx = f1.HighPart;
        }

        return;
    }

    //
    // Para qualquer outra leaf, executa o CPUID real no hardware e repassa
    // o resultado de volta para o guest. O guest nao sabe que passou pelo
    // hypervisor -- tudo e transparente.
    //
    // __cpuidex usa tanto EAX (leaf) quanto ECX (subleaf), necessario para
    // leaves como a 4h e Bh que tem multiplos niveis de informacao.
    //
    __cpuidex(cpu_info, (INT32)VpState->VpRegs->Rax, (INT32)VpState->VpRegs->Rcx);

    //
    // Copia os resultados do CPUID de volta para os registradores do guest.
    // O guest vai ler esses valores como se o CPUID tivesse executado
    // diretamente no hardware -- ele nao tem como saber que passou pelo SHV.
    //
    VpState->VpRegs->Rax = cpu_info[0];
    VpState->VpRegs->Rbx = cpu_info[1];
    VpState->VpRegs->Rcx = cpu_info[2];
    VpState->VpRegs->Rdx = cpu_info[3];
}


//
// === HOOK REAL DE SYSCALL (LSTAR trampoline) ================================
//
// REQUER: KPTI (KVA Shadow) desativado na maquina de teste.
//
// O KPTI e uma mitigacao Meltdown que remove paginas de kernel do mapa de
// usermode (shadow CR3). Quando o hardware executa SYSCALL, o trampoline roda
// com o shadow CR3 ainda ativo -- se tentar escrever em globais do kernel
// (NonPagedPool) que nao estao no shadow CR3, gera #PF sem pilha kernel valida
// → double fault → BSOD 0x7F.
//
// Para desativar o KPTI na maquina de teste, execute como administrador:
//
//   reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" ^
//     /v FeatureSettingsOverride     /t REG_DWORD /d 3 /f
//   reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" ^
//     /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f
//
// Reinicie apos o comando. O proximo passo de implementacao correto sem
// precisar desativar o KPTI e usar um EPT hook no KiSystemCall64, que
// intercepta a execucao no nivel do hypervisor antes da troca de CR3.
//
// O codigo abaixo esta comentado ate que o KPTI seja desativado no ambiente
// de teste.
//
#if 0

UINT64 ShvOriginalLstar = 0;
UINT64 ShvSyscallCount = 0;
UINT64 ShvLastSyscallNumber = 0;

VOID
ShvVmxInstallSyscallHook (
    VOID
    )
{
    UINT64 currentLstar = __readmsr(MSR_LSTAR);
    if (ShvOriginalLstar == 0)
    {
        ShvOriginalLstar = currentLstar;
    }
    __writemsr(MSR_LSTAR, (UINT64)ShvSyscallTrampoline);
}

#endif /* KPTI deve estar desativado para usar o hook acima */

VOID
ShvVmxHandleMsrRead (
    _In_ PSHV_VP_STATE VpState
    )
{
    UINT32 msr;
    LARGE_INTEGER value;

    msr = (UINT32)VpState->VpRegs->Rcx;
    value.QuadPart = __readmsr(msr);

    //
    // Modo passivo: conta, registra e empurra evento ao ring buffer.
    // Nao altera o valor retornado -- o guest le o LSTAR real.
    //
    if (msr == MSR_LSTAR)
    {
        UINT64 rip = ShvVmxRead(GUEST_RIP);
        ShvLstarReadCount++;
        ShvLastLstarValue = value.QuadPart;
        // Value = valor do MSR, ReturnAddr = RIP de quem fez RDMSR, Aux = 0
        ShvHvPushEvent(SHV_EVENT_LSTAR_READ, value.QuadPart, rip, 0, 0);
    }

    VpState->VpRegs->Rax = value.LowPart;
    VpState->VpRegs->Rdx = value.HighPart;
}

VOID
ShvVmxHandleMsrWrite (
    _In_ PSHV_VP_STATE VpState
    )
{
    UINT32 msr;
    LARGE_INTEGER value;

    msr = (UINT32)VpState->VpRegs->Rcx;
    value.LowPart = (UINT32)VpState->VpRegs->Rax;
    value.HighPart = (UINT32)VpState->VpRegs->Rdx;

    //
    // Modo passivo: conta, registra e empurra evento ao ring buffer.
    // Deixa a escrita passar para o hardware sem redirecionar.
    //
    if (msr == MSR_LSTAR)
    {
        UINT64 rip = ShvVmxRead(GUEST_RIP);
        ShvLstarWriteCount++;
        ShvLastLstarValue = value.QuadPart;
        ShvHvPushEvent(SHV_EVENT_LSTAR_WRITE, value.QuadPart, rip, 0, 0);
    }

    __writemsr(msr, value.QuadPart);
}

VOID
ShvVmxHandleXsetbv (
    _In_ PSHV_VP_STATE VpState
    )
{
    //
    // Simply issue the XSETBV instruction on the native logical processor.
    //

    _xsetbv((UINT32)VpState->VpRegs->Rcx,
            VpState->VpRegs->Rdx << 32 |
            VpState->VpRegs->Rax);
}

VOID
ShvVmxHandleVmx (
    _In_ PSHV_VP_STATE VpState
    )
{
    //
    // Set the CF flag, which is how VMX instructions indicate failure
    //
    VpState->GuestEFlags |= 0x1; // VM_FAIL_INVALID

    //
    // RFLAGs is actually restored from the VMCS, so update it here
    //
    __vmx_vmwrite(GUEST_RFLAGS, VpState->GuestEFlags);
}

//
// Le [RSP] do guest de forma segura em VMX root.
// So tenta dereferenciar enderecos canonicos de kernel (>= 0xFFFF800000000000),
// alinhados a 8 bytes. Pilha de kernel e sempre non-paged -- acesso seguro.
// RSP em modo usuario (< 0x8000000000000000) retorna 0.
//
static UINT64
ShvReadGuestReturnAddress (
    VOID
    )
{
    UINT64 rsp = ShvVmxRead(GUEST_RSP);

    if (rsp >= 0xFFFF800000000000ULL && (rsp & 0x7) == 0)
    {
        return *(volatile UINT64*)rsp;
    }
    return 0;
}

//
// Handler para EXIT_REASON_EPT_VIOLATION (razao 48).
//
// Suporta violacoes de Execute (bit 2), Write (bit 1) e Read (bit 0).
//
// Fluxo para qualquer tipo de violacao:
//   1. Identifica o tipo (exec/write) e o hook ativo (legado ou tabela).
//   2. Registra o hit e publica o evento no ring buffer.
//   3. Restaura permissoes completas temporariamente para o guest executar 1 instrucao.
//   4. Liga o MTF para re-armar o hook apos essa instrucao.
//
// SkipRipAdvance = TRUE: a instrucao que causou a violation nao foi executada
// ainda -- o guest deve re-tenta-la com as permissoes temporariamente restauradas.
//

static volatile UINT64 ShvLastEptEventLinearAddr = 0;
static volatile UINT64 ShvLastEptEventCr3         = 0;
static volatile UINT64 ShvLastEptEventTimestamp   = 0;
static volatile UINT8  ShvLastEptEventType        = 0xFF;

//
// Dedup de evento EPT por janela de tempo curta.
//
// O EPT e por-CPU (cada core mantem sua PROPRIA copia das paginas EPT -- ver
// comentario em ShvVmxEptApplyHooks). O mecanismo de "abrir a pagina por 1
// instrucao" (restaura RWX, arma MTF, guest re-executa, MTF re-restringe) so
// abre a pagina NO CORE ATUAL. Se o Windows migrar a thread que esta
// re-executando a instrucao pra OUTRO core core ANTES dela de fato rodar
// (preempcao por interrupcao entre o VM-entry e a instrucao retirar), o novo
// core ainda tem a pagina restrita (nunca recebeu o override temporario) e
// gera OUTRA violacao de EPT real pro MESMO acesso logico -- cada core por
// onde a thread passar loga seu proprio evento, fazendo "1 leitura" aparecer
// como 2 ou 3 eventos identicos (mesmo VA/Cr3/Tipo), nao-deterministico
// dependendo de quantas migracoes acontecerem. Sem suporte a abrir a pagina
// em TODOS os cores de uma vez (custaria um IPI broadcast por violation),
// filtramos aqui: se o evento tem o mesmo Tipo+VA+CR3 do ultimo evento EPT
// dentro de uma janela curta, e' quase certamente um retry migrado do MESMO
// acesso, nao um acesso novo -- nao loga de novo.
//
#define SHV_EPT_EVENT_DEDUP_WINDOW_100NS  500ULL // ~50 microsegundos

static UINT8
ShvHookShouldDedupEvent (
    _In_ UINT8  Type,
    _In_ UINT64 LinearAddr,
    _In_ UINT64 Cr3
    )
{
    UINT64 now = ShvReadSystemTime();
    UINT8  dup = (UINT8)(Type == ShvLastEptEventType &&
                          LinearAddr == ShvLastEptEventLinearAddr &&
                          Cr3 == ShvLastEptEventCr3 &&
                          (now - ShvLastEptEventTimestamp) < SHV_EPT_EVENT_DEDUP_WINDOW_100NS);

    ShvLastEptEventType       = Type;
    ShvLastEptEventLinearAddr = LinearAddr;
    ShvLastEptEventCr3        = Cr3;
    ShvLastEptEventTimestamp  = now;

    return dup;
}

VOID
ShvVmxHandleEptViolation (
    _In_ PSHV_VP_STATE VpState,
    _In_ PSHV_VP_DATA  VpData
    )
{
    UINT64 exitQual;
    UINT64 guestPa;
    UINT64 page;
    UINT64 controls;
    UINT64 linearAddr;
    UINT64 guestCr3;
    UINT32 i;

    exitQual   = ShvVmxRead(EXIT_QUALIFICATION);
    guestPa    = ShvVmxRead(GUEST_PHYSICAL_ADDRESS);
    page       = guestPa & ~0xFFFULL;
    // VA do acesso que causou a violacao (so para a coluna "VA Fault" da GUI).
    linearAddr = ShvVmxRead(GUEST_LINEAR_ADDRESS);
    guestCr3   = ShvVmxRead(GUEST_CR3);

    // Bit 2 = instruction fetch (execute violation)
    if ((exitQual & 0x4) != 0)
    {
        //
        // Value      = GuestRIP (VA da instrucao que sera executada = inicio da funcao).
        // ReturnAddr = [GUEST_RSP] = quem chamou essa funcao (return address do caller).
        //              Se RSP for user-mode (e.g. na fronteira de SYSCALL), retorna 0.
        // Aux        = GPA da pagina executada.
        //
        UINT64 guestRip = ShvVmxRead(GUEST_RIP);
        UINT64 retAddr  = ShvReadGuestReturnAddress();

        if (page == ShvEptHookPhysical)
        {
            ShvEptHookHitCount++;
            ShvHvPushEvent(SHV_EVENT_EPT_EXEC, guestRip, retAddr, guestPa, linearAddr);
        }

        for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
        {
            if ((ShvHookTable[i].PhysAddr != 0) &&
                SHV_HOOK_PAGE_IN_RANGE(i, page) &&
                SHV_HOOK_VA_MATCH(i, linearAddr) &&
                (ShvHookTable[i].Type & SHV_HOOK_EXEC))
            {
                ShvHookTable[i].HitCount++;
                if (!ShvHookShouldDedupEvent(SHV_EVENT_EPT_EXEC, linearAddr, guestCr3))
                    ShvHvPushEvent(SHV_EVENT_EPT_EXEC, guestRip, retAddr, guestPa, linearAddr);
            }
        }
    }
    // Bit 1 = data write violation
    else if ((exitQual & 0x2) != 0)
    {
        //
        // Value      = GuestRIP (instrucao que esta escrevendo = o "caller").
        // ReturnAddr = [GUEST_RSP] = quem chamou a funcao que esta escrevendo.
        // Aux        = GPA da pagina que esta sendo escrita.
        //
        // Nota: se a pagina tem SHV_HOOK_READ (r=0 w=0), um write tambem dispara
        // bit 1. Nesse caso emitimos SHV_EVENT_EPT_READ (nao WRITE), porque o hook
        // instalado e de leitura, nao de escrita.
        //
        UINT64 guestRip = ShvVmxRead(GUEST_RIP);
        UINT64 retAddr  = ShvReadGuestReturnAddress();

        for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
        {
            if (ShvHookTable[i].PhysAddr == 0 || ShvHookTable[i].ShadowPhysAddr != 0)
                continue;
            if (!SHV_HOOK_PAGE_IN_RANGE(i, page))
                continue;
            if (!SHV_HOOK_VA_MATCH(i, linearAddr))
                continue;
            if (ShvHookTable[i].Type & SHV_HOOK_WRITE)
            {
                ShvHookTable[i].HitCount++;
                if (!ShvHookShouldDedupEvent(SHV_EVENT_EPT_WRITE, linearAddr, guestCr3))
                    ShvHvPushEvent(SHV_EVENT_EPT_WRITE, guestRip, retAddr, guestPa, linearAddr);
            }
            else if (ShvHookTable[i].Type & SHV_HOOK_READ)
            {
                // Write numa pagina read-restricted (r=0 w=0): reporta como READ
                ShvHookTable[i].HitCount++;
                if (!ShvHookShouldDedupEvent(SHV_EVENT_EPT_READ, linearAddr, guestCr3))
                    ShvHvPushEvent(SHV_EVENT_EPT_READ, guestRip, retAddr, guestPa, linearAddr);
            }
        }
    }
    // Bit 0 = data read violation (leitura pura, sem write, sem exec)
    else if ((exitQual & 0x1) != 0)
    {
        UINT64 guestRip = ShvVmxRead(GUEST_RIP);
        UINT64 retAddr  = ShvReadGuestReturnAddress();

        for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
        {
            if ((ShvHookTable[i].PhysAddr != 0) &&
                (ShvHookTable[i].ShadowPhysAddr == 0) &&
                SHV_HOOK_PAGE_IN_RANGE(i, page) &&
                SHV_HOOK_VA_MATCH(i, linearAddr) &&
                (ShvHookTable[i].Type & SHV_HOOK_READ))
            {
                ShvHookTable[i].HitCount++;
                if (!ShvHookShouldDedupEvent(SHV_EVENT_EPT_READ, linearAddr, guestCr3))
                    ShvHvPushEvent(SHV_EVENT_EPT_READ, guestRip, retAddr, guestPa, linearAddr);
            }
        }
    }

    // Restaura acesso temporario para o guest executar/ler/escrever 1 instrucao.
    // Shadow hook: o PTE aponta para shadow PA; precisa trocar para original PA.
    // Hook normal: o PTE ja aponta para a PA correta; apenas restaura permissoes.
    {
        UINT8 isShadow = 0;
        for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
        {
            if (ShvHookTable[i].PhysAddr == page &&
                ShvHookTable[i].ShadowPhysAddr != 0)
            {
                isShadow = 1;
                break;
            }
        }

        if (isShadow)
        {
            // Mapeia GPA para a PA original (page == GPA == original PA),
            // R=1 W=1 X=1: precisa de X=1 para que o CPU consiga fazer
            // instruction fetch ao re-executar a instrucao (SkipRipAdvance=TRUE).
            // Sem X=1, o fetch causa nova EPT violation -> loop infinito -> freeze.
            // Janela de 1 instrucao (EPT per-CPU), MTF restaura shadow logo apos.
            ShvVmxEptSetPhysAndPerms(VpData, page, page, 1, 1, 1);
        }
        else
        {
            ShvVmxEptSetPermissions(VpData, page, 1, 1, 1);
        }
    }
    ShvVmxInveptLocal(VpData);

    // Arma MTF para re-restringir apos essa instrucao
    VpData->MtfRestorePhysical = page;
    controls = ShvVmxRead(CPU_BASED_VM_EXEC_CONTROL);
    __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, controls | CPU_BASED_MONITOR_TRAP_FLAG);

    // Nao avanca o RIP -- o guest deve re-executar a instrucao com permissoes ok
    VpState->SkipRipAdvance = TRUE;
}

//
// Handler para EXIT_REASON_MONITOR_TRAP_FLAG (razao 37).
//
// O MTF dispara um VM-exit apos exatamente 1 instrucao do guest.
// Usa ShvVmxEptRearmHook para restaurar as restricoes corretas
// consultando tanto o hook legado quanto a tabela de hooks.
//
VOID
ShvVmxHandleMtf (
    _In_ PSHV_VP_STATE VpState,
    _In_ PSHV_VP_DATA  VpData
    )
{
    UINT64 controls;

    if (VpData->MtfRestorePhysical != 0)
    {
        ShvVmxEptRearmHook(VpData, VpData->MtfRestorePhysical);
        VpData->MtfRestorePhysical = 0;
    }

    // Desliga o MTF
    controls = ShvVmxRead(CPU_BASED_VM_EXEC_CONTROL);
    __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, controls & ~CPU_BASED_MONITOR_TRAP_FLAG);

    // MTF nao tem VM_EXIT_INSTRUCTION_LEN valido; nao avancamos o RIP
    VpState->SkipRipAdvance = TRUE;
}

VOID
ShvVmxHandleExit (
    _In_ PSHV_VP_STATE VpState,
    _In_ PSHV_VP_DATA  VpData
    )
{
    ShvExitCount++;
    ShvLastExitReason = VpState->ExitReason;

    // Aplica hooks pendentes a este CPU quando a tabela foi atualizada
    if (VpData->EptHookVersion != ShvHookVersion)
    {
        ShvVmxEptApplyHooks(VpData);
        VpData->EptHookVersion = ShvHookVersion;
    }

    // Por default avancamos o RIP; EPT violation e MTF desligam esse flag.
    VpState->SkipRipAdvance = FALSE;

    switch (VpState->ExitReason)
    {
    case EXIT_REASON_CPUID:
        ShvVmxHandleCpuid(VpState);
        break;
    case EXIT_REASON_INVD:
        ShvVmxHandleInvd();
        break;
    case EXIT_REASON_XSETBV:
        ShvVmxHandleXsetbv(VpState);
        break;
    case EXIT_REASON_MSR_READ:
        ShvVmxHandleMsrRead(VpState);
        break;
    case EXIT_REASON_MSR_WRITE:
        ShvVmxHandleMsrWrite(VpState);
        break;
    case EXIT_REASON_EPT_VIOLATION:
        ShvVmxHandleEptViolation(VpState, VpData);
        break;
    case EXIT_REASON_MONITOR_TRAP_FLAG:
        ShvVmxHandleMtf(VpState, VpData);
        break;
    case EXIT_REASON_VMCALL:
        if (VpState->VpRegs->Rax == 0x42424242)
        {
            VpState->VpRegs->Rcx = 0x43434343;
        }
        break;
    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMLAUNCH:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
        ShvVmxHandleVmx(VpState);
        break;
    default:
        break;
    }

    // Avanca o RIP somente para exits que representam instrucoes completas.
    // EPT violation e MTF nao devem adiantar o RIP.
    if (VpState->SkipRipAdvance == FALSE)
    {
        VpState->GuestRip += ShvVmxRead(VM_EXIT_INSTRUCTION_LEN);
        __vmx_vmwrite(GUEST_RIP, VpState->GuestRip);
    }
}

DECLSPEC_NORETURN
VOID
ShvVmxEntryHandler (
    _In_ PCONTEXT Context
    )
{
    SHV_VP_STATE guestContext;
    PSHV_VP_DATA vpData;

    //
    // Because we had to use RCX when calling ShvOsCaptureContext, its value
    // was actually pushed on the stack right before the call. Go dig into the
    // stack to find it, and overwrite the bogus value that's there now.
    //
    Context->Rcx = *(UINT64*)((uintptr_t)Context - sizeof(Context->Rcx));

    //
    // Get the per-VP data for this processor.
    //
    vpData = (VOID*)((uintptr_t)(Context + 1) - KERNEL_STACK_SIZE);

    //
    // Build a little stack context to make it easier to keep track of certain
    // guest state, such as the RIP/RSP/RFLAGS, and the exit reason. The rest
    // of the general purpose registers come from the context structure that we
    // captured on our own with RtlCaptureContext in the assembly entrypoint.
    //
    guestContext.GuestEFlags = ShvVmxRead(GUEST_RFLAGS);
    guestContext.GuestRip = ShvVmxRead(GUEST_RIP);
    guestContext.GuestRsp = ShvVmxRead(GUEST_RSP);
    guestContext.ExitReason = ShvVmxRead(VM_EXIT_REASON) & 0xFFFF;
    guestContext.VpRegs = Context;
    guestContext.ExitVm = FALSE;
    guestContext.SkipRipAdvance = FALSE;

    //
    // Call the generic handler
    //
    ShvVmxHandleExit(&guestContext, vpData);

    //
    // Did we hit the magic exit sequence, or should we resume back to the VM
    // context?
    //
    if (guestContext.ExitVm != FALSE)
    {
        //
        // Return the VP Data structure in RAX:RBX which is going to be part of
        // the CPUID response that the caller (ShvVpUninitialize) expects back.
        // Return confirmation in RCX that we are loaded
        //
        Context->Rax = (uintptr_t)vpData >> 32;
        Context->Rbx = (uintptr_t)vpData & 0xFFFFFFFF;
        Context->Rcx = 0x43434343;

        //
        // Perform any OS-specific CPU uninitialization work
        //
        ShvOsUnprepareProcessor(vpData);

        //
        // Our callback routine may have interrupted an arbitrary user process,
        // and therefore not a thread running with a systemwide page directory.
        // Therefore if we return back to the original caller after turning off
        // VMX, it will keep our current "host" CR3 value which we set on entry
        // to the PML4 of the SYSTEM process. We want to return back with the
        // correct value of the "guest" CR3, so that the currently executing
        // process continues to run with its expected address space mappings.
        //
        __writecr3(ShvVmxRead(GUEST_CR3));

        //
        // Finally, restore the stack, instruction pointer and EFLAGS to the
        // original values present when the instruction causing our VM-Exit
        // execute (such as ShvVpUninitialize). This will effectively act as
        // a longjmp back to that location.
        //
        Context->Rsp = guestContext.GuestRsp;
        Context->Rip = (UINT64)guestContext.GuestRip;
        Context->EFlags = (UINT32)guestContext.GuestEFlags;

        //
        // Turn off VMX root mode on this logical processor. We're done here.
        //
        __vmx_off();
    }
    else
    {
        //
        // Because we won't be returning back into assembly code, nothing will
        // ever know about the "pop rcx" that must technically be done (or more
        // accurately "add rsp, 4" as rcx will already be correct thanks to the
        // fixup earlier. In order to keep the stack sane, do that adjustment
        // here.
        //
        Context->Rsp += sizeof(Context->Rcx);

        //
        // Return into a VMXRESUME intrinsic, which we broke out as its own
        // function, in order to allow this to work. No assembly code will be
        // needed as RtlRestoreContext will fix all the GPRs, and what we just
        // did to RSP will take care of the rest.
        //
        Context->Rip = (UINT64)ShvVmxResume;
    }

    //
    // Restore the context to either ShvVmxResume, in which case the CPU's VMX
    // facility will do the "true" return back to the VM (but without restoring
    // GPRs, which is why we must do it here), or to the original guest's RIP,
    // which we use in case an exit was requested. In this case VMX must now be
    // off, and this will look like a longjmp to the original stack and RIP.
    //
    ShvOsRestoreContext(Context);
}


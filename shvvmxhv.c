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
    UINT64 VirtAddr;       // VA original do hook (para exibicao na GUI)
    UINT64 Pid;            // PID do processo alvo (0 = kernel)
    UINT64 RangeSize;      // numero de paginas hookadas neste bloco
    UINT64 TargetCr3;      // CR3 do processo alvo (0 = qualquer processo)
} SHV_HOOK_ENTRY;

static SHV_HOOK_ENTRY ShvHookTable[SHV_HOOK_MAX_ENTRIES];
volatile UINT64       ShvHookVersion = 0;

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
} SHV_HV_EVENT, *PSHV_HV_EVENT;

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
    _In_ UINT64 Aux
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
    _In_ UINT64 TargetCr3
    )
{
    UINT32 i;
    UINT64 page = PhysAddr & ~0xFFFULL;

    // Atualiza entrada existente para esta pagina
    for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
    {
        if (ShvHookTable[i].PhysAddr == page)
        {
            ShvHookTable[i].Type |= HookType;
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
            ShvHookTable[i].VirtAddr   = VirtAddr;
            ShvHookTable[i].Pid        = Pid;
            ShvHookTable[i].RangeSize  = RangeSize ? RangeSize : 1;
            ShvHookTable[i].TargetCr3  = TargetCr3;
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
            ShvHookTable[i].PhysAddr       = 0;
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
VOID
ShvClearEvents (
    VOID
    )
{
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
        UINT64 pa;
        UINT8  type;
        UINT8  r, w, x;

        if (ShvHookTable[i].PhysAddr == 0)
        {
            continue;
        }

        pa   = ShvHookTable[i].PhysAddr;
        type = ShvHookTable[i].Type;

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
            // READ hook requer r=0; EPT nao permite w=1 com r=0, logo w=0 tambem.
            r = (type & SHV_HOOK_READ)  ? 0 : 1;
            w = ((type & SHV_HOOK_WRITE) || (r == 0)) ? 0 : 1;
            x = (type & SHV_HOOK_EXEC)  ? 0 : 1;
            ShvVmxEptSetPermissions(VpData, pa, r, w, x);
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

    // Tabela de hooks do usermode (EPT normal)
    for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
    {
        if (ShvHookTable[i].PhysAddr == page &&
            ShvHookTable[i].ShadowPhysAddr == 0)
        {
            if (ShvHookTable[i].Type & SHV_HOOK_EXEC)  x = 0;
            if (ShvHookTable[i].Type & SHV_HOOK_WRITE) w = 0;
            if (ShvHookTable[i].Type & SHV_HOOK_READ)  { r = 0; w = 0; }
        }
    }

    ShvVmxEptSetPermissions(VpData, page, r, w, x);
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
        ShvHvPushEvent(SHV_EVENT_LSTAR_READ, value.QuadPart, rip, 0);
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
        ShvHvPushEvent(SHV_EVENT_LSTAR_WRITE, value.QuadPart, rip, 0);
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
    UINT32 i;

    exitQual = ShvVmxRead(EXIT_QUALIFICATION);
    guestPa  = ShvVmxRead(GUEST_PHYSICAL_ADDRESS);
    page     = guestPa & ~0xFFFULL;

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
            ShvHvPushEvent(SHV_EVENT_EPT_EXEC, guestRip, retAddr, guestPa);
        }

        {
            UINT64 guestCr3 = ShvVmxRead(GUEST_CR3);
            for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
            {
                if ((ShvHookTable[i].PhysAddr == page) &&
                    (ShvHookTable[i].Type & SHV_HOOK_EXEC) &&
                    (ShvHookTable[i].TargetCr3 == 0 || guestCr3 == ShvHookTable[i].TargetCr3))
                {
                    ShvHookTable[i].HitCount++;
                    ShvHvPushEvent(SHV_EVENT_EPT_EXEC, guestRip, retAddr, guestPa);
                }
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

        {
            UINT64 guestCr3 = ShvVmxRead(GUEST_CR3);
            for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
            {
                if (ShvHookTable[i].PhysAddr != page || ShvHookTable[i].ShadowPhysAddr != 0)
                    continue;
                if (ShvHookTable[i].TargetCr3 != 0 && guestCr3 != ShvHookTable[i].TargetCr3)
                    continue;
                if (ShvHookTable[i].Type & SHV_HOOK_WRITE)
                {
                    ShvHookTable[i].HitCount++;
                    ShvHvPushEvent(SHV_EVENT_EPT_WRITE, guestRip, retAddr, guestPa);
                }
                else if (ShvHookTable[i].Type & SHV_HOOK_READ)
                {
                    // Write numa pagina read-restricted (r=0 w=0): reporta como READ
                    ShvHookTable[i].HitCount++;
                    ShvHvPushEvent(SHV_EVENT_EPT_READ, guestRip, retAddr, guestPa);
                }
            }
        }
    }
    // Bit 0 = data read violation (leitura pura, sem write, sem exec)
    else if ((exitQual & 0x1) != 0)
    {
        UINT64 guestRip = ShvVmxRead(GUEST_RIP);
        UINT64 retAddr  = ShvReadGuestReturnAddress();

        {
            UINT64 guestCr3 = ShvVmxRead(GUEST_CR3);
            for (i = 0; i < SHV_HOOK_MAX_ENTRIES; i++)
            {
                if ((ShvHookTable[i].PhysAddr == page) &&
                    (ShvHookTable[i].ShadowPhysAddr == 0) &&
                    (ShvHookTable[i].Type & SHV_HOOK_READ) &&
                    (ShvHookTable[i].TargetCr3 == 0 || guestCr3 == ShvHookTable[i].TargetCr3))
                {
                    ShvHookTable[i].HitCount++;
                    ShvHvPushEvent(SHV_EVENT_EPT_READ, guestRip, retAddr, guestPa);
                }
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


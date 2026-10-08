/*++

Module Name:

    shv_comm.h

Abstract:

    Constantes compartilhadas entre o hypervisor (modo kernel) e o programa
    de monitoramento (modo usuario). Apenas #defines -- nenhum tipo especifico
    de modo -- para que o arquivo possa ser incluido em ambos os contextos.

--*/

#pragma once

//
// Leaf CPUID usada para toda comunicacao com o SimpleVisor.
// Qualquer processo (inclusive sem privilegios) pode chamar:
//
//   int info[4];
//   __cpuidex(info, SHV_CPUID_LEAF, sub_leaf);
//
#define SHV_CPUID_LEAF              0x80000042u

//
// Sub-leaves (valor passado em ECX ao chamar __cpuidex).
// O retorno sempre usa EAX/EBX para valores de 64 bits:
//   EAX = 32 bits baixos, EBX = 32 bits altos.
//
#define SHV_QUERY_PRESENCE          0   // EAX=leaf (assinatura), EBX=cpu, ECX=versao
#define SHV_QUERY_LSTAR_READS       1   // total de RDMSR LSTAR interceptados
#define SHV_QUERY_LSTAR_WRITES      2   // total de WRMSR LSTAR interceptados
#define SHV_QUERY_EXIT_COUNT        3   // total de VM-exits desde o load
#define SHV_QUERY_LAST_LSTAR        4   // ultimo valor lido/escrito no LSTAR
#define SHV_QUERY_HOOK_HITS         5   // total de EPT execute hooks disparados (KiSystemCall64)
#define SHV_QUERY_EVENT_INFO        10  // EAX=total de eventos escritos, EBX=ring size
#define SHV_QUERY_EVENT_BASE        11  // ECX=11+slot -> entrada do ring buffer:
                                        //   EAX=SeqNum, EBX=Value.Low,
                                        //   ECX=Value.High, EDX=(Type<<8)|CpuNum
                                        // Value = GuestRIP para EPT; MSR value para LSTAR
#define SHV_QUERY_EVENT_EXT_BASE    27  // ECX=27+slot -> parte extendida do mesmo slot:
                                        //   EAX=ReturnAddr.Low, EBX=ReturnAddr.High
                                        //   ECX=Aux.Low (GPA para write, 0 para exec)
                                        //   EDX=Aux.High

//
// Tipos de evento armazenados no ring buffer.
// Adicionados pelo hypervisor a cada interceptacao; lidos pelo usermode.
//
#define SHV_EVENT_LSTAR_READ        1   // RDMSR no LSTAR (ex: PatchGuard verificando)
#define SHV_EVENT_LSTAR_WRITE       2   // WRMSR no LSTAR (ex: Windows configurando syscall)
#define SHV_EVENT_EPT_EXEC          3   // EPT execute violation
#define SHV_EVENT_EPT_WRITE         4   // EPT write violation

//
// Tamanho do ring buffer de eventos. Deve ser potencia de 2.
// Quando cheio, entradas mais antigas sao sobrescritas.
//
#define SHV_EVENT_RING_SIZE         16

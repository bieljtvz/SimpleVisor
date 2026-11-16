/*++

Module Name:

    thread_utils.h

Abstract:

    Captura de contexto/stack de uma thread arbitraria via APC especial de
    kernel -- mesma tecnica usada pelo KProcessHacker/Process Hacker
    (KphCaptureStackBackTraceThread em thread.c) pra ver a stack de threads
    de processos protegidos (PPL), onde PsGetContextThread falha (ver
    memory/fixes.md: PspGetContextThreadInternal tem checagens proprias que
    nao tem a ver com PP/PPL em si, mas acabam nao funcionando pra esse caso).

    Como funciona: enfileira uma APC ESPECIAL de kernel na thread alvo. Uma
    APC de kernel e entregue e executada usando a PROPRIA pilha/registradores
    da thread alvo, no proximo ponto seguro -- entao o codigo dentro da APC
    roda "como se fosse" a thread alvo, e RtlCaptureContext/RtlWalkFrameChain
    ali dentro capturam o estado de verdade dela, sem precisar de handle
    usermode nem passar pela logica adicional de PsGetContextThread. Isso
    nao e afetado por protecao de processo (PPL/PP), porque APC de kernel e
    um mecanismo puramente kernel-mode, sem check de handle/ACL.

    IMPORTANTE: a stack capturada e a stack de KERNEL da thread no momento
    da entrega da APC (ela pode estar no meio de um syscall) -- os frames
    incluem modulos do KERNEL (ntoskrnl.exe + drivers), igual o Process
    Hacker mostra. NAO e a stack de usermode (pra isso, o caminho classico
    via OpenProcess/OpenThread/StackWalk64 em tab_procs.cpp continua sendo
    usado quando possivel, com simbolos de verdade).

Environment:

    Kernel mode, PASSIVE_LEVEL no chamador (HpvCaptureThreadStack espera a
    APC completar) -- a APC em si roda em APC_LEVEL no contexto da thread
    alvo.

--*/

#pragma once
#include <ntifs.h>

#define HPV_STACK_MAX_FRAMES 32

typedef struct _HPV_THREAD_STACK_CAPTURE
{
    UINT64 Rip;
    UINT64 Rsp;
    UINT64 Rbp;
    ULONG  FrameCount;
    UINT64 Frames[HPV_STACK_MAX_FRAMES]; // enderecos de retorno (RtlWalkFrameChain)
} HPV_THREAD_STACK_CAPTURE, *PHPV_THREAD_STACK_CAPTURE;

// Resolve dinamicamente (MmGetSystemRoutineAddress) KeInitializeApc/
// KeInsertQueueApc/KeWaitForSingleObject/RtlWalkFrameChain -- nao estao nos
// headers publicos desta WDK, mas sao exportadas pelo ntoskrnl (confirmado
// via dumpbin). Chamar uma vez em DriverEntry, igual HpvResolveOptionalApis
// em nt/shvos.c. Loga cada uma via ShvLog.
VOID
HpvThreadUtilsResolveApis (
    VOID
    );

// Captura Rip/Rsp/Rbp + ate HPV_STACK_MAX_FRAMES enderecos de retorno da
// pilha de KERNEL da thread Thread, via APC especial. STATUS_NOT_SUPPORTED
// se as APIs dinamicas nao foram resolvidas (ver acima); STATUS_UNSUCCESSFUL
// se a APC nao pode ser enfileirada (thread terminando) ou a thread saiu
// antes da entrega (rundown).
NTSTATUS
HpvCaptureThreadStack (
    _In_  PETHREAD Thread,
    _Out_ PHPV_THREAD_STACK_CAPTURE Capture
    );

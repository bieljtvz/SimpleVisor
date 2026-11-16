/*++

Module Name:

    thread_utils.c

Abstract:

    Implementacao de HpvCaptureThreadStack (ver thread_utils.h) -- captura
    de contexto/stack de uma thread arbitraria via APC especial de kernel,
    mesma tecnica do KProcessHacker/Process Hacker. Extraido pra arquivo
    proprio (em vez de ir direto em nt/shvos.c) pra nao misturar mais uma
    maquinaria de resolucao dinamica de API com o dispatch de IOCTL.

Environment:

    Kernel mode.

--*/

#include <ntifs.h>
#pragma warning(disable:4996)  // ExAllocatePoolWithTag deprecated em WDK recente
#include "shvos_internal.h"
#include "thread_utils.h"

//
// KAPC_ENVIRONMENT / PKNORMAL_ROUTINE / PKKERNEL_ROUTINE / PKRUNDOWN_ROUTINE
// -- layout x64 estavel desde Vista, usado por KeInitializeApc/
// KeInsertQueueApc, mas NAO declarados nos headers publicos desta WDK (igual
// as outras APIs hand-declared em nt/shvos.c). O struct KAPC em si (KAPC,
// *PKAPC, *PRKAPC) continua vindo do header publico (wdm.h) -- so os tipos
// de callback e o enum de ambiente precisam ser declarados aqui.
//
typedef enum _HPV_KAPC_ENVIRONMENT
{
    HpvOriginalApcEnvironment,
    HpvAttachedApcEnvironment,
    HpvCurrentApcEnvironment,
    HpvInsertApcEnvironment
} HPV_KAPC_ENVIRONMENT;

typedef VOID (*PHPV_KNORMAL_ROUTINE)(
    _In_opt_ PVOID NormalContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

typedef VOID (*PHPV_KKERNEL_ROUTINE)(
    _In_    PKAPC Apc,
    _Inout_ PHPV_KNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
    );

typedef VOID (*PHPV_KRUNDOWN_ROUTINE)(
    _In_ PKAPC Apc
    );

//
// KeInitializeApc/KeInsertQueueApc/KeWaitForSingleObject/RtlWalkFrameChain --
// exportadas pelo ntoskrnl (confirmado via dumpbin /exports no .lib do WDK),
// mas sem prototype nos headers publicos desta WDK especifica. Resolvidas
// dinamicamente (mesmo motivo/padrao de nt/shvos.c: import estatico de algo
// nao exportado pela build real do Windows derruba o driver inteiro no
// "sc start", sem log nenhum -- ver memory/fixes.md).
//
typedef VOID (*PFN_KeInitializeApc)(
    _Out_    PRKAPC Apc,
    _In_     PKTHREAD Thread,
    _In_     HPV_KAPC_ENVIRONMENT Environment,
    _In_     PHPV_KKERNEL_ROUTINE KernelRoutine,
    _In_opt_ PHPV_KRUNDOWN_ROUTINE RundownRoutine,
    _In_opt_ PHPV_KNORMAL_ROUTINE NormalRoutine,
    _In_opt_ KPROCESSOR_MODE ProcessorMode,
    _In_opt_ PVOID NormalContext
    );

typedef BOOLEAN (*PFN_KeInsertQueueApc)(
    _Inout_  PRKAPC Apc,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _In_     KPRIORITY Increment
    );

typedef NTSTATUS (*PFN_KeWaitForSingleObject)(
    _In_     PVOID Object,
    _In_     KWAIT_REASON WaitReason,
    _In_     KPROCESSOR_MODE WaitMode,
    _In_     BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef ULONG (*PFN_RtlWalkFrameChain)(
    _Out_ PVOID* Callers,
    _In_  ULONG Count,
    _In_  ULONG Flags
    );

static PFN_KeInitializeApc       g_pKeInitializeApc       = NULL;
static PFN_KeInsertQueueApc      g_pKeInsertQueueApc      = NULL;
static PFN_KeWaitForSingleObject g_pKeWaitForSingleObject = NULL;
static PFN_RtlWalkFrameChain     g_pRtlWalkFrameChain     = NULL;

VOID
HpvThreadUtilsResolveApis (
    VOID
    )
{
    struct {
        PCWSTR Name;
        PVOID* Target;
    } apis[] = {
        { L"KeInitializeApc",       (PVOID*)&g_pKeInitializeApc       },
        { L"KeInsertQueueApc",      (PVOID*)&g_pKeInsertQueueApc      },
        { L"KeWaitForSingleObject", (PVOID*)&g_pKeWaitForSingleObject },
        { L"RtlWalkFrameChain",     (PVOID*)&g_pRtlWalkFrameChain     },
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(apis); i++)
    {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, apis[i].Name);
        *apis[i].Target = MmGetSystemRoutineAddress(&name);

        ShvLog("[SHV] API opcional %ws: %s\n", apis[i].Name,
               *apis[i].Target ? "OK" : "NAO ENCONTRADA nesta build do Windows");
    }
}

typedef struct _HPV_CAPTURE_APC_CTX
{
    KAPC                     Apc;
    KEVENT                   Done;
    HPV_THREAD_STACK_CAPTURE Capture;
} HPV_CAPTURE_APC_CTX, *PHPV_CAPTURE_APC_CTX;

//
// Roda DENTRO do contexto da thread alvo (entrega de APC especial de
// kernel) -- RtlCaptureContext/RtlWalkFrameChain aqui pegam o estado de
// VERDADE da thread alvo (pilha de kernel dela), nao da thread que chamou
// HpvCaptureThreadStack.
//
static VOID
HpvCaptureStackKernelRoutine (
    _In_    PKAPC Apc,
    _Inout_ PHPV_KNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
    )
{
    PHPV_CAPTURE_APC_CTX ctx = CONTAINING_RECORD(Apc, HPV_CAPTURE_APC_CTX, Apc);
    CONTEXT fullCtx;

    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    *NormalRoutine = NULL; // APC especial de kernel -- sem fase "normal" depois

    RtlZeroMemory(&fullCtx, sizeof(fullCtx));
    fullCtx.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&fullCtx);

    ctx->Capture.Rip = fullCtx.Rip;
    ctx->Capture.Rsp = fullCtx.Rsp;
    ctx->Capture.Rbp = fullCtx.Rbp;
    ctx->Capture.FrameCount = g_pRtlWalkFrameChain(
        (PVOID*)ctx->Capture.Frames, HPV_STACK_MAX_FRAMES, 0);

    KeSetEvent(&ctx->Done, IO_NO_INCREMENT, FALSE);
}

//
// A thread saiu antes da APC ser entregue -- so libera quem esta esperando
// (FrameCount fica 0, ja zerado na alocacao).
//
static VOID
HpvCaptureStackRundownRoutine (
    _In_ PKAPC Apc
    )
{
    PHPV_CAPTURE_APC_CTX ctx = CONTAINING_RECORD(Apc, HPV_CAPTURE_APC_CTX, Apc);
    KeSetEvent(&ctx->Done, IO_NO_INCREMENT, FALSE);
}

NTSTATUS
HpvCaptureThreadStack (
    _In_  PETHREAD Thread,
    _Out_ PHPV_THREAD_STACK_CAPTURE Capture
    )
{
    PHPV_CAPTURE_APC_CTX ctx;

    RtlZeroMemory(Capture, sizeof(*Capture));

    if (g_pKeInitializeApc == NULL || g_pKeInsertQueueApc == NULL ||
        g_pKeWaitForSingleObject == NULL || g_pRtlWalkFrameChain == NULL)
        return STATUS_NOT_SUPPORTED;

    ctx = (PHPV_CAPTURE_APC_CTX)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*ctx), 'kSpH');
    if (ctx == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(ctx, sizeof(*ctx));
    KeInitializeEvent(&ctx->Done, NotificationEvent, FALSE);

    g_pKeInitializeApc(&ctx->Apc,
                       (PKTHREAD)Thread,
                       HpvOriginalApcEnvironment,
                       HpvCaptureStackKernelRoutine,
                       HpvCaptureStackRundownRoutine,
                       NULL,
                       KernelMode,
                       NULL);

    if (!g_pKeInsertQueueApc(&ctx->Apc, NULL, NULL, 0))
    {
        // Falha tipica: thread ja comecou a terminar (ApcQueueable=0).
        ExFreePoolWithTag(ctx, 'kSpH');
        return STATUS_UNSUCCESSFUL;
    }

    g_pKeWaitForSingleObject(&ctx->Done, Executive, KernelMode, FALSE, NULL);

    *Capture = ctx->Capture;
    ExFreePoolWithTag(ctx, 'kSpH');

    return (Capture->Rip != 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

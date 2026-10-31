/*++

Module Name:

    shvos_beep.c

Abstract:

    Hijack do driver Beep, usado como canal de comunicacao encoberto
    (SHV_COMM_MODE == SHV_COMM_BEEP_HIJACK) quando o driver nao usa um
    device object proprio. So compilado nesse modo de comunicacao.

    Duas etapas (ver comentario em ShvBeepHijackSetup):
      1. Boot (antes do ShvLoad): hijack direto da tabela de dispatch.
      2. Depois (IOCTL SHV_CMD_BEEP_SHADOW_SETUP, hipervisor ja rodando):
         upgrade pra hook via EPT shadow na funcao original -- ver
         nt/shvos_ioctl.c.

    Extraido de shvos.c para isolar essa responsabilidade.

Environment:

    Kernel mode only.

--*/

#include <ntifs.h>
#include <intrin.h>
#include "..\shv_x.h"
#include "..\shv_dbg.h"
#include "shvos_internal.h"

#if SHV_COMM_MODE == SHV_COMM_BEEP_HIJACK

// Forward declaration: definida em nt/shvos_ioctl.c.
NTSTATUS ShvDispatchIoctl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

// IoDriverObjectType nao e declarado em todos os headers do WDK moderno
extern POBJECT_TYPE *IoDriverObjectType;

//
// Estado do hijack do driver Beep.
// Guardamos o dispatch original para restaurar no unload.
//
static PDRIVER_OBJECT   g_BeepDriverObject   = NULL;
static PDRIVER_DISPATCH g_BeepOriginalControl = NULL;

typedef NTSTATUS (*pfnObReferenceObjectByName)(
    PUNICODE_STRING ObjectPath,
    ULONG           Attributes,
    PACCESS_STATE   PassedAccessState,
    ACCESS_MASK     DesiredAccess,
    POBJECT_TYPE    ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID           ParseContext,
    PVOID*          ObjectPtr);

// Nao-static: usada tambem por nt/shvos.c (SHV_CMD_BEEP_SHADOW_SETUP) para
// obter o PDRIVER_OBJECT do Beep quando o hijack de tabela ja nao esta
// ativo (ShvBeepGetOriginalControl() == NULL).
NTSTATUS
ShvBeepGetDriverObject (
    _Out_ PDRIVER_OBJECT* OutObject
    )
{
    UNICODE_STRING routineName, drvName;
    pfnObReferenceObjectByName ObRefByName;

    RtlInitUnicodeString(&routineName, L"ObReferenceObjectByName");
    ObRefByName = (pfnObReferenceObjectByName)
        MmGetSystemRoutineAddress(&routineName);
    if (ObRefByName == NULL)
        return STATUS_NOT_FOUND;

    RtlInitUnicodeString(&drvName, L"\\Driver\\Beep");
    return ObRefByName(&drvName,
                       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                       NULL, 0,
                       *IoDriverObjectType,
                       KernelMode, NULL,
                       (PVOID*)OutObject);
}

NTSTATUS
ShvBeepHijackSetup (
    VOID
    )
{
    NTSTATUS status = ShvBeepGetDriverObject(&g_BeepDriverObject);
    if (!NT_SUCCESS(status))
        return status;

    // ETAPA 1 (boot, ANTES do ShvLoad): hijack direto da entrada da tabela
    // de dispatch -- simples, funciona imediatamente, nao depende do
    // hipervisor estar rodando. NAO use HpvHookFuncByVa aqui: ela precisa
    // de ShvEptExecuteOnlySupported (so setado durante ShvLoad) e de
    // ShvFlushHooksAllCpus (precisa da VMLAUNCH ja ter rodado) -- chamada
    // neste ponto, SEMPRE retorna STATUS_NOT_SUPPORTED silenciosamente.
    //
    // ETAPA 2 (depois, via IOCTL SHV_CMD_BEEP_SHADOW_SETUP, com o
    // hipervisor ja carregado): troca esse hijack direto pelo hook via EPT
    // shadow na funcao original (ai sim usando HpvHookFuncByVa), e restaura
    // MajorFunction[...] pro valor original -- o "stealth" so existe a
    // partir dessa segunda etapa.
    g_BeepOriginalControl = g_BeepDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    g_BeepDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ShvDispatchIoctl;

    // ObReferenceObjectByName ja incrementou a refcount; decrementamos
    // pois so precisamos do ponteiro para restaurar no unload.
    ObDereferenceObject(g_BeepDriverObject);
    return STATUS_SUCCESS;
}

// Le o valor atual de g_BeepOriginalControl -- usado por nt/shvos_ioctl.c
// (SHV_CMD_BEEP_SHADOW_SETUP) para saber o handler original antes de
// chamar ShvBeepHijackTeardown (que o zera). NULL se o hijack de tabela
// (Etapa 1) nao estiver mais ativo.
PDRIVER_DISPATCH
ShvBeepGetOriginalControl (
    VOID
    )
{
    return g_BeepOriginalControl;
}

VOID
ShvBeepHijackTeardown (
    VOID
    )
{
    if (g_BeepOriginalControl == NULL)
        return;

    // Re-obtem o objeto para garantir que ainda e valido
    PDRIVER_OBJECT beepObj = NULL;
    if (NT_SUCCESS(ShvBeepGetDriverObject(&beepObj)))
    {
        // Restaura atomicamente para evitar race com IRP em voo
        InterlockedExchangePointer(
            (PVOID*)&beepObj->MajorFunction[IRP_MJ_DEVICE_CONTROL],
            (PVOID)g_BeepOriginalControl);
        ObDereferenceObject(beepObj);
    }
    g_BeepOriginalControl = NULL;
    g_BeepDriverObject    = NULL;
}

#endif // SHV_COMM_BEEP_HIJACK

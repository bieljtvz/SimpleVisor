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

#pragma warning(disable:4152)  // conversao ponteiro de funcao / dado (ShvDispatchIoctl como PVOID)
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

//
// ETAPA 2: upgrade do hijack direto de tabela (Etapa 1, ShvBeepHijackSetup)
// pra um shadow hook via EPT na funcao ORIGINAL do Beep -- so pode rodar
// depois do hipervisor ja estar carregado (chamado via IOCTL
// SHV_CMD_BEEP_SHADOW_SETUP, nunca direto do DriverEntry, mesmo motivo do
// comentario em ShvBeepHijackSetup: HpvHookFuncByVa precisa de
// ShvEptExecuteOnlySupported/ShvFlushHooksAllCpus, que so existem apos
// ShvLoad ter rodado).
//
// g_BeepShadowVa != NULL == upgrade ja instalado (idempotente: chamar de
// novo so devolve a GPA ja em uso, nao reinstala nem falha).
//
static PVOID g_BeepShadowVa = NULL;

NTSTATUS
ShvBeepShadowSetup (
    _Out_ UINT64* OutGpa
    )
{
    PDRIVER_DISPATCH  origControl;
    PHYSICAL_ADDRESS  pa;
    PVOID             trampoline = NULL;
    NTSTATUS          status;

    *OutGpa = 0;

    if (g_BeepShadowVa != NULL)
    {
        __try
        {
            pa = MmGetPhysicalAddress(g_BeepShadowVa);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            pa.QuadPart = 0;
        }
        *OutGpa = (UINT64)pa.QuadPart & ~0xFFFULL;
        return STATUS_SUCCESS;
    }

    // ShvBeepGetOriginalControl() devolve NULL se a Etapa 1 nunca foi
    // instalada (ShvBeepHijackSetup falhou no DriverEntry) -- nada pra
    // fazer upgrade.
    origControl = ShvBeepGetOriginalControl();
    if (origControl == NULL)
        return STATUS_NOT_FOUND;

    status = HpvHookFuncByVa((PVOID)origControl, (PVOID)ShvDispatchIoctl, &trampoline);
    if (!NT_SUCCESS(status))
        return status;

    __try
    {
        pa = MmGetPhysicalAddress((PVOID)origControl);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        HpvUnhookFuncByVa((PVOID)origControl);
        return STATUS_ACCESS_VIOLATION;
    }

    g_BeepShadowVa = (PVOID)origControl;

    // Restaura MajorFunction[IRP_MJ_DEVICE_CONTROL] pro handler ORIGINAL do
    // Beep -- a partir de agora e o shadow EPT que redireciona execucoes
    // daquela funcao pra ShvDispatchIoctl, nao mais um ponteiro alterado na
    // tabela de dispatch (que um `!drvobj \Driver\Beep` no WinDbg, ou
    // qualquer scanner de integridade de MajorFunction[], mostraria
    // modificado -- esse e o "stealth" da Etapa 2). Isso tambem zera
    // g_BeepOriginalControl (ShvBeepGetOriginalControl() passa a devolver
    // NULL, "Etapa 1 nao mais ativa").
    ShvBeepHijackTeardown();

    *OutGpa = (UINT64)pa.QuadPart & ~0xFFFULL;
    return STATUS_SUCCESS;
}

//
// Remove o shadow hook da Etapa 2 (se instalado) -- chamar no DriverUnload
// ANTES do VMXOFF (mesma exigencia de qualquer outro shadow hook deste
// projeto, ver ShvPolicyHooksUninit/HpvUnhookFuncByVa). Sem isso, a funcao
// original do Beep.sys ficaria redirecionando pra ShvDispatchIoctl (agora
// um endereco invalido, dentro do .sys ja descarregado) pra sempre --
// qualquer chamada real ao Beep.sys depois do nosso driver descarregar
// bugchecaria o sistema.
//
VOID
ShvBeepShadowTeardown (
    VOID
    )
{
    if (g_BeepShadowVa != NULL)
    {
        HpvUnhookFuncByVa(g_BeepShadowVa);
        g_BeepShadowVa = NULL;
    }
}

//
// Downgrade da Etapa 2 DE VOLTA pra Etapa 1 (SHV_CMD_BEEP_SHADOW_REMOVE,
// usado pelo checkbox "Beep Shadow" da GUI quando desmarcado) -- diferente
// de ShvBeepShadowTeardown (chamada so no DriverUnload, deixa o Beep
// completamente intocado): aqui a COMUNICACAO precisa continuar
// funcionando depois, entao reinstala o hijack direto de tabela
// (ShvBeepHijackSetup) no lugar do shadow EPT removido. Sem isso, remover
// o shadow pela aba Filtros->Hook Shadow (botao generico "Remover Shadow
// (pagina inteira)") so tira o redirecionamento sem recolocar nada no
// lugar -- a tabela de dispatch do Beep fica apontando pro handler
// ORIGINAL (sem nenhum caminho pra ShvDispatchIoctl), e o canal de
// comunicacao Beep para de responder a SHV_IOCTL_SUBMIT -- exatamente o
// sintoma relatado pelo usuario.
//
NTSTATUS
ShvBeepShadowRemove (
    VOID
    )
{
    if (g_BeepShadowVa == NULL)
        return STATUS_SUCCESS; // nada instalado -- idempotente

    HpvUnhookFuncByVa(g_BeepShadowVa);
    g_BeepShadowVa = NULL;

    // Reinstala a Etapa 1 -- MajorFunction[IRP_MJ_DEVICE_CONTROL] esta
    // apontando pro handler ORIGINAL do Beep agora (foi restaurado quando
    // a Etapa 2 foi instalada), entao ShvBeepHijackSetup salva esse valor
    // de novo em g_BeepOriginalControl e sobrescreve com ShvDispatchIoctl,
    // igual fez a primeira vez no DriverEntry.
    return ShvBeepHijackSetup();
}

#endif // SHV_COMM_BEEP_HIJACK

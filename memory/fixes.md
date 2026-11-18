# Fixes aplicados no SimpleVisor

Histórico de bugs resolvidos: o que quebrava, a causa raiz e a correção aplicada.

---

## 2026-11-18 — Remover Beep Shadow pela aba generica Hook Shadow perdia a comunicacao com o hypervisor

**Contexto:** continuação direta da implementação do Beep Shadow (entrada abaixo). Usuário
notou que removendo o hook pela aba Filtros→Hook Shadow (botão genérico "Remover Shadow (página
inteira)") o canal de comunicação Beep parava de responder.

**Causa raiz:** `SHV_CMD_UNHOOK_SHADOW` (usado pelo botão genérico) só remove o redirecionamento
EPT — não sabe nem precisa saber que, no caso específico do Beep, é a ÚNICA coisa que leva
chamadas a `ShvDispatchIoctl`. A Etapa 2 do Beep Shadow (`ShvBeepShadowSetup`) já tinha restaurado
`MajorFunction[IRP_MJ_DEVICE_CONTROL]` pro handler ORIGINAL do Beep (esse é o próprio "stealth"
da Etapa 2) — então remover só o shadow EPT por ali deixa a tabela de dispatch apontando pro
Beep original, SEM NENHUM caminho de volta pra `ShvDispatchIoctl`: o canal Beep para de
responder a `SHV_IOCTL_SUBMIT` de qualquer cliente.

**Fix:** "Beep Shadow" virou um **checkbox** na GUI (`tab_tools.cpp` e `tab_memory.cpp`) em vez
de um botão de setup só-ida. Desmarcar chama o novo `SHV_CMD_BEEP_SHADOW_REMOVE` →
`ShvBeepShadowRemove` (`nt/shvos_beep.c`), que remove o shadow EPT **e reinstala o hijack de
tabela** (`ShvBeepHijackSetup` de novo) no mesmo IOCTL — a comunicação nunca fica sem um caminho
válido pra `ShvDispatchIoctl`. Documentado nos comentários de `ShvBeepShadowRemove` e no
checkbox: **nunca** usar o "Remover Shadow" genérico nesta GPA especificamente.

---

## 2026-11-18 — Beep Shadow (SHV_CMD_BEEP_SHADOW_SETUP) nunca foi implementado, so retornava OK/GPA=0

**Contexto:** usuário clicou no botão "Beep Shadow" na GUI e recebeu `Beep shadow OK, GPA=0x0`
— sem nenhum hook de verdade sendo instalado.

**Causa raiz:** não era bug — o handler em `nt/shvos.c` era um **stub** desde que a Etapa 2 (ver
comentário em `nt/shvos_beep.c`) foi planejada: `case SHV_CMD_BEEP_SHADOW_SETUP: resp->Status =
SHVD_STATUS_OK; break;` — não fazia nada além de devolver sucesso, com `resp->PhysAddr`
(GPA) zerado por padrão (`RtlZeroMemory(resp, ...)` no topo do dispatcher). `shv_dbg.h` já
marcava isso: `// upgrade beep hijack para EPT shadow (nao implementado)`.

**Fix — implementação completa da Etapa 2** (`nt/shvos_beep.c`):
- `ShvBeepShadowSetup(&gpa)`: pega o handler ORIGINAL do Beep (`ShvBeepGetOriginalControl()`,
  salvo pela Etapa 1 em `ShvBeepHijackSetup`, chamada no `DriverEntry`) e instala um shadow hook
  via EPT nele (`HpvHookFuncByVa`) redirecionando pra `ShvDispatchIoctl` — depois restaura
  `MajorFunction[IRP_MJ_DEVICE_CONTROL]` pro valor original (`ShvBeepHijackTeardown`), removendo
  o ponteiro visivelmente alterado na tabela de dispatch (o "stealth" da Etapa 2: um
  `!drvobj \Driver\Beep` no WinDbg volta a mostrar o handler original do Beep.sys, mas qualquer
  chamada que entre nele é redirecionada pelo EPT). Idempotente — chamar de novo só devolve a GPA
  já instalada (`g_BeepShadowVa` cacheada), não reinstala nem falha.
- `ShvBeepShadowTeardown()`: remove o shadow hook (`HpvUnhookFuncByVa`) — chamada no
  `DriverUnload` **antes** do VMXOFF (mesma exigência de `ShvPolicyHooksUninit`/qualquer outro
  shadow hook deste projeto: remover depois do EPT desligado não sincroniza as outras CPUs
  corretamente). Sem isso, a função original do Beep.sys ficaria redirecionando pra um endereço
  dentro do nosso driver já descarregado — qualquer chamada real ao Beep.sys depois bugchecaria.
- `nt/shvos.c` (`SHV_CMD_BEEP_SHADOW_SETUP`): agora chama `ShvBeepShadowSetup` de verdade e
  preenche `resp->PhysAddr` com a GPA retornada.

---

## 2026-11-18 — Hook Shadow: linhas por função ainda mostravam os MESMOS bytes/offset (vinham da página, não da função)

**Contexto:** continuação direta da entrada abaixo ("Hook Shadow escondia funções"). Depois do
fix de tooltip→linhas por função, o usuário apontou que faltava distinguir por **VA** (já feito)
mas os bytes/offset de cada linha ainda vinham de **um lugar só** — a correção anterior só
resolvia o `FuncVa`; `Offset`/`PatchLen`/`PatchBytes` continuavam vindo de `g_ShadowPages[i]`
(a página), que só guarda o patch do **ÚLTIMO** hook instalado nela. Então 2+ funções na mesma
página apareciam com os mesmos bytes/offset — errado pra todas, exceto a última instalada.

**Causa raiz real:** `HpvHookFuncByVa` (`nt/hpv_hooks.c`) escrevia `Offset`/`PatchLen`/
`PatchBytes` só em `g_ShadowPages[slot]` (um record por **página física**), nunca por função.
Quando uma segunda função reusa a página (via `RefCount`), seu patch sobrescreve o registro da
página — a primeira função perde seu offset/bytes registrados, mesmo com o patch dela ainda
ativo e funcionando na EPT (o bug era só de **relato/exibição**, não de execução).

**Fix:** `SHV_SYSCALL_HOOK_ENTRY` (um registro por FUNÇÃO hookeada, já existia pra guardar
`FuncVa`/`Trampoline`/etc.) ganhou `PatchOffset`/`PatchLen`/`PatchBytes` PRÓPRIOS, preenchidos em
`HpvHookFuncByVa` junto com o resto do registro (cada função grava seu próprio patch de 12 bytes
no seu próprio offset). `SHV_SHADOW_HOOK_INFO` (protocolo IOCTL) virou um array de
`SHV_SHADOW_FUNC_INFO{FuncVa,Offset,PatchLen,PatchBytes}` por página (`Funcs[8]`), em vez de um
único offset/bytes pra página inteira — o handler em `nt/shvos.c` agora copia o patch de **cada**
`g_SyscallHooks[]` que casa com a GPA, não só a VA. Preserva o caso de shadow patch manual (aba
Memória→Shadow Patch, sem `g_SyscallHooks` associado) como uma linha "sintética" com `FuncVa=0`
usando o record da página. GUI (`ShvShadowEntry`/`ShvShadowFuncEntry`, `tab_filters.cpp`) segue
o mesmo padrão: cada linha pega offset/len/bytes do SEU `ShvShadowFuncEntry`, não mais de campos
compartilhados da página.

---

## 2026-11-18 — Filtros->Hook Shadow escondia funcoes quando varias compartilhavam a mesma pagina

**Contexto:** usuário notou que a aba Filtros→Hook Shadow listava 7 shadow patches, enquanto a
aba Status (que lista por FUNÇÃO, não por página) mostrava 10 — todos os 10 hooks estavam
corretamente instalados.

**Causa raiz:** não é bug de contagem — `HpvHookFuncByVa` reutiliza a mesma shadow page via
`RefCount` quando duas funções hookeadas caem na mesma página física de 4KB (comum com `Zw*`
vizinhas no binário, ex. `ZwOpenKey`/`ZwOpenKeyEx`). A aba Hook Shadow é **por página**
(`g_ShadowPages[]`), não por função — 10 funções em 7 páginas únicas é esperado. O problema real
era de **exibição**: o handler `SHV_CMD_LIST_SHADOW_PATCHES` (`nt/shvos.c`) fazia `break` no
primeiro `g_SyscallHooks[]` que casasse com a GPA da página, então quando uma página tinha 2+
funções, só UMA aparecia na coluna "VA" — as demais ficavam completamente invisíveis na GUI.

**Fix:** `SHV_SHADOW_HOOK_INFO.FuncVa` (singular) → `FuncVaCount`/`FuncVas[SHV_SHADOW_MAX_FUNCS_PER_PAGE]`
(`shv_dbg.h`/`shv_client.h`, cap de 8 por página). O handler agora lista TODAS as correspondências
em vez de parar na primeira. `ShvShadowEntry` (GUI) ganhou um `std::vector<uint64_t> vas` (mantém
`va` = `vas[0]` por compatibilidade com o lookup de módulo/CR3 existente, que só fazia sentido
pra uma VA). A coluna "VA" em `tab_filters.cpp` mostra a primeira + "+..." quando há mais, com
tooltip listando todas (endereço + nome do módulo de cada uma).

---

## 2026-11-17 — NtGdiBitBlt: MmGetSystemRoutineAddress nao resolve exports de win32k mesmo com attach

**Contexto:** hook de `NtGdiBitBlt` (win32kfull.sys, ver project_architecture.md) logava
`[WIN32K] NtGdiBitBlt: falhou (0xC000007A) -- va=0000000000000000 (nao fatal)` mesmo com o
`KeStackAttachProcess(winlogon)` já implementado. `0xC000007A` = `STATUS_PROCEDURE_NOT_FOUND`.

**Causa raiz:** `MmGetSystemRoutineAddress` consulta a lista **global** de módulos do kernel
(a mesma que `PsLoadedModuleList` cobre) — `win32k.sys`/`win32kfull.sys` fica numa lista **por
sessão**, separada, que essa API não percorre, independente de estar attached ou não num
processo Win32. O attach resolve o problema de *mapeamento de memória* (ler/traduzir VA de
win32k), não o de *resolução por nome* — são dois problemas diferentes que pareciam o mesmo.

**Fix:** dois passos, ambos dentro do mesmo `KeStackAttachProcess(winlogon)`:
1. `ShvOsFindKernelModuleBase("win32kfull.sys", &base)` (novo helper em `nt/shvos.c`) — acha a
   base do módulo via `ZwQuerySystemInformation(SystemModuleInformation)` (que SIM lista módulos
   de sessão, mesmo walk de `SHV_CMD_LIST_MODULES`).
2. `RtlFindExportedRoutineByName(base, "NtGdiBitBlt")` — rotina **interna do ntoskrnl** (não de
   win32k), resolvida dinamicamente via `MmGetSystemRoutineAddress` (essa sim funciona, pois é
   exportada pelo próprio ntoskrnl.exe), que percorre o Export Directory do PE em memória
   recebido como parâmetro. É o caminho que de fato resolve exports de módulos fora da lista
   global — usado por técnicas conhecidas de resolução de API em kernel.

---

## 2026-11-17 — Lista de drivers (SHV_CMD_LIST_MODULES) parava de trazer "Tamanho" a partir de certo ponto

**Contexto:** usuário notou que a aba Drivers (`tab_drivers.cpp`) mostrava "Tamanho: ---" pra
drivers a partir de um certo ponto da lista.

**Causa raiz:** não era falta de memória — era o mesmo limite estrutural já visto e corrigido em
`SHV_CMD_LIST_PROCESS_MEMORY` (ver entrada "585 regiões" abaixo). `SHV_CMD_LIST_MODULES`
preenchia `resp->Modules[]` até `SHV_MAX_READ_SIZE / sizeof(SHV_MODULE_ENTRY)` (~113 entradas) e
devolvia, **sem paginação**, mesmo quando `ZwQuerySystemInformation(SystemModuleInformation)`
tinha retornado mais que isso (uma VM com muitos drivers carregados facilmente passa de 113).
`tab_drivers.cpp` usa `EnumDeviceDrivers` (psapi) como lista completa (fonte 1) e só *enriquece*
com o tamanho vindo de `backend.State().kernelModules` (fonte 2, via hypervisor) — qualquer
driver cujo índice no array do kernel caísse depois do corte de 113 simplesmente não tinha
correspondência em `kernelModules`, e `d.size` ficava 0 → coluna mostra "---".

**Fix:** paginação igual a `SHV_CMD_LIST_PROCESS_MEMORY` (que já usa `StartAddr`): novo campo
`req.ListModules.StartIndex` (`shv_dbg.h`/`shv_client.h`) — o handler em `nt/shvos.c` começa a
preencher `resp->Modules[]` a partir desse índice no array `mods->Modules[]` em vez de sempre do
0. `ShvClient::ListModules` ganhou um parâmetro `startIndex` opcional (default 0, compatível com
chamadas antigas). `ShvBackend::PollOnce` agora pagina automaticamente (mesmo padrão de
`ShvBackend::ListProcessMemory`): chama em loop com `startIndex += n` até a página voltar menor
que o buffer (fim da lista) ou vazia, com um teto de 50 páginas (~5650 módulos) contra loop
infinito. Transparente pros consumidores (`tab_drivers.cpp` não mudou).

---

## 2026-11-17 — Comentário de bloco C fechado prematuramente em hpv_registry_hooks.c

**Contexto:** build inicial do novo monitoramento de registro (ver project_architecture.md)
falhou com uma cascata de erros de sintaxe (`C2143`, `C2061`, `C2059`) a partir da linha 17 do
arquivo novo, e warning `C4138: '*/' encontrado fora de comentário` na linha 39.

**Causa raiz:** o comentário de cabeçalho do módulo (estilo `/*++ ... --*/` usado no projeto)
continha o texto `Nt*/Zw*` — o `*/` dentro dessa sequência fecha o comentário de bloco ali
mesmo, no meio da explicação, fazendo o compilador tratar o resto do texto do comentário como
código C de verdade.

**Fix:** reescrito `Nt*/Zw*` como `Nt* e Zw*` (sem a sequência `*/` literal). Lição geral:
qualquer comentário de bloco neste projeto que precise mencionar dois identificadores separados
por `/` (ex. `Nt*/Zw*`, `read/write`) corre esse risco se o segundo terminar logo antes de outro
caractere que complete `*/` — evitar `X*/Y` dentro de `/* ... */`.

---

## 2026-11-16 — HOST_CR3 capturado via __readcr3() podia apontar pra processo errado (triple fault silencioso)

**Contexto:** continuação da pesquisa sobre `DriverEntry` fora do caminho padrão do loader —
usuário trouxe um relato externo (apontando pra este projeto) descrevendo um bug real: `shv.c`
(`ShvLoad()`) fazia `callbackContext.Cr3 = __readcr3();` assumindo que `DriverEntry`/`ShvLoad`
sempre rodam no contexto do processo **System**. Esse valor vira `HOST_CR3` da VMCS
(`shvvmx.c:725`, `vpData->SystemDirectoryTableBase`).

**Problema:** se `DriverEntry` rodar no contexto de OUTRO processo (ex.: carregamento fora do
caminho normal do I/O Manager), `__readcr3()` captura o CR3 **desse outro processo**. Quando
esse processo termina, as tabelas de página dele são liberadas — o próximo VM-exit usa um
`HOST_CR3` morto, dá page fault em VMX root, e vira **triple fault silencioso em todas as
CPUs** (sem BSOD, WinDbg não consegue nem quebrar). O mesmo `__readcr3()` era re-executado toda
vez que `ShvLoad()` rodava, inclusive a partir de `PowerCallback` (resume de sleep) — mesmo
risco ali.

**Fix:** nova função OS-specific `ShvOsGetSystemCr3()` (declarada em `shv.h`, ao lado das
outras `ShvOs*`):
- **NT** (`nt/shvos.c`): devolve o CR3 real do processo System
  (`*(UINT64*)((UINT8*)PsInitialSystemProcess + EPROCESS_DIR_TABLE_BASE_OFFSET)`,
  `PsInitialSystemProcess` é exportada e documentada em `ntddk.h`, ao contrário das outras APIs
  hand-declared neste projeto) — estável pela vida inteira do SO, cacheado em `g_SystemCr3`
  após a primeira chamada.
- **UEFI** (`uefi/shvos.c`): continua `__readcr3()` direto — nessa fase não existe o problema
  (espaço de endereçamento único, sem processos sendo criados/destruídos), então o
  comportamento de sempre já está correto ali.
- `shv.c` (`ShvLoad()`, compartilhado NT/UEFI) trocado pra chamar `ShvOsGetSystemCr3()` em vez
  de `__readcr3()` direto. Como `PowerCallback` só chama `ShvLoad()` de novo, o fix cobre os
  dois lugares automaticamente.
- Removida a declaração morta `extern UINT64 ShvSystemCr3;` (`nt/shvos_internal.h`) — nunca
  tinha definição em lugar nenhum, leftover de uma tentativa anterior incompleta.

**Importante — `ShvCaptureSpecialRegisters` (`shvvp.c:56`) NÃO foi mexido**: aquele
`__readcr3()` alimenta `GUEST_CR3` (não `HOST_CR3`), e ali o comportamento correto É ler o CR3
ao vivo de cada CPU (representa o processo/thread que estava rodando naquela CPU no momento do
`VMLAUNCH`, pra o guest retomar exatamente de onde parou) — trocar esse quebraria a entrada em
VMX non-root.

Build NT recompilado limpo (rebuild completo). Build UEFI não pôde ser validado nesta máquina
(falta o toolset v141/VS2017, limitação do ambiente, não relacionada à mudança) — revisão visual
confirma que segue o mesmo padrão das outras funções `ShvOs*` já existentes em `uefi/shvos.c`.

---

## 2026-11-16 — DriverEntry: checagem de NULL em DriverObject/RegistryPath

**Contexto:** pesquisa (não implementação) sobre problemas ao iniciar o driver fora do
caminho padrão do I/O Manager levantou vários pontos de atrito; usuário pediu pra corrigir só
os dois mais simples: `DriverObject` e `RegistryPath` sendo usados sem checagem de NULL.

**Fix (versão 1):** `DriverEntry` validava `DriverObject == NULL || RegistryPath == NULL` logo
no início e devolvia `STATUS_INVALID_PARAMETER` se qualquer um fosse NULL.

**Fix (versão 2, pedido do usuário):** em vez de recusar a carga inteira, o driver agora
**degrada graciosamente**: `RegistryPath` nunca foi usado mesmo (`UNREFERENCED_PARAMETER`),
então NULL nele não muda nada — a checagem foi removida. `DriverObject` é usado por
`DriverUnload`/`MajorFunction[]`/`IoCreateDevice`/`IoCreateSymbolicLink` — se for NULL, só essa
parte é pulada (`if (DriverObject != NULL) { ... } else { ShvLog(...) }`), via uma flag
`haveDevice` que os caminhos de erro seguintes (`g_PowerCallbackRegistration` falha,
`HpvTrampolinePoolInit` falha, `ShvBeepHijackSetup` falha, `ShvLoad` falha) agora checam antes
de chamar `IoDeleteSymbolicLink`/`IoDeleteDevice` (senão tentariam desfazer um device que nunca
existiu). O resto do `DriverEntry` (`HpvResolveOptionalApis`, trampoline pool, Beep hijack,
`ShvLoad` do hipervisor, `ShvHooksInit`, `ShvPolicyHooksInit`) roda normalmente mesmo sem
`DriverObject` — só fica sem interface IOCTL (nenhum device/symlink criado) e sem
`DriverUnload` automático nessa carga (consequência inerente: sem `DriverObject` real não tem
como o I/O Manager chamar `DriverUnload` de qualquer jeito). `DriverUnload` em si também
ganhou guarda (`if (g_ShvDeviceObject != NULL)`) antes do `IoDeleteSymbolicLink`, pro caso de
`IoCreateDevice` ter falhado mas a carga ter continuado mesmo assim.

**Nota:** isso cobre só os dois parâmetros de `DriverEntry` — não resolve os outros pontos
levantados na pesquisa (objeto `DriverObject` precisar ser um objeto real do Object Manager
quando não-NULL, `.pdata`/relocations precisarem estar resolvidos antes de `DriverEntry`
rodar, `ShvLoad()` não ser reentrante, etc.), que ficam de fora por enquanto.

Driver recompilado limpo.

---

## 2026-11-16 — Auditoria de alocações: 3 vazamentos encontrados e corrigidos

**Pedido:** listar toda alocação de memória de vida longa do driver (não as transientes de
IOCTL) e corrigir o que precisasse. Lista completa em [[allocations]].

**Vazamentos encontrados e corrigidos:**
1. **Trampoline pool em erro de `DriverEntry`**: se `ShvBeepHijackSetup()` ou `ShvLoad()`
   falhasse DEPOIS de `HpvTrampolinePoolInit()` ter sucesso, os 4KB nunca eram liberados antes
   do `return`. Fix: `HpvTrampolinePoolFree()` adicionado nos dois caminhos de erro (seguro
   liberar direto ali, sem a ordenação pós-VMXOFF, já que EPT nunca chegou a rodar nesse
   ponto).
2. **Shadow page órfã quando `g_SyscallHooks` enche**: `HpvHookFuncByVa` alocava shadow
   page/trampolim ANTES de reservar entrada em `g_SyscallHooks[32]`; se não sobrasse vaga,
   seguia em frente como se tivesse dado certo, sem jeito de desfazer depois (`HpvUnhookFuncByVa`
   procura por `FuncVa` nessa tabela). Fix: desfaz tudo (libera/decrementa shadow, recua
   `g_TrampolineUsed`) e devolve `STATUS_INSUFFICIENT_RESOURCES` em vez de sucesso fantasma.
3. **`DriverUnload` nunca varria `g_ShadowPages[]`**: só desfazia os 3 hooks automáticos
   (`ShvPolicyHooksUninit`); um shadow patch manual (`SHV_CMD_HOOK_SHADOW`, aba "Shadow Patch")
   que o usuário não desinstalasse antes do unload vazava os 4KB até reboot. Fix: nova
   `HpvShadowPagesReleaseAll()` (`nt/hpv_hooks.c`), chamada em `DriverUnload` logo depois de
   `ShvUnload()` (VMXOFF) — libera qualquer shadow page que sobrar, dos dois caminhos
   (automático ou manual).

Driver recompilado limpo (rebuild completo). Ainda não testado em execução real (precisa
forçar os caminhos de erro de `DriverEntry` e/ou deixar um shadow patch manual sem
desinstalar antes do unload).

---

## 2026-11-13 — View Stack de processo protegido: APC especial de kernel (técnica do Process Hacker) em vez de PsGetContextThread

**Contexto:** mesmo com todos os fixes anteriores (Mode=KernelMode, retry, PsSuspendProcess,
PsSuspendThread via pattern scan), `GET_CONTEXT` continuava falhando com `STATUS_UNSUCCESSFUL`
pra threads de processos protegidos especificamente — e o usuário notou que o **Process
Hacker** consegue ver a stack dessas threads, inclusive com frames de módulos do kernel.

**Investigação (decompilação do `ntoskrnl.exe` real via IDA Pro MCP, com ajuda do usuário):**
- `PsGetContextThread` → thunk pra `PspGetContextThreadInternal`.
- Pra thread diferente da chamadora, essa função enfileira uma **APC especial de kernel**
  própria (`PspGetSetContextSpecialApc`) via `KeInsertQueueApc` e espera um gate — se
  `KeInsertQueueApc` devolver `FALSE`, a função devolve exatamente `STATUS_UNSUCCESSFUL`
  (`0xC0000001`), batendo com o erro observado.
- Dentro de `KeInsertQueueApc`: falha quando o bit `ApcQueueable` (bit 14, máscara `0x4000`)
  do campo `MiscFlags` do `_KTHREAD` (offset 0x74) está zerado — não é uma checagem de PP/PPL
  explícita, mas o efeito prático acabou correlacionando com threads de processo protegido
  nos testes.
- Checado o código-fonte do **KProcessHacker** (`thread.c`, função
  `KphCaptureStackBackTraceThread`): eles **não usam `PsGetContextThread`/`PsSetContextThread`
  em nenhum momento** — implementam a própria APC especial de kernel (`KeInitializeApc` +
  `KeInsertQueueApc` com rotina própria), que roda no contexto da thread alvo e usa
  `RtlWalkFrameChain` pra desenrolar a pilha diretamente. É assim que o Process Hacker
  consegue ver stack de processo protegido — e explica por que os frames mostrados por ele são
  de **módulos do kernel** (é a pilha de kernel da thread, não a de usermode).

**Fix:** implementado o mesmo mecanismo, extraído pra arquivos próprios `nt/thread_utils.h`/
`.c` (pedido do usuário, pra não bagunçar `shvos.c`):
- `HpvCaptureThreadStack(PETHREAD, PHPV_THREAD_STACK_CAPTURE)`: `KeInitializeApc` +
  `KeInsertQueueApc` com rotina própria (`HpvCaptureStackKernelRoutine`) que roda DENTRO do
  contexto da thread alvo (é assim que entrega de APC de kernel funciona) e ali chama
  `RtlCaptureContext`/`RtlWalkFrameChain` pra pegar Rip/Rsp/Rbp + até 32 endereços de retorno
  da pilha de KERNEL da thread naquele instante. `KeInitializeApc`/`KeInsertQueueApc`/
  `KeWaitForSingleObject`/`RtlWalkFrameChain` resolvidas dinamicamente (mesmo padrão/motivo das
  outras APIs não-documentadas desta sessão — nenhuma delas tem prototype nos headers desta
  WDK, apesar de exportadas) via `HpvThreadUtilsResolveApis()`, chamada no `DriverEntry` junto
  com `HpvResolveOptionalApis()`.
- Novo comando `SHV_CMD_THREAD_GET_STACK` (32) em `nt/shvos.c`: `PsLookupThreadByThreadId` +
  `HpvCaptureThreadStack`, devolve `SHV_THREAD_STACK{Rip,Rsp,Rbp,FrameCount,Frames[32]}`.
- `tab_procs.cpp`: `WalkThreadStackKernel` (a tentativa anterior via `PsGetContextThread`+
  `StackWalk64` com hProcess falso) foi **substituída** por `WalkThreadStackViaApc` — chama
  `backend.GetThreadStack` e resolve cada endereço contra `backend.State().kernelModules`
  (módulo+offset do KERNEL, igual o Process Hacker mostra), sem StackWalk64/dbghelp nenhum
  (não precisa, já vem a lista de frames pronta do kernel via `RtlWalkFrameChain`). Continua
  sendo o fallback quando `OpenProcess`/`OpenThread`/`GetThreadContext` usermode falham (PPL);
  o caminho clássico (stack de usermode com símbolos via dbghelp) continua tentado primeiro
  quando possível.

Driver e GUI recompilados limpos. Ainda não testado em execução real contra processo protegido.

---

## 2026-11-13 — PsSuspendThread/PsResumeThread encontradas por pattern scan (não exportadas por nome)

**Contexto:** confirmado que `ZwSuspendThread`/`ZwResumeThread` (que existem no `.lib` do WDK)
não são encontradas via `MmGetSystemRoutineAddress` na build real da VM, e `PsSuspendThread`/
`PsResumeThread`/`KeSuspendThread`/`KeResumeThread` nem aparecem no `.lib` como export — ou
seja, a função INTERNA de verdade que suspende/resume uma thread existe no binário, só não é
exportada por nome. Usuário forneceu as assinaturas de bytes (via disassembly do `ntoskrnl.exe`
real da VM) pra achar as duas por pattern scan, igual já é feito pra `PspExitProcess` em
`hpv_policy_hooks.c`.

**Implementação:** `nt/shvos.c`, dentro de `HpvResolveOptionalApis` (mesmo lugar que resolve as
APIs por nome): depois do loop de `MmGetSystemRoutineAddress`, chama
`HpvFindNtoskrnlModule`+`HpvFindPattern` (funções já existentes em `nt/hpv_pattern.c`, usadas
pra `PspExitProcess`) com as assinaturas fornecidas, setando `g_pPsSuspendThread`/
`g_pPsResumeThread` (novos ponteiros de função, tomam `PETHREAD` direto — sem handle nenhum,
diferente dos wrappers `Zw*`). **Diferente de `PspExitProcess`**: aqui não tem hook nenhum
instalado (não é interceptação) — o VA achado vira ponteiro de função chamado diretamente pelo
driver, pra suspender/resumir uma thread arbitrária de verdade.

Atualizada a ordem de preferência em `SHV_CMD_THREAD_SUSPEND`/`RESUME` e `GET_CONTEXT`:
1. `PsSuspendThread`/`PsResumeThread` (pattern scan) — melhor opção, sem handle.
2. `ZwSuspendThread`/`ZwResumeThread` (nome) — precisa de handle via `ObOpenObjectByPointer`.
3. (só em `GET_CONTEXT`) `PsSuspendProcess`/`PsResumeProcess` — processo inteiro, último
   recurso.
4. Nenhuma das três — lê sem congelar, com retry.

Com isso, `SHV_CMD_THREAD_SUSPEND`/`RESUME` devem sair de `ERR_UNSUPPORTED` nessa build (se as
assinaturas baterem) — e deixam de depender do fallback usermode (`OpenThread`) pra funcionar
até com processos protegidos (PPL).

Driver recompilado limpo. Ainda não confirmado em execução real se as assinaturas batem.

---

## 2026-11-13 — Processos→Memory limitado a 585 regiões (buffer fixo do IOCTL)

**Symptom:** aba Processos→Memory nunca mostrava mais que 585 regiões, mesmo em processos com
mais VADs que isso.

**Root cause:** `585 = SHV_MAX_READ_SIZE / sizeof(SHV_MEMREGION_ENTRY)` (16384 / 28 bytes) —
`SHV_CMD_LIST_PROCESS_MEMORY` enchia o buffer de resposta do IOCTL (compartilhado por todos os
comandos de lista) numa única chamada e simplesmente parava aí, sem nenhum mecanismo de
continuação. Não dava pra só aumentar `SHV_MAX_READ_SIZE` porque ele é usado por `SHV_RESPONSE`
inteira (afetaria o tamanho do buffer de TODOS os comandos, não só esse).

**Fix:** paginação. Novo campo `req.ListProcMemory.StartAddr` no protocolo (0 = do início do
address space); `nt/shvos.c` agora começa o loop de `ZwQueryVirtualMemory` a partir desse
endereço em vez de sempre `0`. `ShvBackend::ListProcessMemory` (GUI) virou um loop transparente:
reenvia o IOCTL com `StartAddr = Base+Size` da última região recebida sempre que o buffer vem
cheio (`n == kPageCap`), concatenando tudo, até uma página vir incompleta (chegou ao fim do
address space) ou vazia — quem chama (`tab_procs.cpp`) continua recebendo a lista inteira de
uma vez, sem saber que foi paginada por baixo dos panos. Limite de segurança de 500 páginas
(~290 mil regiões) contra loop infinito.

Driver e GUI recompilados limpos.

---

## 2026-11-13 — GET_CONTEXT: PsGetContextThread falhava com STATUS_ACCESS_VIOLATION sem suspensão

**Contexto:** continuação do fix de suspend/resume ausentes nessa build (`ZwSuspendThread`/
`ZwResumeThread` não exportados, `PsGetContextThread` sim). Mesmo não exigindo mais
suspend/resume pra `GET_CONTEXT`, o comando ainda falhava.

**Symptom:** log mostrou `PsGetContextThread(UserMode) falhou 0xC0000005`
(`STATUS_ACCESS_VIOLATION`) — retornado pela própria função como valor de retorno, não uma
exceção pega pelo `__except`.

**Root cause:** sem conseguir suspender a thread primeiro, ler o contexto dela enquanto pode
estar rodando no exato momento da chamada é uma corrida genuína (não é erro de permissão) —
`PsGetContextThread` precisa que a thread não esteja em execução naquele instante pra capturar
o trap frame de usermode com segurança.

**Fix:** quando não foi possível suspender (`hThread == NULL`), `PsGetContextThread` agora é
tentada em loop (até 20x, com `KeDelayExecutionThread` de 100us entre tentativas) em vez de
desistir na primeira falha — a maioria das threads passa a maior parte do tempo bloqueada
esperando (I/O, mensagem, mutex), então algumas tentativas tendem a pegar uma janela segura.
Quando a suspensão funciona (`hThread != NULL`), continua só 1 tentativa (já seguro por
definição). Log detalhado (`NTSTATUS`/código de exceção, `canSuspend`, se suspendeu de
verdade) adicionado pra facilitar diagnóstico se ainda falhar.

Driver recompilado limpo.

**Update (mesmo dia):** usuário perguntou se existe alguma forma de suspender uma thread de
verdade nessa build. Checagem (`dumpbin /exports`) confirmou: **não existe** `PsSuspendThread`/
`PsResumeThread` nem `KeSuspendThread`/`KeResumeThread` exportados pelo kernel — só
`PsSuspendProcess`/`PsResumeProcess` (suspende/resume o **processo inteiro**, mecanismo usado
pelo "freeze" de apps UWP do Windows). Adicionado como terceira opção em `GET_CONTEXT`: se não
dá pra suspender só a thread (`ZwSuspendThread` ausente), tenta `PsSuspendProcess` no processo
dono da thread por um instante curtinho (1 tentativa de leitura basta, sem precisar do retry),
resume logo depois. **Importante**: isso NUNCA é usado pros comandos dedicados
`SHV_CMD_THREAD_SUSPEND`/`RESUME` — suspender o processo inteiro ali seria um efeito colateral
inesperado (usuário pediu suspender uma thread, não o processo todo); esses dois continuam
`ERR_UNSUPPORTED` nessa build, com o fallback usermode (`OpenThread`) do GUI cobrindo processos
não-protegidos.

Driver recompilado limpo.

**Update 2 (mesmo dia) — causa real encontrada:** usuário questionou se `Mode = UserMode` em
`g_pPsGetContextThread(thread, &ctx, UserMode)` estava certo. **Não estava — essa era a causa
real do `STATUS_ACCESS_VIOLATION`**, não corrida de suspensão. O parâmetro `Mode` de
`PsGetContextThread` não escolhe "pega contexto de usermode ou kernel" (a função sempre devolve
os registradores de usermode do alvo, independente desse parâmetro) — ele diz se o **buffer de
saída** (`&ctx`) está em memória de usermode ou kernel, pra decidir se faz `ProbeForWrite` nele
antes de escrever. `ctx` é uma variável local na pilha do **kernel** (deste driver), então o
modo certo é `KernelMode`; com `UserMode`, o probe falha pra qualquer endereço de kernel —
batendo exatamente com o `ACCESS_VIOLATION` visto, 100% das vezes, independente de a thread
estar parada ou não (por isso nem o retry nem o freeze do processo resolviam: o parâmetro
errado fazia falhar sempre, não só às vezes). Corrigido: `Mode = KernelMode`.

Driver recompilado limpo.

**Update 3 (mesmo dia):** mesmo com `Mode=KernelMode` corrigido, `GET_CONTEXT` ainda falhava —
dessa vez com `0xC0000001` (`STATUS_UNSUCCESSFUL`) **mesmo com `procSuspended=1`** (processo
congelado) e só 1 tentativa (o código tratava "processo congelado" como garantia de sucesso
imediato, igual thread suspensa via `ZwSuspendThread`). Causa provável: `PsSuspendProcess`
normalmente suspende cada thread via APC, que só é entregue no próximo ponto de checagem da
thread -- `PsGetContextThread` falha com `STATUS_UNSUCCESSFUL` se pegar a thread ainda
"Running" bem no instante logo após `PsSuspendProcess` retornar (a suspensão via APC não é tão
imediata/síncrona quanto `ZwSuspendThread` de uma thread específica). Fix: quando o processo
foi congelado (`procSuspended != NULL`), agora tenta até 8x com delay curto entre tentativas
(em vez de 1 tentativa só) -- só quando é `ZwSuspendThread` de verdade (`hThread != NULL`,
síncrono) que continua sendo 1 tentativa. Caso sem suspensão nenhuma continua em até 20
tentativas. Log corrigido pra dizer "KernelMode" (texto antigo ainda dizia "UserMode" por
engano, mesmo já passando `KernelMode` desde o fix anterior).

Driver recompilado limpo.

**Update 4 (mesmo dia):** mesmo com retries e congelamento de processo, `GET_CONTEXT`
continuava falhando com `STATUS_UNSUCCESSFUL`. Usuário sugeriu que talvez faltasse estar
anexado (`KeStackAttachProcess`) no processo dono da thread antes de chamar
`PsGetContextThread` -- todos os outros handlers que lidam com memória/PEB de um processo já
fazem isso, mas `GET_CONTEXT` não fazia. Fix: `KeStackAttachProcess(PsGetThreadProcess(thread),
&apcState)` adicionado envolvendo todo o loop de retry + chamada de `PsGetContextThread`,
`KeUnstackDetachProcess` depois do `__except`. Driver recompilado limpo.

---

## 2026-11-13 — `sc start hpv` falhava com "procedimento não encontrado" (import estático de API não garantida)

**Symptom:** depois dos fixes de WOW64/Threads/Memory/Suspend-Resume, `sc start hpv` passou a
retornar "Não foi possível encontrar o procedimento especificado" (`STATUS_PROCEDURE_NOT_FOUND`)
— o driver nem chegava a carregar, então nenhum log aparecia.

**Root cause:** `shvos.c` importava **estaticamente** (linkadas direto no PE, resolvidas pelo
loader do Windows no carregamento) seis funções do `ntoskrnl` que não têm prototype público na
WDK (`ZwQuerySystemInformation`, `PsGetProcessPeb`, `PsGetProcessWow64Process`,
`ZwSuspendThread`, `ZwResumeThread`, `PsGetContextThread`) — hand-declaradas e confirmadas como
exportadas via `dumpbin /exports` no `ntoskrnl.lib` do **WDK** (build 10.0.28000.0), mas isso
não garante que a build real do Windows rodando na VM exporte exatamente as mesmas com o mesmo
nome. Se UMA faltar, o PE loader recusa carregar o driver inteiro (import estático não resolvido
= `STATUS_PROCEDURE_NOT_FOUND`), e como isso acontece ANTES do `DriverEntry` rodar, nenhum log
do driver aparece — diagnóstico às cegas.

**Fix:** as seis funções agora são resolvidas **dinamicamente** via `MmGetSystemRoutineAddress`
em `HpvResolveOptionalApis()` (chamada logo no início do `DriverEntry`, antes de tudo), cada uma
logada individualmente em `C:\ShvL.txt` ("OK" ou "NAO ENCONTRADA nesta build do Windows"). Os
ponteiros (`g_pZwQuerySystemInformation`, `g_pPsGetProcessPeb`, etc.) substituem as chamadas
diretas em todos os handlers que dependiam delas; cada handler agora checa `if (ponteiro ==
NULL)` no início e devolve o novo status `SHVD_STATUS_ERR_UNSUPPORTED` (em vez de
`ERR_ACCESS`, que seria enganoso — o problema não é permissão, é a API não existir nessa build)
em vez de travar o carregamento do driver inteiro. Confirmado via `dumpbin /imports` no
`shv.sys` final que nenhuma das seis aparece mais como import estático de `ntoskrnl.exe`.

**Lição**: qualquer API de kernel não documentada/hand-declarada daqui pra frente deve ser
resolvida via `MmGetSystemRoutineAddress` (runtime) em vez de prototype+link estático — um
import estático que falhe impede o driver de carregar por completo, sem log nenhum, e só
funções já comprovadamente estáveis desde sempre (como as já existentes antes desta sessão:
`PsLookupProcessByProcessId`, `ObOpenObjectByPointer`, etc., todas declaradas oficialmente em
`ntifs.h`) são seguras pra importar estaticamente.

Driver e GUI recompilados limpos (rebuild completo).

**Update (mesmo dia, depois do deploy):** confirmado na VM real — `ZwSuspendThread`/
`ZwResumeThread` **NÃO** foram encontradas nessa build (apesar de aparecerem no `.lib` do WDK
usado aqui), mas `PsGetContextThread` foi encontrada normalmente. Isso quebrava
`SHV_CMD_THREAD_GET_CONTEXT` sem necessidade, porque o handler original exigia as três
(`g_pZwSuspendThread == NULL || g_pZwResumeThread == NULL || g_pPsGetContextThread == NULL` →
`ERR_UNSUPPORTED`), mesmo `PsGetContextThread` sendo a única estritamente necessária. Fix:
`GET_CONTEXT` agora só exige `PsGetContextThread`; suspende/resume em volta da leitura é
**best-effort** (`canSuspend = g_pZwSuspendThread && g_pZwResumeThread`), se não disponível lê
o contexto sem congelar a thread (pode ficar levemente impreciso se ela estiver rodando
naquele instante, mas ainda útil pra stack walk na maioria dos casos). **Suspend/Resume como
comandos próprios continuam `ERR_UNSUPPORTED` nessa build** (GUI já cai pro `OpenThread`
usermode como fallback — funciona pra processos não-protegidos, só não pra PPL nessa VM
específica).

---

## 2026-11-13 — Suspend/Resume/View Stack de thread também via kernel (Terminate adiado)

**Pedido:** completar a aba Processos→Threads com suspend/resume/terminate/view-stack via
kernel (mesma motivação de PPL dos fixes anteriores). Terminate explicitamente adiado pelo
usuário.

**Investigação (`dumpbin /exports` no `ntoskrnl.lib` do WDK):**
- `ZwSuspendThread`, `ZwResumeThread`, `PsGetContextThread`, `PsSetContextThread`,
  `PsThreadType` — **exportados**, mas sem prototype em nenhum header da WDK (hand-declared,
  mesmo padrão já usado pra `PsGetProcessPeb`).
- `ZwTerminateThread` — **NÃO exportado** pro kernel (só existe como entrypoint usermode via
  ntdll/syscall). Terminar uma thread arbitrária de dentro do driver exige outra técnica (ex.:
  enfileirar uma APC kernel que chame `PsTerminateSystemThread` quando rodar no contexto da
  própria thread alvo) — fica pra uma sessão futura.

**Implementação:**
- `SHV_CMD_THREAD_SUSPEND`/`RESUME` (29/30): `PsLookupThreadByThreadId` → handle kernel-mode
  via `ObOpenObjectByPointer(..., KernelMode, ...)` (sem `OpenThread` usermode, sem access
  check de ACL) → `ZwSuspendThread`/`ZwResumeThread`.
- `SHV_CMD_THREAD_GET_CONTEXT` (31): suspende, `PsGetContextThread(thread, &ctx, UserMode)`
  (so `CONTEXT_CONTROL|CONTEXT_INTEGER` — o suficiente pra `Rip`/`Rsp`/`Rbp`), resume. Response
  novo `SHV_THREAD_CONTEXT{Rip,Rsp,Rbp}`.
- `tab_procs.cpp`: menu Suspend/Resume tenta `backend.SuspendThread`/`ResumeThread` (IOCTL)
  primeiro, cai pro `OpenThread` usermode antigo só se o backend não estiver conectado.
- **View Stack**: `WalkThreadStack` (caminho clássico `OpenProcess`+`OpenThread`+
  `GetThreadContext`+`StackWalk64`) agora cai pra `WalkThreadStackKernel` quando qualquer
  handle falha (PPL). O fallback usa `backend.GetThreadContext` pra semear
  `Rip`/`Rsp`/`Rbp`, um **handle FALSO** só como chave interna do `dbghelp` (nunca usado pra
  acessar o processo de verdade), módulos carregados manualmente via `SymLoadModule64` +
  `backend.ListProcessModules` (em vez da enumeração automática do `SymInitialize`, que
  precisaria de handle real), e leitura de memória via `backend.ReadVirt` no lugar de
  `ReadProcessMemory` (callback customizado `ReadMemoryViaBackend` passado pro `StackWalk64`).

**Limitação conhecida:** o `CONTEXT` do fallback só tem `Rip`/`Rsp`/`Rbp` preenchidos (resto
zerado) — o desenrolamento via `.pdata`/`.xdata` (`RtlVirtualUnwind`, usado internamente pelo
`StackWalk64` em x64) normalmente não depende do valor anterior dos outros registradores
não-voláteis pra computar a cadeia de `Rip`, mas pode degradar em frames que dependam deles.

Driver e GUI recompilados limpos (rebuild completo). Ainda não testado em execução real.

---

## 2026-11-13 — Threads e Memory (aba Processos) também via kernel (mesmo problema de PPL)

**Pedido:** estender pra Threads e Memory da aba Processos o mesmo tratamento já feito pra
Modules — listar via kernel em vez de API usermode, pra funcionar com processos protegidos.

**Implementação:**
- `SHV_CMD_LIST_PROCESS_THREADS` (27): `ZwQuerySystemInformation(SystemProcessInformation)`
  no kernel, filtra pelo PID, devolve `{Tid, StartAddress}` de cada thread. Precisou expandir
  `SYSTEM_PROCESS_INFORMATION_SHV` (também usada por `SHV_CMD_LIST_PROCS`) com os campos reais
  que faltavam entre `SessionId` e o array de threads — sem isso o cálculo
  `entry + sizeof(struct)` pra achar o array de threads saía no offset errado (a struct
  antiga só ia até `SessionId`, suficiente pros campos que `LIST_PROCS` lê por nome, mas não
  pro tamanho real da entrada).
- `SHV_CMD_LIST_PROCESS_MEMORY` (28): `KeStackAttachProcess` + `ZwQueryVirtualMemory` com
  pseudo-handle `(HANDLE)-1` ("processo atual" = o processo anexado) — sem handle de verdade,
  sem access check, funciona com PPL. Diferente de `PsGetProcessPeb`/`ZwQuerySystemInformation`,
  `ZwQueryVirtualMemory` **já vem declarada em `ntifs.h`** — tentei redeclarar do mesmo jeito
  que as outras e deu erro de compilação (`C4028`: parâmetro 3 diferente da declaração,
  `C4273`: linkage de DLL inconsistente), porque `MemoryInformationClass` é
  `MEMORY_INFORMATION_CLASS` (enum), não `ULONG` cru. Corrigido usando a declaração/struct já
  existentes do WDK (`MEMORY_BASIC_INFORMATION`, enum `MemoryBasicInformation`) em vez de
  redeclarar.
- `tab_procs.cpp`: `FetchThreads`/`FetchMemRegions` agora tentam `backend.ListProcessThreads`/
  `ListProcessMemory` primeiro, com fallback pro código usermode antigo (Toolhelp32/
  `VirtualQueryEx`) só se o backend não estiver conectado ou o IOCTL não retornar nada.

Driver e GUI recompilados limpos (rebuild completo). Ainda não testado em execução real.

---

## 2026-11-13 — Aba Processos→Modules ainda usava Toolhelp32 (IOCTL só estava no desmontador)

**Symptom:** depois de implementar `SHV_CMD_LIST_PROCESS_MODULES` + fix WOW64, usuário
reportou "ainda o mesmo problema" — processos sem módulos continuavam sem módulos.

**Root cause:** o IOCTL só tinha sido ligado em `tab_disasm.cpp` (usado dentro de
Memória→Leitura→Desmontar). A aba **Processos→Modules** (`tab_procs.cpp`, `FetchModules`)
tem sua PRÓPRIA listagem de módulos, independente, que ainda chamava
`CreateToolhelp32Snapshot` puro em usermode — nunca tinha sido tocada, então continuava
falhando pros mesmos processos protegidos/PPL de sempre.

**Fix:** `tab_procs.cpp` (`FetchModules`) agora recebe `ShvBackend&` e tenta
`backend.ListProcessModules(pid, ...)` (IOCTL) primeiro; só cai pro Toolhelp32 antigo se o
backend não estiver conectado ou a chamada via IOCTL não retornar nada (fallback, não
substituição — mantém funcionando se o driver não estiver carregado). As duas chamadas de
`FetchModules` (seleção de processo na lista e refresh da sub-aba "Modules") foram
atualizadas pra passar `backend`.

**Lição**: havia DUAS listagens de módulo de processo na GUI (desmontador e aba Processos),
que pareciam a mesma feature mas eram código totalmente separado — ao portar pro IOCTL,
esquecer de procurar TODOS os usos de Toolhelp32/módulos antes de declarar terminado.

Driver recompilado limpo. Ainda não testado em execução real.

---

## 2026-11-13 — SHV_CMD_LIST_PROCESS_MODULES: processos WOW64 (32-bit) não mostravam módulos

**Symptom:** depois de implementar `SHV_CMD_LIST_PROCESS_MODULES` (lista módulos de um
processo lendo a PEB via kernel, pra funcionar com processos protegidos/PPL), alguns
processos continuavam sem mostrar módulo nenhum na aba Memória→Leitura→Desmontar.

**Root cause:** o handler só lia a PEB **nativa** (64-bit) do processo via `PsGetProcessPeb`.
Para um processo **WOW64** (app 32-bit rodando em Windows x64 — bem comum), a PEB nativa tem
`Ldr` vazio ou não-representativo; a lista de verdade dos módulos 32-bit carregados fica na
**PEB32**, uma estrutura separada só alcançável via `PsGetProcessWow64Process`.

**Fix:** `nt/shvos.c` agora chama `PsGetProcessWow64Process(process)` primeiro; se não-NULL
(processo é WOW64), percorre a PEB32/`PEB_LDR_DATA32`/`LDR_DATA_TABLE_ENTRY32` (structs novas
`HPV_PEB32`/`HPV_PEB_LDR_DATA32`/`HPV_LDR_DATA_TABLE_ENTRY32`/`HPV_LIST_ENTRY32`/
`HPV_UNICODE_STRING32` em `nt/shvos.c`, campos como `ULONG` em vez de ponteiro de 64-bit,
zero-extendidos pra endereço válido já que WOW64 roda abaixo de 4GB no mesmo address space);
se NULL (processo nativo x64), cai no caminho antigo (PEB/`PEB_LDR_DATA`/`LDR_DATA_TABLE_ENTRY`
normais). Ambos os caminhos continuam dentro do mesmo `__try/__except` já existente.

**Limitação conhecida que PERMANECE** (não é bug, é esperado): processos "minimal"/sem PEB de
verdade (System, Registry, Secure System, Memory Compression) continuam sem módulos —
`PsGetProcessPeb` retorna NULL ou `Ldr` vazio pra eles, não há nada pra ler.

Driver recompilado (`MSBuild.exe shv.sln /p:Configuration="Windows NT" /p:Platform=x64
/t:Rebuild`), sem erros/avisos. Ainda não testado em execução real contra um app 32-bit de
verdade.

---

## 2026-11-13 — HpvFindPattern (PspExitProcess) restrito à .text, deveria varrer o módulo inteiro

**Symptom:** usuário suspeitava que a assinatura de `PspExitProcess` (confirmada correta por
ele) não estava sendo encontrada; hipótese inicial era a troca de `strlen(Mask)` por
`HpvMaskLength(Mask)` em `HpvFindPattern`.

**Investigação:** revisão de `nt/hpv_pattern.c` mostrou que `HpvMaskLength` é funcionalmente
idêntica a `strlen` (conta bytes até `'\0'`), e toda a lógica de `HpvFindPattern`/
`HpvPatternCompareAt` (bounds check, avanço de ponteiros, comparação por máscara) está
correta — não é a causa. A máscara `"xxxx?xxxx?xxxx?xxxxxx"` (21 chars) bate com o tamanho do
`kPspExitProcessPattern` (21 bytes), confirmando que não há mismatch de tamanho.

**Root cause (real):** `HpvFindNtoskrnlTextSection` restringe a busca à seção `.text` do
`ntoskrnl.exe`. Se a assinatura estiver em outra seção, ou se o parsing de seções não achar o
range certo na build atual, `HpvFindPattern` nunca vai encontrar a assinatura mesmo estando
correta.

**Fix:** extraído o lookup de `DllBase`/`SizeOfImage` via `PsLoadedModuleList` para uma função
interna compartilhada `HpvFindNtoskrnlModuleBase` (`nt/hpv_pattern.c`). Nova função pública
`HpvFindNtoskrnlModule(Base, Size)` devolve o módulo `ntoskrnl.exe` inteiro (sem parsing de PE,
sem restringir a `.text`), declarada em `nt/shvos_internal.h`. `ShvPolicyHooksInit`
(`nt/hpv_policy_hooks.c`) agora chama `HpvFindNtoskrnlModule` em vez de
`HpvFindNtoskrnlTextSection` antes do `HpvFindPattern` de `PspExitProcess`.
`HpvFindNtoskrnlTextSection` continua existindo (ainda restrita a `.text`) pra quem precisar
dela no futuro.

Driver recompilado (`MSBuild.exe shv.sln /p:Configuration="Windows NT" /p:Platform=x64`), sem
erros/avisos, `shv.sys` assinado com sucesso. Ainda não testado em execução real (carregar o
driver e confirmar que a assinatura é encontrada).

---

## 2026-11-12 — EPT Hook: VA exibido na GUI sempre virava o início da página

**Symptom:** usuário instalou um EPT hook em `0x40009` (dentro da página `0x40000`); a coluna
VA em Filtros/Status mostrava `0x40000` em vez de `0x40009`. Suspeita inicial (confirmada como
NÃO ser bug): múltiplos eventos de leitura em endereços consecutivos (`0x40000..0x40003`) para
um único acesso de DWORD — na verdade causado pela ferramenta de teste (CE) fazendo leituras
byte a byte separadas, não um bug do hypervisor (EPT já loga o `GUEST_LINEAR_ADDRESS` exato por
violação, coluna "VA Fault").

**Root cause (bug real, 2 partes):**
1. `nt/shvos.c` (`SHV_CMD_HOOK_EPT`): `vaBase = req.Hook.VirtAddr & ~0xFFF` fazia o IOCTL
   arredondar o VA para o início da página *antes* de passar pra `ShvHookInstall`, tanto no
   caminho kernel (loop por `va`) quanto no caminho usermode (loop por `pfnArray[i]`) — o VA
   exato pedido pelo usuário nunca era armazenado, só o VA da página.
2. `shvvmxhv.c` (`ShvHookInstall`): quando já existia uma entrada pra mesma página física
   (ex.: um hook anterior de teste em `0x40000`), o código só fazia `Type |= HookType` e
   retornava — nunca atualizava `VirtAddr`/`Pid`/`RangeSize` da entrada existente. Então um
   hook novo na mesma página mantinha o VA/RangeSize do hook antigo.

**Fix:**
- `nt/shvos.c`: primeira página do range agora guarda `req.Hook.VirtAddr` (VA exato, com
  offset dentro da página) em vez do VA alinhado; páginas seguintes (quando `RangeSize > 1`)
  continuam usando o VA de página (não há "VA exato" pra elas).
- `shvvmxhv.c` (`ShvHookInstall`): a branch de "entrada já existe pra esta página" agora
  também atualiza `VirtAddr`, `Pid` e `RangeSize`, não só o `Type`.
- O matching de violação EPT continua por página (`SHV_HOOK_PAGE_IN_RANGE`), que é o
  comportamento correto/esperado em hardware — só a exibição do VA na GUI estava errada.

Driver recompilado com `MSBuild.exe shv.sln /p:Configuration="Windows NT" /p:Platform=x64`,
sem erros, `shv.sys` assinado com sucesso.

---

## 2026-11-12 — EPT Hook: filtro por byte exato (não só por página)

**Symptom:** mesmo depois do fix do VA acima, hookar `0x40009` com range pequeno e ler
`0x40000` (fora do range pedido, mas na mesma página de 4KB) ainda gerava evento/hit.
Pedido explícito do usuário: `VA=0x40009, Range=1` só deveria contar hit se o acesso real
fosse exatamente em `0x40009`; `Range=2` só se fosse em `0x40009` ou `0x4000A`; etc.

**Root cause:** EPT só pode restringir permissão por página inteira (4KB) — isso é limite
de hardware, continua sendo. Mas o código nunca comparava o `GUEST_LINEAR_ADDRESS` exato
contra o range de bytes pedido antes de contar `HitCount++`/logar o evento — qualquer
acesso em qualquer lugar da página batia.

**Fix:**
- `shvvmxhv.c`: campo novo `ByteLen` em `SHV_HOOK_ENTRY` (tamanho exato em bytes do range
  pedido, separado de `RangeSize` que agora é só "quantas páginas aplicar permissão EPT").
  Novo macro `SHV_HOOK_VA_MATCH(entryIdx, va)`: `va` tem que cair em
  `[VirtAddr, VirtAddr+ByteLen)` (ou `VirtAddr==0` desativa o filtro). Aplicado nos três
  branches de `ShvVmxHandleEptViolation` (EXEC/WRITE/READ) antes de `HitCount++`/
  `ShvHvPushEvent` — a página continua sendo liberada/re-armada por 1 instrução
  normalmente (isso é obrigatório, hardware não tem escolha), só o *log/contagem* do hit
  é filtrado por byte agora.
- `ShvHookInstall` ganhou parâmetro `ByteLen` (assinatura atualizada em `shv.h` e
  `nt/shvos_internal.h`).
- `nt/shvos.c` (`SHV_CMD_HOOK_EPT`): corrigida a conflação bytes/páginas que causava o bug
  anterior do VA errado de voltar — agora calcula `pageCountTotal` (páginas realmente
  cobertas, usado só pra aplicar a permissão EPT) separado de `byteLen` (o valor "Range" da
  GUI, em bytes, usado só pro filtro de VA exato). Antes o mesmo valor bruto de
  `req.Hook.RangeSize` era passado tanto como "páginas para abrir EPT" quanto embutido nas
  entradas da tabela, misturando os dois conceitos.

Driver recompilado (`MSBuild.exe shv.sln /p:Configuration="Windows NT" /p:Platform=x64`),
sem erros, `shv.sys` assinado com sucesso. Semântica final do campo "Range" na GUI de EPT
Hook: número de BYTES a partir do VA, não páginas.

---

## 2026-11-12 — EPT Hook/Shadow: leitura às vezes não dispara nenhuma violação

**Symptom:** usuário reportou que, mesmo com hook instalado corretamente, algumas leituras
de teste não geram evento/hit nenhum — como se o hook simplesmente não existisse pra
aquele acesso específico (intermitente, não determinístico).

**Root cause:** o EPT é **por CPU** (cada core tem sua própria cópia das tabelas de
paginação EPT, ver `ShvVmxEptApplyHooks`/comentário "EPT per-CPU" em `shvvmxhv.c`).
`ShvHookInstall`/`ShvHookInstallShadow`/`ShvHookRemove*` só atualizam a tabela GLOBAL
(`ShvHookTable[]`) e incrementam `ShvHookVersion` — cada CPU só aplica essa mudança à
PRÓPRIA cópia do EPT de forma *lazy*, no topo do próximo VM-exit que ele mesmo tomar
(`if (VpData->EptHookVersion != ShvHookVersion) ShvVmxEptApplyHooks(VpData);` em
`ShvVmxHandleExit`). Se a thread de teste for escalonada pra um core que não toma NENHUM
VM-exit entre o IOCTL de instalação e a leitura de teste (comum em cores ociosos/pouco
usados — não há VM-exits "espontâneos" o suficiente), aquele core continua rodando com o
EPT antigo (sem o hook) e a leitura passa batida, sem violação, sem log.

Achamos até uma função já existente feita exatamente pra resolver isso —
`ShvOsForceAllCpuVmExit()` (`nt/shvos.c`, usa `KeGenericCallDpc` pra forçar TODOS os CPUs a
executarem um CPUID síncrono, o que dispara `ShvVmxHandleExit` em cada um e reaplica a
tabela de hooks) — mas ela nunca era chamada em lugar nenhum do código.

**Fix:** `nt/shvos.c` agora chama `ShvOsForceAllCpuVmExit()` logo após toda operação que
muda `ShvHookTable[]`/`g_ShadowPages[]` com sucesso: `SHV_CMD_HOOK_EPT` (os dois ramos,
kernel e usermode), `SHV_CMD_UNHOOK_EPT` (os dois ramos), `SHV_CMD_HOOK_SHADOW` e
`SHV_CMD_UNHOOK_SHADOW` (logo depois de `ShvHookRemoveShadow`, reforçando também a
proteção contra o BSOD 0x139 de shadow page liberada enquanto algum core ainda não
reaplicou — ver fix "Fix BSOD on driver stop" anterior). Agora o IOCTL só retorna pro
usermode depois que o hook/unhook já está ativo em 100% dos CPUs, eliminando a janela de
leitura perdida.

Driver recompilado (`MSBuild.exe shv.sln /p:Configuration="Windows NT" /p:Platform=x64`),
sem erros, `shv.sys` assinado com sucesso.

## BSOD 0x139 (KERNEL_SECURITY_CHECK_FAILURE / guard_icall_bugcheck) ao dar `stop` no driver depois de usar o hook de NtOpenProcess (2026-11-09)

**Sintoma:** `sc stop hpv` sozinho (start → stop, sem rodar nada) funcionava sempre. Mas se o `usermode_gui.exe` fosse aberto (mesmo só abrir e fechar uma vez) antes do stop, o `DriverUnload` dava BSOD logo depois do log `[SHV-HOOK] Shadow page liberada: GPA=...`. O motivo de o GUI disparar o bug e o `usermode.exe` de teste não: o Windows Defender (`MsMpEng.exe`) escaneia processos novos chamando `NtOpenProcess`, então abrir o GUI garante que o hook de `NtOpenProcess` seja de fato executado por outra CPU durante a janela de unload; sem isso, o hook quase nunca era exercitado no teste rápido.

**Causa raiz (em duas partes, achada incrementalmente):**

1. **EPT nunca restaurava a página original ao remover o shadow hook.** Em `ShvHookRemoveShadow` (shvvmxhv.c), a entrada da tabela (`ShvHookTable[i]`) era zerada (`PhysAddr = 0`). Mas `ShvVmxEptApplyHooks` (que cada vCPU roda lazily para reaplicar a tabela) faz `continue` em qualquer entrada com `PhysAddr == 0` — ou seja, nunca desfazia o mapeamento de EPT daquela GPA. O PTE continuava apontando para a shadow page indefinidamente, mesmo depois dela ser liberada (`MmFreeContiguousMemory`) e a memória física ser potencialmente reaproveitada por outra alocação, causando execução de dados arbitrários por outra CPU → bugcheck.

2. **Mesmo corrigindo (1) para manter a entrada e reaplicar com `ShvVmxEptSetPermissions(..., r=1,w=1,x=1)`, o bug persistia.** Causa: `ShvVmxEptSetPermissions` (shvvmx.c) só escreve os bits `.Read/.Write/.Execute` da PTE — **nunca toca em `.PageFrameNumber`**. Resultado: a PTE virava "full RWX" mas continuava com o PFN da **shadow page** (confirmado via WinDbg: `u <FuncVa>` continuava mostrando os bytes do patch `mov rax, HpvOpenProcessHook; jmp rax` mesmo depois do log "Shadow page liberada").

**Fix aplicado:**

- `shvvmxhv.c` — `ShvHookRemoveShadow` não zera mais `PhysAddr`; só desliga `ShadowPhysAddr`/`Type` (mantém a entrada "ativa" como hook normal sem restrição). Isso faz `ShvVmxEptApplyHooks` reaplicar essa GPA no próximo vm-exit de cada vCPU, em vez de ignorá-la.
- Novo `ShvHookFreeSlot` — libera o slot da tabela (`PhysAddr = 0`) de fato, chamado só **depois** da sincronização de todas as CPUs já ter restaurado a identidade (não precisa bump de versão, pois nenhuma PTE muda nesse passo).
- `ShvVmxEptApplyHooks` e `ShvVmxEptRearmHook` (shvvmxhv.c) — troquei `ShvVmxEptSetPermissions` por `ShvVmxEptSetPhysAndPerms(VpData, pa, pa, r, w, x)` nos ramos que restauram identidade, garantindo que o `PageFrameNumber` da PTE também volte para a PA original, não só os bits de permissão.
- `nt/shvos.c` — novo `ShvOsForceAllCpuVmExit()`, que usa `KeGenericCallDpc` com uma DPC dedicada (`ShvForceVmExitDpcRoutine`, só `__cpuid`) para forçar **todas** as CPUs (não só a atual) a processar um VM-exit síncrono — garantindo que cada vCPU reaplique a tabela + rode INVEPT local antes de retornar. (Importante: essa DPC não chama `ShvVmxCleanup` — essa rotina só é válida após o `iretq` do caminho de VMXOFF; chamá-la fora desse contexto corrompe `FS.base`, quebrando o tratamento de exceção do kernel.)
- `nt/hpv_hooks.c` — `HpvUnhookFuncByVa` agora segue a ordem: `ShvHookRemoveShadow` (restaura identidade na tabela) → `ShvOsForceAllCpuVmExit` (sincroniza todas as CPUs) → `ShvHookFreeSlot` (libera o slot) → só então `MmFreeContiguousMemory` (libera a shadow page).

**Lição geral:** ao desfazer qualquer redirecionamento de EPT (shadow hook ou split-page), não basta mudar os bits de permissão da PTE — é preciso explicitamente restaurar o `PageFrameNumber` para a PA original (usar a função que seta PA+perms juntos, nunca só perms, quando a PTE pode ter vindo de um redirecionamento). E antes de liberar qualquer memória física que a EPT deixou de referenciar, é preciso sincronizar TODAS as CPUs (forçar cada uma a reaplicar a tabela, não só a CPU que fez a remoção) — do contrário, outra CPU pode ainda enxergar/executar a página antiga via EPT, mesmo depois dela ser liberada e reaproveitada.

**Como diagnosticar esse tipo de bug (ficou registrado para o próximo caso parecido):** bugcheck 0x139 com args zerados é pouco informativo por si só. O que resolveu foi: (1) `sxe av` antes do repro pra confirmar que NÃO era um acesso a memória inválida (eliminou a teoria de "executando memória liberada/sem mapeamento"); (2) usar o `FuncVa` do log de instalação do hook e rodar `u <FuncVa> L6` no WinDbg, com o driver ainda carregado, depois da remoção do hook — isso expôs diretamente que a EPT ainda servia o conteúdo da shadow page em vez do original.

---

## Colunas "Destino" e "CR3" vazias/sem identificação na tab Eventos → EPT do usermode_gui (2026-11-09)

**Sintoma:** usuário reportou que, na tab Eventos → EPT, as colunas "Destino" e "CR3" nunca mostravam nada útil.

**Causa raiz:** o GUI (`shv_client.cpp`) e o `shv_client.h` já tinham o lado cliente pronto há tempo — consultavam o sub-leaf CPUID `SHV_QUERY_EVENT_EXT2_BASE+slot` esperando `EAX=Cr3.Low, EBX=Cr3.High` — mas essa funcionalidade nunca tinha sido implementada do lado do hypervisor:
- `SHV_HV_EVENT` (struct interna do ring buffer, em `shvvmxhv.c`) não tinha nenhum campo `Cr3`.
- `ShvHvPushEvent` nunca capturava `GUEST_CR3`.
- O handler de CPUID (`ShvVmxHandleExit`'s leaf de comunicação) não tinha nenhum `else if` para o sub-leaf `EXT2_BASE` — a constante nem existia em `shv_comm.h` (só em `shv_client.h`, usado apenas pelo lado GUI). Qualquer sub-leaf não reconhecido cai no default (`Rax=Rbx=Rcx=Rdx=0`), então o cliente sempre lia CR3=0.

Como "Causador" (processo) e a resolução de módulos user-mode (via `ProcModsByCr3`) dependem do CR3 vir preenchido, isso também deixava "Causador" sempre em "---" para esses casos e a coluna "Destino" nunca checava os módulos do processo (só os módulos do kernel), então qualquer hook em código usermode também caía sempre em "não identificado".

**Fix aplicado:**
- `shv_comm.h` — nova constante `SHV_QUERY_EVENT_EXT2_BASE` (mesma fórmula que já existia duplicada em `shv_client.h`), documentada no protocolo compartilhado.
- `shvvmxhv.c` — `SHV_HV_EVENT` ganhou o campo `Cr3`; `ShvHvPushEvent` agora captura `ShvVmxRead(GUEST_CR3)` a cada evento; novo `else if` no handler de CPUID para `EXT2_BASE+slot` retornando `Cr3.Low/Cr3.High`. (Precisou de um forward-declare de `ShvVmxRead` no topo do arquivo, já que a definição `FORCEINLINE` dela só aparece mais abaixo no mesmo arquivo, depois do ponto onde `ShvHvPushEvent` é definida.)
- `usermode_gui/.../tab_events.cpp` — coluna "Destino" agora também verifica `ProcModsByCr3(e.cr3)` (módulos do processo identificado pelo CR3 do evento), não só os módulos do kernel — mesmo padrão já usado pelas colunas RIP/Value, RetAddr e VA Fault.

**Ainda não implementado (mesmo tipo de gap, fora do pedido desta vez):** os sub-leaves `EXT3` (timestamp), `EXT4` (linear address / VA Fault) e `EXT5`-`EXT8` (stack trace) também são consultados pelo `shv_client.cpp`, mas o hypervisor não tem campos equivalentes em `SHV_HV_EVENT` nem handler de CPUID pra eles — ou seja, as colunas "Hora", "VA Fault" e o painel de stack trace na tab Eventos provavelmente têm o mesmo problema (sempre 0/vazio). Mencionado aqui pra não precisar re-investigar do zero se o usuário pedir pra arrumar depois.

**Update 2026-11-09 (coluna "Hora" implementada, mesmo padrão do CR3):** mesmo gap do CR3 (sub-leaf não implementado no hypervisor). Fix: `shv_comm.h` ganhou `SHV_QUERY_EVENT_EXT3_BASE`; `SHV_HV_EVENT` ganhou campo `Timestamp`; `ShvHvPushEvent` captura via nova `ShvReadSystemTime()` (lê `KUSER_SHARED_DATA->SystemTime` direto do endereço fixo `0xFFFFF78000000000+0x14` — seguro em VMX root/interrupções desligadas porque é memória sempre residente, sem nenhuma chamada de SO; usa o padrão High1/Low/High2 + retry pra evitar leitura torn do contador de 64 bits escrito em partes pelo kernel real); novo `else if` no handler de CPUID pra `EXT3_BASE+slot`. `EXT4`-`EXT8` (VA Fault/stack trace) continuam sem implementação.

---

## Botão "Limpar histórico" não limpava de fato + ring buffer de eventos pequeno (256) (2026-11-09)

**Sintoma:** usuário reportou que clicar em "Limpar histórico" (tab Eventos → EPT) não parecia fazer efeito, e pediu pra aumentar o limite de eventos.

**Causa raiz do botão não funcionar:** `ShvClearEvents()` (shvvmxhv.c), chamada pelo IOCTL `SHV_CMD_CLEAR_EVENTS`, só resetava o contador `ShvEventCount` para 0 — nunca zerava o CONTEÚDO do array `ShvEventBuffer[256]`. O lado GUI (`ShvBackend::ClearEvents`, shv_backend.cpp) também zera seu `m_lastSeqSeen` para 0 ao limpar. Resultado: no próximo poll, a condição `e.seqNum <= m_lastSeqSeen(0)` deixava passar QUALQUER slot do ring com `SeqNum > 0` — incluindo os slots antigos que ainda tinham os dados (e o SeqNum alto) de ANTES do clear, que nunca tinham sido sobrescritos por eventos novos. Ou seja: o histórico antigo inteiro era reexibido quase imediatamente após o "clear", dando a impressão de que o botão não fazia nada.

**Fix:** `ShvClearEvents()` agora zera o buffer inteiro (`__stosb` sobre `ShvEventBuffer`, mesmo padrão já usado em `ShvListEptHooks`) antes de resetar o contador.

**Limite aumentado:** `SHV_EVENT_RING_SIZE` (ring buffer do hypervisor) foi de 256 para 4096 — precisa ser EXATAMENTE o mesmo valor em `shv_comm.h` (lado kernel) e `shv_client.h` (lado GUI), já que os sub-leaves `EXT_BASE`/`EXT2_BASE`/etc. do protocolo CPUID são calculados como `SHV_QUERY_EVENT_BASE + N*RING_SIZE` dos dois lados — mudar só de um lado desalinha o protocolo inteiro silenciosamente. `kEventHistoryMax` (cap do histórico mostrado na GUI, em `shv_backend.h`) subiu de 2000 para 20000. Como o array `ShvEventRecord newEvs[SHV_EVENT_RING_SIZE]` em `shv_backend.cpp::PollOnce` passou a ser grande o suficiente pra não caber confortavelmente na stack da thread de poll com 4096 entradas, foi trocado para `static` (vai para `.bss`, não para a stack).

**Nota:** `usermode_teste/main.cpp` tem seu próprio `#define SHV_EVENT_RING_SIZE 16` local e independente (só limita quantos slots aquele programinha de teste lê por poll) — não precisa e não deve ser sincronizado com o valor real do protocolo.

---

## Colunas da tabela de Eventos → EPT desalinhadas (Hora aparecia em Seq, Seq em CPU, etc.) (2026-11-09)

**Sintoma:** depois de implementar a coluna "Hora" (ver acima), o usuário notou que os valores apareciam deslocados uma coluna pra direita: o horário aparecia embaixo do header "Seq", o SeqNum embaixo de "CPU", e assim por diante — com o último item (CR3) sumindo (na real, vazando pra linha seguinte).

**Causa raiz (bug estrutural pré-existente em `tab_events.cpp::RenderEventTable`, não causado pelas mudanças de hoje — só ficou visível porque antes a coluna "Hora" sempre mostrava "---"):** o código fazia `TableSetColumnIndex(0)` pra desenhar o `Selectable` invisível (coluna 0 = "Hora"), e **depois** chamava `TableNextColumn()` de novo antes de desenhar o próprio conteúdo da "Hora" — isso empurrava o conteúdo pra coluna 1 ("Seq"). A partir daí, cada um dos 11 itens de dado (Hora, Seq, CPU, Tipo, Causador, Destino, Value, RetAddr, Aux, VA Fault, CR3) ocupava a coluna do item ANTERIOR na lista, e o 11º item (CR3) não tinha mais coluna disponível na linha (só existem 11 colunas, 0-10, e o "Hora" já tinha avançado pra coluna 1 sem usar a coluna 0) — o `TableNextColumn()` extra fazia esse último "vazar" pra coluna 0 da próxima linha, corrompendo a linha seguinte também.

**Fix:** removido o `TableNextColumn()` extra antes do bloco que desenha a "Hora" — o conteúdo agora fica na MESMA coluna 0 onde o `Selectable` já foi posicionado (via `SameLine()`), igual ao padrão usado pros outros itens compostos de várias chamadas (ex.: o botão "x" do stack trace que compartilha linha com o texto do título).

**Update 2026-11-09 (ainda garblado depois do fix acima):** depois de corrigir o shift, a coluna "Hora" sozinha (só ela, as outras 10 ficaram perfeitas) continuava mostrando um glifo estranho (visualmente parecido com `##algumacoisa`) grudado no texto do horário. Causa: o `Selectable` embutia o ID diretamente na própria label (`snprintf(selId, "##sel%u", e.seqNum)` + `ImGui::Selectable(selId, ...)`) e usava `ImGui::SameLine()` (com o espaçamento padrão de item) antes de desenhar o texto da hora na mesma coluna — diferente do padrão já comprovado em `tab_procs.cpp`/`tab_drivers.cpp`, que usa label vazia (`""`) com `ImGui::PushID(i)`/`PopID()` pra unicidade, `Selectable(..., ImVec2(0,0))`, e `ImGui::SameLine(0, 0)` (espaçamento zero) antes do texto que compartilha a coluna. Troquei para esse padrão exato em `RenderEventTable`. Lição: quando um `Selectable` compartilha coluna com texto via `SameLine()`, usar `PushID`/label vazia (em vez de embutir o ID dentro da própria label) e espaçamento explícito zero — é o padrão que já funciona em todo o resto do projeto.

---

## Causador/Destino vazios para eventos de acesso DIRETO em usermode (ex.: memcpy) (2026-11-09)

**Sintoma:** usuário notou que eventos gerados por um teste de `memcpy` direto em usermode (RIP na faixa `0x00007FF...`) mostravam "não identificado" tanto em "Causador" quanto "Destino", enquanto eventos equivalentes disparados em modo kernel (RIP em `ntoskrnl.exe`) resolviam o processo/módulo normalmente.

**Causa raiz:** já documentada como limitação conhecida em [[feedback_cr3_filter_broke_usermode]] (bug diferente, mesma causa de fundo). Com KPTI/KVA-shadow ativo, código rodando em **ring 3** usa o CR3 "user" (`EPROCESS.UserDirectoryTableBase`), DIFERENTE do CR3 "kernel" (`KPROCESS.DirectoryTableBase`, em `EPROCESS+0x28`) usado quando o mesmo processo está em modo kernel. `ListProcs` (nt/shvos.c) só capturava o CR3 kernel, então `ProcNameByCr3`/`ProcModsByCr3` na GUI nunca batiam para eventos cujo `GUEST_CR3` (capturado corretamente pelo hypervisor, ver fix do CR3 acima) era o CR3 "user" de um acesso ring-3 direto.

**Fix:** `SHV_PROC_ENTRY` (shv_dbg.h + shv_client.h, precisam ficar com o MESMO layout nos dois lados) ganhou o campo `UserDirBase`. `ListProcs` (nt/shvos.c) agora lê `EPROCESS+0x388` (`EPROCESS_USER_DIR_TABLE_BASE_OFFSET`) além do `+0x28` de sempre — **atenção:** esse offset (ao contrário do `DirectoryTableBase`, estável desde sempre) muda entre builds do Windows; `0x388` é o valor publicamente documentado pra build 19041 (a desta VM), mas não foi verificado ao vivo — se `UserDirBase` aparecer sempre com lixo, confirmar via `dt nt!_EPROCESS UserDirectoryTableBase` no WinDbg e ajustar a constante. Do lado da GUI (`tab_events.cpp`), `ProcNameByCr3` e `ProcModsByCr3`/`RefreshProcModCache` agora comparam o CR3 do evento contra `DirBase` OU `UserDirBase` de cada processo, em vez de só `DirBase`.

---

## Coluna "VA Fault" implementada (último dos sub-leaves EXT pendentes) (2026-11-09)

**Sintoma:** igual aos gaps de CR3/Hora — a GUI já consultava o sub-leaf `EXT4_BASE` esperando `GUEST_LINEAR_ADDRESS`, mas o hypervisor nunca implementou esse sub-leaf nem tinha campo equivalente em `SHV_HV_EVENT`.

**Fix:** `shv_comm.h` ganhou `SHV_QUERY_EVENT_EXT4_BASE`. `SHV_HV_EVENT` ganhou campo `LinearAddr`. Diferente do CR3/Timestamp (que `ShvHvPushEvent` lia sozinha via `ShvVmxRead`), `GUEST_LINEAR_ADDRESS` só é um valor válido/com sentido durante uma violação de EPT (para eventos LSTAR não se aplica) — então, em vez de ler dentro de `ShvHvPushEvent`, adicionei um parâmetro `LinearAddr` à função e: `ShvVmxHandleEptViolation` lê `ShvVmxRead(GUEST_LINEAR_ADDRESS)` uma vez no topo e repassa pros 5 call sites de `ShvHvPushEvent(SHV_EVENT_EPT_*, ...)` dentro dela; os 2 call sites de LSTAR passam `0` (não aplicável). Novo `else if` no handler de CPUID pra `EXT4_BASE+slot`. Do lado GUI nada precisou mudar — `shv_client.cpp`, `shv_backend.cpp` e `tab_events.cpp` (coluna "VA Fault", via `RenderAddrCell`) já estavam prontos desde antes, só faltava o hypervisor preencher o valor.

**Com isso, todos os sub-leaves `EXT2`-`EXT4` (CR3, Timestamp, LinearAddr) estão implementados.** Só ficam pendentes `EXT5`-`EXT8` (stack trace, painel inferior da tab Eventos) — mesmo tipo de gap, ninguém pediu ainda.

---

## Stack trace (painel inferior da tab Eventos) implementado — scan heurístico de pilha (2026-11-10)

**Pedido:** usuário pediu uma forma de capturar o stack walk pros eventos. Antes de implementar, discuti alternativas (ver conversa): (1) scan bruto de QWORDs acima do RSP, (2) scan + filtro heurístico de "parece um call-site", (3) unwind estruturado de verdade via `.pdata`/`UNWIND_INFO`, (4) chamar `RtlVirtualUnwind` direto (descartada — não dá pra chamar API do SO de dentro do handler de VM-exit, VMX root/interrupções desligadas). Usuário escolheu a opção 2.

**Restrição importante decidida durante a implementação:** não existe hoje neste projeto um tradutor de VA→PA seguro via `GUEST_CR3` arbitrário (o antigo foi removido junto do caminho EFER.SCE, ver [[project_ept_hook_over_efer_sce]]) — e reimplementar isso é exatamente a classe de risco que já causou bugchecks 0xD1 `DISABLED_INTERRUPT_FAULT` neste projeto (ver [[feedback_direct_map_single_offset_bugcheck]]). Por isso o stack trace **só funciona pra eventos em modo kernel** (`GUEST_RSP` sendo um VA de kernel) — mesma restrição que `ShvReadGuestReturnAddress` já tinha pra 1 nível. Eventos usermode (ex.: o teste de `memcpy`) ficam com o stack trace vazio/zerado por enquanto; resolver isso exigiria reimplementar um tradutor CR3 seguro, que é um trabalho/risco separado.

**Fix de segurança adicional (achado durante a implementação, não pedido mas necessário):** mesmo pra RSP de kernel, o scan heurístico precisa LER os bytes perto de cada "candidato" (endereço tirado da pilha) pra verificar se parecem um call-site — ao contrário do próprio RSP (que é seguro de ler cru, pois a CPU estava usando-o agora), um valor qualquer lido da pilha pode ser lixo e, se dereferenciado sem checagem, pode gerar o MESMO tipo de bugcheck 0xD1 documentado antes. Como o projeto não tinha mais nenhuma função de "checar residência sem ler o conteúdo" (a antiga foi removida com o resto do path CR3), adicionei uma nova: `ShvOsIsAddressValid()` (shv.h/nt/shvos.c), wrapper fino de `MmIsAddressValid` — documentada pela Microsoft como segura em QUALQUER IRQL (só consulta a PTE, nunca bloqueia/falha). Toda leitura de endereço "não confiável por construção" no stack walk (tanto os slots da pilha quanto os candidatos a call-site) passa por essa checagem antes de ser dereferenciada.

**Implementação (shvvmxhv.c):**
- `SHV_HV_EVENT` ganhou `Stack[SHV_EVENT_STACK_FRAMES]` (8 slots).
- `ShvLooksLikeCallSite(candidate)`: confirma residência via `ShvOsIsAddressValid` e então verifica se os 8 bytes antes do candidato terminam numa instrução `CALL` plausível — `E8` direto (5 bytes) ou `FF /2` indireto por registrador (2-3 bytes, com/sem prefixo REX). É heurística: não cobre `CALL` por memória com ModRM/SIB mais longo, mas cobre os casos mais comuns sem precisar de um parser de instruções completo.
- `ShvCaptureStackHeuristic(guestRsp, outFrames)`: varre até `SHV_STACK_SCAN_WINDOW` (64) QWORDs acima do RSP (cada um verificado com `ShvOsIsAddressValid` antes de ler), filtra por VA de kernel canônico + bit0==0 (alinhamento de instrução) + `ShvLooksLikeCallSite`, e guarda até 8 candidatos aceitos. Chamada de dentro de `ShvHvPushEvent` (mesmo padrão de CR3/Timestamp — sempre captura, para qualquer tipo de evento).
- `shv_comm.h` ganhou `SHV_QUERY_EVENT_EXT5_BASE`..`EXT8_BASE` + `SHV_EVENT_STACK_FRAMES` (o lado GUI já tinha essas constantes e já lia/renderizava o painel de stack desde a implementação anterior do CR3/Hora — só faltava o hypervisor preencher, igual ao padrão dos fixes anteriores).

**Nota:** isso é uma heurística, não um stack trace garantidamente correto — pode ocasionalmente pular um frame real ou (raramente) aceitar um falso positivo. Se precisar de precisão real no futuro, a alternativa 3 (unwind estruturado via `.pdata`) discutida com o usuário é o caminho, mas é bem mais trabalho/risco.

**Update 2026-11-10 (estendido pra usermode):** depois de discutir as alternativas pra cobrir eventos usermode (reimplementar tradutor CR3 vs. capturar só o RSP cru e ler depois via `ReadProcessMemory` — descartada, porque a pilha já teria mudado no próximo poll da GUI, ~1s depois; o dado viria desatualizado), o usuário pediu a opção A (tradutor CR3 de verdade). Implementado:

- `ShvOsPaToVa()` (shv.h/nt/shvos.c) — wrapper de `MmGetVirtualForPhysical`, chamado **sempre fresco** (nunca cacheado — essa exigência vem direto da lição de [[feedback_direct_map_single_offset_bugcheck]], que já causou bugcheck 0xD1 com uma versão em snapshot).
- `ShvReadPhys8()` / `ShvTranslateGvaWithCr3()` (shvvmxhv.c) — andam manualmente PML4→PDPT→PD→PT (cobrindo páginas de 4KB/2MB/1GB) a partir de um `Cr3` arbitrário, convertendo cada PA de entrada de tabela pra VA via `ShvOsPaToVa` + `ShvOsIsAddressValid` antes de ler — nunca lê nada sem essa dupla checagem. Aborta (retorna 0) em qualquer nível que falhe, nunca "adivinha".
- `ShvLooksLikeCallSite`/`ShvCaptureStackHeuristic` agora recebem o `Cr3` do evento e decidem o caminho pela faixa do próprio endereço: RSP/candidato de kernel → leitura direta (como antes); RSP/candidato de usermode → `ShvTranslateGvaWithCr3`. Os dois caminhos são mutuamente exclusivos por construção (nunca se misturam pro mesmo evento) — confirmado com o usuário que isso não gera conflito nem quando o acesso vem de `ReadProcessMemory`/outro processo: nesse caso o RSP no momento do fault já é de **kernel** (a instrução que falha roda dentro de `MmCopyVirtualMemory`), então cai no caminho de leitura direta de sempre, sem nunca acionar o tradutor novo.
- `ShvHvPushEvent` passa `ev->Cr3` (já capturado antes) pro `ShvCaptureStackHeuristic`.

Com isso, o stack trace passa a funcionar tanto pra eventos de kernel quanto pra acesso direto em usermode (ex.: o teste de `memcpy`), usando a GUEST_CR3 da thread que de fato gerou o evento.

**Update 2026-11-10 (diagnóstico — stack usermode veio vazio no primeiro teste):** adicionados contadores globais em `shvvmxhv.c` (mesmo padrão de `ShvPaToVaRejectCount`/`ShvPaToVaLastBadResult` já usado antes neste projeto), legíveis direto no WinDbg sem precisar de nada na GUI:

```
dq shv!ShvStackWalkAttempts        -- quantas vezes rodou o caminho usermode
dq shv!ShvStackWalkSuccess         -- quantas traducoes de slot deram certo
dq shv!ShvStackWalkPml4Fail        -- falhou no nivel PML4 (CR3 errado/nao presente)
dq shv!ShvStackWalkPdptFail        -- falhou no nivel PDPT
dq shv!ShvStackWalkPdFail          -- falhou no nivel PD
dq shv!ShvStackWalkPtFail          -- falhou no nivel PT
dq shv!ShvStackWalkFinalFail       -- PA->VA final falhou (MmGetVirtualForPhysical/IsAddressValid)
dq shv!ShvStackWalkCallSiteReject  -- slot traduzido com sucesso mas nao bateu o filtro de call-site
dq shv!ShvStackWalkLastCr3         -- Cr3 usado na ultima tentativa
dq shv!ShvStackWalkLastGva         -- GVA que estava sendo traduzido na ultima falha
```

Se `Attempts==0`: o código nem está entrando no caminho usermode (RSP não foi reconhecido como < `SHV_KERNEL_VA_MIN`, ou o evento nem está chamando `ShvCaptureStackHeuristic`). Se `Pml4Fail` alto: o CR3 capturado no evento pode estar errado/zerado. Se chega em `PtFail`/`FinalFail`: a tradução anda mas a página final não está presente (ex.: página paginada/não residente nesse instante). Se `Success` é alto mas `CallSiteReject` é MUITO maior (e por isso nenhum frame aparece): o scan está funcionando, só o filtro heurístico de "parece um CALL" está rejeitando tudo — nesse caso o próximo passo é relaxar/revisar `ShvLooksLikeCallSite`, não o tradutor CR3.

**Update 2026-11-10 (achado real: `MmGetVirtualForPhysical` devolvia conteúdo ERRADO, não só "falhava"):** no primeiro teste real, `PdptFail` bateu 100% (12 de 12 tentativas), mesmo com `PdptReadFail=0` (ou seja, a "leitura" tecnicamente "funcionava", só devolvia dado errado). Processo de diagnóstico, com o usuário ativamente ajudando a comparar:
1. `!vtop <cr3> <gva>` no WinDbg mostrou que a tradução *de verdade* para aquele GVA/CR3 tinha sucesso, com uma PDPT em PFN `0x20B10D000`.
2. Meu código, no mesmo instante (sistema congelado inteiro pelo debugger, processo de teste ainda vivo — comparação justa), tinha lido a PML4E como apontando para PFN `0x103E9D000` — completamente diferente.
3. **Decisivo:** pedi pro usuário ler a física DIRETO via WinDbg (`!dq 168df8000 L1`, sem passar pelo meu código) → resultado `0x0A000002`0B10D867` → PFN `0x20B10D000`, batendo com o `!vtop`. Ou seja: a física real tem um valor, meu código (via `MmGetVirtualForPhysical` + dereference) lia **outro**, silenciosamente, sem erro nenhum — pior que travar, porque não dá nenhum sinal de que algo está errado.

**Causa provável:** `MmGetVirtualForPhysical` é documentada como segura em qualquer IRQL, mas essa garantia (e a receita já validada neste projeto antes) foi pensada pra páginas de dados "normais" via o *direct map* do sistema — não necessariamente confiável pra páginas que são elas mesmas **tabelas de página de outro processo** (há suspeita de aliasing/granularidade diferente nesse tipo de PFN).

**Fix (sugestão do usuário, adotada):** trocar o mecanismo inteiro de leitura física por `MmCopyMemory(..., MM_COPY_MEMORY_PHYSICAL, ...)` — documentada pela Microsoft como segura em IRQL ≤ `DISPATCH_LEVEL`, e é literalmente o mecanismo que o próprio WinDbg usa pra ler física (explica por que bateu certo com `!dq`). Diferença de design: em vez de "traduz pra um VA e eu dereferencio depois" (`ShvOsPaToVa`, removida), agora é "copia os bytes direto pra um buffer" (`ShvOsReadPhysical`, nova, em shv.h/nt/shvos.c). `ShvTranslateGvaWithCr3` agora devolve o **endereço físico final** (não mais um VA), e um novo `ShvReadGvaWithCr3` faz tradução+leitura num só passo, sempre via `ShvOsReadPhysical` — nunca mais por dereference direto de um ponteiro obtido separadamente.

**Lição geral:** "seguro em qualquer IRQL" não é o mesmo que "devolve sempre o conteúdo correto" — pra ler memória física arbitrária de forma confiável (inclusive tabelas de página de outros processos), usar uma função de **cópia** dedicada (`MmCopyMemory`/`MM_COPY_MEMORY_PHYSICAL`) em vez de "traduzir pra VA e dereferenciar manualmente", mesmo que a tradução pareça ter funcionado sem erro.

**Update 2026-11-10 (tradução confirmada correta, mas zero frames ainda apareciam):** reteste confirmou que o fix do `MmCopyMemory` funcionou — `ShvStackWalkLastPml4Entry`/`LastPdptPa` bateram exatamente com `!dq`/`!vtop`. Novos números: `Attempts=82`, `Success=5412` (tradução funcionando muito bem, ~66 leituras por evento), mas `CallSiteReject=4346` e **zero frames aceitos**.

**Causa:** o filtro heurístico de "parece um CALL" (`ShvLooksLikeCallSite`) só cobria `CALL rel32` direto (`E8`, 5 bytes) e `CALL` indireto por **registrador** (`FF /2`, 2-3 bytes) — mas a forma mais comum de chamar funções importadas (CRT/API do Windows, ex. `memcpy`) em builds sem otimização é `call qword ptr [rip+disp32]` (`FF 15` + 4 bytes, 6 bytes, ModRM fixo `0x15` sem SIB/base/index variável) — exatamente o caso que a documentação original já citava como "não coberto", só que na prática era o caso DOMINANTE, não uma exceção rara.

**Fix:** adicionado o padrão de 6 bytes (`bytes[2]==0xFF && bytes[3]==0x15`) em `ShvLooksLikeCallSite`. Também apertei o filtro de "parece um VA de usermode plausível" em `ShvCaptureStackHeuristic`: antes aceitava qualquer valor `< SHV_KERNEL_VA_MIN` (deixava passar lixo não-canônico, como `0xCCCCCCCCCCCCCCCC` — padrão clássico de pilha não inicializada em build debug, que apareceu num `ShvStackWalkLastGva` durante o diagnóstico); agora exige o teto real de VA canônico de usermode (`< 0x0000800000000000`).

**Update 2026-11-10 (ainda zero frames mesmo com o fix do FF15 — causa diferente: janela de scan pequena demais):** reteste ainda sem frames. Adicionei um toggle de diagnóstico ao vivo (`ShvStackWalkDebugNoFilter`, escrito via `ed shv!ShvStackWalkDebugNoFilter 1` no WinDbg, sem precisar recompilar) que desliga o filtro de call-site e mostra os candidatos crus. Resultado na GUI: a maioria dos "frames" eram ponteiros pra dentro da própria pilha ou padrão clássico `0xCCCCCCCC` de memória não inicializada (build debug) — nenhum parecia um retorno de verdade.

Comparação decisiva: `dps <rsp> L20` no WinDbg (trocando o contexto pro processo via `.process /r /p <EPROCESS>`, símbolos carregados) mostrou que a janela INTEIRA de 64 QWORDs (512 bytes) acima do RSP real é quase toda preenchimento de debug — só 1 ponteiro real lá (pra uma string, não pra código). Ou seja: **não tinha bug nenhum na tradução** — o endereço de retorno de verdade simplesmente está fora do alcance da janela de scan, porque frames de pilha em build sem otimização (padding, canário do `/RTC`, locals maiores) facilmente passam de 512 bytes.

**Fix:** `SHV_STACK_SCAN_WINDOW` (shvvmxhv.c) subiu de 64 para 512 QWORDs (4KB, ~1 página) — ainda não testado na VM depois dessa mudança.

**Lição geral desse ciclo inteiro de diagnóstico:** sempre que uma heurística "não encontra nada", antes de mexer no filtro, comparar contra uma fonte de verdade independente (aqui, `dps`/`!vtop`/`!dq` do próprio WinDbg) pra saber se o problema é "o filtro está errado" ou "o dado que eu olho nem contém o que eu procuro". As duas causas reais encontradas nesta sessão (tradução física errada via `MmGetVirtualForPhysical`, e depois janela de scan pequena demais) só ficaram claras comparando com o WinDbg, não só olhando os contadores internos.

**Update 2026-11-10 (confirmado com `SHV_STACK_SCAN_WINDOW=512`: stack walk funciona, mas faltava comparação independente e mais profundidade):** com a janela de 512 QWORDs, o stack trace passou a trazer frames reais (`ucrtbased.dll`/`ntdll.dll`) — mas o usuário notou que o frame `[0]` não era dentro do próprio `detect_shv.exe`, e sim já dentro do CRT debug (`ucrtbased.dll`), o que pareceu suspeito. Pra confirmar sem depender só da heurística, o usuário comparou com a call stack **real**, vista via Cheat Engine (hardware breakpoint no mesmo ponto + `k`/debug context) — mas inicialmente o breakpoint de hardware armado pelo CE não disparava, porque o WinDbg (kernel) estava interceptando a exceção de debug (#DB) do sistema inteiro antes do handler de usermode do CE: corrigido com `sxd sse`/`sxd bpe` no kd (desliga o kd parar nessas exceções, deixando passar direto pro processo). Depois disso o CE conseguiu capturar, e a call stack real mostrada por ele **também** tinha lixo no início (mesma assinatura: chamadas através do CRT debug) — confirmando que a heurística do hypervisor estava correta, e que o comportamento "estranho" é esperado em build Debug (CRT não-inline + várias camadas de wrapper antes de voltar pro código do usuário).

**Update 2026-11-10 (feature, não é fix de bug): colunas com auto-fit de largura + menu de contexto "Copiar" por célula (tab_events.cpp, tabela da aba EPT):**

- **Auto-fit de largura**: cada coluna agora mede a largura em pixels do texto mais largo já desenhado nela (via `ImGui::CalcTextSize`) e aplica isso como largura da coluna no próximo frame (`s_colWidth`/`colWNext`, atraso de 1 frame — padrão usual pra isso em ImGui modo imediato, já que a largura tem que ser conhecida *antes* de desenhar qualquer célula daquele frame). Nunca encolhe abaixo da largura do próprio label do cabeçalho.
- **Menu de contexto "Copiar"**: nova função `RenderCopyableCell` (texto + `ImGui::BeginPopupContextItem` com `"Copiar"` → `ImGui::SetClipboardText`). Cada célula fica dentro de `PushID(seqNum)` (por linha, agora envolvendo a linha inteira, não só o `Selectable`) + `PushID(coluna)` (por célula) — a dupla garante um ID único pro popup de cada célula, evitando que todas colidam no mesmo popup.
- `RenderAddrCell` foi refatorada: a lógica de montar o texto (módulo+offset ou hex cru) virou `FormatAddrCell` (retorna `std::string` + flag "disabled" em vez de desenhar direto), reusada tanto pela tabela principal (via `RenderCopyableCell`) quanto pelo painel de stack trace embaixo (que continua chamando `RenderAddrCell`, sem copiar — só a tabela ganhou o menu de contexto).

**Update 2026-11-10 (bug): só dava pra selecionar a linha (clicar p/ ver a stack) quando a coluna "Hora" estava ativa.**

**Causa raiz:** o `Selectable` invisível com `ImGuiSelectableFlags_SpanAllColumns` (usado pra selecionar a linha inteira ao clicar em qualquer ponto dela) era sempre desenhado dentro da coluna 0 ("Hora"), via `ImGui::TableNextColumn()` fixo no início da linha. Quando "Hora" é desligada no popup "Colunas" (`ImGui::TableSetColumnEnabled(0, false)`), aquela coluna vira uma célula de largura zero/oculta — um widget desenhado ali não recebe clique nenhum, mesmo com `SpanAllColumns`.

**Fix:** calculado `selCol` (a primeira coluna realmente visível, segundo `g_cfg.evtColVis[]`) uma vez por frame, antes do loop de linhas. Nova função `PlaceRowSelectableIfOwned(selCol, ci, isSelected)` só desenha o `Selectable` quando a coluna atual (`ci`) é essa primeira coluna visível — chamada logo após o `TableNextColumn()` de cada uma das 11 colunas (0 a 10), em vez de só na coluna 0. Assim a seleção de linha sempre funciona em qualquer coluna visível que esteja na frente, independente de "Hora" estar ligada.

**Update 2026-11-10 (bug real + feature pedida): aba Filtros->Hook Shadow — colunas VA/Módulo/CR3, Offset/Len/Bytes "não funcionando", botão de remover por seleção.**

**Causa raiz do "Offset/Len/Bytes não funcionando":** a aba mostrava DUAS listas sobrepostas pra cada shadow patch instalado pela própria GUI — `kernelShadows` (vinda do poll periódico via `SHV_CMD_LIST_SHADOW_PATCHES`, rotulada "[K]") e `shadowPatches` (cache só local, criada no momento do clique em "Aplicar", rotulada "[U]"). O cache local (`ShvBackend::ShadowPatch`) guardava a GPA **exatamente como digitada** (sem alinhar à página), enquanto o kernel sempre alinha (`gpa & ~0xFFF`) tanto ao criar quanto ao devolver no poll — então a linha "[U]" ficava com uma GPA ligeiramente diferente da "[K]" (mesmo valor, bits baixos diferentes), e nunca mais era atualizada/removida em sincronia com a de verdade — dando a impressão de que os campos "não funcionavam" (valores nunca batiam, remoção de uma não refletia na outra).

**Fix:** `ShvBackend::ShadowPatch` agora alinha a GPA (`gpa & ~0xFFFULL`) antes de guardar no cache local, igual o kernel faz — elimina a duplicação/dessincronia. Além disso a lista da aba passou a usar **só** `kernelShadows` (a fonte de verdade, sempre fresca via poll) — `shadowPatches` virou só um cache auxiliar interno (usado para lembrar VA/CR3 que o kernel não guarda, ver abaixo), não é mais renderizado como lista separada.

**Feature (colunas VA/Módulo/CR3):** o protocolo do kernel não guarda a VA original usada pra achar a GPA (`SHV_SHADOW_HOOK_INFO.FuncVa` é hardcoded `0` em `nt/shvos.c`) — só a GPA física. Pra mostrar VA/Módulo/CR3 mesmo assim: `ShvBackend::ShadowPatch` ganhou parâmetros opcionais `va`/`cr3`, gravados no cache local (`ShvShadowEntry.va/cr3`, novos campos em shv_backend.h) no momento da criação; a cada poll, `ShvBackend::Refresh` casa cada entrada de `kernelShadows` (por GPA) com o cache local pra recuperar VA/CR3 sem perder a informação entre polls. Tab Memória->Shadow Patch ganhou um modo "Por VA+PID" (além do "Por GPA direta" original): resolve VA->GPA via `TranslateVa` antes de chamar `ShadowPatch`, e já busca o CR3 (DirBase) do PID informado em `backend.State().procs` pra gravar junto. Tab Filtros->Hook Shadow ganhou colunas VA, Módulo (resolvido contra `kernelModules` por faixa de endereço, só para VA de kernel — módulo usermode não resolvido, fora de escopo) e CR3 ("kernel" se 0); "---" quando a VA não é conhecida (shadow pré-existente antes desta sessão, ou criado via GPA direta).

**Feature (remover por seleção):** a lista agora tem `Selectable` por linha (como as outras abas do projeto) + um botão "Remover Shadow selecionado" acima da tabela, que remove a GPA da linha selecionada — além do menu de contexto "Remover Shadow" (clique direito) que já existia, mantido.

**Update 2026-11-10 (causa raiz de verdade do "só a GPA funciona" em Filtros->Hook Shadow): havia DOIS caminhos de instalação de shadow hook, e só um preenchia a metadata.**

O usuário notou que `Status->Syscall Hooks` mostrava informação de verdade (FuncVA, HookFunc, Trampoline, FuncGPA) pra hooks como o de `NtOpenProcess`, enquanto a mesma entrada em `Filtros->Hook Shadow` só tinha a GPA preenchida (Offset/Len/Bytes/VA vazios). Investigando, existem DOIS caminhos completamente diferentes que escrevem em `g_ShadowPages[]` (a tabela por trás de `SHV_CMD_LIST_SHADOW_PATCHES`, usada pela aba Hook Shadow):

1. **Caminho manual** (`SHV_CMD_HOOK_SHADOW`, nt/shvos.c): usuário digita GPA+offset+bytes na aba Memória->Shadow Patch — grava `.Offset`/`.PatchLen`/`.PatchBytes` corretamente.
2. **Caminho de hook de função** (`HpvHookFuncByVa`, nt/hpv_hooks.c, usado internamente p/ hooks como `NtOpenProcess`): aloca/reusa o MESMO slot em `g_ShadowPages[]` e escreve o patch de verdade (JMP de 12 bytes) na shadow page via `HpvWriteJmp12` — mas **nunca atualizava `.Offset`/`.PatchLen`/`.PatchBytes` daquele slot**, só `.Gpa`/`.ShadowPa`/`.ShadowVa`/`.RefCount`. Resultado: pra qualquer hook instalado por esse caminho (que é o único caminho usado na prática pelos hooks reais do projeto), a listagem sempre devolvia Offset=0/Len=0/Bytes vazio — só a GPA (que de fato é gravada) aparecia.

Além disso, a VA nunca é guardada em `g_ShadowPages[]` (só a GPA da página) — mas o PRÓPRIO VALOR real da VA existe em `g_SyscallHooks[].FuncVa`, uma tabela SEPARADA, preenchida só por esse caminho de hook de função (é o que alimenta `Status->Syscall Hooks`). `SHV_CMD_LIST_SHADOW_PATCHES` sempre devolvia `FuncVa=0` (hardcoded), nunca tentava cruzar com `g_SyscallHooks[]`.

**Fix:**
- `nt/hpv_hooks.c` (`HpvHookFuncByVa`): depois de escrever o JMP de 12 bytes na shadow page, agora grava `g_ShadowPages[slot].Offset/PatchLen/PatchBytes` também (mesmos campos que o caminho manual já preenchia).
- `nt/shvos.c` (`SHV_CMD_HOOK_SHADOW`, branch "shadow page já existe"): idem — reaplicar um patch manual num shadow já existente antes só copiava os bytes pra memória, sem atualizar a metadata exibida (mesma classe de bug).
- `nt/shvos.c` (`SHV_CMD_LIST_SHADOW_PATCHES`): em vez de `shi->FuncVa = 0` fixo, agora procura em `g_SyscallHooks[]` uma entrada cujo `FuncGpa` (paginado) bata com a GPA do shadow, e usa o `FuncVa` real de lá quando encontrar.
- `usermode_gui/shv_backend.cpp` (`Refresh`): usa esse `FuncVa` vindo do kernel como fonte primária da coluna VA; só cai pro cache local (`shadowPatches`, só preenchido quando a própria GUI cria o shadow via Memória->Shadow Patch "Por VA+PID") quando o kernel não souber.

Driver e GUI recompilados sem erro; ainda não testado na VM.

**Update 2026-11-10 (feature): shadow hook em `MmCopyVirtualMemory` (nt/hpv_policy_hooks.c).**

`MmCopyVirtualMemory` é a função usada internamente pelo kernel pra copiar memória entre processos (caminho de `NtReadVirtualMemory`/`NtWriteVirtualMemory`, ou seja, `ReadProcessMemory`/`WriteProcessMemory` em usermode, e também usada por drivers que fazem acesso cross-process direto). Não está declarada em `ntifs.h`/`wdm.h` desta WDK, então só foi criado o tipo do trampolim (`PfnMmCopyVirtualMemory`) — a resolução é dinâmica por nome via `HpvHookFuncByName`/`MmGetSystemRoutineAddress`, igual o hook de `NtOpenProcess` já existente, sem precisar de declaração estática importada.

**Implementação:** `HpvCopyVirtualMemoryHook` — pega o PID de `FromProcess`/`ToProcess` via `PsGetProcessId`, reusa os helpers já existentes (`CheckProcess`/`PidProtected`/`PidMonitored`/`ShvHooksIsTrustedName`) pra aplicar a MESMA política do hook de `NtOpenProcess`: loga se qualquer um dos dois lados estiver monitorado, e bloqueia (retorna `STATUS_ACCESS_DENIED`, zera `NumberOfBytesCopied`) se o processo de origem (`FromProcess`) estiver protegido e o chamador não for um nome confiável. `ShvReadVirtualMemoryHookHitCount` (contador que já existia na ABI, mas sempre voltava 0 — "placeholder" deixado de propósito) agora é incrementado de verdade a cada chamada interceptada.

Instalado em `ShvPolicyHooksInit`/removido em `ShvPolicyHooksUninit`, do mesmo jeito que `NtOpenProcess` — mas como falha **não é fatal** (o hook de `NtOpenProcess` continua sendo o crítico; este é bônus de visibilidade). Driver recompilado sem erro; ainda não testado na VM.

**Update 2026-11-10:** log do hook passou a incluir o nome do processo sendo LIDO (`FromProcess`), via `PsGetProcessImageFileName(FromProcess)` (seguro sem `__try` — só lê o campo `ImageFileName` do próprio `EPROCESS`, não toca memória de usuário).

**Update 2026-11-10 (usuário reportou que o hook não aparece no log mesmo com o Cheat Engine marcado como monitorado):** a lógica de monitoramento em si está correta (mesmos helpers `CheckProcess`/`PidMonitored` já usados e validados pelo hook de `NtOpenProcess`) — não encontrei bug nela. Explicação mais provável, registrada aqui porque não é óbvia pelo código: **o Cheat Engine, quando tem o driver kernel dele próprio carregado/habilitado (DBK/DBVM — visível neste projeto pelas ferramentas MCP `read_process_memory_cr3`, `dbk_get_cr3`, etc.), lê memória de outro processo fazendo ELE MESMO o walk de page table via CR3 e lendo a física diretamente — sem nunca passar por `NtReadVirtualMemory`/`MmCopyVirtualMemory`.** Se for esse o caso, não existe hook de função de kernel que capture isso (é exatamente a técnica que projetos como este existem pra estudar/testar). Hooking de EPT nas páginas físicas sendo lidas seria a única forma de ver esse tipo de acesso, não hooking de função.

**Update 2026-11-10:** faltava o nome também na linha de log do caminho BLOQUEADO (`MmCopyVirtualMemory BLOQUEADO: caller=... -> PID=...`) — só a linha do caminho "monitorado" (não bloqueado) tinha o nome do processo lido. Adicionado `fromName` (via `PsGetProcessImageFileName(FromProcess)`) também nessa linha.

**Diagnóstico adicionado pra confirmar a causa:** novo sub-leaf CPUID `SHV_QUERY_COPYVM_HITS=7` (shv_comm.h/shv_client.h) expõe `ShvReadVirtualMemoryHookHitCount` (incrementado pelo hook de `MmCopyVirtualMemory`) sem depender do filtro de monitorado — `shvvmxhv.c` lê esse global NT-side diretamente via `extern` (é só um `UINT64`, sem dependência de WDK). GUI: novo campo `ShvStats.copyVmHits`, exibido em `Status` como "MmCopyVirtualMemory Hits". **Como usar pra diagnosticar:** se esse contador ficar em 0 mesmo fazendo o Cheat Engine ler outro processo normalmente, confirma que a chamada nem está passando por `MmCopyVirtualMemory` (reforça a teoria do driver próprio do CE); se o contador subir mas nenhuma linha aparecer no log, aí sim é bug na lógica de PID/monitorado (não encontrado até agora). Driver e GUI recompilados sem erro; ainda não testado na VM.

**Update 2026-11-12 (usuário reportou: hook EPT com "range de 1 byte" ainda hookeia a página inteira).**

**Resposta curta: isso é esperado e inevitável — EPT (Extended Page Tables) só tem granularidade de página (4KB), nunca de byte.** Uma PTE de EPT cobre a página inteira; não existe jeito de restringir leitura/escrita/execução a um sub-trecho dela no hardware. Qualquer acesso em QUALQUER byte da página hookada dispara a violação — é por isso que a coluna "VA Fault" (`GUEST_LINEAR_ADDRESS`) existe: ela mostra o endereço EXATO do acesso que disparou, pra filtrar depois na GUI quais eventos realmente caem no endereço de interesse, já que o hook em si nunca pode ser mais fino que a página inteira.

**Mas investigando encontrei um bug real e diferente, no campo "Range" (múltiplas páginas), que respondia: `ShvVmxEptApplyHooks`/`ShvVmxEptRearmHook`/`ShvVmxHandleEptViolation` (shvvmxhv.c) sempre compararam `ShvHookTable[i].PhysAddr == page`** (igualdade exata com a PRIMEIRA página do hook) **em vez de verificar se `page` cai dentro do intervalo `[PhysAddr, PhysAddr + RangeSize*0x1000)`.** Resultado: um hook instalado com `RangeSize > 1` (via aba Memória->EPT Hook, campo "Range") só de fato cobria a primeira página — `ShvVmxEptApplyHooks` nunca aplicava a permissão nas páginas seguintes do range, e mesmo que aplicasse, o matching no VM-exit só reconheceria a primeira página mesmo assim. O campo "Range" > 1 era puramente cosmético, sem efeito real.

**Fix:** novo helper `SHV_HOOK_PAGE_IN_RANGE(entryIdx, pg)` (shvvmxhv.c) centraliza o cálculo `pg >= PhysAddr && pg < PhysAddr + max(RangeSize,1)*0x1000`. `ShvVmxEptApplyHooks` agora itera `j = 0..RangeSize-1` aplicando a permissão em `PhysAddr + j*0x1000` pra cada página do range (hooks com shadow page continuam sempre de 1 página só, por construção — shadow é 1 PFN). `ShvVmxEptRearmHook` e os 3 pontos de matching em `ShvVmxHandleEptViolation` (EXEC/WRITE/READ) trocaram a comparação exata pelo novo helper, então agora reconhecem corretamente qualquer página dentro do range, não só a primeira. Driver recompilado sem erro; ainda não testado na VM.

**Melhoria pedida em seguida (não é fix de bug, é feature):** (1) toggle no GUI (aba Eventos → EPT) pra ligar/desligar o filtro de call-site (`ShvLooksLikeCallSite`) sem precisar do WinDbg/`ed` — novo comando IOCTL `SHV_CMD_SET_STACK_FILTER` (shv_dbg.h/shv_client.h), nova função `ShvSetStackFilterEnabled` (shvvmxhv.c, só inverte `ShvStackWalkDebugNoFilter`), novo método `ShvClient::SetStackFilter`/`ShvBackend::SetStackFilter`, e um checkbox "Filtro call-site (stack)" em `tab_events.cpp` (só na sub-aba EPT, via novo parâmetro `showStackFilterToggle` em `RenderEventTable`). (2) `SHV_EVENT_STACK_FRAMES` subiu de 8 para 16 (shv_comm.h/shv_client.h) — adicionadas sub-leaves CPUID `EXT9_BASE`..`EXT12_BASE` (mesmo esquema de 2 frames por sub-leaf dos EXT5-8) pro ring buffer carregar as 8 frames extras; o range-check do handler CPUID em `shvvmxhv.c` (`subleaf >= EXT5_BASE && subleaf < ...`) só precisou do limite superior ajustado pra `EXT12_BASE`, porque o cálculo de `group`/`slot` já era genérico. Lado GUI (`tab_events.cpp`, painel de stack trace) já iterava via `SHV_EVENT_STACK_FRAMES`, então passou a mostrar 16 frames automaticamente sem mudança de código ali. Driver e GUI recompilados sem erro; ainda não testado na VM.

---

## 2026-11-12 — EPT Hook: evento/hit duplicado ou triplicado pro mesmo acesso real

**Symptom:** usuário reportou que algumas leituras "diretas" (não via ReadProcessMemory)
geravam 2 ou 3 eventos na aba Eventos->EPT pra uma única tentativa de leitura real.

**Root cause:** `nt/shvos.c` (`SHV_CMD_HOOK_EPT`), nos dois ramos (kernel e usermode),
criava **uma entrada na `ShvHookTable[]` POR PÁGINA** do range pedido (loop por
`va`/`pfnArray[i]`), e cada uma dessas entradas recebia o `RangeSize` TOTAL do range
inteiro (não 1). Como `SHV_HOOK_PAGE_IN_RANGE` já soma `RangeSize` páginas a partir do
`PhysAddr` de CADA entrada pra decidir o que bate com a violação, pra um range de N>1
páginas isso cria N entradas todas se sobrepondo: a entrada da página 0 "pensa" que cobre
as páginas 0..N-1, a da página 1 TAMBÉM pensa que cobre as páginas 1..N, etc. Qualquer
acesso numa página do meio do range batia em 2 (ou mais) entradas ao mesmo tempo, e o loop
de `ShvVmxHandleEptViolation` em `shvvmxhv.c` loga um evento (e soma `HitCount`) POR
ENTRADA que bate — gerando 2-3 eventos pra um único acesso real.

**Fix:** os dois ramos de `SHV_CMD_HOOK_EPT` agora instalam **uma única entrada** na
tabela (na primeira página física válida do range), com `RangeSize` = total de páginas.
`ShvVmxEptApplyHooks`/`ShvVmxEptRearmHook`/`ShvVmxHandleEptViolation` (já corrigidos numa
passada anterior) sabem varrer as N páginas de UMA entrada só via `SHV_HOOK_PAGE_IN_RANGE`
— não precisava (e não devia) existir mais de uma entrada por hook instalado.

**Nota/limitação ainda aberta:** essa correção resolve range multi-página (RangeSize
resultando em >1 página, incluindo bytes que cruzam limite de página). Se o usuário ainda
via duplicação com range pequeno (1-4 bytes) dentro de UMA página só, a causa é outra (ex.:
hook antigo de um teste anterior não removido ainda na tabela, ou a ferramenta de teste
fazendo mais de um acesso real por "tentativa") e precisa de mais investigação/repro.

Driver recompilado (`MSBuild.exe shv.sln /p:Configuration="Windows NT" /p:Platform=x64`),
sem erros, `shv.sys` assinado com sucesso.

---

## 2026-11-12 — EPT Hook: 1 leitura real gerando 1-3 eventos idênticos (mesmo core)

**Symptom:** com o hook já restrito a 1 byte exato (ByteLen fix anterior), o usuário ainda
via 1, 2 ou 3 eventos idênticos (mesmo VA/CR3) pra uma única leitura real (`F9` no
`detect_shv.exe`, que lê só 1 byte). Confirmado que acontecia no MESMO core/CPU — descartando
a hipótese de migração de thread entre cores com EPT per-CPU desincronizado.

**Root cause provável:** o mecanismo de "abrir a página por 1 instrução" (restaura RWX
completo, arma MTF, guest re-executa a instrução que faltou, MTF re-restringe) depende de
que a PRÓXIMA instrução retirada depois do VM-entry seja exatamente a instrução re-tentada.
Se houver uma INTERRUPÇÃO PENDENTE nesse instante, o processador pode entregar essa
interrupção ANTES de re-executar a instrução do guest — o MTF então dispara depois da
PRIMEIRA instrução do handler da interrupção (nada a ver com a leitura), e o handler de MTF
re-restringe a página cedo demais. Quando a interrupção termina e a execução volta pro RIP
original (que não avançou, `SkipRipAdvance=TRUE`), a leitura real finalmente tenta executar
— mas a página já está restrita de novo, gerando OUTRA violação de EPT real pro MESMO
acesso lógico, no MESMO core. Corrigir isso de verdade exigiria bloquear entrega de
interrupção durante a janela de single-step (VMCS "interrupt-window exiting"), uma mudança
maior fora do escopo desta correção.

**Fix (mitigação pragmática):** dedup por janela de tempo curta (~50us, via
`ShvReadSystemTime`) em `shvvmxhv.c`: novo `ShvHookShouldDedupEvent(Type, LinearAddr, Cr3)`
compara contra o último evento EPT logado (globais `ShvLastEptEvent*`); se Tipo+VA+CR3
forem iguais e dentro da janela, trata como retry do mesmo acesso e NÃO loga de novo
(`HitCount` ainda soma, só o evento do ring buffer é suprimido). Aplicado nos 3 branches de
`ShvVmxHandleEptViolation` (EXEC/WRITE/READ) antes de cada `ShvHvPushEvent`.

**Nota:** isso é uma mitigação do SINTOMA (log duplicado), não elimina a violação EPT real
extra que ainda ocorre por baixo dos panos (overhead minúsculo, sem efeito funcional).

Driver recompilado (`MSBuild.exe shv.sln /p:Configuration="Windows NT" /p:Platform=x64`),
sem erros, `shv.sys` assinado com sucesso.

---

## 2026-11-12 — GUI: checkbox "Ignorar Duplicados" na aba Eventos->EPT

**Pedido:** o dedup por janela de tempo no kernel (fix anterior) não eliminou 100% os
eventos duplicados/triplicados de uma mesma leitura real (causa raiz provável: corrida
entre interrupção pendente e o MTF single-step, difícil de eliminar sem bloquear entrega
de interrupção na VMCS). Usuário decidiu que não é um problema que afeta o uso real, e
pediu um filtro do lado da GUI pra esconder as duplicatas da lista.

**Fix:** `tab_events.cpp` (`RenderEventTable`): novo checkbox "Ignorar Duplicados" na
barra de ferramentas da tabela de eventos. Quando ligado, cada linha é comparada contra
TODAS as já renderizadas nesta mesma passada (não só a anterior) por uma assinatura
(hash de Tipo+Value/RIP+ReturnAddr+Aux+CR3+LinearAddr — propositalmente SEM SeqNum/
Timestamp/tickMs, que sempre diferem mesmo entre retries da mesma leitura real); a segunda
ocorrência da mesma assinatura é pulada. Usa `std::unordered_set<uint64_t>` (não
comparação O(n²) linha-a-linha) pra não travar com histórico grande (`kEventHistoryMax`
= 20000).

GUI (`usermode_gui.exe`) recompilada (`MSBuild.exe usermode_gui.slnx
/p:Configuration=Debug /p:Platform=x64`), sem erros.

---

## 2026-11-12 — nt/hpv_pattern.c: utilitário de pattern/signature scan

**Pedido:** adicionar um `find_pattern` genérico (baseado num snippet clássico de
`data_compare`/`find_pattern` usado em RE) como utilitário no projeto, pra permitir achar
funções do `ntoskrnl.exe` que NÃO são exportadas (`MmGetSystemRoutineAddress` só resolve
exports) — motivação: planejar hookar `PspExitProcess` (não exportada) futuramente, pra
desfazer automaticamente MDLs/EPT hooks de um processo quando ele termina, sem usar
`PsSetCreateProcessNotifyRoutineEx`.

**Implementação:** novo arquivo `nt/hpv_pattern.c` (adicionado em `shv.vcxproj`, mesma
condição `Configuration=='NT'` dos outros arquivos de `nt/`), com:
- `HpvPatternCompareAt` (static): compara um offset contra `Pattern`/`Mask`, onde `Mask[i]
  == 'x'` significa "compara este byte" e qualquer outro caractere é wildcard — mesma
  convenção clássica do snippet original (`bmask`/`szmask`), adaptada pra C puro (sem
  `bool`/`uintptr_t`, usa `BOOLEAN`/`UINT64`/`UINT8`).
- `HpvMaskLength` (static): tamanho da máscara sem depender de `strlen` do CRT (pode não
  linkar em driver de kernel).
- `HpvFindPattern(Base, Size, Pattern, Mask)` (pública, declarada em `shvos_internal.h`):
  varre `[Base, Base+Size)` e retorna o endereço do primeiro offset que bate com a
  assinatura inteira, ou 0 se não achar.

**Nota importante (ainda NÃO implementada):** ainda falta a parte de localizar a *base* e
o *tamanho da seção `.text`* do `ntoskrnl.exe` carregado pra passar como `Base`/`Size` —
isso normalmente vem de `PsLoadedModuleList`/`MmGetSystemRoutineAddress` (pra achar a base
pelo nome do módulo) + parsing do PE (`IMAGE_NT_HEADERS`/seção `.text`) pra achar o
tamanho. `HpvFindPattern` em si só faz a busca linear — quem chama ainda precisa fornecer
`Base`/`Size` corretos.

Driver recompilado (`MSBuild.exe shv.sln /p:Configuration="Windows NT" /p:Platform=x64`),
sem erros, `shv.sys` assinado com sucesso.

---

## 2026-11-12 — Hook em PspExitProcess: limpa MDL/EPT hook automaticamente no exit do processo

**Pedido:** em vez de `PsSetCreateProcessNotifyRoutineEx`, usar o mesmo mecanismo de shadow
hook (split-page EPT) já usado em `NtOpenProcess`/`MmCopyVirtualMemory`, mas em
`PspExitProcess` (não exportada), pra resolver o BSOD `PROCESS_HAS_LOCKED_PAGES` (0xCB)
quando um processo com EPT Hook de usermode ativo é fechado sem desinstalar o hook
primeiro (ver fix anterior "BSOD ao fechar processo com hook EPT").

**Implementação (4 peças novas):**
1. `nt/hpv_pattern.c`: `HpvFindNtoskrnlTextSection(Base, Size)` — acha a base do
   `ntoskrnl.exe` via `RtlPcToFileHeader` (ancorado num export estável, `NtOpenProcess`,
   resolvido via `MmGetSystemRoutineAddress`) e faz parsing manual do PE
   (`IMAGE_DOS_HEADER`/`IMAGE_NT_HEADERS`/`IMAGE_SECTION_HEADER` via `<ntimage.h>`) pra
   achar a seção `.text` — é o range que `HpvFindPattern` varre.
2. `shvvmxhv.c`: `ShvHookRemoveByPid(Pid, OutPhysAddrs, MaxOut)` — nova função que remove
   da `ShvHookTable[]` global todo hook normal (não-shadow) de um PID, devolvendo os
   `PhysAddr` removidos (pra quem chama achar o MDL correspondente). Declarada em
   `shv.h`/`shvos_internal.h`; `SHV_HOOK_MAX_ENTRIES` (antes só local em `shvvmxhv.c`)
   também foi publicado em `shv.h`/`shvos_internal.h` (guardado com `#ifndef`) pra
   dimensionar o buffer de saída sem duplicar o número mágico.
3. `nt/shvos.c`: `ShvCleanupExitedProcess(Pid)` — chama `ShvHookRemoveByPid`, e pra cada
   `PhysAddr` devolvido usa `ShvHookTakeMdl`/`MmUnlockPages`/`IoFreeMdl` (a mesma tabela de
   MDLs já usada pelo `SHV_CMD_UNHOOK_EPT` manual) + `ShvOsForceAllCpuVmExit()`.
4. `nt/hpv_policy_hooks.c`: hook de `HpvExitProcessHook(LastThread, Process)` em
   `PspExitProcess` — quando `LastThread==TRUE`, chama `ShvCleanupExitedProcess(pid)` ANTES
   de repassar pro original. Resolvido em `ShvPolicyHooksInit` via
   `HpvFindNtoskrnlTextSection` + `HpvFindPattern` com a assinatura
   `\x48\x89\x5C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x00\x48\x8B\xDA\x40\x8A\xF1`
   (`xxxx?xxxx?xxxx?xxxxxx`) fornecida pelo usuário, depois `HpvHookFuncByVa` (mesmo
   split-page EPT de `NtOpenProcess`). **Não-fatal** se a seção `.text` ou a assinatura não
   for encontrada (builds diferentes do Windows podem ter bytes diferentes) — só perde a
   limpeza automática, resto do driver segue normal. VA encontrado é cacheado
   (`g_PspExitProcessVa`) porque, sendo não-exportada, não dá pra re-resolver no
   `ShvPolicyHooksUninit` via `MmGetSystemRoutineAddress` como os outros dois hooks.

**Limitação conhecida (avisada ao usuário antes de implementar):** assinatura de bytes é
frágil entre builds do Windows — pode parar de bater numa atualização futura. Se isso
acontecer, o hook simplesmente não instala (log não-fatal), sem quebrar o resto do driver.

Driver recompilado (`MSBuild.exe shv.sln /p:Configuration="Windows NT" /p:Platform=x64`),
sem erros, `shv.sys` assinado com sucesso.

---

## 2026-11-12 — HpvFindNtoskrnlTextSection: RtlPcToFileHeader nao achava a base corretamente

**Symptom:** a assinatura de PspExitProcess estava correta (confirmada pelo usuario), mas
HpvFindPattern nao achava nada -- suspeita apontada: problema em HpvFindNtoskrnlTextSection
(a busca nao estava rodando no range certo).

**Fix (sugestao do usuario):** troquei a forma de achar a base do ntoskrnl.exe. Antes usava
RtlPcToFileHeader(anyExport, &base) ancorado num export generico (NtOpenProcess) -- trocado
por um walk direto em PsLoadedModuleList (dado exportado, lista duplamente encadeada dos
modulos carregados), comparando BaseDllName com "ntoskrnl.exe" via RtlEqualUnicodeString,
usando DllBase/SizeOfImage da entrada encontrada. Nova struct local
HPV_LDR_DATA_TABLE_ENTRY (layout estavel desde Vista/7, so os campos iniciais usados:
InLoadOrderLinks/DllBase/SizeOfImage/BaseDllName). Mantido o parsing de PE pra achar a
secao .text especifica, com fallback pra varrer o modulo inteiro (DllBase..DllBase+SizeOfImage)
se a secao .text nao for encontrada no cabecalho, em vez de simplesmente falhar.

Driver recompilado (MSBuild.exe shv.sln /p:Configuration="Windows NT" /p:Platform=x64),
sem erros, shv.sys assinado com sucesso. Ainda nao confirmado pelo usuario se agora acha
a assinatura.

# Fixes aplicados no SimpleVisor

Histórico de bugs resolvidos: o que quebrava, a causa raiz e a correção aplicada.

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

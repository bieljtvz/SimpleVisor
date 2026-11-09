# Fixes aplicados no SimpleVisor

Histórico de bugs resolvidos: o que quebrava, a causa raiz e a correção aplicada.

---

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

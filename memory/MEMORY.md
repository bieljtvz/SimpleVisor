# SimpleVisor Project Memory

## Regras fixas (ler antes de qualquer tarefa)
- [ia_prompt.md](ia_prompt.md) — em qual arquivo documentar cada tipo de mudança (fix, arquitetura, build/deploy, problema em aberto, feedback) ao fim de cada prompt

## Arquitetura e estado atual
- [Arquitetura completa do projeto](project_architecture.md) — arquivos, globals, fluxo EPT, ring buffer, hook types, MDL locking, protocolo CPUID, restrições
- [Build e deploy](project_build_deploy.md) — compilar shv.sys/GUI, deploy para VM 192.168.0.102, serviço `hpv`, reboot quando stop falhar

## Problemas em aberto
- [READ hook só dispara via ReadProcessMemory](project_ept_read_hook_issue.md) — acesso direto usermode não gera eventos; hipótese: execute-only EPT não suportado (fix: usar x=0 para READ hooks); verificar ShvEptExecuteOnlySupported via WinDbg
- [EFER SCE mode desativado, EPT hook é o caminho](project_ept_hook_over_efer_sce.md) — monitoramento de syscall via EFER.SCE=0+#UD foi desativado; caminho atual é EPT execute hook em KiSystemCall64

## Fixes detalhados
- [fixes.md](fixes.md) — histórico de bugs resolvidos (o que quebrou, causa raiz, correção). Atualizar sempre que resolver algo.
- [feedback_fixes_log.md](feedback_fixes_log.md) — regra: sempre atualizar fixes.md ao resolver um bug (pedido do usuário)

## Bugs corrigidos / regras
- [Filtro CR3 quebra acessos usermode](feedback_cr3_filter_broke_usermode.md) — NUNCA filtrar por GUEST_CR3 no EPT handler: com KPTI, user CR3 ≠ kernel CR3; acessos ring-3 são filtrados

- [Direct map single-offset bugcheck fix](feedback_direct_map_single_offset_bugcheck.md) — D1 DISABLED_INTERRUPT_FAULT em ShvTranslateVaWithCr3: PA_TO_VA precisa de uma tabela multi-range (ShvPaRanges)

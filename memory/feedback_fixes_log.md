---
name: feedback-fixes-log
description: "Usuario quer um log cumulativo de bugs resolvidos em fixes.md, atualizado sempre"
metadata:
  node_type: memory
  type: feedback
---

Sempre que um bug/problema do SimpleVisor for resolvido (confirmado pelo usuário, ex.: "resolvido"), atualizar `C:\Users\admin\Documents\Github\SimpleVisor\memory\fixes.md` com uma nova seção descrevendo: o sintoma, a causa raiz (incluindo becos sem saída investigados, se houve) e a correção aplicada (arquivos/funções tocados).

**Why:** pedido explícito do usuário em 2026-11-09, depois de uma sessão de debug longa (BSOD 0x139 no unload do driver) com várias hipóteses erradas antes da causa real. Ele quer esse histórico para não perder o raciocínio/solução entre sessões.

**How to apply:** não esperar o usuário pedir de novo — ao fechar qualquer investigação de bug com confirmação de que funcionou, criar/atualizar `fixes.md` automaticamente, no mesmo estilo (seção por bug, com data). Ver [[project-architecture]] para onde esse arquivo se encaixa no índice ([MEMORY.md](MEMORY.md)).

---
name: feedback-cr3-filter-broke-usermode
description: Filtro por GUEST_CR3 no EPT violation handler quebra acessos ring-3 — nunca fazer isso
metadata:
  node_type: memory
  type: feedback
  originSessionId: 9e1e8b0f-464b-44e8-95dc-e10a4dc509ea
  modified: 2026-11-05T19:40:29.950Z
---

Nunca adicionar filtro por `GUEST_CR3` no `ShvVmxHandleEptViolation` para discriminar por processo.

**Why:** Com KPTI (KVA Shadow), código ring-3 roda com `UserDirectoryTableBase` (user CR3), mas `KeStackAttachProcess` / `__readcr3()` retorna `DirectoryTableBase` (kernel CR3). Os dois valores são DIFERENTES. Resultado: acessos diretos usermode são filtrados (CR3 mismatch), enquanto acessos via ReadProcessMemory (kernel mode, kernel CR3) passam. O usuário vê apenas eventos de ReadProcessMemory.

**How to apply:** Se quiser filtrar por processo no futuro, seria necessário capturar AMBOS os CR3 (kernel e user) do processo alvo e comparar contra os dois. Mas o usuário explicitamente não quer esse filtro — a proteção de PA via MDL é suficiente.

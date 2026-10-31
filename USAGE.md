# SimpleVisor — Guia de Uso

Hypervisor VT-x minimalista com monitoramento EPT em tempo real via console usermode.

---

## Visão geral

```
[Máquina de teste]
  shv.sys (hypervisor)          ← driver de kernel, roda em VMX root
      |
      | IOCTL (\\.\SimpleVisor)
      |
  shv_monitor.exe               ← janela de comandos  (sem argumentos)
      |
      | CreateProcess
      |
  shv_monitor.exe --events      ← janela de eventos   (abre automaticamente)
```

O monitor abre **duas janelas**:
- **Janela de eventos** — exibe o ring buffer do hypervisor em tempo real (polling 100 ms)
- **Janela de comandos** — interface interativa para instalar hooks, traduzir endereços, etc.

---

## Iniciar

### 1. Carregar o driver

```cmd
sc start hpv
```

O hypervisor está ativo quando `sc query hpv` mostrar `RUNNING`.

### 2. Abrir o monitor

```cmd
C:\shv_monitor\usermode.exe
```

A janela de eventos abre automaticamente em uma nova janela.

---

## Janela de eventos

Exibe os últimos 20 eventos capturados pelo hypervisor, atualizados a cada 100 ms.

```
  #Seq  CPU  Tipo        RIP              Ret              Aux
----------------------------------------------------------------
  [00003] C2  EPT Write   FFFFF807F5971093  FFFFF807F5971AAC  000000040C0E1004
  [00002] C1  EPT Write   FFFFF807F5971093  FFFFF807F5971AAC  000000040C0E1003
```

| Campo | Significado |
|---|---|
| `#Seq` | Número sequencial do evento (monotônico) |
| `CPU` | Núcleo lógico que interceptou |
| `Tipo` | Tipo de evento (ver tabela abaixo) |
| `RIP` | Endereço da instrução que causou a interceptação |
| `Ret` | `[RSP]` — return address do caller (0 se RSP for usermode) |
| `Aux` | GPA (endereço físico do guest) para eventos EPT |

### Tipos de evento

| Tipo | Cor | Quando dispara |
|---|---|---|
| `EPT Execute` | Ciano | Instrução executada na página hookada |
| `EPT Write` | Amarelo | Escrita na página hookada |
| `EPT Read` | Verde | Leitura da página hookada |
| `RDMSR LSTAR` | Verde | `RDMSR` no MSR LSTAR (ex: PatchGuard) |
| `WRMSR LSTAR` | Amarelo | `WRMSR` no MSR LSTAR (ex: boot do Windows) |

---

## Janela de comandos

### status

Exibe o estado atual do hypervisor: presença, contadores de VM-exit, LSTAR, eventos no ring buffer.

```
status
```

---

### hook exec / hook write / hook read

Instala um hook EPT no endereço especificado. O driver **sempre traduz VA→PA automaticamente** — nunca é necessário passar PA diretamente.

#### Sintaxe 1 — VA de kernel

```
hook exec  <VA_kernel_hex> [tamanho]
hook write <VA_kernel_hex> [tamanho]
hook read  <VA_kernel_hex> [tamanho]
```

- `VA_kernel_hex` — endereço virtual de kernel (ex: endereço de função ou variável global).
- `tamanho` — opcional. Número de bytes a monitorar a partir do VA. Sem tamanho = página inteira (4 KB).

Exemplos:
```
hook write FFFFF807F5A00120          # página inteira que contém 0x...120
hook write FFFFF807F5A00120 8        # somente os 8 bytes a partir de 0x...120
hook exec  FFFFF807F5971093          # página inteira que contém essa função
hook exec  FFFFF807F5971093 1        # somente o byte exato (prologue da função)
```

#### Sintaxe 2 — VA de processo usermode

```
hook exec  <PID> <VA_proc_hex> [tamanho]
hook write <PID> <VA_proc_hex> [tamanho]
hook read  <PID> <VA_proc_hex> [tamanho]
```

- `PID` — ID numérico decimal do processo (< 100000). Use `procs` para listá-los.
- `VA_proc_hex` — endereço virtual no espaço do processo.
- `tamanho` — opcional. Filtro de sub-página em bytes.

Exemplos:
```
hook write 1587 040000000            # página inteira do VA 0x40000000 do PID 1587
hook write 1587 040000000 8          # somente os 8 bytes naquele endereço
hook exec  4512 00007FF6ABCD1000     # hook de execução em função usermode
```

> **Detecção automática de sintaxe:** se o primeiro argumento for inteiro decimal puro (sem letras) e < 100000, é interpretado como PID + VA de processo; caso contrário é VA de kernel.

#### Tipos de hook

| Comando | Evento gerado | Uso típico |
|---|---|---|
| `hook exec` | `EPT Execute` | Contar execuções, detectar ROP |
| `hook write` | `EPT Write` | Monitorar quem escreve em uma variável |
| `hook read` | `EPT Read` | Monitorar quem lê dados sensíveis |

> **Limitação — Copy-on-Write:** páginas de DLLs/executáveis são compartilhadas. Na primeira escrita o Windows aloca um novo PA privado (CoW). O hook no PA original não dispara. Use write hooks em **dados privados** (heap, pool, variáveis globais de drivers, memória VirtualAlloc).

> **`hook read` e execute-only:** quando o hardware suporta execute-only EPT (IA32_VMX_EPT_VPID_CAP bit 0), `R=0` não bloqueia execute — a página continua executável. Nesse caso é seguro usar `hook read` em páginas de código. Quando execute-only não é suportado, `R=0` implica `X=0` também; o monitor avisa na instalação.

> **Sub-página:** o hardware dispara a violação EPT na granularidade de 4 KB. O filtro de tamanho é implementado em software: o handler verifica se o GPA exato (campo VMCS) está dentro do range `[PA, PA+tamanho)`. Acessos fora do range são ignorados silenciosamente e a execução do guest continua normal.

---

### unhook

Remove qualquer hook (exec/write/read). Passe o mesmo VA usado no `hook`.

```
unhook <VA_kernel_hex>
```

### unhook all

Remove **todos** os hooks de uma vez e restaura permissões EPT completas.

```
unhook all
```

---

### translate — VA de kernel

Converte um endereço virtual de kernel em endereço físico (PA).

```
translate <VA_hex>
```

Exemplo:
```
translate FFFFF807F5971093
```

### translate — VA de processo

Converte um endereço virtual de um processo usermode em PA.

```
translate <PID> <VA_hex>
```

Exemplo:
```
translate 1234 00007FF6ABCD1000
```

---

### read

Lê bytes diretamente da memória física (até 3072 bytes).

```
read <PA_hex> <tamanho_decimal>
```

Exemplo:
```
read FFFFF807F5971000 64
```

---

### procs

Lista todos os processos em execução com PID e CR3.

```
procs
```

### modules

Lista os módulos do kernel carregados (base, tamanho, nome).

```
modules
```

### help / exit

```
help    # exibe menu de comandos
exit    # encerra o monitor (não descarrega o hypervisor)
```

---

## Fluxo típico: monitorar uma função de driver

1. **Descubra o VA da função** via WinDbg (`x nt!NtCreateFile`) ou `modules` + offset
2. **Instale o hook diretamente pelo VA:**
   ```
   hook exec FFFFF807F5971093
   ```
3. **Observe na janela de eventos** — cada execução aparece com RIP e Ret

---

## Fluxo típico: monitorar escrita em variável de processo usermode

1. **Liste os processos:**
   ```
   procs
   ```
2. **Instale o hook com PID + VA:**
   ```
   hook write 1587 040000000 8
   ```
3. **Qualquer instrução que escreva naquele endereço** aparece em `EPT Write`

---

## Fluxo típico: monitorar escrita em variável de kernel

1. **Descubra o VA da variável** (ex: `dq nt!PsInitialSystemProcess`)
2. **Instale o hook com filtro de tamanho:**
   ```
   hook write FFFFF807F5A00120 8
   ```
3. **Qualquer escrita nos 8 bytes** aparece em `EPT Write` com o RIP de quem escreveu

---

## Limitações atuais

| Limitação | Detalhe |
|---|---|
| Máx. 16 hooks simultâneos | `SHV_HOOK_MAX_ENTRIES` em shvvmxhv.c |
| Granularidade de hardware: 4 KB | EPT opera por página; filtro de sub-página é em software |
| Write hook + CoW | Não funciona em páginas compartilhadas (DLLs) |
| Read hook bloqueia execute | Apenas em CPUs sem execute-only EPT; o monitor avisa |
| `Ret` = 0 para callers usermode | RSP de usermode não é lido em VMX root |
| Ring buffer de 16 eventos | Eventos mais antigos são sobrescritos quando cheio |
| PID+VA: página deve estar mapeada | `MmGetPhysicalAddress` retorna 0 para páginas não presentes (demand-paged) |

---

## Parar o hypervisor

```cmd
sc stop hpv
```

Os hooks são desinstalados automaticamente ao descarregar o driver.

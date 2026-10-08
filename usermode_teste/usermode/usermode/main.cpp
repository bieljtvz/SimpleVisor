/*++

Module Name:

    main.cpp

Abstract:

    SimpleVisor Monitor -- programa usermode de debugging.

    Modos de execucao:
      shv_monitor.exe            -> janela de comandos (abre janela de eventos)
      shv_monitor.exe --events   -> janela de eventos (so exibe ring buffer)

    Comunicacao com o hypervisor:
      - Eventos   : CPUID leaf 0x80000042 (ring buffer, sempre disponivel)
      - Comandos  : DeviceIoControl em \\.\SimpleVisor (IOCTL)

    Flexivel para futuro ImGui: a camada de UI e isolada da logica.

--*/

#include <windows.h>
#include <stdio.h>
#include <intrin.h>
#include <stdint.h>
#include <string.h>

// ============================================================
// Protocolo CPUID -- deve ser identico a shv_comm.h
// ============================================================
#define SHV_CPUID_LEAF          0x80000042u
#define SHV_EVENT_RING_SIZE     16
#define SHV_QUERY_PRESENCE      0
#define SHV_QUERY_LSTAR_READS   1
#define SHV_QUERY_LSTAR_WRITES  2
#define SHV_QUERY_EXIT_COUNT    3
#define SHV_QUERY_LAST_LSTAR    4
#define SHV_QUERY_HOOK_HITS     5
#define SHV_QUERY_EVENT_INFO    10
#define SHV_QUERY_EVENT_BASE    11
#define SHV_QUERY_EVENT_EXT_BASE 27
#define SHV_EVENT_LSTAR_READ    1
#define SHV_EVENT_LSTAR_WRITE   2
#define SHV_EVENT_EPT_EXEC      3
#define SHV_EVENT_EPT_WRITE     4

// ============================================================
// IOCTL interface -- identico a shv_dbg.h
// ============================================================
#ifndef CTL_CODE
#define FILE_DEVICE_UNKNOWN 0x00000022
#define METHOD_BUFFERED     0
#define FILE_ANY_ACCESS     0
#define CTL_CODE(dev,func,meth,acc) (((dev)<<16)|((acc)<<14)|((func)<<2)|(meth))
#endif

#define SHV_DEVICE_WIN32        L"\\\\.\\SimpleVisor"
#define SHV_IOCTL_SUBMIT        CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define SHV_CMD_HOOK_EPT        1
#define SHV_CMD_UNHOOK_EPT      2
#define SHV_CMD_TRANSLATE_VA    3
#define SHV_CMD_READ_PHYS       4
#define SHV_CMD_LIST_PROCS      5
#define SHV_CMD_LIST_MODULES    6
#define SHV_HOOK_EXEC           0x01
#define SHV_HOOK_WRITE          0x02
#define SHVD_STATUS_OK          0
#define SHVD_STATUS_ERR_FULL    1
#define SHVD_STATUS_ERR_NOTFOUND 2
#define SHVD_STATUS_ERR_NOMEM   3
#define SHVD_STATUS_ERR_INVALID 4
#define SHVD_STATUS_ERR_ACCESS  5
#define SHV_MAX_READ_SIZE       3072
#define SHV_PROC_NAME_LEN       64
#define SHV_MOD_NAME_LEN        128

#pragma pack(push, 1)
typedef struct { unsigned long long PhysAddr; unsigned char HookType; } SHV_HOOK_ARGS;
typedef struct { unsigned long long PhysAddr; } SHV_UNHOOK_ARGS;
typedef struct { unsigned long long VirtAddr; unsigned long long Pid; } SHV_TRANSLATE_ARGS;
typedef struct { unsigned long long PhysAddr; unsigned int Size; } SHV_READPHYS_ARGS;

typedef struct _SHV_REQUEST {
    unsigned int Command;
    union {
        SHV_HOOK_ARGS      Hook;
        SHV_UNHOOK_ARGS    Unhook;
        SHV_TRANSLATE_ARGS Translate;
        SHV_READPHYS_ARGS  ReadPhys;
    };
} SHV_REQUEST;

typedef struct _SHV_PROC_ENTRY {
    unsigned long long Pid;
    unsigned long long DirBase;
    char               Name[SHV_PROC_NAME_LEN];
} SHV_PROC_ENTRY;

typedef struct _SHV_MODULE_ENTRY {
    unsigned long long Base;
    unsigned long long Size;
    char               Name[SHV_MOD_NAME_LEN];
} SHV_MODULE_ENTRY;

typedef struct _SHV_RESPONSE {
    unsigned int Status;
    unsigned int Count;
    union {
        unsigned long long PhysAddr;
        unsigned char      Data[SHV_MAX_READ_SIZE];
        SHV_PROC_ENTRY     Procs[SHV_MAX_READ_SIZE / sizeof(SHV_PROC_ENTRY)];
        SHV_MODULE_ENTRY   Modules[SHV_MAX_READ_SIZE / sizeof(SHV_MODULE_ENTRY)];
    };
} SHV_RESPONSE;
#pragma pack(pop)

// ============================================================
// Helpers CPUID
// ============================================================

static bool IsPresent(int* outCpu = nullptr, int* outVer = nullptr)
{
    int r[4];
    __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_PRESENCE);
    if (r[0] != (int)SHV_CPUID_LEAF) return false;
    if (outCpu) *outCpu = r[1];
    if (outVer) *outVer = r[2];
    return true;
}

static uint64_t ReadCounter(int sub)
{
    int r[4];
    __cpuidex(r, SHV_CPUID_LEAF, sub);
    return ((uint64_t)(uint32_t)r[1] << 32) | (uint32_t)r[0];
}

struct EventEntry {
    uint32_t seqNum;
    uint8_t  type;
    uint8_t  cpu;
    uint64_t value;       // GuestRIP para EPT; valor MSR para LSTAR
    uint64_t returnAddr;  // [RSP] no momento da violacao (caller return addr)
    uint64_t aux;         // GPA para EPT; GuestRIP para LSTAR
};

static EventEntry ReadSlot(int slot)
{
    int r[4];
    EventEntry e = {};

    // Parte base: SeqNum, Value (GuestRIP/MSR), Type, CPU
    __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_EVENT_BASE + slot);
    e.seqNum = (uint32_t)r[0];
    e.value  = ((uint64_t)(uint32_t)r[2] << 32) | (uint32_t)r[1];
    e.type   = (uint8_t)((r[3] >> 8) & 0xFF);
    e.cpu    = (uint8_t)(r[3] & 0xFF);

    // Parte extendida: ReturnAddr, Aux
    __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_EVENT_EXT_BASE + slot);
    e.returnAddr = ((uint64_t)(uint32_t)r[1] << 32) | (uint32_t)r[0];
    e.aux        = ((uint64_t)(uint32_t)r[3] << 32) | (uint32_t)r[2];

    return e;
}

// ============================================================
// IOCTL client
// ============================================================

static HANDLE g_Device = INVALID_HANDLE_VALUE;

static bool DevOpen()
{
    g_Device = CreateFileW(SHV_DEVICE_WIN32,
                           GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    return g_Device != INVALID_HANDLE_VALUE;
}

static bool DevSubmit(const SHV_REQUEST& req, SHV_RESPONSE& resp)
{
    if (g_Device == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    DWORD returned = 0;
    return DeviceIoControl(g_Device,
                           SHV_IOCTL_SUBMIT,
                           (LPVOID)&req, sizeof(req),
                           &resp, sizeof(resp),
                           &returned, NULL) != FALSE;
}

static const char* StatusStr(unsigned int s)
{
    switch (s) {
        case SHVD_STATUS_OK:           return "OK";
        case SHVD_STATUS_ERR_FULL:     return "ERR_FULL";
        case SHVD_STATUS_ERR_NOTFOUND: return "ERR_NOTFOUND";
        case SHVD_STATUS_ERR_NOMEM:    return "ERR_NOMEM";
        case SHVD_STATUS_ERR_INVALID:  return "ERR_INVALID";
        case SHVD_STATUS_ERR_ACCESS:   return "ERR_ACCESS";
        default:                       return "ERR_UNKNOWN";
    }
}

// ============================================================
// Console helpers
// ============================================================

static HANDLE hCon;

static void GotoXY(int x, int y)
{
    COORD c = { (SHORT)x, (SHORT)y };
    SetConsoleCursorPosition(hCon, c);
}

static void SetColor(WORD attr)
{
    SetConsoleTextAttribute(hCon, attr);
}

static void HideCursor()
{
    CONSOLE_CURSOR_INFO ci = { 1, FALSE };
    SetConsoleCursorInfo(hCon, &ci);
}

static void ShowCursor()
{
    CONSOLE_CURSOR_INFO ci = { 25, TRUE };
    SetConsoleCursorInfo(hCon, &ci);
}

#define C_HEADER  (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_INTENSITY)
#define C_LABEL   (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define C_VALUE   (FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define C_OK      (FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define C_WARN    (FOREGROUND_RED|FOREGROUND_INTENSITY)
#define C_READ    (FOREGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_INTENSITY)
#define C_WRITE   (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define C_EPT     (FOREGROUND_RED|FOREGROUND_INTENSITY)
#define C_NORMAL  (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE)
#define C_CMD     (FOREGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_INTENSITY)
#define C_ERR     (FOREGROUND_RED|FOREGROUND_INTENSITY)

static WORD EventColor(uint8_t type)
{
    switch (type) {
        case SHV_EVENT_LSTAR_READ:  return C_READ;
        case SHV_EVENT_LSTAR_WRITE: return C_WRITE;
        case SHV_EVENT_EPT_EXEC:    return C_EPT;
        case SHV_EVENT_EPT_WRITE:   return C_WRITE;
        default:                    return C_NORMAL;
    }
}

static const char* EventName(uint8_t type)
{
    switch (type) {
        case SHV_EVENT_LSTAR_READ:  return "RDMSR LSTAR";
        case SHV_EVENT_LSTAR_WRITE: return "WRMSR LSTAR";
        case SHV_EVENT_EPT_EXEC:    return "EPT Execute";
        case SHV_EVENT_EPT_WRITE:   return "EPT Write  ";
        default:                    return "Desconhecido";
    }
}

// ============================================================
// ======================================================
//  MODO EVENTOS  (shv_monitor.exe --events)
//  Janela separada: exibe ring buffer em tempo real.
// ======================================================
// ============================================================

#define DISPLAY_ROWS 10

struct DisplayEvent {
    uint32_t seqNum;
    uint8_t  type;
    uint8_t  cpu;
    uint64_t value;       // GuestRIP (EPT) ou valor MSR (LSTAR)
    uint64_t returnAddr;  // [RSP] = caller return address
    uint64_t aux;         // GPA (EPT) ou GuestRIP (LSTAR)
};

static DisplayEvent g_log[DISPLAY_ROWS];
static int          g_logHead  = 0;
static int          g_logCount = 0;

static void PushLog(DisplayEvent e)
{
    g_log[g_logHead] = e;
    g_logHead  = (g_logHead + 1) % DISPLAY_ROWS;
    if (g_logCount < DISPLAY_ROWS) g_logCount++;
}

static void RunEventsMode()
{
    system("cls");
    SetConsoleTitle(TEXT("SimpleVisor -- Eventos"));
    hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    HideCursor();

    uint32_t lastEventCount = 0;

    for (;;)
    {
        // Le novos eventos do ring buffer
        int r[4];
        __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_EVENT_INFO);
        uint32_t totalEvents = (uint32_t)r[0];
        uint32_t newCount = totalEvents - lastEventCount;
        if (newCount > SHV_EVENT_RING_SIZE) newCount = SHV_EVENT_RING_SIZE;

        for (uint32_t i = newCount; i > 0; i--)
        {
            uint32_t seqTarget = totalEvents - i;
            uint32_t slot      = seqTarget % SHV_EVENT_RING_SIZE;
            EventEntry e       = ReadSlot((int)slot);
            if (e.type != 0 && e.seqNum == seqTarget)
            {
                DisplayEvent de;
                de.seqNum     = e.seqNum;
                de.type       = e.type;
                de.cpu        = e.cpu;
                de.value      = e.value;
                de.returnAddr = e.returnAddr;
                de.aux        = e.aux;
                PushLog(de);
            }
        }
        lastEventCount = totalEvents;

        // Redesenha
        GotoXY(0, 0);

        SetColor(C_HEADER);
        printf("========================================================\n");
        printf("  SimpleVisor -- Eventos em Tempo Real                  \n");
        printf("========================================================\n");

        bool present = IsPresent();
        if (present) {
            SetColor(C_OK);
        } else {
            SetColor(C_WARN);
        }
        printf("  Hypervisor: %-6s  Total Eventos: %-10u         \n",
               present ? "ATIVO" : "INATIVO", totalEvents);

        SetColor(C_HEADER);
        printf("  #Seq    CPU  Tipo        RIP/Valor                   \n");
        printf("         RetAddr / Caller  Aux (GPA)                   \n");
        printf("--------------------------------------------------------\n");

        for (int i = 0; i < DISPLAY_ROWS; i++)
        {
            int idx = (g_logHead - 1 - i + DISPLAY_ROWS * 2) % DISPLAY_ROWS;
            if (i < g_logCount)
            {
                DisplayEvent& e = g_log[idx];
                SetColor(EventColor(e.type));

                // Linha 1: sequencia, CPU, tipo, RIP/Value
                printf("  [%05u]  CPU%u  %-10s  0x%016llX    \n",
                       e.seqNum, e.cpu, EventName(e.type), e.value);

                // Linha 2: returnAddr e aux (indentado para parecer hierarquico)
                SetColor(C_NORMAL);
                if (e.returnAddr != 0 || e.aux != 0)
                {
                    printf("         ret=0x%016llX  aux=0x%016llX\n",
                           e.returnAddr, e.aux);
                }
                else
                {
                    printf("%-56s\n", "");
                }
            }
            else
            {
                SetColor(C_NORMAL);
                printf("%-56s\n", "");
                printf("%-56s\n", "");
            }
        }

        SetColor(C_HEADER);
        printf("========================================================\n");
        SetColor(C_NORMAL);
        printf("  Polling 100ms  |  Feche esta janela para sair          \n");

        Sleep(100);
    }
}

// ============================================================
// ======================================================
//  MODO COMANDOS  (shv_monitor.exe, sem argumentos)
//  Janela principal: input de comandos + dashboard CPUID.
// ======================================================
// ============================================================

static void PrintHelp()
{
    SetColor(C_LABEL);
    printf("\nComandos disponiveis:\n");
    SetColor(C_NORMAL);
    printf("  status                      - status do hypervisor\n");
    printf("  hook exec <PA_hex>          - EPT execute hook em PA\n");
    printf("  hook write <PA_hex>         - EPT write hook em PA\n");
    printf("  unhook <PA_hex>             - remove hook em PA\n");
    printf("  translate <VA_hex>          - VA kernel -> PA\n");
    printf("  translate <PID> <VA_hex>    - VA de processo -> PA\n");
    printf("  read <PA_hex> <size>        - le bytes da memoria fisica\n");
    printf("  procs                       - lista processos\n");
    printf("  modules                     - lista modulos do kernel\n");
    printf("  help                        - este menu\n");
    printf("  exit                        - encerra o monitor\n\n");
}

static void PrintSeparator()
{
    SetColor(C_HEADER);
    printf("--------------------------------------------------------\n");
    SetColor(C_NORMAL);
}

static void RunCommandMode()
{
    char cmdLine[512];

    SetConsoleTitle(TEXT("SimpleVisor -- Comandos"));
    hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    ShowCursor();
    system("cls");

    // Verifica presenca do hypervisor
    SetColor(C_HEADER);
    printf("========================================================\n");
    printf("  SimpleVisor Monitor -- Interface de Comandos          \n");
    printf("========================================================\n");

    int hvCpu = 0, hvVer = 0;
    if (!IsPresent(&hvCpu, &hvVer))
    {
        SetColor(C_WARN);
        printf("\n  [!] Hypervisor NAO detectado (CPUID[%08X] sem resposta)\n", SHV_CPUID_LEAF);
        printf("      Carregue o driver: sc start hpv\n\n");
        SetColor(C_NORMAL);
    }
    else
    {
        SetColor(C_OK);
        printf("  [+] Hypervisor ATIVO (CPU %d, versao %d)\n", hvCpu, hvVer);
        SetColor(C_NORMAL);
    }

    // Abre IOCTL
    if (!DevOpen())
    {
        SetColor(C_WARN);
        printf("  [!] Device \\\\.\\SimpleVisor nao abriu (IOCTL indisponivel)\n");
        printf("      Comandos hook/unhook/translate/read/procs/modules desativados\n");
        SetColor(C_NORMAL);
    }
    else
    {
        SetColor(C_OK);
        printf("  [+] IOCTL conectado a \\\\.\\SimpleVisor\n");
        SetColor(C_NORMAL);
    }

    PrintHelp();

    for (;;)
    {
        SetColor(C_CMD);
        printf("> ");
        SetColor(C_NORMAL);

        if (!fgets(cmdLine, sizeof(cmdLine), stdin))
        {
            break;
        }

        // Remove newline
        size_t len = strlen(cmdLine);
        if (len > 0 && cmdLine[len-1] == '\n') cmdLine[--len] = 0;
        if (len > 0 && cmdLine[len-1] == '\r') cmdLine[--len] = 0;

        if (len == 0) continue;

        // ---- Parsing de comandos ----

        if (strcmp(cmdLine, "exit") == 0 || strcmp(cmdLine, "quit") == 0)
        {
            break;
        }
        else if (strcmp(cmdLine, "help") == 0)
        {
            PrintHelp();
        }
        else if (strcmp(cmdLine, "status") == 0)
        {
            IsPresent(&hvCpu, &hvVer);
            uint64_t exits    = ReadCounter(SHV_QUERY_EXIT_COUNT);
            uint64_t lstarR   = ReadCounter(SHV_QUERY_LSTAR_READS);
            uint64_t lstarW   = ReadCounter(SHV_QUERY_LSTAR_WRITES);
            uint64_t hookHits = ReadCounter(SHV_QUERY_HOOK_HITS);

            PrintSeparator();
            SetColor(C_LABEL);  printf("  VM-Exits       : "); SetColor(C_VALUE); printf("%llu\n", exits);
            SetColor(C_LABEL);  printf("  LSTAR Leituras : "); SetColor(C_READ);  printf("%llu\n", lstarR);
            SetColor(C_LABEL);  printf("  LSTAR Escritas : "); SetColor(C_WRITE); printf("%llu\n", lstarW);
            SetColor(C_LABEL);  printf("  EPT Exec Hits  : "); SetColor(C_EPT);   printf("%llu  (KiSystemCall64)\n", hookHits);
            PrintSeparator();
        }
        else if (strncmp(cmdLine, "hook exec ", 10) == 0)
        {
            unsigned long long pa = strtoull(cmdLine + 10, nullptr, 16);
            SHV_REQUEST req = {};
            SHV_RESPONSE resp = {};
            req.Command        = SHV_CMD_HOOK_EPT;
            req.Hook.PhysAddr  = pa;
            req.Hook.HookType  = SHV_HOOK_EXEC;

            if (DevSubmit(req, resp))
            {
                if (resp.Status == SHVD_STATUS_OK)
                {
                    SetColor(C_OK);
                    printf("  [+] Execute hook instalado em PA 0x%llX\n", pa);
                }
                else
                {
                    SetColor(C_ERR);
                    printf("  [!] Erro: %s\n", StatusStr(resp.Status));
                }
            }
            else
            {
                SetColor(C_ERR);
                printf("  [!] IOCTL falhou (GetLastError=%lu)\n", GetLastError());
            }
            SetColor(C_NORMAL);
        }
        else if (strncmp(cmdLine, "hook write ", 11) == 0)
        {
            unsigned long long pa = strtoull(cmdLine + 11, nullptr, 16);
            SHV_REQUEST req = {};
            SHV_RESPONSE resp = {};
            req.Command        = SHV_CMD_HOOK_EPT;
            req.Hook.PhysAddr  = pa;
            req.Hook.HookType  = SHV_HOOK_WRITE;

            if (DevSubmit(req, resp))
            {
                if (resp.Status == SHVD_STATUS_OK)
                {
                    SetColor(C_OK);
                    printf("  [+] Write hook instalado em PA 0x%llX\n", pa);
                }
                else
                {
                    SetColor(C_ERR);
                    printf("  [!] Erro: %s\n", StatusStr(resp.Status));
                }
            }
            else
            {
                SetColor(C_ERR);
                printf("  [!] IOCTL falhou (GetLastError=%lu)\n", GetLastError());
            }
            SetColor(C_NORMAL);
        }
        else if (strncmp(cmdLine, "unhook ", 7) == 0)
        {
            unsigned long long pa = strtoull(cmdLine + 7, nullptr, 16);
            SHV_REQUEST req = {};
            SHV_RESPONSE resp = {};
            req.Command         = SHV_CMD_UNHOOK_EPT;
            req.Unhook.PhysAddr = pa;

            if (DevSubmit(req, resp))
            {
                if (resp.Status == SHVD_STATUS_OK)
                {
                    SetColor(C_OK);
                    printf("  [+] Hook removido em PA 0x%llX\n", pa);
                }
                else
                {
                    SetColor(C_ERR);
                    printf("  [!] Erro: %s\n", StatusStr(resp.Status));
                }
            }
            else
            {
                SetColor(C_ERR);
                printf("  [!] IOCTL falhou\n");
            }
            SetColor(C_NORMAL);
        }
        else if (strncmp(cmdLine, "translate ", 10) == 0)
        {
            // Formatos:
            //   translate <VA_hex>           -> kernel (PID=0)
            //   translate <PID_dec> <VA_hex> -> processo
            const char* args = cmdLine + 10;
            unsigned long long pid = 0;
            unsigned long long va  = 0;

            // Detecta se ha espaco depois do primeiro token
            const char* sp = strchr(args, ' ');
            if (sp != nullptr)
            {
                pid = strtoull(args, nullptr, 10);
                va  = strtoull(sp + 1, nullptr, 16);
            }
            else
            {
                va = strtoull(args, nullptr, 16);
            }

            SHV_REQUEST req = {};
            SHV_RESPONSE resp = {};
            req.Command              = SHV_CMD_TRANSLATE_VA;
            req.Translate.VirtAddr   = va;
            req.Translate.Pid        = pid;

            if (DevSubmit(req, resp))
            {
                if (resp.Status == SHVD_STATUS_OK)
                {
                    SetColor(C_VALUE);
                    printf("  [PA] VA 0x%llX (PID %llu) -> PA 0x%llX\n",
                           va, pid, resp.PhysAddr);
                }
                else
                {
                    SetColor(C_ERR);
                    printf("  [!] Erro: %s\n", StatusStr(resp.Status));
                }
            }
            else
            {
                SetColor(C_ERR);
                printf("  [!] IOCTL falhou\n");
            }
            SetColor(C_NORMAL);
        }
        else if (strncmp(cmdLine, "read ", 5) == 0)
        {
            // read <PA_hex> <size_dec>
            const char* args = cmdLine + 5;
            char* endp = nullptr;
            unsigned long long pa   = strtoull(args, &endp, 16);
            unsigned int       size = (unsigned int)strtoul(endp, nullptr, 10);

            if (size == 0 || size > SHV_MAX_READ_SIZE)
            {
                SetColor(C_ERR);
                printf("  [!] Tamanho invalido (max %d bytes)\n", SHV_MAX_READ_SIZE);
                SetColor(C_NORMAL);
                continue;
            }

            SHV_REQUEST req = {};
            SHV_RESPONSE resp = {};
            req.Command             = SHV_CMD_READ_PHYS;
            req.ReadPhys.PhysAddr   = pa;
            req.ReadPhys.Size       = size;

            if (DevSubmit(req, resp))
            {
                if (resp.Status == SHVD_STATUS_OK)
                {
                    SetColor(C_VALUE);
                    printf("  [Mem] PA 0x%llX  %u bytes:\n", pa, resp.Count);
                    SetColor(C_NORMAL);

                    for (unsigned int i = 0; i < resp.Count; i++)
                    {
                        if (i % 16 == 0) printf("  %04X: ", i);
                        printf("%02X ", resp.Data[i]);
                        if ((i % 16) == 15) printf("\n");
                    }
                    if (resp.Count % 16 != 0) printf("\n");
                }
                else
                {
                    SetColor(C_ERR);
                    printf("  [!] Erro: %s\n", StatusStr(resp.Status));
                }
            }
            else
            {
                SetColor(C_ERR);
                printf("  [!] IOCTL falhou\n");
            }
            SetColor(C_NORMAL);
        }
        else if (strcmp(cmdLine, "procs") == 0)
        {
            SHV_REQUEST req = {};
            SHV_RESPONSE resp = {};
            req.Command = SHV_CMD_LIST_PROCS;

            if (DevSubmit(req, resp))
            {
                if (resp.Status == SHVD_STATUS_OK)
                {
                    SetColor(C_LABEL);
                    printf("  %-10s  %-18s  %s\n", "PID", "CR3 (DirBase)", "Nome");
                    PrintSeparator();
                    SetColor(C_NORMAL);
                    for (unsigned int i = 0; i < resp.Count; i++)
                    {
                        SHV_PROC_ENTRY& p = resp.Procs[i];
                        printf("  %-10llu  0x%016llX  %s\n",
                               p.Pid, p.DirBase, p.Name[0] ? p.Name : "(System)");
                    }
                    PrintSeparator();
                    printf("  Total: %u processos\n", resp.Count);
                }
                else
                {
                    SetColor(C_ERR);
                    printf("  [!] Erro: %s\n", StatusStr(resp.Status));
                }
            }
            else
            {
                SetColor(C_ERR);
                printf("  [!] IOCTL falhou\n");
            }
            SetColor(C_NORMAL);
        }
        else if (strcmp(cmdLine, "modules") == 0)
        {
            SHV_REQUEST req = {};
            SHV_RESPONSE resp = {};
            req.Command = SHV_CMD_LIST_MODULES;

            if (DevSubmit(req, resp))
            {
                if (resp.Status == SHVD_STATUS_OK)
                {
                    SetColor(C_LABEL);
                    printf("  %-18s  %-12s  %s\n", "Base", "Tamanho", "Nome");
                    PrintSeparator();
                    SetColor(C_NORMAL);
                    for (unsigned int i = 0; i < resp.Count; i++)
                    {
                        SHV_MODULE_ENTRY& m = resp.Modules[i];
                        printf("  0x%016llX  0x%-10llX  %s\n",
                               m.Base, m.Size, m.Name);
                    }
                    PrintSeparator();
                    printf("  Total: %u modulos\n", resp.Count);
                }
                else
                {
                    SetColor(C_ERR);
                    printf("  [!] Erro: %s\n", StatusStr(resp.Status));
                }
            }
            else
            {
                SetColor(C_ERR);
                printf("  [!] IOCTL falhou\n");
            }
            SetColor(C_NORMAL);
        }
        else
        {
            SetColor(C_WARN);
            printf("  [?] Comando desconhecido. Digite 'help' para ajuda.\n");
            SetColor(C_NORMAL);
        }
    }

    if (g_Device != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_Device);
    }
}

// ============================================================
// main
// ============================================================

int main(int argc, char* argv[])
{
    // Modo --events: janela de eventos (aberta pela janela de comandos)
    if (argc >= 2 && strcmp(argv[1], "--events") == 0)
    {
        if (!IsPresent())
        {
            printf("Hypervisor nao detectado. Pressione Enter para sair.\n");
            getchar();
            return 1;
        }
        RunEventsMode();
        return 0;
    }

    // Modo padrao: janela de comandos
    // Abre a janela de eventos como processo filho
    {
        char selfPath[MAX_PATH];
        GetModuleFileNameA(NULL, selfPath, MAX_PATH);

        char cmdLine2[MAX_PATH + 20];
        sprintf_s(cmdLine2, "\"%s\" --events", selfPath);

        STARTUPINFOA        si = {};
        PROCESS_INFORMATION pi = {};
        si.cb = sizeof(si);
        CreateProcessA(NULL, cmdLine2, NULL, NULL, FALSE,
                       CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
        // Nao esperamos o processo filho -- ele roda independentemente
        if (pi.hProcess) CloseHandle(pi.hProcess);
        if (pi.hThread)  CloseHandle(pi.hThread);
    }

    RunCommandMode();
    return 0;
}

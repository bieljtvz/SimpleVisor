#include <windows.h>
#include <stdio.h>
#include <intrin.h>
#include <stdint.h>

//
// Constantes de comunicacao -- devem ser identicas a shv_comm.h no driver.
// (Copie shv_comm.h para o projeto usermode ou adicione o caminho raiz
//  do SimpleVisor ao include path para usar #include diretamente.)
//
#define SHV_CPUID_LEAF          0x80000042u
#define SHV_EVENT_RING_SIZE     16
#define SHV_QUERY_PRESENCE      0
#define SHV_QUERY_LSTAR_READS   1
#define SHV_QUERY_LSTAR_WRITES  2
#define SHV_QUERY_EXIT_COUNT    3
#define SHV_QUERY_LAST_LSTAR    4
#define SHV_QUERY_HOOK_HITS     5   // contagem de EPT execute hook (KiSystemCall64)
#define SHV_QUERY_EVENT_INFO    10
#define SHV_QUERY_EVENT_BASE    11
#define SHV_EVENT_LSTAR_READ    1
#define SHV_EVENT_LSTAR_WRITE   2
#define SHV_EVENT_EPT_EXEC      3

// ============================================================
// Helpers CPUID
// ============================================================

static bool IsPresent(int* outCpu, int* outVer)
{
    int r[4];
    __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_PRESENCE);
    if (r[0] != (int)SHV_CPUID_LEAF) return false;
    if (outCpu) *outCpu = r[1];
    if (outVer) *outVer = r[2];
    return true;
}

// Le um contador de 64 bits via CPUID (EAX=low, EBX=high)
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
    uint64_t value;
};

// Le uma entrada do ring buffer pelo indice do slot (0..SHV_EVENT_RING_SIZE-1)
static EventEntry ReadSlot(int slot)
{
    int r[4];
    __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_EVENT_BASE + slot);
    EventEntry e = {};
    e.seqNum = (uint32_t)r[0];
    e.value  = ((uint64_t)(uint32_t)r[2] << 32) | (uint32_t)r[1];
    e.type   = (uint8_t)((r[3] >> 8) & 0xFF);
    e.cpu    = (uint8_t)(r[3] & 0xFF);
    return e;
}

// ============================================================
// Console
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

// Paleta de cores
#define C_HEADER  (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_INTENSITY)
#define C_LABEL   (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define C_VALUE   (FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define C_OK      (FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define C_WARN    (FOREGROUND_RED|FOREGROUND_INTENSITY)
#define C_READ    (FOREGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_INTENSITY)  // ciano
#define C_WRITE   (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_INTENSITY)   // amarelo
#define C_EPT     (FOREGROUND_RED|FOREGROUND_INTENSITY)                    // vermelho
#define C_NORMAL  (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE)

static WORD EventColor(uint8_t type)
{
    switch (type) {
        case SHV_EVENT_LSTAR_READ:  return C_READ;
        case SHV_EVENT_LSTAR_WRITE: return C_WRITE;
        case SHV_EVENT_EPT_EXEC:    return C_EPT;
        default:                    return C_NORMAL;
    }
}

static const char* EventName(uint8_t type)
{
    switch (type) {
        case SHV_EVENT_LSTAR_READ:  return "RDMSR LSTAR ";
        case SHV_EVENT_LSTAR_WRITE: return "WRMSR LSTAR ";
        case SHV_EVENT_EPT_EXEC:    return "EPT Execute ";
        default:                    return "Desconhecido";
    }
}

// ============================================================
// Log circular de eventos para exibicao (mais recente no topo)
// ============================================================

#define DISPLAY_ROWS 14

struct DisplayEvent {
    uint32_t seqNum;
    uint8_t  type;
    uint8_t  cpu;
    uint64_t value;
};

static DisplayEvent g_log[DISPLAY_ROWS];
static int          g_logHead  = 0;   // proximo slot de escrita
static int          g_logCount = 0;   // quantos slots validos

static void PushLog(DisplayEvent e)
{
    g_log[g_logHead] = e;
    g_logHead  = (g_logHead + 1) % DISPLAY_ROWS;
    if (g_logCount < DISPLAY_ROWS) g_logCount++;
}

// ============================================================
// Desenho do dashboard (redesenha inteiro a cada iteracao,
// partindo do canto superior esquerdo -- sem piscar)
// ============================================================

static void DrawDashboard(bool present, int hvCpu, int hvVer,
                           uint64_t exits, uint64_t lstarR,
                           uint64_t lstarW, uint64_t lastLstar,
                           uint64_t hookHits)
{
    GotoXY(0, 0);

    SetColor(C_HEADER);
    printf("========================================================\n");
    printf("  SimpleVisor Monitor                                    \n");
    printf("========================================================\n");

    // Status
    if (present) {
        SetColor(C_OK);
        printf("  Status : ATIVO   (ultima resposta: CPU %d, v%d)       \n",
               hvCpu, hvVer);
    } else {
        SetColor(C_WARN);
        printf("  Status : INATIVO -- driver nao detectado              \n");
    }

    SetColor(C_HEADER);
    printf("--------------------------------------------------------\n");

    // Contadores
    SetColor(C_LABEL);  printf("  VM-Exits       : ");
    SetColor(C_VALUE);  printf("%-20llu              \n", exits);

    SetColor(C_LABEL);  printf("  LSTAR Leituras : ");
    SetColor(C_READ);   printf("%-20llu              \n", lstarR);

    SetColor(C_LABEL);  printf("  LSTAR Escritas : ");
    SetColor(C_WRITE);  printf("%-20llu              \n", lstarW);

    SetColor(C_LABEL);  printf("  Ultimo LSTAR   : ");
    SetColor(C_VALUE);  printf("0x%016llX              \n", lastLstar);

    SetColor(C_LABEL);  printf("  EPT Exec Hook  : ");
    SetColor(C_EPT);    printf("%-20llu  (KiSystemCall64) \n", hookHits);

    SetColor(C_HEADER);
    printf("========================================================\n");
    printf("  Eventos em tempo real (mais recente no topo)           \n");
    printf("========================================================\n");

    // Linhas de eventos -- do mais recente para o mais antigo
    for (int i = 0; i < DISPLAY_ROWS; i++)
    {
        int idx = (g_logHead - 1 - i + DISPLAY_ROWS * 2) % DISPLAY_ROWS;
        if (i < g_logCount)
        {
            DisplayEvent& e = g_log[idx];
            SetColor(EventColor(e.type));
            printf("  [%05u] CPU%u  %s  0x%016llX       \n",
                   e.seqNum, e.cpu, EventName(e.type), e.value);
        }
        else
        {
            SetColor(C_NORMAL);
            printf("%-56s\n", "");
        }
    }

    SetColor(C_HEADER);
    printf("========================================================\n");
    SetColor(C_NORMAL);
    printf("  Polling: 100ms  |  Ctrl+C para sair                   \n");
}

// ============================================================
// main
// ============================================================

int main()
{
    hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    HideCursor();

    // Limpa a tela uma unica vez no inicio
    system("cls");

    // Verificacao inicial de presenca
    int hvCpu = 0, hvVer = 0;
    if (!IsPresent(&hvCpu, &hvVer))
    {
        SetColor(C_WARN);
        printf("\nSimpleVisor NAO detectado (CPUID[%08X] nao respondeu).\n",
               SHV_CPUID_LEAF);
        printf("Carregue o driver com 'sc start hpv' e execute novamente.\n\n");
        SetColor(C_NORMAL);
        printf("Pressione Enter para sair...\n");
        getchar();
        return 1;
    }

    uint32_t lastEventCount = 0;

    for (;;)
    {
        // --- Leitura de contadores via CPUID ---
        uint64_t exits     = ReadCounter(SHV_QUERY_EXIT_COUNT);
        uint64_t lstarR    = ReadCounter(SHV_QUERY_LSTAR_READS);
        uint64_t lstarW    = ReadCounter(SHV_QUERY_LSTAR_WRITES);
        uint64_t lastLstar = ReadCounter(SHV_QUERY_LAST_LSTAR);
        uint64_t hookHits  = ReadCounter(SHV_QUERY_HOOK_HITS);

        // --- Leitura de novos eventos do ring buffer ---
        int r[4];
        __cpuidex(r, SHV_CPUID_LEAF, SHV_QUERY_EVENT_INFO);
        uint32_t totalEvents = (uint32_t)r[0];  // total escrito pelo hypervisor

        uint32_t newCount = totalEvents - lastEventCount;
        if (newCount > SHV_EVENT_RING_SIZE)
        {
            // Overflow: perdemos alguns eventos. Lemos o maximo disponivel.
            newCount = SHV_EVENT_RING_SIZE;
        }

        // Processa eventos do mais antigo para o mais novo
        for (uint32_t i = newCount; i > 0; i--)
        {
            uint32_t seqTarget = totalEvents - i;
            uint32_t slot      = seqTarget % SHV_EVENT_RING_SIZE;
            EventEntry e       = ReadSlot((int)slot);

            // Confirma que o slot ainda contem o evento esperado
            // (nao foi sobrescrito enquanto liamos)
            if (e.type != 0 && e.seqNum == seqTarget)
            {
                DisplayEvent de;
                de.seqNum = e.seqNum;
                de.type   = e.type;
                de.cpu    = e.cpu;
                de.value  = e.value;
                PushLog(de);
            }
        }
        lastEventCount = totalEvents;

        // Re-detecta presenca (suporta reload do driver)
        IsPresent(&hvCpu, &hvVer);

        // --- Redesenha ---
        DrawDashboard(true, hvCpu, hvVer, exits, lstarR, lstarW, lastLstar, hookHits);

        Sleep(100);
    }
}

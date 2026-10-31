/*
    detect_shv — detector do SimpleVisor (SHV)

    Verifica:
      1. Leaf privada SHV_CPUID_LEAF/SHV_QUERY_PRESENCE  (deteccao confiavel)
      2. CPUID leaf 1 ECX[31]  "Hypervisor Present"      (deve estar OCULTO pelo SHV)
      3. CPUID leaf 0x40000000 vendor string              (deve estar ZERADO pelo SHV)
      4. CPUID timing overhead                            (VM-exits aumentam latencia)
      5. Counters e stats do SHV (se presente)
*/

#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <stdint.h>
#include <conio.h>

#include "../../../shv_comm.h"

// ============================================================
// Console colors
// ============================================================

enum Color { C_NORMAL = 7, C_OK = 10, C_WARN = 14, C_ERR = 12, C_LABEL = 11, C_DIM = 8 };

static HANDLE g_Con;
static void SetColor(Color c) { SetConsoleTextAttribute(g_Con, (WORD)c); }

static void PrintSep()
{
    SetColor(C_DIM);
    printf("  -------------------------------------------------------\n");
    SetColor(C_NORMAL);
}

// ============================================================
// CPUID helpers
// ============================================================

struct CpuidResult { uint32_t eax, ebx, ecx, edx; };

static CpuidResult Cpuid(uint32_t leaf, uint32_t subleaf = 0)
{
    int r[4];
    __cpuidex(r, (int)leaf, (int)subleaf);
    return { (uint32_t)r[0], (uint32_t)r[1], (uint32_t)r[2], (uint32_t)r[3] };
}

static uint64_t CpuidU64(int subleaf)
{
    auto r = Cpuid(SHV_CPUID_LEAF, subleaf);
    return ((uint64_t)r.ebx << 32) | r.eax;
}

// ============================================================
// Timing: mede latencia media de CPUID
// ============================================================

static uint64_t MeasureCpuidLatency(int iterations = 1000)
{
    // Aquece
    for (int i = 0; i < 100; i++) Cpuid(1);

    uint64_t total = 0;
    for (int i = 0; i < iterations; i++)
    {
        _mm_lfence();
        uint64_t t0 = __rdtsc();
        _mm_lfence();
        Cpuid(1);
        _mm_lfence();
        uint64_t t1 = __rdtsc();
        _mm_lfence();
        total += (t1 - t0);
    }
    return total / (uint64_t)iterations;
}

// ============================================================
// Checks individuais
// ============================================================

// Retorna TRUE se SHV presente (leaf privada).
static bool CheckShvPresence(int* outCpu, int* outVer)
{
    auto r = Cpuid(SHV_CPUID_LEAF, SHV_QUERY_PRESENCE);
    if (r.eax == SHV_CPUID_LEAF)
    {
        if (outCpu) *outCpu = (int)r.ebx;
        if (outVer) *outVer = (int)r.ecx;
        return true;
    }
    return false;
}

// Verifica CPUID leaf 1 ECX[31].
// Retorna TRUE se o bit esta setado (hypervisor anunciado ao SO).
static bool CheckCpuid1HvBit()
{
    auto r = Cpuid(1);
    return (r.ecx & 0x80000000u) != 0;
}

// Verifica leaf 0x40000000 (vendor string + max HV leaf).
// Retorna TRUE apenas se EAX esta na faixa de folhas de hypervisor
// [0x40000001, 0x4000ffff].  CPUs sem hypervisor retornam o valor da folha
// padrao maxima nessa posicao (ex: 0xB54, 0x16...) -- nao e um hypervisor.
static bool CheckHvVendorLeaf(char outVendor[13])
{
    auto r = Cpuid(0x40000000u);
    memcpy(outVendor + 0, &r.ebx, 4);
    memcpy(outVendor + 4, &r.ecx, 4);
    memcpy(outVendor + 8, &r.edx, 4);
    outVendor[12] = '\0';
    return (r.eax >= 0x40000001u && r.eax <= 0x4000ffffu);
}

// ============================================================
// main
// ============================================================

int main()
{
    g_Con = GetStdHandle(STD_OUTPUT_HANDLE);

    SetColor(C_LABEL);
    printf("\n  ========================================================\n");
    printf("   SimpleVisor Detector v1.0\n");
    printf("  ========================================================\n\n");

    // --------------------------------------------------------
    // 1. Leaf privada SHV_CPUID_LEAF
    // --------------------------------------------------------
    SetColor(C_LABEL);
    printf("  [1] Leaf privada SHV (0x%08X / sub=0)\n", SHV_CPUID_LEAF);
    PrintSep();

    int hvCpu = 0, hvVer = 0;
    bool shvPresent = CheckShvPresence(&hvCpu, &hvVer);

    if (shvPresent)
    {
        SetColor(C_OK);
        printf("  [+] SHV DETECTADO\n");
        SetColor(C_NORMAL);
        printf("      CPU logica : %d\n", hvCpu);
        printf("      Versao     : %d\n\n", hvVer);
    }
    else
    {
        SetColor(C_WARN);
        printf("  [-] SHV nao detectado (leaf privada nao respondeu)\n\n");
    }

    // --------------------------------------------------------
    // 2. CPUID leaf 1 ECX[31] — "Hypervisor Present Bit"
    // --------------------------------------------------------
    SetColor(C_LABEL);
    printf("  [2] CPUID leaf 1 ECX[31]  (Hypervisor Present Bit)\n");
    PrintSep();

    bool hvBit = CheckCpuid1HvBit();
    if (hvBit)
    {
        SetColor(C_ERR);
        printf("  [!] BIT SETADO — hypervisor visivel para scanners\n\n");
    }
    else
    {
        SetColor(C_OK);
        printf("  [+] Bit limpo — oculto para scanners\n\n");
    }

    // --------------------------------------------------------
    // 3. CPUID leaf 0x40000000 — vendor string / max leaf
    // --------------------------------------------------------
    SetColor(C_LABEL);
    printf("  [3] CPUID leaf 0x40000000  (HV vendor string)\n");
    PrintSep();

    char vendor[13] = {};
    bool hvVendorVisible = CheckHvVendorLeaf(vendor);

    auto r0 = Cpuid(0x40000000u);
    SetColor(C_NORMAL);
    printf("      EAX=0x%08X  EBX=0x%08X  ECX=0x%08X  EDX=0x%08X\n",
           r0.eax, r0.ebx, r0.ecx, r0.edx);

    if (hvVendorVisible)
    {
        // EAX esta na faixa de hypervisor: indica folhas HV validas
        SetColor(C_ERR);
        printf("  [!] Vendor visivel: \"%s\" (max HV leaf 0x%08X) -- detectavel\n\n",
               vendor, r0.eax);
    }
    else
    {
        SetColor(C_OK);
        // EAX fora da faixa [0x40000001, 0x4000ffff]: hardware refletindo
        // a folha padrao maxima, nao e identidade de hypervisor.
        printf("  [+] EAX=0x%08X fora da faixa HV -- nao e vendor de hypervisor\n\n",
               r0.eax);
    }

    // --------------------------------------------------------
    // 4. Timing CPUID
    // --------------------------------------------------------
    SetColor(C_LABEL);
    printf("  [4] Latencia CPUID (leaf 1, media de 1000 iteracoes)\n");
    PrintSep();

    uint64_t latency = MeasureCpuidLatency();
    SetColor(C_NORMAL);
    printf("      Media: %llu ciclos\n", (unsigned long long)latency);

    // Bare metal tipico: ~20-80 ciclos.
    // Sob VMX: todo CPUID gera VM-exit incondicional -> 500-2000+ ciclos.
    // Essa latencia NAO pode ser ocultada por software.
    if (latency > 500)
    {
        SetColor(C_WARN);
        printf("  [!] %llu ciclos -- VM-exit overhead inevitavel (VMX ativo)\n\n",
               (unsigned long long)latency);
    }
    else if (latency > 100)
    {
        SetColor(C_WARN);
        printf("  [?] %llu ciclos -- latencia moderada, possivelmente virtualizado\n\n",
               (unsigned long long)latency);
    }
    else
    {
        SetColor(C_OK);
        printf("  [+] %llu ciclos -- dentro do esperado para bare metal\n\n",
               (unsigned long long)latency);
    }

    // --------------------------------------------------------
    // 5. Stats do SHV (apenas se presente)
    // --------------------------------------------------------
    if (shvPresent)
    {
        SetColor(C_LABEL);
        printf("  [5] Counters do SHV\n");
        PrintSep();

        uint64_t exits    = CpuidU64(SHV_QUERY_EXIT_COUNT);
        uint64_t lstarR   = CpuidU64(SHV_QUERY_LSTAR_READS);
        uint64_t lstarW   = CpuidU64(SHV_QUERY_LSTAR_WRITES);
        uint64_t eptHits  = CpuidU64(SHV_QUERY_HOOK_HITS);
        auto     caps     = Cpuid(SHV_CPUID_LEAF, SHV_QUERY_EPT_CAPS);
        // SHV_QUERY_EVENT_INFO: EAX = total de eventos escritos (32 bits),
        //                        EBX = tamanho do ring buffer (nao alto-32 do count)
        auto     evInfo   = Cpuid(SHV_CPUID_LEAF, SHV_QUERY_EVENT_INFO);
        uint32_t evTotal  = evInfo.eax;
        uint32_t evRing   = evInfo.ebx;

        SetColor(C_NORMAL);
        printf("      VM-exits totais    : %llu\n",  (unsigned long long)exits);
        printf("      RDMSR LSTAR        : %llu\n",  (unsigned long long)lstarR);
        printf("      WRMSR LSTAR        : %llu\n",  (unsigned long long)lstarW);
        printf("      EPT hook hits      : %llu\n",  (unsigned long long)eptHits);
        printf("      Eventos no ring    : %u / %u\n", evTotal, evRing);
        printf("      Execute-only EPT   : %s\n\n",
               (caps.eax & 1) ? "suportado" : "nao suportado");
    }

    // --------------------------------------------------------
    // Resumo
    // --------------------------------------------------------
    PrintSep();
    SetColor(C_LABEL);
    printf("  Resumo:\n");
    SetColor(C_NORMAL);
    printf("    Leaf privada SHV       : ");
    if (shvPresent) { SetColor(C_OK);   printf("PRESENTE\n"); }
    else            { SetColor(C_WARN); printf("ausente\n"); }

    SetColor(C_NORMAL);
    printf("    CPUID ECX[31] visivel  : ");
    if (hvBit)      { SetColor(C_ERR);  printf("SIM (detectavel)\n"); }
    else            { SetColor(C_OK);   printf("nao (oculto)\n"); }

    SetColor(C_NORMAL);
    printf("    Vendor leaf visivel    : ");
    if (hvVendorVisible) { SetColor(C_ERR); printf("SIM (detectavel)\n"); }
    else                 { SetColor(C_OK);  printf("nao (oculto)\n"); }

    SetColor(C_NORMAL);
    printf("\n");

    SetColor(C_DIM);
    printf("  Nota: CR4.VMXE nao e acessivel a partir de ring-3.\n");
    printf("        Para verificar, use o WinDbg: r cr4 e confirme bit 13.\n\n");

    // --------------------------------------------------------
    // Loop interativo: testes de EPT hook
    // --------------------------------------------------------
    {
        BYTE*   textPage = (BYTE*)GetModuleHandleA(NULL) + 0x1000;

        SetColor(C_LABEL);
        printf("\n  ========================================================\n");
        printf("   Teste de EPT Read Hook\n");
        printf("  ========================================================\n");
        SetColor(C_NORMAL);
        printf("   Base modulo : 0x%p\n", GetModuleHandleA(NULL));
        printf("   .text+0x1000: 0x%p\n\n", textPage);
        SetColor(C_DIM);
        printf("   F9  -- leitura DIRETA via ponteiro\n");
        printf("   F8  -- leitura via ReadProcessMemory\n");
        printf("   ESC -- sair\n\n");
        SetColor(C_NORMAL);

        for (;;)
        {
            int c = _getch();

            // Teclas de funcao: _getch retorna 0x00 seguido do codigo
            if (c == 0x00 || c == 0xE0)
            {
                int fn = _getch();

                if (fn == 0x43) // F9
                {
                    SetColor(C_LABEL);
                    printf("  [F9] Leitura direta  addr=0x%p  ->  ", textPage);
                    SetColor(C_NORMAL);

                    // Leitura direta: o CPU gera EPT fault aqui
                    volatile BYTE b0 = textPage[0];
                    volatile BYTE b1 = textPage[1];
                    volatile BYTE b2 = textPage[2];
                    volatile BYTE b3 = textPage[3];

                    printf("%02X %02X %02X %02X\n",
                           (unsigned)b0, (unsigned)b1,
                           (unsigned)b2, (unsigned)b3);
                }
                else if (fn == 0x42) // F8
                {
                    SetColor(C_LABEL);
                    printf("  [F8] ReadProcessMemory addr=0x%p  ->  ", textPage);
                    SetColor(C_NORMAL);

                    BYTE    buf[4]    = {};
                    SIZE_T  nRead     = 0;
                    BOOL    ok        = ReadProcessMemory(
                                            GetCurrentProcess(),
                                            textPage,
                                            buf, sizeof(buf),
                                            &nRead);
                    if (ok && nRead == sizeof(buf))
                        printf("%02X %02X %02X %02X\n",
                               buf[0], buf[1], buf[2], buf[3]);
                    else
                        printf("FALHOU (err=%lu, nRead=%zu)\n",
                               GetLastError(), nRead);
                }
            }
            else if (c == 0x1B) // ESC
            {
                break;
            }
        }
    }

    SetColor(C_NORMAL);
    printf("\n");
    return 0;
}

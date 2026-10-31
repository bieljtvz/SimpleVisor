/*++

Module Name:

    main.cpp

Abstract:

    Entry point da GUI do SimpleVisor Monitor.
    Janela Win32 + DirectX 9 + Dear ImGui.

    Arquivos ImGui ja presentes em imgui\ :
      imgui.cpp / imgui_draw.cpp / imgui_tables.cpp / imgui_widgets.cpp
      imgui_impl_win32.cpp / imgui_impl_dx9.cpp
      imgui_hexview\imgui_hex.cpp

--*/

#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "psapi.lib")

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d9.h>

#include "imgui/imgui.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx9.h"

#include "shv_backend.h"
#include "shv_config.h"
#include "tab_status.h"
#include "tab_events.h"
#include "tab_memory.h"
#include "tab_procs.h"
#include "tab_drivers.h"
#include "tab_tools.h"
#include "tab_filters.h"

// ============================================================
// D3D9 globals
// ============================================================
static LPDIRECT3D9       g_pD3D       = nullptr;
static LPDIRECT3DDEVICE9 g_pd3dDevice = nullptr;
static D3DPRESENT_PARAMETERS g_d3dpp  = {};

static bool CreateDeviceD3D(HWND hWnd)
{
    g_pD3D = Direct3DCreate9(D3D_SDK_VERSION);
    if (!g_pD3D) return false;

    ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
    g_d3dpp.Windowed               = TRUE;
    g_d3dpp.SwapEffect             = D3DSWAPEFFECT_DISCARD;
    g_d3dpp.BackBufferFormat       = D3DFMT_UNKNOWN;
    g_d3dpp.EnableAutoDepthStencil = TRUE;
    g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    g_d3dpp.PresentationInterval   = D3DPRESENT_INTERVAL_ONE;

    return g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd,
                                D3DCREATE_HARDWARE_VERTEXPROCESSING,
                                &g_d3dpp, &g_pd3dDevice) >= 0;
}

static void CleanupDeviceD3D()
{
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
    if (g_pD3D)       { g_pD3D->Release();       g_pD3D       = nullptr; }
}

static void ResetDevice()
{
    ImGui_ImplDX9_InvalidateDeviceObjects();
    g_pd3dDevice->Reset(&g_d3dpp);
    ImGui_ImplDX9_CreateDeviceObjects();
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;

    switch (msg)
    {
    case WM_SIZE:
        if (g_pd3dDevice && wParam != SIZE_MINIMIZED)
        {
            g_d3dpp.BackBufferWidth  = LOWORD(lParam);
            g_d3dpp.BackBufferHeight = HIWORD(lParam);
            ResetDevice();
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ============================================================
// Tema escuro personalizado
// ============================================================
static void ApplyTheme()
{
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding   = 4.0f;
    s.FrameRounding    = 3.0f;
    s.GrabRounding     = 3.0f;
    s.TabRounding      = 4.0f;
    s.ScrollbarRounding = 3.0f;
    s.WindowBorderSize = 1.0f;
    s.FrameBorderSize  = 0.0f;
    s.ItemSpacing      = ImVec2(8, 5);
    s.WindowPadding    = ImVec2(10, 10);

    ImVec4* c = s.Colors;
    c[ImGuiCol_WindowBg]           = { 0.10f, 0.10f, 0.12f, 1.00f };
    c[ImGuiCol_ChildBg]            = { 0.12f, 0.12f, 0.15f, 1.00f };
    c[ImGuiCol_PopupBg]            = { 0.10f, 0.10f, 0.12f, 0.95f };
    c[ImGuiCol_Border]             = { 0.28f, 0.28f, 0.32f, 1.00f };
    c[ImGuiCol_FrameBg]            = { 0.16f, 0.16f, 0.20f, 1.00f };
    c[ImGuiCol_FrameBgHovered]     = { 0.22f, 0.22f, 0.28f, 1.00f };
    c[ImGuiCol_FrameBgActive]      = { 0.26f, 0.26f, 0.34f, 1.00f };
    c[ImGuiCol_TitleBg]            = { 0.08f, 0.08f, 0.10f, 1.00f };
    c[ImGuiCol_TitleBgActive]      = { 0.10f, 0.10f, 0.14f, 1.00f };
    c[ImGuiCol_ScrollbarBg]        = { 0.10f, 0.10f, 0.12f, 1.00f };
    c[ImGuiCol_ScrollbarGrab]      = { 0.30f, 0.30f, 0.38f, 1.00f };
    c[ImGuiCol_ScrollbarGrabHovered]= { 0.40f, 0.40f, 0.50f, 1.00f };
    c[ImGuiCol_ScrollbarGrabActive] = { 0.50f, 0.50f, 0.62f, 1.00f };
    c[ImGuiCol_CheckMark]          = { 0.20f, 0.85f, 0.45f, 1.00f };
    c[ImGuiCol_Button]             = { 0.18f, 0.26f, 0.38f, 1.00f };
    c[ImGuiCol_ButtonHovered]      = { 0.24f, 0.35f, 0.52f, 1.00f };
    c[ImGuiCol_ButtonActive]       = { 0.30f, 0.44f, 0.65f, 1.00f };
    c[ImGuiCol_Header]             = { 0.18f, 0.26f, 0.38f, 1.00f };
    c[ImGuiCol_HeaderHovered]      = { 0.24f, 0.35f, 0.52f, 1.00f };
    c[ImGuiCol_HeaderActive]       = { 0.30f, 0.44f, 0.65f, 1.00f };
    c[ImGuiCol_Tab]                = { 0.12f, 0.16f, 0.22f, 1.00f };
    c[ImGuiCol_TabHovered]         = { 0.20f, 0.28f, 0.42f, 1.00f };
    c[ImGuiCol_TabActive]          = { 0.16f, 0.36f, 0.60f, 1.00f };
    c[ImGuiCol_TabUnfocused]       = { 0.10f, 0.14f, 0.18f, 1.00f };
    c[ImGuiCol_TabUnfocusedActive] = { 0.14f, 0.26f, 0.42f, 1.00f };
    c[ImGuiCol_TableHeaderBg]      = { 0.14f, 0.18f, 0.26f, 1.00f };
    c[ImGuiCol_TableBorderStrong]  = { 0.28f, 0.30f, 0.38f, 1.00f };
    c[ImGuiCol_TableBorderLight]   = { 0.20f, 0.22f, 0.28f, 1.00f };
    c[ImGuiCol_TableRowBg]         = { 0.00f, 0.00f, 0.00f, 0.00f };
    c[ImGuiCol_TableRowBgAlt]      = { 1.00f, 1.00f, 1.00f, 0.03f };
    c[ImGuiCol_Separator]          = { 0.28f, 0.28f, 0.35f, 1.00f };
    c[ImGuiCol_Text]               = { 0.90f, 0.90f, 0.92f, 1.00f };
    c[ImGuiCol_TextDisabled]       = { 0.45f, 0.45f, 0.50f, 1.00f };
}

// ============================================================
// WinMain
// ============================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int)
{
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_CLASSDC;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = L"ShvMonitorGui";
    wc.hIcon         = LoadIconW(NULL, IDI_APPLICATION);
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(0, L"ShvMonitorGui",
                                L"SimpleVisor Monitor",
                                WS_OVERLAPPEDWINDOW,
                                100, 100, 1280, 820,
                                NULL, NULL, hInstance, NULL);
    if (!hwnd) return 1;

    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, hInstance);
        return 1;
    }

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = "shv_gui.ini";

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);
    ApplyTheme();

    CfgLoad();

    ShvBackend backend;
    backend.Connect();

    bool done = false;
    while (!done)
    {
        MSG msg;
        while (PeekMessageW(&msg, NULL, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // ── Janela principal (preenche a area cliente) ──────────────────────
        RECT cr;
        GetClientRect(hwnd, &cr);
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2((float)(cr.right), (float)(cr.bottom)));
        ImGui::SetNextWindowBgAlpha(1.0f);

        ImGui::Begin("##main", nullptr,
            ImGuiWindowFlags_NoTitleBar  | ImGuiWindowFlags_NoResize  |
            ImGuiWindowFlags_NoMove      | ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoScrollbar);

        // ── Cabecalho ────────────────────────────────────────────────────────
        {
            bool connected = backend.IsConnected();
            ImGui::PushStyleColor(ImGuiCol_Text,
                connected ? ImVec4(0.20f, 0.90f, 0.40f, 1.0f)
                          : ImVec4(1.00f, 0.30f, 0.20f, 1.0f));
            ImGui::Text(connected ? "[●] Conectado" : "[○] Desconectado");
            ImGui::PopStyleColor();

            backend.Lock();
            const ShvStats& stats = backend.State().stats;
            if (stats.present)
            {
                ImGui::SameLine(0, 20);
                ImGui::TextDisabled("CPU %d  |  v%d  |  Exits: %llu  |  Hits: %llu",
                    stats.cpu, stats.version, stats.exitCount, stats.hookHits);
            }
            backend.Unlock();

            if (!backend.StatusMsg().empty())
            {
                ImGui::SameLine(0, 24);
                ImGui::PushStyleColor(ImGuiCol_Text,
                    backend.StatusIsError()
                        ? ImVec4(1.00f, 0.30f, 0.20f, 1.0f)
                        : ImVec4(0.20f, 0.90f, 0.40f, 1.0f));
                ImGui::TextUnformatted(backend.StatusMsg().c_str());
                ImGui::PopStyleColor();
            }
        }

        ImGui::Separator();
        ImGui::Spacing();

        // ── Tab bar ──────────────────────────────────────────────────────────
        if (ImGui::BeginTabBar("MainTabs"))
        {
            if (ImGui::BeginTabItem("Status"))
            {
                ImGui::BeginChild("##ts", ImVec2(0, 0), false);
                RenderTabStatus(backend);
                ImGui::EndChild();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Eventos"))
            {
                ImGui::BeginChild("##te", ImVec2(0, 0), false);
                RenderTabEvents(backend);
                ImGui::EndChild();
                ImGui::EndTabItem();
            }
            {
                ImGuiTabItemFlags memFlags = g_memTabSelectPending
                    ? ImGuiTabItemFlags_SetSelected : 0;
                if (g_memTabSelectPending) g_memTabSelectPending = false;
                if (ImGui::BeginTabItem("Memoria", nullptr, memFlags))
                {
                    ImGui::BeginChild("##tm", ImVec2(0, 0), false,
                        ImGuiWindowFlags_HorizontalScrollbar);
                    RenderTabMemory(backend);
                    ImGui::EndChild();
                    ImGui::EndTabItem();
                }
            }
            if (ImGui::BeginTabItem("Processos"))
            {
                ImGui::BeginChild("##tp", ImVec2(0, 0), false);
                RenderTabProcs(backend);
                ImGui::EndChild();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Drivers"))
            {
                ImGui::BeginChild("##td", ImVec2(0, 0), false);
                RenderTabDrivers(backend);
                ImGui::EndChild();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Tools"))
            {
                ImGui::BeginChild("##tt", ImVec2(0, 0), false);
                RenderTabTools(backend);
                ImGui::EndChild();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Filtros"))
            {
                ImGui::BeginChild("##tf", ImVec2(0, 0), false);
                RenderTabFilters(backend);
                ImGui::EndChild();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }

        ImGui::End();

        // ── Render DX9 ───────────────────────────────────────────────────────
        ImGui::Render();
        g_pd3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
        g_pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
        g_pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);
        g_pd3dDevice->Clear(0, nullptr,
                            D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER,
                            D3DCOLOR_RGBA(20, 20, 25, 255), 1.0f, 0);
        if (g_pd3dDevice->BeginScene() >= 0)
        {
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            g_pd3dDevice->EndScene();
        }
        HRESULT result = g_pd3dDevice->Present(nullptr, nullptr, nullptr, nullptr);
        if (result == D3DERR_DEVICELOST &&
            g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET)
            ResetDevice();
    }

    CfgSave();
    backend.Disconnect();
    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, hInstance);
    return 0;
}

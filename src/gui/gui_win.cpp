// The window behind the GUI: Win32 window, Direct3D 11 device, fonts, DPI,
// the file dialog, relaunching and the crash dialog. What gets drawn is in
// gui_ui.cpp.
#ifdef _WIN32
#include "gui.hpp"

#include <windows.h>
#include <commdlg.h>
#include <d3d11.h>
#include <dwmapi.h>
#include <shellapi.h>

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

#include "../util.hpp"
#include "../windows/win_util.hpp"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace scan {
namespace gui {

namespace {

HWND g_hwnd = nullptr;
ID3D11Device* g_device = nullptr;
ID3D11DeviceContext* g_context = nullptr;
IDXGISwapChain* g_swap = nullptr;
ID3D11RenderTargetView* g_target = nullptr;
UINT g_resize_w = 0, g_resize_h = 0;
bool g_occluded = false;
float g_scale = 1.0f;
bool g_scale_changed = false;

// Settings travel to a relaunched copy in these, because any command line
// argument would switch it to CLI mode.
const wchar_t* kEnvScan = L"VESTIGE_GUI_SCAN";
const wchar_t* kEnvDeep = L"VESTIGE_GUI_DEEP";
const wchar_t* kEnvSigs = L"VESTIGE_GUI_SIGS";
const wchar_t* kEnvSkip = L"VESTIGE_GUI_SKIP";

std::string take_env(const wchar_t* name) {
    wchar_t buf[4096];
    DWORD n = GetEnvironmentVariableW(name, buf, 4096);
    SetEnvironmentVariableW(name, nullptr);
    if (n == 0 || n >= 4096) return "";
    return win::narrow(buf, n);
}

Settings settings_from_env() {
    Settings s;
    s.autoscan = take_env(kEnvScan) == "1";
    s.deep = take_env(kEnvDeep) == "1";
    s.sig_path = take_env(kEnvSigs);
    for (const std::string& name : split(take_env(kEnvSkip), ','))
        if (!trim(name).empty()) s.skip.insert(trim(name));
    return s;
}

void create_target() {
    ID3D11Texture2D* back = nullptr;
    g_swap->GetBuffer(0, IID_PPV_ARGS(&back));
    if (back) {
        g_device->CreateRenderTargetView(back, nullptr, &g_target);
        back->Release();
    }
}

void release_target() {
    if (g_target) { g_target->Release(); g_target = nullptr; }
}

bool create_device(HWND hwnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL got;
    // Graphics card first, then the software renderer (remote desktop, VMs, broken drivers).
    const D3D_DRIVER_TYPE drivers[] = {D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP};
    for (D3D_DRIVER_TYPE driver : drivers) {
        HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, driver, nullptr, 0, levels, 2, D3D11_SDK_VERSION, &sd,
                                                   &g_swap, &g_device, &got, &g_context);
        if (SUCCEEDED(hr)) {
            create_target();
            return g_target != nullptr;
        }
    }
    return false;
}

void release_device() {
    release_target();
    if (g_swap) { g_swap->Release(); g_swap = nullptr; }
    if (g_context) { g_context->Release(); g_context = nullptr; }
    if (g_device) { g_device->Release(); g_device = nullptr; }
}

LRESULT WINAPI wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wp, lp)) return 1;
    switch (msg) {
        case WM_SIZE:
            if (wp != SIZE_MINIMIZED) {
                g_resize_w = LOWORD(lp);
                g_resize_h = HIWORD(lp);
            }
            return 0;
        case WM_GETMINMAXINFO: {
            MINMAXINFO* mm = reinterpret_cast<MINMAXINFO*>(lp);
            mm->ptMinTrackSize.x = static_cast<LONG>(1000 * g_scale);
            mm->ptMinTrackSize.y = static_cast<LONG>(600 * g_scale);
            return 0;
        }
        case WM_DPICHANGED: {
            // Moved to a monitor with a different scale: take the size Windows
            // suggests and rebuild the style at the new scale.
            g_scale = static_cast<float>(HIWORD(wp)) / 96.0f;
            g_scale_changed = true;
            const RECT* r = reinterpret_cast<const RECT*>(lp);
            SetWindowPos(hwnd, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
            return 0;
        }
        case WM_SYSCOMMAND:
            if ((wp & 0xfff0) == SC_KEYMENU) return 0;   // no Alt menu
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

bool file_there(const std::wstring& path) {
    DWORD a = GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

// Segoe UI and Consolas from the Windows font folder, ImGui's built-in font
// when they are missing. Sizes are picked per use and scaled with the DPI.
Fonts load_fonts() {
    ImGuiIO& io = ImGui::GetIO();
    wchar_t win[MAX_PATH];
    UINT n = GetWindowsDirectoryW(win, MAX_PATH);
    std::wstring dir = (n > 0 && n < MAX_PATH ? std::wstring(win, n) : std::wstring(L"C:\\Windows")) + L"\\Fonts\\";
    auto load = [&](const wchar_t* file) -> ImFont* {
        std::wstring path = dir + file;
        if (!file_there(path)) return nullptr;
        return io.Fonts->AddFontFromFileTTF(win::narrow(path).c_str(), 15.0f);
    };
    Fonts f;
    f.body = load(L"segoeui.ttf");
    if (!f.body) f.body = io.Fonts->AddFontDefault();   // first font added is the default
    f.bold = load(L"segoeuib.ttf");
    if (!f.bold) f.bold = load(L"seguisb.ttf");
    if (!f.bold) f.bold = f.body;
    f.mono = load(L"consola.ttf");
    if (!f.mono) f.mono = io.Fonts->AddFontDefault();
    return f;
}

// A double click gives the exe its own console window. Close it. A console
// that belongs to a terminal the user started from is left alone.
void drop_own_console() {
    DWORD pids[2];
    if (GetConsoleProcessList(pids, 2) == 1) FreeConsole();
}

}  // namespace

std::string pick_signature_file() {
    wchar_t file[1024] = L"";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof ofn;
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = L"Signature lists (*.txt)\0*.txt\0All files\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = 1024;
    ofn.lpstrTitle = L"Pick a signature file";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_HIDEREADONLY;
    if (!GetOpenFileNameW(&ofn)) return "";
    return win::narrow(file, wcslen(file));
}

void open_in_shell(const std::string& utf8_path) {
    ShellExecuteW(g_hwnd, L"open", win::widen(utf8_path).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

bool relaunch(const Settings& s) {
    wchar_t exe[MAX_PATH * 4];
    DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH * 4);
    if (n == 0 || n >= MAX_PATH * 4) return false;

    std::string skip;
    for (const std::string& name : s.skip) skip += (skip.empty() ? "" : ",") + name;
    SetEnvironmentVariableW(kEnvScan, s.autoscan ? L"1" : nullptr);
    SetEnvironmentVariableW(kEnvDeep, s.deep ? L"1" : nullptr);
    SetEnvironmentVariableW(kEnvSigs, s.sig_path.empty() ? nullptr : win::widen(s.sig_path).c_str());
    SetEnvironmentVariableW(kEnvSkip, skip.empty() ? nullptr : win::widen(skip).c_str());

    // No arguments, so the new copy opens the GUI. It inherits the environment
    // and the administrator token, so there is no second UAC prompt.
    STARTUPINFOW si{};
    si.cb = sizeof si;
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"\"" + std::wstring(exe, n) + L"\"";
    bool ok = CreateProcessW(exe, &cmd[0], nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi) != 0;
    if (ok) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    for (const wchar_t* name : {kEnvScan, kEnvDeep, kEnvSigs, kEnvSkip}) SetEnvironmentVariableW(name, nullptr);
    return ok;
}

void request_close() {
    if (g_hwnd) PostMessageW(g_hwnd, WM_CLOSE, 0, 0);
}

void report_crash(const char* check, unsigned long code, void* address) {
    const UINT flags = MB_ICONERROR | MB_TASKMODAL | MB_SETFOREGROUND;
    if (check && *check) {
        std::string msg = strf("Vestige crashed in the check \"%s\" (code 0x%lX at %p).\n\n"
                               "Nothing from this scan was saved. Scan again without that check?",
                               check, code, address);
        if (MessageBoxW(nullptr, win::widen(msg).c_str(), L"Vestige", flags | MB_YESNO) == IDYES) {
            Settings s = ui_settings();
            s.skip.insert(check);
            s.autoscan = true;
            relaunch(s);
        }
    } else {
        std::string msg = strf("Vestige crashed outside of a check (code 0x%lX at %p).\n\n"
                               "The command line still works: open a terminal as administrator and run\n"
                               "Vestige.exe --out C:\\SSTools\\ForensicScanner",
                               code, address);
        MessageBoxW(nullptr, win::widen(msg).c_str(), L"Vestige", flags | MB_OK);
    }
}

int run() {
    drop_own_console();
    Settings settings = settings_from_env();

    ImGui_ImplWin32_EnableDpiAwareness();
    HINSTANCE inst = GetModuleHandleW(nullptr);
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof wc;
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hbrBackground = CreateSolidBrush(RGB(0x0b, 0x0c, 0x0f));
    wc.lpszClassName = L"VestigeWindow";
    RegisterClassExW(&wc);

    g_hwnd = CreateWindowW(wc.lpszClassName, L"Vestige", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1180, 760,
                           nullptr, nullptr, inst, nullptr);
    if (!g_hwnd || !create_device(g_hwnd)) {
        release_device();
        MessageBoxW(nullptr,
                    L"Could not start Direct3D 11, so the window can't open.\n\n"
                    L"The command line still works: open a terminal as administrator and run\n"
                    L"Vestige.exe --out C:\\SSTools\\ForensicScanner",
                    L"Vestige", MB_ICONERROR | MB_OK);
        return 1;
    }

    // Size the window for the monitor it opened on.
    g_scale = ImGui_ImplWin32_GetDpiScaleForHwnd(g_hwnd);
    SetWindowPos(g_hwnd, nullptr, 0, 0, static_cast<int>(1180 * g_scale), static_cast<int>(760 * g_scale),
                 SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    BOOL dark = TRUE;
    DwmSetWindowAttribute(g_hwnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof dark);
    ShowWindow(g_hwnd, SW_SHOWDEFAULT);
    UpdateWindow(g_hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;   // read-only tool: no imgui.ini, no log file
    io.LogFilename = nullptr;
    Fonts fonts = load_fonts();
    ui_apply_style(g_scale);
    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX11_Init(g_device, g_context);
    ui_init(settings);

    const float clear[4] = {0x0b / 255.0f, 0x0c / 255.0f, 0x0f / 255.0f, 1.0f};
    bool done = false;
    while (!done) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        if (IsIconic(g_hwnd) || (g_occluded && g_swap->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)) {
            Sleep(30);
            continue;
        }
        g_occluded = false;

        if (g_resize_w != 0 && g_resize_h != 0) {
            release_target();
            g_swap->ResizeBuffers(0, g_resize_w, g_resize_h, DXGI_FORMAT_UNKNOWN, 0);
            g_resize_w = g_resize_h = 0;
            create_target();
        }
        if (g_scale_changed) {
            ui_apply_style(g_scale);
            g_scale_changed = false;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        ui_frame(fonts, g_scale);
        ImGui::Render();

        g_context->OMSetRenderTargets(1, &g_target, nullptr);
        g_context->ClearRenderTargetView(g_target, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        HRESULT hr = g_swap->Present(1, 0);   // vsync
        g_occluded = hr == DXGI_STATUS_OCCLUDED;
    }

    ui_shutdown();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    release_device();
    g_hwnd = nullptr;
    return 0;
}

}  // namespace gui
}  // namespace scan
#endif

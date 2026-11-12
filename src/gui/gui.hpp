// Windows GUI (Dear ImGui on Win32 + DirectX 11). Opened when the exe is
// started with no arguments. It only shows what run_scan() produces: no
// detection logic lives in here.
//
//   gui_win.cpp  window, Direct3D, fonts, DPI, file dialog, relaunch, crash dialog
//   gui_ui.cpp   the scan worker thread and everything that is drawn
#pragma once
#ifdef _WIN32
#include <set>
#include <string>

struct ImFont;

namespace scan {
namespace gui {

// Opens the window and runs until it is closed. Returns the exit code.
int run();

// Called by the crash handler in main.cpp when the GUI is up. Shows which
// check crashed and offers to scan again without it.
void report_crash(const char* check, unsigned long code, void* address);

// ---- shared between gui_win.cpp and gui_ui.cpp -----------------------------

// What a scan was started with. Carried across a relaunch in environment
// variables, because any command line argument means "run as CLI".
struct Settings {
    bool deep = false;
    std::string sig_path;              // UTF-8, empty = built-in list only
    std::set<std::string> skip;        // checks that crashed in an earlier scan
    bool autoscan = false;             // start scanning as soon as the window is up
};

struct Fonts {
    ImFont* body = nullptr;
    ImFont* bold = nullptr;
    ImFont* mono = nullptr;
};

// Services the UI asks the window for.
std::string pick_signature_file();                 // "" if cancelled
void open_in_shell(const std::string& utf8_path);   // file or folder
bool relaunch(const Settings& s);                   // start a fresh copy of the exe with these settings
void request_close();

// UI entry points the window calls.
void ui_init(const Settings& s);
void ui_apply_style(float scale);
void ui_frame(const Fonts& fonts, float scale);
void ui_shutdown();                                 // window is closing
Settings ui_settings();                             // current settings (for the crash dialog)

}  // namespace gui
}  // namespace scan
#endif

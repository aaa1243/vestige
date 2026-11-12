// Windows on screen: capture-hidden ("streamproof") windows and click-through
// overlays drawn on top of the game.
#ifdef _WIN32
#include "win_util.hpp"

#include <set>

#include "../util.hpp"

namespace scan {
using namespace win;

namespace {

struct Win {
    HWND hwnd;
    DWORD pid;
    std::string title, cls;
    RECT rc;
    LONG_PTR style, ex;
    DWORD affinity;
    bool visible;
};

BOOL CALLBACK collect(HWND h, LPARAM lp) {
    auto* out = reinterpret_cast<std::vector<Win>*>(lp);
    Win w{};
    w.hwnd = h;
    GetWindowThreadProcessId(h, &w.pid);
    wchar_t buf[256];
    int n = GetWindowTextW(h, buf, 256);
    w.title = narrow(buf, n > 0 ? n : 0);
    n = GetClassNameW(h, buf, 256);
    w.cls = narrow(buf, n > 0 ? n : 0);
    GetWindowRect(h, &w.rc);
    w.style = GetWindowLongPtrW(h, GWL_STYLE);
    w.ex = GetWindowLongPtrW(h, GWL_EXSTYLE);
    w.visible = IsWindowVisible(h) != 0;
    w.affinity = 0;
    GetWindowDisplayAffinity(h, &w.affinity);
    out->push_back(w);
    return TRUE;
}

// Overlays from common, legitimate software.
bool known_overlay(const std::string& proc, const std::string& path) {
    static const char* const ok[] = {
        "nvcontainer", "nvidia", "nvsphelper", "discord", "steam", "gameoverlayui", "gamebar", "gamebarftserver",
        "xboxgamebar", "obs64", "obs32", "msiafterburner", "rtss", "radeonsoftware", "amdrsserv", "overwolf",
        "medal", "textinputhost", "shellexperiencehost", "searchhost", "startmenuexperiencehost", "explorer",
        "dwm", "lockapp", "applicationframehost", "systemsettings", "snippingtool", "screenclippinghost",
        "powertoys", "lghub", "icue", "razer", "steelseries", "wallpaper", "lively", "rainmeter", "translucenttb",
        "sharex", "lightshot", "nahimic", "sonar", "voicemeeter", "eartrumpet", "f.lux", "flux", "outplayed",
        "lunarclient", "lunar client", "badlion", "feather", "peopleexperiencehost", "widgets", "msedgewebview2",
        "csrss", "ctfmon", "taskmgr", "crashpad", "teams", "zoom", "parsec", "anydesk", "moonlight"};
    std::string l = lower(proc) + " " + lower(path);
    for (const char* k : ok)
        if (contains(l, k)) return true;
    return false;
}

}  // namespace

SCAN_CHECK(180, screen_windows, Scope::InGame, "Windows hidden from capture and click-through overlays") {
    std::vector<Win> wins;
    EnumWindows(collect, reinterpret_cast<LPARAM>(&wins));
    if (wins.empty()) {
        ctx.note("no windows could be listed (the scan may be running in another session)");
        return;
    }
    std::set<DWORD> game_pids;
    for (const ProcInfo& g : game_processes()) game_pids.insert(g.pid);
    int sw = GetSystemMetrics(SM_CXVIRTUALSCREEN), sh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    RECT game_rc{};
    bool have_game = false;
    for (const Win& w : wins)
        if (game_pids.count(w.pid) && w.visible && (w.rc.right - w.rc.left) > 300 && !have_game) {
            game_rc = w.rc;
            have_game = true;
        }

    std::set<DWORD> hidden_done, overlay_done;
    for (const Win& w : wins) {
        const ProcInfo* p = find_process(w.pid);
        std::string proc = p ? p->name : strf("PID %lu", w.pid);
        std::string path = p ? p->path : std::string();
        std::string who = (path.empty() ? proc : path) + strf(" (PID %lu)", w.pid) +
                          (w.title.empty() ? std::string() : ", window \"" + cut(w.title, 60) + "\"") +
                          ", class " + w.cls;
        int ww = w.rc.right - w.rc.left, wh = w.rc.bottom - w.rc.top;

        // WDA_MONITOR (1) shows black in captures, WDA_EXCLUDEFROMCAPTURE (0x11) vanishes entirely.
        if (w.affinity != 0 && hidden_done.insert(w.pid).second) {
            bool exclude = w.affinity == 0x11;
            std::vector<std::string> strong = ctx.match_names(proc);
            bool trusted = !path.empty() && verify_file(path).trusted;
            Severity sev = !strong.empty() ? Severity::Detection
                           : (game_pids.count(w.pid) || (!trusted && w.visible)) ? Severity::Detection : Severity::Warning;
            std::string why = game_pids.count(w.pid)
                                  ? "A window inside the game process is hidden from screen capture. The game "
                                    "does not do this itself, so injected code created or changed that window."
                                  : "This window is set so screen capture and screenshare cannot see it" +
                                        std::string(exclude ? " at all." : " (it shows as black).") +
                                        " That is how streamproof cheat menus stay off a shared screen. Password "
                                        "managers and DRM video players also use it.";
            ctx.add(sev, "Window hidden from capture: " + proc,
                    why + (trusted ? " The program has a valid signature (" + verify_file(path).signer + ")." : " The program is not signed."),
                    who + strf(", affinity 0x%lX, %dx%d, %s", w.affinity, ww, wh, w.visible ? "visible" : "not visible"));
        }

        // Overlay: on top of everything, lets clicks pass through, visible, and big.
        bool topmost = (w.ex & WS_EX_TOPMOST) != 0, layered = (w.ex & WS_EX_LAYERED) != 0;
        bool click_through = (w.ex & WS_EX_TRANSPARENT) != 0, no_taskbar = (w.ex & (WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE)) != 0;
        if (!(w.visible && topmost && layered && click_through) || game_pids.count(w.pid)) continue;
        bool covers_screen = ww >= sw * 6 / 10 && wh >= sh * 6 / 10;
        bool covers_game = false;
        if (have_game) {
            RECT inter;
            if (IntersectRect(&inter, &w.rc, &game_rc)) {
                long long ia = 1LL * (inter.right - inter.left) * (inter.bottom - inter.top);
                long long ga = 1LL * (game_rc.right - game_rc.left) * (game_rc.bottom - game_rc.top);
                covers_game = ga > 0 && ia * 10 >= ga * 6;
            }
        }
        if (!covers_screen && !covers_game) continue;
        if (!overlay_done.insert(w.pid).second) continue;
        std::vector<std::string> strong = ctx.match_names(proc);
        bool trusted = !path.empty() && verify_file(path).trusted;
        if (strong.empty() && trusted && known_overlay(proc, path)) continue;
        Severity sev = !strong.empty() ? Severity::Detection : Severity::Warning;
        ctx.add(sev, "Click-through overlay on top of the screen: " + proc,
                std::string("A see-through window that stays on top and lets clicks pass to the game") +
                    (covers_game ? ", covering the game window." : ", covering most of the screen.") +
                    " External ESP and cheat menus draw this way. Recording tools, crosshair apps and GPU "
                    "overlays do too, so check what the program is." +
                    (trusted ? " Signed by " + verify_file(path).signer + "." : " The program is not signed.") +
                    (no_taskbar ? " It has no taskbar button." : ""),
                who + strf(", %dx%d", ww, wh));
    }
    ctx.add(Severity::Integrity, "Windows checked",
            strf("%zu top-level windows. A streamproof or overlay window only shows up while it exists, so "
                 "a cheat closed before the scan is not seen here.", wins.size()), "", Scope::None);
}

}  // namespace scan
#endif

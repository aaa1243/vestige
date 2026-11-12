// Vestige: read-only screenshare scanner for Windows, macOS, Linux.
// With any argument it is a command line tool. On Windows, started with no
// arguments (a double click), it opens the GUI in src/gui/.
#include <cstdio>
#include <cstring>
#include <set>

#ifdef _WIN32
#include <windows.h>
#include "gui/gui.hpp"
#endif
#include "core.hpp"
#include "scan_run.hpp"
#include "util.hpp"

using namespace scan;

static void usage() {
    printf("Vestige (read-only)\n\n"
           "  --out DIR     save report.html and report.json in DIR\n"
           "  --json FILE   save results as JSON\n"
           "  --html FILE   save results as an HTML report\n"
           "  --sigs FILE   add your own signatures (type|value|label per line)\n"
           "  --only a,b    run only these checks\n"
           "  --skip a,b    skip these checks\n"
           "  --deep        slower, wider scans (full game memory, more folders)\n"
           "  --list        list the checks for this system\n"
           "  --no-pause    don't wait for Enter at the end (Windows)\n");
}

#ifdef _WIN32
// If a check crashes (bad memory read on an unusual system), say which one
// instead of closing silently. In the GUI the same handler shows a dialog.
static bool g_gui_mode = false;
static LONG WINAPI crash_filter(EXCEPTION_POINTERS* info) {
    const char* check = running_check();
    if (g_gui_mode) {
        gui::report_crash(check, info->ExceptionRecord->ExceptionCode, info->ExceptionRecord->ExceptionAddress);
    } else {
        fprintf(stderr, "\nThe scanner crashed in the check \"%s\" (code 0x%lX at %p).\n"
                        "Run it again with:  --skip %s\n",
                check, info->ExceptionRecord->ExceptionCode, info->ExceptionRecord->ExceptionAddress, check);
        fflush(stderr);
    }
    TerminateProcess(GetCurrentProcess(), 3);
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

int main(int argc, char** argv) {
#ifdef _WIN32
    SetUnhandledExceptionFilter(crash_filter);
    if (argc <= 1) {
        g_gui_mode = true;
        return gui::run();
    }
#endif
    std::string json_path, html_path, out_dir;
    ScanOptions opt;
    bool list = false, no_pause = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
        if (a == "--json") json_path = next();
        else if (a == "--html") html_path = next();
        else if (a == "--out") out_dir = next();
        else if (a == "--sigs") opt.sig_path = next();
        else if (a == "--only") { for (auto& s : split(next(), ',')) opt.only.insert(trim(s)); }
        else if (a == "--skip") { for (auto& s : split(next(), ',')) opt.skip.insert(trim(s)); }
        else if (a == "--list") list = true;
        else if (a == "--deep") opt.deep = true;
        else if (a == "--no-pause") no_pause = true;
        else if (a == "-h" || a == "--help") { usage(); return 0; }
        else { printf("Unknown option: %s\n\n", a.c_str()); usage(); return 2; }
    }

    if (list) {
        for (const CheckInfo& c : sorted_checks()) printf("%-22s %s\n", c.name, c.summary);
        return 0;
    }

    Context ctx;
    double started = run_scan(ctx, opt);

    print_console(ctx, now_epoch() - started);

    if (out_dir.empty() && json_path.empty() && html_path.empty()) out_dir = default_report_dir();
    if (!out_dir.empty()) {
        make_dirs(out_dir);
        if (json_path.empty()) json_path = out_dir + "/report.json";
        if (html_path.empty()) html_path = out_dir + "/report.html";
    }
    if (!json_path.empty())
        printf("  %s %s\n", write_file(json_path, to_json(ctx, started)) ? "Saved" : "Could not save", json_path.c_str());
    if (!html_path.empty())
        printf("  %s %s\n", write_file(html_path, to_html(ctx, started)) ? "Saved" : "Could not save", html_path.c_str());

#ifdef _WIN32
    if (!no_pause) {
        printf("\nPress Enter to close.");
        fflush(stdout);
        getchar();
    }
#else
    (void)no_pause;
#endif
    return 0;
}

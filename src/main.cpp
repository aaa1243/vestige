// Forensic Scanner: read-only screenshare scanner for Windows, macOS, Linux.
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <exception>
#include <set>

#ifdef _WIN32
#include <windows.h>
#endif
#include "core.hpp"
#include "util.hpp"

using namespace scan;

static void usage() {
    printf("Forensic Scanner (read-only)\n\n"
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
// instead of closing silently.
static const char* g_current_check = "";
static LONG WINAPI crash_filter(EXCEPTION_POINTERS* info) {
    fprintf(stderr, "\nThe scanner crashed in the check \"%s\" (code 0x%lX at %p).\n"
                    "Run it again with:  --skip %s\n",
            g_current_check, info->ExceptionRecord->ExceptionCode, info->ExceptionRecord->ExceptionAddress, g_current_check);
    fflush(stderr);
    TerminateProcess(GetCurrentProcess(), 3);
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

int main(int argc, char** argv) {
#ifdef _WIN32
    SetUnhandledExceptionFilter(crash_filter);
#endif
    std::string json_path, html_path, out_dir, sig_path;
    std::set<std::string> only, skip;
    bool list = false, no_pause = false, deep = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
        if (a == "--json") json_path = next();
        else if (a == "--html") html_path = next();
        else if (a == "--out") out_dir = next();
        else if (a == "--sigs") sig_path = next();
        else if (a == "--only") { for (auto& s : split(next(), ',')) only.insert(trim(s)); }
        else if (a == "--skip") { for (auto& s : split(next(), ',')) skip.insert(trim(s)); }
        else if (a == "--list") list = true;
        else if (a == "--deep") deep = true;
        else if (a == "--no-pause") no_pause = true;
        else if (a == "-h" || a == "--help") { usage(); return 0; }
        else { printf("Unknown option: %s\n\n", a.c_str()); usage(); return 2; }
    }

    Context ctx;
#if defined(_WIN32)
    ctx.os = "windows";
#elif defined(__APPLE__)
    ctx.os = "macos";
#else
    ctx.os = "linux";
#endif
    ctx.deep = deep;

    std::vector<CheckInfo> checks = registry();
    std::sort(checks.begin(), checks.end(),
              [](const CheckInfo& a, const CheckInfo& b) { return a.order < b.order; });
    if (list) {
        for (const CheckInfo& c : checks) printf("%-22s %s\n", c.name, c.summary);
        return 0;
    }

    std::vector<std::string> sig_errors;
    ctx.sigs.load_text(kDefaultSignatures, &sig_errors);
    if (!sig_path.empty()) {
        std::string text;
        if (read_file(sig_path, text)) ctx.sigs.load_text(text, &sig_errors);
        else ctx.notes.push_back("could not read signature file " + sig_path);
    }
    for (const std::string& e : sig_errors) ctx.notes.push_back("signatures: " + e);

    platform_prepare(ctx);
    ctx.admin = platform_is_admin();
    ctx.boot_time = platform_boot_time();

    double started = now_epoch();
    for (const CheckInfo& c : checks) {
        if (!only.empty() && !only.count(c.name)) continue;
        if (skip.count(c.name)) continue;
        ctx.current = c.name;
#ifdef _WIN32
        g_current_check = c.name;
#endif
        ctx.current_scope = c.scope;
        try {
            c.fn(ctx);
        } catch (const std::exception& e) {
            ctx.note(std::string("failed: ") + e.what());
        } catch (...) {
            ctx.note("failed with an unknown error");
        }
    }
    ctx.current.clear();

    print_console(ctx, now_epoch() - started);

#ifdef _WIN32
    if (out_dir.empty() && json_path.empty() && html_path.empty()) out_dir = "C:\\SSTools\\ForensicScanner";
#endif
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

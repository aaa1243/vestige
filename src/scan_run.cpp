#include "scan_run.hpp"

#include <algorithm>
#include <atomic>
#include <exception>

#include "util.hpp"

namespace scan {

static std::atomic<const char*> g_running_check{""};

const char* running_check() { return g_running_check.load(); }

std::string default_report_dir() {
#ifdef _WIN32
    return "C:\\SSTools\\ForensicScanner";
#else
    return "";
#endif
}

std::vector<CheckInfo> sorted_checks() {
    std::vector<CheckInfo> checks = registry();
    std::sort(checks.begin(), checks.end(),
              [](const CheckInfo& a, const CheckInfo& b) { return a.order < b.order; });
    return checks;
}

double run_scan(Context& ctx, const ScanOptions& opt, const ProgressFn& progress) {
#if defined(_WIN32)
    ctx.os = "windows";
#elif defined(__APPLE__)
    ctx.os = "macos";
#else
    ctx.os = "linux";
#endif
    ctx.deep = opt.deep;

    std::vector<std::string> sig_errors;
    ctx.sigs.load_text(kDefaultSignatures, &sig_errors);
    if (!opt.sig_path.empty()) {
        std::string text;
        if (read_file(opt.sig_path, text)) ctx.sigs.load_text(text, &sig_errors);
        else ctx.notes.push_back("could not read signature file " + opt.sig_path);
    }
    for (const std::string& e : sig_errors) ctx.notes.push_back("signatures: " + e);

    platform_prepare(ctx);
    ctx.admin = platform_is_admin();
    ctx.boot_time = platform_boot_time();

    std::vector<CheckInfo> checks;
    for (const CheckInfo& c : sorted_checks()) {
        if (!opt.only.empty() && !opt.only.count(c.name)) continue;
        if (opt.skip.count(c.name)) continue;
        checks.push_back(c);
    }

    double started = now_epoch();
    ScanProgress p;
    p.total = checks.size();
    for (const CheckInfo& c : checks) {
        ++p.index;
        p.name = c.name;
        p.done = false;
        if (progress) progress(p);

        ctx.current = c.name;
        ctx.current_scope = c.scope;
        g_running_check = c.name;
        try {
            c.fn(ctx);
        } catch (const std::exception& e) {
            ctx.note(std::string("failed: ") + e.what());
        } catch (...) {
            ctx.note("failed with an unknown error");
        }
        g_running_check = "";
        ctx.current.clear();

        p.done = true;
        if (progress) progress(p);
    }
    ctx.current.clear();
    return started;
}

}  // namespace scan

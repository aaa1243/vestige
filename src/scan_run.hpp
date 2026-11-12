// The scan runner shared by the command line and the Windows GUI: loads
// signatures, prepares the context and runs every registered check in order.
#pragma once
#include <functional>
#include <set>
#include <string>
#include <vector>

#include "core.hpp"

namespace scan {

struct ScanOptions {
    std::set<std::string> only;   // --only (empty = every check)
    std::set<std::string> skip;   // --skip
    bool deep = false;            // --deep
    std::string sig_path;         // --sigs (empty = built-in list only)
};

// Sent twice per check: once right before it runs (done = false) and once
// right after it returns (done = true). Called on the thread that runs the scan.
struct ScanProgress {
    size_t index = 0;             // 1-based position among the checks that will run
    size_t total = 0;             // how many checks will run
    const char* name = "";
    bool done = false;
};
using ProgressFn = std::function<void(const ScanProgress&)>;

// Every check for this system, sorted by its order.
std::vector<CheckInfo> sorted_checks();

// Fills ctx (os, deep, signatures, admin, boot time), then runs the checks.
// Returns the time the checks started (epoch seconds), which the reports use.
double run_scan(Context& ctx, const ScanOptions& opt, const ProgressFn& progress = nullptr);

// Name of the check that is running right now, "" between checks. Safe to
// read from a crash handler on any thread.
const char* running_check();

// Where reports go when no path is given. Empty on macOS and Linux.
std::string default_report_dir();

}  // namespace scan

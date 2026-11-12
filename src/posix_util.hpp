#pragma once
#if !defined(_WIN32)
#include <cstdio>
#include <string>
#include <unistd.h>

namespace scan {

// Runs a fixed command line and returns its stdout. Only ever called with
// commands written in this source, never with text taken from the machine.
inline std::string run_cmd(const std::string& cmd) {
    std::string out;
    FILE* p = popen((cmd + " 2>/dev/null").c_str(), "r");
    if (!p) return out;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, p)) > 0) {
        out.append(buf, n);
        if (out.size() > (32u << 20)) break;
    }
    pclose(p);
    return out;
}

// Quotes a value for use inside a shell command.
inline std::string sh_quote(const std::string& s) {
    std::string o = "'";
    for (char c : s) {
        if (c == '\'') o += "'\\''";
        else o += c;
    }
    return o + "'";
}

}  // namespace scan
#endif

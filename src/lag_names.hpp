// Names of programs used for fake lag and lag switching, shared by the
// Windows, macOS and Linux lag checks. Matched against lowercase process
// names, file names and command lines.
#pragma once
#include <string>

#include "core.hpp"
#include "util.hpp"

namespace scan {

struct LagTool {
    const char* needle;   // lowercase, matched with contains()
    const char* label;
    Severity sev;         // how strong it is on its own
    const char* what;
};

// Order matters: the first match wins.
inline const LagTool kLagTools[] = {
    {"clumsy", "clumsy", Severity::Detection,
     "clumsy delays, drops and reorders the PC's network packets on a hotkey. It is the usual fake-lag tool for PvP."},
    {"lagswitch", "lag switch", Severity::Detection, "Named as a lag switch."},
    {"lag switch", "lag switch", Severity::Detection, "Named as a lag switch."},
    {"lag_switch", "lag switch", Severity::Detection, "Named as a lag switch."},
    {"fakelag", "fake lag", Severity::Detection, "Named as a fake-lag tool."},
    {"fake lag", "fake lag", Severity::Detection, "Named as a fake-lag tool."},
    {"fake_lag", "fake lag", Severity::Detection, "Named as a fake-lag tool."},
    {"pingspoof", "ping spoofer", Severity::Detection, "Named as a ping spoofer."},
    {"ping spoof", "ping spoofer", Severity::Detection, "Named as a ping spoofer."},
    {"nlclientapp", "NetLimiter", Severity::Warning,
     "NetLimiter can limit or block any program's traffic with a click, which players use as a lag switch. "
     "It is also a normal bandwidth tool, so check its rules."},
    {"nlsvc", "NetLimiter", Severity::Warning,
     "NetLimiter can limit or block any program's traffic with a click, which players use as a lag switch. "
     "It is also a normal bandwidth tool, so check its rules."},
    {"netlimiter", "NetLimiter", Severity::Warning,
     "NetLimiter can limit or block any program's traffic with a click, which players use as a lag switch. "
     "It is also a normal bandwidth tool, so check its rules."},
    {"netbalancer", "NetBalancer", Severity::Warning,
     "NetBalancer can limit or block any program's traffic, which works as a lag switch. It is also a normal bandwidth tool."},
    {"connectionemulator", "SoftPerfect Connection Emulator", Severity::Warning,
     "A network emulator that adds delay and packet loss. Made for testing, rare on a gaming PC."},
    {"connection emulator", "SoftPerfect Connection Emulator", Severity::Warning,
     "A network emulator that adds delay and packet loss. Made for testing, rare on a gaming PC."},
};

inline const LagTool* match_lag_tool(const std::string& lowered) {
    for (const LagTool& t : kLagTools)
        if (contains(lowered, t.needle)) return &t;
    return nullptr;
}

}  // namespace scan

// Fake lag and lag switches: packet tools (clumsy, WinDivert, NetLimiter,
// NetBalancer), firewall rules that cut the game off on a hotkey, and
// settings that make the connection worse on purpose (QoS throttles, a
// network card forced to 10 Mbps, a tiny MTU, the connection dropping
// while the game is open). Read-only like every other check.
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include "win_util.hpp"

#include <iphlpapi.h>
#include <psapi.h>

#include <algorithm>
#include <map>
#include <set>

#include "../lag_names.hpp"
#include "../util.hpp"

namespace scan {
using namespace win;

namespace {

bool game_like(const std::string& l) {
    return ends_with(l, "javaw.exe") || ends_with(l, "\\java.exe") || l == "java.exe" || contains(l, "minecraft") ||
           contains(l, "lunar client") || contains(l, "lunarclient") || contains(l, "badlion") || contains(l, "feather");
}

// Programs that use WinDivert for something other than lag: DPI and
// censorship bypass tools, common in some countries.
bool dpi_bypass(const std::string& l) {
    return contains(l, "goodbyedpi") || contains(l, "winws") || contains(l, "zapret") || contains(l, "byedpi") ||
           contains(l, "dpi");
}

std::wstring since_xpath(const char* ids, double since_epoch) {
    double ms = std::max(60000.0, (now_epoch() - since_epoch) * 1000.0 + 60000.0);
    return widen(strf("*[System[(%s) and TimeCreated[timediff(@SystemTime) <= %.0f]]]", ids, ms));
}

std::string program_data() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return windows_dir().substr(0, 3) + "ProgramData";
    return narrow(buf, n);
}

std::string proc_label(const ProcInfo& p) {
    return (p.path.empty() ? p.name : p.path) + strf(" (PID %lu, started %s)", p.pid, fmt_time(p.start).c_str());
}

// Firewall rule text "v2.33|Action=Block|Dir=Out|App=...|" as key -> value.
std::map<std::string, std::string> parse_rule(const std::string& text) {
    std::map<std::string, std::string> out;
    for (const std::string& part : split(text, '|')) {
        size_t eq = part.find('=');
        if (eq == std::string::npos) continue;
        std::string key = lower(part.substr(0, eq));
        if (!out.count(key)) out[key] = part.substr(eq + 1);
    }
    return out;
}

bool port_listed(const std::string& ports, const char* port) {
    for (const std::string& p : split(ports, ',')) {
        std::string t = trim(p);
        if (t == port) return true;
        size_t dash = t.find('-');
        if (dash != std::string::npos) {
            int lo = atoi(t.substr(0, dash).c_str()), hi = atoi(t.substr(dash + 1).c_str()), v = atoi(port);
            if (lo > 0 && lo <= v && v <= hi && hi - lo < 1000) return true;
        }
    }
    return false;
}

}  // namespace

// ---------------------------------------------------------------------------
SCAN_CHECK(257, lag_tools, Scope::Boot, "Fake-lag and lag-switch tools: clumsy, WinDivert, NetLimiter, NetBalancer") {
    // 1. Lag tools running right now, one finding per tool. Names that are in
    //    the signature list are already reported by running_processes.
    std::map<std::string, std::pair<const LagTool*, std::vector<std::string>>> running;
    for (const ProcInfo& p : processes()) {
        const LagTool* t = match_lag_tool(lower(p.name));
        if (!t || !ctx.match_names(p.name).empty()) continue;
        running[t->label].first = t;
        running[t->label].second.push_back(proc_label(p));
    }
    for (const auto& r : running)
        ctx.add(r.second.first->sev, std::string(r.second.first->label) + " is running", r.second.first->what,
                join(r.second.second, "\n"));

    // 2. The WinDivert driver. It loads when a program opens it and stays
    //    loaded until the next reboot, so a loaded driver means some program
    //    used it this boot, even if that program is closed now.
    std::vector<LPVOID> bases(4096);
    DWORD needed = 0;
    std::string driver;
    if (EnumDeviceDrivers(bases.data(), static_cast<DWORD>(bases.size() * sizeof(LPVOID)), &needed)) {
        size_t n = std::min<size_t>(needed / sizeof(LPVOID), bases.size());
        for (size_t i = 0; i < n && driver.empty(); ++i) {
            wchar_t w[1024];
            if (GetDeviceDriverFileNameW(bases[i], w, 1024) && starts_with(lower(base_name(narrow(w))), "windivert"))
                driver = narrow(w);
        }
    } else {
        ctx.note("could not list kernel drivers");
    }

    if (!driver.empty()) {
        // Who has WinDivert.dll loaded right now.
        std::vector<std::pair<const ProcInfo*, std::string>> users;
        for (const ProcInfo& p : processes()) {
            if (p.pid <= 4) continue;
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, p.pid);
            if (!h) continue;
            HMODULE mods[1024];
            DWORD got = 0;
            if (EnumProcessModulesEx(h, mods, sizeof mods, &got, LIST_MODULES_ALL)) {
                for (DWORD i = 0; i < got / sizeof(HMODULE); ++i) {
                    wchar_t w[MAX_PATH * 2];
                    DWORD len = GetModuleFileNameExW(h, mods[i], w, MAX_PATH * 2);
                    if (len && starts_with(lower(base_name(narrow(w, len))), "windivert")) {
                        users.push_back({&p, narrow(w, len)});
                        break;
                    }
                }
            }
            CloseHandle(h);
        }
        for (const auto& u : users) {
            const ProcInfo& p = *u.first;
            std::string where = lower(p.path + " " + p.name + " " + u.second);
            const LagTool* t = match_lag_tool(where);
            std::string ev = proc_label(p) + "\nWinDivert: " + u.second;
            if (t && t->sev == Severity::Detection)
                ctx.add(Severity::Detection, "Fake-lag tool is intercepting network traffic: " + p.name,
                        std::string(t->what) + " It is using WinDivert to hold back or drop packets right now.", ev);
            else if (dpi_bypass(where))
                ctx.add(Severity::Integrity, "WinDivert used by a DPI bypass tool: " + p.name,
                        "Tools like GoodbyeDPI and zapret use WinDivert to get around internet censorship. That is normal in "
                        "some countries and does not delay packets, but the same driver is what clumsy uses.", ev);
            else
                ctx.add(Severity::Warning, "A program is intercepting network traffic with WinDivert: " + p.name,
                        "WinDivert lets a program hold back, drop or change every packet the PC sends, which is how "
                        "fake-lag tools work. Some VPNs and network tools use it too, so check what the program is." +
                            std::string(!p.path.empty() && user_writable_path(p.path) ? " It runs from a user folder." : ""),
                        ev);
        }
        if (users.empty())
            ctx.add(Severity::Warning, "WinDivert was used this boot",
                    "The WinDivert packet driver is loaded, but no running program uses it now. It stays loaded until "
                    "the next reboot, so a program that can delay or drop packets (clumsy, for example) ran this boot "
                    "and was closed. Look for it in the BAM, Prefetch and USN results.",
                    device_to_dos(driver));
    }

    // 3. Service installs of WinDivert. Windows logs event 7045 each time the
    //    driver is installed, with the path it was loaded from, so this shows
    //    where the tool sat even after its folder was deleted.
    struct Install { double last = 0; size_t count = 0; std::string name; };
    std::map<std::string, Install> installs;
    for (const Event& e : query_events(L"System", since_xpath("EventID=7045", now_epoch() - 14 * 86400.0), 500)) {
        std::string name = xml_data(e.xml, "ServiceName"), image = xml_data(e.xml, "ImagePath");
        if (!contains(lower(name + " " + image), "windivert")) continue;
        if (starts_with(image, "\\??\\")) image = image.substr(4);
        Install& in = installs[lower(image)];
        if (in.name.empty()) in.name = image;
        in.last = std::max(in.last, e.time);
        ++in.count;
    }
    for (const auto& it : installs) {
        const Install& in = it.second;
        std::string dir = dir_name(in.name);
        // What sits next to the driver tells you which tool it came with.
        std::vector<std::string> next_to;
        const LagTool* t = match_lag_tool(lower(in.name));
        for (const std::string& f : list_dir(dir)) {
            std::string l = lower(f);
            if (ext_of(l) != ".exe" && ext_of(l) != ".bat" && ext_of(l) != ".ahk") continue;
            if (next_to.size() < 8) next_to.push_back(f);
            if (!t) t = match_lag_tool(l);
        }
        bool since = ctx.since_boot(in.last);
        bool lag = t && t->sev == Severity::Detection;
        bool dpi = dpi_bypass(lower(in.name + " " + join(next_to, " ")));
        Severity sev = lag ? (since ? Severity::Detection : Severity::Warning) : dpi ? Severity::Integrity : Severity::Warning;
        std::string title = lag ? std::string(t->label) + " installed its packet driver"
                                : dpi ? "WinDivert installed by a DPI bypass tool" : "WinDivert packet driver was installed";
        std::string detail = strf("Windows logged the WinDivert driver being installed %zu time(s), last at ", in.count) +
                             fmt_time(in.last) + (since ? " (this boot)." : " (before this boot).") +
                             (lag ? std::string(" ") + t->what
                                  : " WinDivert is what fake-lag tools use to hold back packets. It is also used by VPNs and DPI "
                                    "bypass tools, so the folder it came from matters.") +
                             (file_exists(in.name) ? "" : " The driver file is no longer there.");
        std::string ev = in.name + (next_to.empty() ? "" : "\nPrograms in that folder: " + join(next_to));
        ctx.add(sev, title, detail, ev, since ? Scope::Boot : Scope::OutOfInstance);
    }

    // 4. NetLimiter rules or filters that name the game.
    for (const char* ver : {"5", "4"}) {
        std::string path = program_data() + "\\Locktime\\NetLimiter\\" + ver + "\\nl_settings.xml";
        std::string xml;
        if (!read_file(path, xml, 16u << 20)) continue;
        std::string l = lower(xml);
        std::vector<std::string> hits;
        bool block_or_limit = false;
        for (const char* g : {"javaw.exe", "java.exe", "minecraft", "lunar client", "badlion", "feather"}) {
            size_t pos = 0;
            while ((pos = l.find(g, pos)) != std::string::npos && hits.size() < 6) {
                size_t a = pos > 300 ? pos - 300 : 0;
                std::string around = l.substr(a, 700);
                block_or_limit = block_or_limit || contains(around, "block") || contains(around, "limit");
                size_t s = l.rfind('<', pos), e = l.find('>', pos);
                std::string tag = xml.substr(s == std::string::npos ? pos : s,
                                             (e == std::string::npos ? pos + 80 : e + 1) - (s == std::string::npos ? pos : s));
                if (std::find(hits.begin(), hits.end(), tag) == hits.end()) hits.push_back(cut(trim(tag), 240));
                pos += strlen(g);
            }
        }
        if (hits.empty()) continue;
        double t = file_mtime(path);
        bool since = ctx.since_boot(t);
        ctx.add(Severity::Warning,
                block_or_limit ? "NetLimiter has a limit or block rule for the game" : "NetLimiter settings name the game",
                std::string("NetLimiter's saved settings mention the game") +
                    (block_or_limit ? " next to a limit or block rule. Turning a rule like that on and off is a lag switch." : ".") +
                    " Open NetLimiter and look at the rules for Java. Settings last saved " + fmt_time(t) + ".",
                path + "\n" + join(hits, "\n"), since ? Scope::Boot : Scope::OutOfInstance);
    }

    ctx.add(Severity::Integrity, "Lag tools checked",
            driver.empty() ? "The WinDivert packet driver is not loaded, so no WinDivert-based tool (clumsy and others) ran this boot."
                           : "The WinDivert packet driver is loaded.",
            "", Scope::None);
}

// ---------------------------------------------------------------------------
SCAN_CHECK(258, lag_firewall, Scope::Boot, "Firewall rules that block the game's traffic (lag switch on a hotkey)") {
    // Windows' own prompt makes inbound rules for Java, which do not matter
    // for a client. An outbound block is what cuts the game off, and a script
    // or hotkey that switches it on and off is a lag switch.
    struct Store { const wchar_t* path; const char* label; };
    const Store stores[] = {
        {L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules", "local rules"},
        {L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\FirewallRules", "policy rules"},
    };
    std::set<std::string> game_rule_ids;
    size_t rules = 0;
    for (const Store& st : stores) {
        double key_time = reg_key_time(HKEY_LOCAL_MACHINE, st.path);
        for (const RegValue& v : reg_values(HKEY_LOCAL_MACHINE, st.path)) {
            ++rules;
            std::string text = v.text();
            std::map<std::string, std::string> r = parse_rule(text);
            if (lower(r["action"]) != "block" || lower(r["dir"]) != "out") continue;
            std::string app = lower(r["app"]);
            bool game = game_like(app);
            bool mc_port = port_listed(r["rport"], "25565");
            if (!game && !mc_port) continue;
            game_rule_ids.insert(lower(v.name));
            bool active = lower(r["active"]) != "false";
            ctx.add(Severity::Warning,
                    std::string("Outbound firewall rule blocks ") + (game ? "the game" : "Minecraft's server port") + ": " +
                        cut(r["name"].empty() ? v.name : r["name"], 80),
                    std::string("A rule that blocks the game from sending anything. Switched on for a second and off again "
                                "(a script or a hotkey does this), it freezes the player for everyone else: a lag switch. ") +
                        (active ? "The rule is switched ON right now, so the game should not be able to connect at all."
                                : "The rule is switched off, ready to be turned on.") +
                        " The firewall rule list last changed " + fmt_time(key_time) + ".",
                    std::string(st.label) + ": " + cut(text, 400),
                    ctx.since_boot(key_time) ? Scope::Boot : Scope::OutOfInstance);
        }
    }

    // Rule changes since boot that involve the game. The event IDs differ by
    // Windows version (2004/2005/2006 on older builds, 2097/2099/2052 on newer
    // ones), so read the rule out of each event instead of trusting the ID.
    std::vector<Event> events = query_events(L"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
                                             since_xpath("EventID=2004 or EventID=2005 or EventID=2006 or EventID=2052 or "
                                                         "EventID=2071 or EventID=2097 or EventID=2099",
                                                         ctx.boot_time > 0 ? ctx.boot_time : now_epoch() - 86400.0),
                                             3000);
    std::reverse(events.begin(), events.end());   // oldest first, so an add is seen before its delete
    std::vector<std::string> lines;
    std::set<std::string> tools;
    size_t changes = 0;
    for (const Event& e : events) {
        if (!ctx.since_boot(e.time)) continue;
        std::string id = lower(xml_data(e.xml, "RuleId")), name = xml_data(e.xml, "RuleName");
        std::string app = lower(xml_data(e.xml, "ApplicationPath")), dir = xml_data(e.xml, "Direction");
        std::string action = xml_data(e.xml, "Action"), by = xml_data(e.xml, "ModifyingApplication");
        bool known = !id.empty() && game_rule_ids.count(id);
        bool game = game_like(app) && dir != "1";   // 1 = inbound
        if (!known && !game) continue;
        if (!id.empty()) game_rule_ids.insert(id);
        ++changes;
        if (!by.empty()) tools.insert(base_name(by));
        if (lines.size() < 15)
            lines.push_back(fmt_time(e.time) + strf("  event %d  ", e.id) + cut(name, 60) +
                            (action == "2" ? "  [block]" : action == "3" ? "  [allow]" : "") +
                            (by.empty() ? "" : "  by " + by));
    }
    if (changes)
        ctx.add(changes >= 2 ? Severity::Detection : Severity::Warning,
                strf("Firewall rules for the game were changed %zu time(s) this boot", changes),
                "Outbound firewall rules for the game were added, changed or deleted after the PC started. Turning a block "
                "rule on and off is how a firewall lag switch works. Windows and launchers do not normally touch outbound "
                "rules for Java." +
                    (tools.empty() ? std::string() : " Changed by: " + join(std::vector<std::string>(tools.begin(), tools.end())) + "."),
                join(lines, "\n"));
    if (events.empty() && ctx.admin)
        ctx.note("no firewall rule change events since boot (or the firewall log is off)");
    ctx.add(Severity::Integrity, "Firewall rules checked",
            strf("%zu firewall rules read, %zu rule change event(s) since boot.", rules, events.size()), "", Scope::None);
}

// ---------------------------------------------------------------------------
SCAN_CHECK(259, lag_connection, Scope::Boot,
           "Connection made worse on purpose: QoS throttles, network card forced slow, tiny MTU, drops while playing") {
    // 1. Windows QoS policies with a throttle rate. Setting one on javaw.exe
    //    caps how fast the game can send, which works as constant fake lag.
    //    Priority-only (DSCP) policies are normal ping tweaks and are skipped.
    struct Root { HKEY hive; std::wstring path; std::string label; };
    std::vector<Root> roots = {{HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\QoS", "computer"}};
    for (const std::string& sid : user_sids())
        if (!contains(sid, "_Classes"))
            roots.push_back({HKEY_USERS, widen(sid) + L"\\Software\\Policies\\Microsoft\\Windows\\QoS", "user " + sid});
    size_t qos = 0;
    for (const Root& root : roots) {
        for (const std::string& pol : reg_subkeys(root.hive, root.path)) {
            ++qos;
            std::wstring key = root.path + L"\\" + widen(pol);
            std::map<std::string, std::string> vals;
            std::string ev;
            for (const RegValue& v : reg_values(root.hive, key)) {
                std::string t = v.type == REG_DWORD ? strf("%lu", v.dword()) : v.text();
                vals[lower(v.name)] = trim(t);
                ev += v.name + " = " + t + "\n";
            }
            std::string rate = vals["throttle rate"];
            if (rate.empty() || rate == "-1") continue;
            std::string app = lower(vals["application name"]);
            bool game = game_like(app) || port_listed(vals["remote port"], "25565");
            bool all = app.empty() || app == "*";
            if (!game && !all) continue;
            double t = reg_key_time(root.hive, key);
            bool since = ctx.since_boot(t);
            ctx.add(game ? Severity::Detection : Severity::Warning,
                    std::string("Windows QoS policy throttles ") + (game ? "the game's" : "all") + " traffic: " + pol,
                    "A QoS policy caps how fast " + std::string(game ? "the game" : "every program") +
                        " can send data, which makes the player lag for everyone else all the time. People set this "
                        "up to fake a bad connection. Policy last changed " + fmt_time(t) + ".",
                    root.label + " policy\n" + ev, since ? Scope::Boot : Scope::OutOfInstance);
        }
    }

    // 2. Active network adapters: speed, MTU and forced speed/duplex settings.
    struct Nic { std::string guid, name, desc; IFTYPE type; uint64_t tx, rx; ULONG mtu; };
    std::vector<Nic> nics;
    ULONG size = 32 * 1024;
    std::vector<unsigned char> buf;
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int i = 0; i < 4 && rc == ERROR_BUFFER_OVERFLOW; ++i) {
        buf.resize(size);
        rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                  nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &size);
    }
    if (rc == NO_ERROR) {
        for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()); a; a = a->Next) {
            if (a->OperStatus != IfOperStatusUp) continue;
            if (a->IfType != IF_TYPE_ETHERNET_CSMACD && a->IfType != IF_TYPE_IEEE80211) continue;
            Nic n;
            n.guid = lower(a->AdapterName);
            n.name = a->FriendlyName ? narrow(a->FriendlyName, wcslen(a->FriendlyName)) : "";
            n.desc = a->Description ? narrow(a->Description, wcslen(a->Description)) : "";
            n.type = a->IfType;
            n.tx = a->TransmitLinkSpeed;
            n.rx = a->ReceiveLinkSpeed;
            n.mtu = a->Mtu;
            nics.push_back(n);
        }
    } else {
        ctx.note("could not list network adapters");
    }

    std::vector<std::string> summary;
    for (const Nic& n : nics) {
        bool wifi = n.type == IF_TYPE_IEEE80211;
        auto known = [](uint64_t bps) { return bps != 0 && bps != static_cast<uint64_t>(-1); };
        auto mbps = [&](uint64_t bps) { return known(bps) ? strf("%.0f", bps / 1e6) : std::string("?"); };
        summary.push_back(strf("%s (%s, %s): %s Mbps down / %s Mbps up, MTU %lu", n.name.c_str(), wifi ? "Wi-Fi" : "Ethernet",
                               n.desc.c_str(), mbps(n.rx).c_str(), mbps(n.tx).c_str(), n.mtu));
        if (!wifi && known(n.tx) && n.tx <= 10000000)
            ctx.add(Severity::Warning, "Ethernet is connected at only 10 Mbps: " + n.name,
                    "A wired connection this slow is rare on a gaming PC. It happens with a bad cable, or when the network "
                    "card is set to 10 Mbps on purpose to add lag.",
                    summary.back());
        if (n.mtu > 0 && n.mtu < 1000)
            ctx.add(Severity::Warning, strf("Network MTU set very low (%lu): ", n.mtu) + n.name,
                    "The normal MTU is about 1500. A very small one splits every packet into pieces and makes the "
                    "connection worse. It is set by hand with netsh or a \"network tweak\" tool.",
                    summary.back());
    }

    // Forced speed and duplex in the network card's driver settings.
    // *SpeedDuplex: 0 auto, 1 10M half, 2 10M full, 3 100M half.
    const std::wstring cls = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}";
    for (const std::string& sub : reg_subkeys(HKEY_LOCAL_MACHINE, cls)) {
        std::wstring key = cls + L"\\" + widen(sub);
        RegValue id, speed, desc;
        if (!reg_get(HKEY_LOCAL_MACHINE, key, L"NetCfgInstanceId", id)) continue;
        std::string guid = lower(trim(id.text()));
        auto it = std::find_if(nics.begin(), nics.end(), [&](const Nic& n) { return n.guid == guid; });
        if (it == nics.end() || !reg_get(HKEY_LOCAL_MACHINE, key, L"*SpeedDuplex", speed)) continue;
        std::string s = trim(speed.type == REG_DWORD ? strf("%lu", speed.dword()) : speed.text());
        const char* what = s == "1" ? "10 Mbps half duplex" : s == "2" ? "10 Mbps full duplex" : s == "3" ? "100 Mbps half duplex" : nullptr;
        if (!what) continue;
        double t = reg_key_time(HKEY_LOCAL_MACHINE, key);
        bool since = ctx.since_boot(t);
        ctx.add(since ? Severity::Detection : Severity::Warning, std::string("Network card forced to ") + what + ": " + it->name,
                "The card's speed setting was changed from Auto to a slow fixed speed. Nobody needs this on a normal "
                "connection, and it is a known way to make yourself lag. Driver settings last changed " + fmt_time(t) + ".",
                it->desc + "\n*SpeedDuplex = " + s + "\nHKLM\\" + narrow(key), since ? Scope::Boot : Scope::OutOfInstance);
    }

    // 3. The connection dropping while the game is open. A pulled cable, a
    //    hotkey that disables the adapter and a hardware lag switch all log a
    //    "network disconnected" event. Bad Wi-Fi does too, so this is a lead.
    double game_start = 0;
    for (const ProcInfo& g : game_processes())
        if (g.start > 0 && (game_start == 0 || g.start < game_start)) game_start = g.start;
    if (game_start > 0) {
        std::vector<std::string> drops;
        for (const Event& e : query_events(L"Microsoft-Windows-NetworkProfile/Operational", since_xpath("EventID=10001", game_start), 500))
            if (e.time >= game_start) drops.push_back(fmt_time(e.time) + "  " + cut(xml_data(e.xml, "Name"), 60));
        std::reverse(drops.begin(), drops.end());
        if (drops.size() >= 3)
            ctx.add(Severity::Warning, strf("The network disconnected %zu times while the game was open", drops.size()),
                    "A lag switch (a button on the cable, or a hotkey that turns the adapter off) cuts the connection for "
                    "a moment and brings it back. Weak Wi-Fi does the same thing, so ask about it and compare with when "
                    "the player was lagging. Game started " + fmt_time(game_start) + ".",
                    join(drops, "\n"));
        else if (!drops.empty())
            ctx.add(Severity::Integrity, strf("The network disconnected %zu time(s) while the game was open", drops.size()),
                    "Game started " + fmt_time(game_start) + ".", join(drops, "\n"), Scope::None);
    }

    ctx.add(Severity::Integrity, "Network connection checked",
            strf("%zu QoS policies read. Connected adapters:", qos), summary.empty() ? "none found" : join(summary, "\n"),
            Scope::None);
}

}  // namespace scan
#endif

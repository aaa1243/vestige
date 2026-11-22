// Linux checks. Read-only. Most need root to see the game's memory map and
// environment when the game runs as another user.
#if defined(__linux__)
#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <set>
#include <unistd.h>

#include "../core.hpp"
#include "../lag_names.hpp"
#include "../posix_util.hpp"
#include "../util.hpp"

namespace scan {

bool platform_is_admin() { return geteuid() == 0; }

double platform_boot_time() {
    std::string up;
    if (!read_file("/proc/uptime", up, 256)) return 0;
    return now_epoch() - atof(up.c_str());
}

void platform_prepare(Context&) {}

namespace {

struct Proc {
    std::string pid, cmd, exe;
};

const char* const kAgentFlags[] = {"-javaagent:", "-agentpath:", "-agentlib:", "-xbootclasspath"};
// libraries that games legitimately preload on Linux
const char* const kKnownPreloads[] = {"gameoverlayrenderer", "libgamemode", "mangohud", "libstrangle",
                                      "obs-vkcapture", "libjemalloc"};

bool all_digits(const std::string& s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
}

// Java games and anything under Wine, decided by the program that is running
// and not by words in its arguments.
std::vector<Proc> game_procs() {
    std::vector<Proc> out;
    std::string self = std::to_string(getpid());
    for (const std::string& pid : list_dir("/proc")) {
        if (!all_digits(pid) || pid == self) continue;
        std::string raw;
        if (!read_file("/proc/" + pid + "/cmdline", raw, 1 << 20) || raw.empty()) continue;
        std::string argv0 = lower(base_name(raw.substr(0, raw.find('\0'))));
        char link[4096];
        ssize_t n = readlink(("/proc/" + pid + "/exe").c_str(), link, sizeof link - 1);
        std::string exe = n > 0 ? std::string(link, static_cast<size_t>(n)) : std::string();
        std::string exe_l = lower(base_name(exe));
        auto gamey = [](const std::string& s) {
            return starts_with(s, "java") || starts_with(s, "wine") || starts_with(s, "proton") ||
                   contains(s, "minecraft") || contains(s, "lunar");
        };
        if (!gamey(argv0) && !gamey(exe_l)) continue;
        std::string cmd = raw;
        std::replace(cmd.begin(), cmd.end(), '\0', ' ');
        out.push_back({pid, trim(cmd), exe});
    }
    return out;
}

bool risky_path(const std::string& l) {
    return starts_with(l, "/tmp/") || starts_with(l, "/dev/shm/") || starts_with(l, "/var/tmp/") ||
           contains(l, "/downloads/") || contains(l, "/desktop/");
}

}  // namespace

SCAN_CHECK(100, game_cmdline, Scope::InGame, "Java agents and cheat names on the game's launch command") {
    std::vector<Proc> procs = game_procs();
    if (procs.empty()) ctx.note("no Java or Wine process is running, so in-game checks were skipped");
    for (const Proc& p : procs) {
        std::string low = lower(p.cmd);
        for (const char* flag : kAgentFlags)
            if (contains(low, flag))
                ctx.add(Severity::Warning, "Java agent/boot flag on PID " + p.pid,
                        std::string("The launch command uses ") + flag +
                            " which loads code into the game. Some clients use their own agent, "
                            "so check which file it points at.",
                        cut(p.cmd, 1500));
        std::vector<std::string> strong = ctx.match_names(p.cmd);
        if (!strong.empty())
            ctx.add(Severity::Detection, "Known cheat name in the game command (PID " + p.pid + ")",
                    "Matched: " + join(strong) + ".", cut(p.cmd, 1500));
    }
}

SCAN_CHECK(110, game_environment, Scope::InGame, "LD_PRELOAD, ld.so.preload and Java option injection") {
    std::string pre;
    if (read_file("/etc/ld.so.preload", pre, 1 << 16) && !trim(pre).empty())
        ctx.add(Severity::Detection, "/etc/ld.so.preload is set",
                "A system-wide library preload. This file is normally missing or empty. Anything "
                "listed is loaded into every program that starts.", trim(pre));
    std::set<std::string> seen;
    for (const Proc& p : game_procs()) {
        std::string env;
        if (!read_file("/proc/" + p.pid + "/environ", env, 4 << 20)) {
            ctx.note("could not read the environment of PID " + p.pid + " (run as root)");
            continue;
        }
        for (const std::string& kv : split(env, '\0')) {
            size_t eq = kv.find('=');
            if (eq == std::string::npos) continue;
            std::string var = kv.substr(0, eq), val = trim(kv.substr(eq + 1));
            if (val.empty() || (var != "LD_PRELOAD" && var != "JAVA_TOOL_OPTIONS" && var != "_JAVA_OPTIONS"))
                continue;
            if (!seen.insert(kv).second) continue;
            std::string low = lower(val);
            Severity sev;
            std::string why;
            if (var == "LD_PRELOAD") {
                bool known = true;
                std::string tmp = low;
                std::replace(tmp.begin(), tmp.end(), ' ', ':');
                for (const std::string& part : split(tmp, ':')) {
                    if (part.empty()) continue;
                    bool k = false;
                    for (const char* kp : kKnownPreloads) k = k || contains(part, kp);
                    known = known && k;
                }
                if (!ctx.match_names(val).empty()) { sev = Severity::Detection; why = "It names a known cheat."; }
                else if (known) { sev = Severity::Integrity; why = "Only well-known overlay or performance libraries."; }
                else { sev = Severity::Warning; why = "A library is injected into the game. Check what the file is."; }
            } else {
                bool agent = false;
                for (const char* f : kAgentFlags) agent = agent || contains(low, f);
                sev = agent ? Severity::Detection : Severity::Integrity;
                why = agent ? "It loads a Java agent into every Java program." : "It only sets Java options, no agent.";
            }
            ctx.add(sev, var + " set on the game (PID " + p.pid + ")", why, var + "=" + val);
        }
    }
}

SCAN_CHECK(120, game_memory_map, Scope::InGame,
           "Deleted, fileless and injected libraries in the game's memory") {
    for (const Proc& p : game_procs()) {
        std::string maps;
        if (!read_file("/proc/" + p.pid + "/maps", maps, 64 << 20)) {
            ctx.note("could not read the memory map of PID " + p.pid + " (run as root)");
            continue;
        }
        int mem = open(("/proc/" + p.pid + "/mem").c_str(), O_RDONLY);
        std::set<std::string> seen;
        size_t anon_exec = 0, elf_hits = 0;
        for (const std::string& line : split(maps, '\n')) {
            // address perms offset dev inode path
            unsigned long long a = 0, b = 0;
            char perms[8] = {0};
            int consumed = 0;
            if (sscanf(line.c_str(), "%llx-%llx %7s %*s %*s %*s %n", &a, &b, perms, &consumed) < 3) continue;
            std::string path = consumed > 0 && static_cast<size_t>(consumed) < line.size()
                                   ? trim(line.substr(static_cast<size_t>(consumed))) : std::string();
            bool exec = strchr(perms, 'x') != nullptr;
            std::string low = lower(path);
            bool lib = contains(low, ".so") || contains(low, ".jar");

            if (contains(path, "(deleted)") && lib && !starts_with(path, "/memfd:")) {
                if (seen.insert(path).second)
                    ctx.add(Severity::Detection, "Deleted file still loaded in the game (PID " + p.pid + ")",
                            "A jar or library was loaded and then deleted from disk. It can be copied "
                            "back out of /proc/" + p.pid + "/map_files while the game is open.", path);
            } else if (exec && starts_with(path, "/memfd:")) {
                if (seen.insert(path).second)
                    ctx.add(Severity::Warning, "Fileless executable memory in the game (PID " + p.pid + ")",
                            "Code loaded from a memory-only file that never touched disk. Java does "
                            "not do this itself.", path);
            } else if (lib && !path.empty() && path[0] == '/') {
                std::vector<std::string> strong = ctx.match_names(base_name(path));
                if (!strong.empty()) {
                    if (seen.insert(path).second)
                        ctx.add(Severity::Detection, "Known cheat file loaded in the game (PID " + p.pid + ")",
                                "Matched: " + join(strong) + ".", path);
                } else if (exec && risky_path(low) && !contains(low, "lwjgl") && !contains(low, "natives") &&
                           !contains(low, "jna") && !contains(low, "netty")) {
                    if (seen.insert(path).second)
                        ctx.add(Severity::Warning, "Library from a temp or user folder loaded in the game (PID " + p.pid + ")",
                                "Launchers load from their own folders. Check what this file is.", path);
                }
            } else if (exec && path.empty()) {
                ++anon_exec;
                // an ELF header in anonymous executable memory is a library mapped by hand
                unsigned char hdr[4] = {0};
                if (mem >= 0 && pread(mem, hdr, 4, static_cast<off_t>(a)) == 4 &&
                    hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F') {
                    ++elf_hits;
                    ctx.add(Severity::Detection, "Library image in anonymous memory (PID " + p.pid + ")",
                            "A program image sits in memory with no file behind it, which is how "
                            "manually loaded libraries look.",
                            strf("address 0x%llx, size %llu bytes, %s", a, b - a, perms));
                }
            }
        }
        if (mem >= 0) close(mem);
        ctx.add(Severity::Integrity, "Game memory map read (PID " + p.pid + ")",
                strf("%zu anonymous executable regions (normal for Java's JIT), %zu with a library "
                     "image in them.", anon_exec, elf_hits));

        std::string status;
        if (read_file("/proc/" + p.pid + "/status", status, 1 << 16)) {
            size_t t = status.find("TracerPid:");
            if (t != std::string::npos) {
                int tracer = atoi(status.c_str() + t + 10);
                if (tracer > 0) {
                    std::string comm;
                    read_file("/proc/" + std::to_string(tracer) + "/comm", comm, 256);
                    ctx.add(Severity::Warning, "Another program is attached to the game (PID " + p.pid + ")",
                            "Something is debugging the game right now (ptrace). Injectors and memory "
                            "editors attach this way.",
                            strf("tracer PID %d (%s)", tracer, trim(comm).c_str()));
                }
            }
        }
    }
    std::string scope;
    if (read_file("/proc/sys/kernel/yama/ptrace_scope", scope, 16) && trim(scope) == "0")
        ctx.add(Severity::Integrity, "ptrace_scope is 0",
                "Any program can read and write another program's memory. Most distros default to 1.",
                "", Scope::None);
}

SCAN_CHECK(400, shell_history, Scope::OutOfInstance, "Shell history cleared, emptied or turned off") {
    for (const std::string& h : user_homes()) {
        for (const char* name : {".bash_history", ".zsh_history"}) {
            std::string hp = h + "/" + name;
            char link[512];
            ssize_t n = readlink(hp.c_str(), link, sizeof link - 1);
            if (n > 0 && std::string(link, static_cast<size_t>(n)) == "/dev/null") {
                ctx.add(Severity::Detection, std::string(name) + " linked to /dev/null",
                        "Shell history is being thrown away on purpose.", hp);
            } else if (file_exists(hp)) {
                std::string data;
                if (read_file(hp, data, 16) && data.empty())
                    ctx.add(Severity::Warning, std::string(name) + " is empty",
                            "Empty history on a PC that uses the terminal can mean it was cleared.", hp);
            }
        }
        for (const char* rc : {".bashrc", ".zshrc", ".profile", ".bash_profile"}) {
            std::string txt;
            if (!read_file(h + "/" + rc, txt, 1 << 20)) continue;
            if (contains(txt, "HISTFILE=/dev/null") || contains(txt, "HISTSIZE=0") ||
                contains(txt, "unset HISTFILE"))
                ctx.add(Severity::Warning, std::string("History turned off in ") + rc,
                        "A startup file turns off shell history.", h + "/" + rc);
        }
    }
}

SCAN_CHECK(410, system_logs, Scope::OutOfInstance, "System journal wiped or not kept") {
    std::string conf;
    bool volatile_logs = false;
    if (read_file("/etc/systemd/journald.conf", conf, 1 << 20)) {
        for (const std::string& line : split(conf, '\n')) {
            std::string l = lower(trim(line));
            l.erase(std::remove(l.begin(), l.end(), ' '), l.end());
            if (starts_with(l, "storage=volatile") || starts_with(l, "storage=none")) volatile_logs = true;
        }
    }
    if (volatile_logs)
        ctx.add(Severity::Warning, "The system journal is not kept on disk",
                "journald is set to keep logs in memory only, so there is no log history to check. "
                "Some distros ship this way.", "/etc/systemd/journald.conf");
    std::string boots = run_cmd("journalctl --list-boots --no-pager");
    if (!boots.empty() && !volatile_logs) {
        size_t n = 0;
        for (const std::string& l : split(boots, '\n'))
            if (!trim(l).empty() && !contains(l, "IDX")) ++n;
        if (n <= 1)
            ctx.add(Severity::Warning, "Only one boot in the system journal",
                    "On a PC that has been used for a while, a journal holding only the current "
                    "boot can mean it was cleared.", strf("%zu boot(s) listed", n));
    }
}

SCAN_CHECK(500, autostart, Scope::OutOfInstance, "Cron jobs, user services and autostart entries") {
    auto suspicious = [&](const std::string& text) -> std::string {
        std::vector<std::string> hits = ctx.match_names(text);
        std::string low = lower(text);
        for (const char* s : {".jar", "/tmp/", "/dev/shm", "ld_preload"})
            if (contains(low, s)) hits.push_back(s);
        return join(hits);
    };
    for (const std::string& line : split(run_cmd("crontab -l"), '\n')) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        std::string why = suspicious(t);
        if (!why.empty())
            ctx.add(Severity::Warning, "Cron job worth checking", "References: " + why + ".", t);
    }
    for (const std::string& h : user_homes()) {
        for (const char* sub : {"/.config/systemd/user", "/.config/autostart"}) {
            std::string dir = h + sub;
            for (const std::string& f : list_dir(dir)) {
                std::string txt;
                if (!read_file(dir + "/" + f, txt, 1 << 20)) continue;
                std::string why = suspicious(txt);
                if (!why.empty())
                    ctx.add(Severity::Warning, "Autostart entry worth checking: " + f,
                            "Runs at login and references: " + why + ".", dir + "/" + f);
            }
        }
    }
}

SCAN_CHECK(510, kernel_state, Scope::None, "Tainted kernel and out-of-tree modules") {
    std::string taint;
    if (read_file("/proc/sys/kernel/tainted", taint, 64) && trim(taint) != "0" && !trim(taint).empty())
        ctx.add(Severity::Integrity, "Kernel is tainted (value " + trim(taint) + ")",
                "An unsigned or out-of-tree module was loaded at some point. NVIDIA and VirtualBox "
                "do this too, so it is only a lead.");
    std::string mods;
    if (read_file("/proc/modules", mods, 4 << 20)) {
        for (const std::string& line : split(mods, '\n')) {
            std::string name = line.substr(0, line.find(' '));
            std::vector<std::string> strong = ctx.match_names(name);
            if (!strong.empty())
                ctx.add(Severity::Detection, "Kernel module named like a known cheat: " + name,
                        "Matched: " + join(strong) + ".", line);
        }
    }
}

// ---------------------------------------------------------------------------
// Fake lag on Linux: netem (part of tc) adds delay and packet loss to a
// network card, and a firewall rule can drop a random share of packets.
SCAN_CHECK(520, lag_tools, Scope::Boot, "Fake lag: netem delay or loss, speed caps, random packet drops, lag tools running") {
    std::string tc_bin;
    for (const char* p : {"/usr/sbin/tc", "/sbin/tc", "/usr/bin/tc", "/bin/tc"})
        if (file_exists(p)) { tc_bin = p; break; }
    if (tc_bin.empty()) {
        ctx.note("tc is not installed, so netem delay could not be checked");
    } else {
        for (const std::string& raw : split(run_cmd(tc_bin + " qdisc show"), '\n')) {
            std::string line = trim(raw), l = lower(line);
            std::string dev;
            size_t d = l.find(" dev ");
            if (d != std::string::npos) dev = line.substr(d + 5, line.find(' ', d + 5) - (d + 5));
            if (dev == "lo") continue;
            if (contains(l, "qdisc netem")) {
                bool bad = contains(l, " delay ") || contains(l, " loss ") || contains(l, " duplicate ") ||
                           contains(l, " reorder ") || contains(l, " corrupt ") || contains(l, " rate ");
                ctx.add(bad ? Severity::Detection : Severity::Warning, "netem is set on network device " + dev,
                        "netem is a Linux tool for faking a bad network: it adds delay, packet loss and reordering to "
                        "everything the device sends. Developers use it for testing; on a gaming PC it is fake lag.",
                        line);
            } else if (contains(l, "qdisc tbf") || (contains(l, "qdisc htb") && !contains(l, "dev ifb"))) {
                ctx.add(Severity::Warning, "Traffic on " + dev + " is speed capped",
                        "A traffic shaper (tbf or htb) limits how fast this device can send. A low cap makes the game lag. "
                        "Some routers and VPN setups use shapers for real reasons.",
                        line);
            }
        }
    }

    if (ctx.admin) {
        std::string rules;
        std::string tables;
        if (read_file("/proc/net/ip_tables_names", tables, 4096) && !trim(tables).empty())   // tables already exist, so nothing gets loaded
            for (const char* p : {"/usr/sbin/iptables-save", "/sbin/iptables-save"})
                if (file_exists(p)) { rules += run_cmd(p); break; }
        for (const char* p : {"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"})
            if (file_exists(p)) { rules += run_cmd(std::string(p) + " list ruleset"); break; }
        std::vector<std::string> hits;
        for (const std::string& raw : split(rules, '\n')) {
            std::string l = lower(raw);
            bool random = contains(l, "statistic") || contains(l, "numgen random");
            if (random && (contains(l, "drop") || contains(l, "reject")) && hits.size() < 10) hits.push_back(trim(raw));
        }
        if (!hits.empty())
            ctx.add(Severity::Detection, "A firewall rule drops a random share of packets",
                    "Dropping packets at random is fake packet loss: the player rubber-bands and is hard to hit. "
                    "Normal firewalls do not do this.",
                    join(hits, "\n"));
    } else {
        ctx.note("run with sudo to check firewall rules for random packet drops");
    }

    std::string self = std::to_string(getpid());
    std::set<std::string> seen;
    for (const std::string& pid : list_dir("/proc")) {
        if (!all_digits(pid) || pid == self) continue;
        std::string raw;
        if (!read_file("/proc/" + pid + "/cmdline", raw, 1 << 16) || raw.empty()) continue;
        // Only the program's own name, and the .exe a Wine process runs. Words
        // in other arguments (a file being edited, say) do not count.
        std::vector<std::string> args = split(raw, '\0');
        const LagTool* t = match_lag_tool(lower(base_name(args[0])));
        for (size_t i = 1; !t && i < args.size() && i < 4; ++i)
            if (ends_with(lower(args[i]), ".exe")) t = match_lag_tool(lower(base_name(args[i])));
        std::replace(raw.begin(), raw.end(), '\0', ' ');
        if (t && seen.insert(t->label).second)
            ctx.add(t->sev, std::string(t->label) + " is running", t->what, "PID " + pid + ": " + cut(trim(raw), 300));
    }
}

}  // namespace scan
#endif

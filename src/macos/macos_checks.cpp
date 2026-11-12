// macOS checks. Read-only. Uses the system's own tools (ps, lsof, csrutil,
// launchctl) with fixed arguments. Run with sudo to see other users' processes.
#if defined(__APPLE__)
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>

#include <algorithm>
#include <cstring>
#include <set>
#include <unistd.h>

#include "../core.hpp"
#include "../posix_util.hpp"
#include "../util.hpp"

namespace scan {

bool platform_is_admin() { return geteuid() == 0; }

double platform_boot_time() {
    struct timeval tv;
    size_t len = sizeof tv;
    if (sysctlbyname("kern.boottime", &tv, &len, nullptr, 0) != 0) return 0;
    return static_cast<double>(tv.tv_sec) + tv.tv_usec / 1e6;
}

void platform_prepare(Context&) {}

namespace {

struct Proc {
    std::string pid, cmd;
};

const char* const kAgentFlags[] = {"-javaagent:", "-agentpath:", "-agentlib:", "-xbootclasspath"};

std::vector<Proc> game_procs() {
    std::vector<Proc> out;
    std::string self = std::to_string(getpid());
    for (const std::string& raw : split(run_cmd("/bin/ps -axww -o pid=,command="), '\n')) {
        std::string line = trim(raw);
        size_t sp = line.find(' ');
        if (sp == std::string::npos) continue;
        std::string pid = line.substr(0, sp), cmd = trim(line.substr(sp + 1));
        if (pid == self || cmd.empty()) continue;
        std::string first = lower(cmd.substr(0, cmd.find(" -")));
        std::string prog = lower(base_name(cmd.substr(0, cmd.find(' '))));
        bool java = prog == "java" || ends_with(first, "/java") || contains(first, "/bin/java");
        bool named = contains(first, "minecraft") || contains(first, "lunar client") || contains(first, "badlion") ||
                     contains(first, "feather");
        if (!java && !named) continue;
        if (contains(first, "launcher") && !java) continue;
        out.push_back({pid, cmd});
    }
    return out;
}

bool risky_path(const std::string& l) {
    return starts_with(l, "/tmp/") || starts_with(l, "/private/tmp/") || starts_with(l, "/var/tmp/") ||
           starts_with(l, "/private/var/tmp/") || starts_with(l, "/users/shared/") ||
           contains(l, "/downloads/") || contains(l, "/desktop/") || contains(l, "/documents/") ||
           contains(l, "/.trash/");
}

bool known_lib(const std::string& l) {
    for (const char* k : {"lwjgl", "natives", "jna", "jinput", "openal", "glfw", "netty", "sqlite", "jansi", "oshi",
                          "sodium", "iris", "voicechat", "opus", "lunar", "badlion", "feather", "jcef", "skija",
                          "/library/java/", "/jre", "/jdk", "/runtime/", "zulu", "temurin"})
        if (contains(l, k)) return true;
    return false;
}

// Environment of a process as "ps" shows it: the words after the command that
// look like NAME=value. Only visible for your own processes unless root.
std::string env_value(const std::string& ps_line, const std::string& var) {
    std::string key = " " + var + "=";
    size_t p = ps_line.find(key);
    if (p == std::string::npos) return std::string();
    size_t start = p + key.size();
    size_t end = ps_line.find(' ', start);
    return ps_line.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

}  // namespace

// ---------------------------------------------------------------------------
SCAN_CHECK(10, integrity_system, Scope::None, "Boot time, System Integrity Protection and Gatekeeper") {
    double up = now_epoch() - ctx.boot_time;
    ctx.add(Severity::Integrity, "Last boot: " + fmt_time(ctx.boot_time),
            strf("Up for %.1f hours. Findings tagged Boot happened after this time.", up / 3600));
    if (ctx.boot_time > 0 && up < 15 * 60)
        ctx.add(Severity::Warning, "The Mac was restarted less than 15 minutes ago",
                "A restart right before a screenshare clears everything held in memory. Ask when and why.");
    std::string sip = lower(run_cmd("/usr/bin/csrutil status"));
    if (contains(sip, "disabled"))
        ctx.add(Severity::Warning, "System Integrity Protection is off",
                "With SIP off, programs can inject into other programs and load unsigned kernel code. "
                "Developers turn it off sometimes; most people never do.", trim(sip));
    else if (contains(sip, "enabled"))
        ctx.add(Severity::Integrity, "System Integrity Protection is on", "");
    std::string gk = lower(run_cmd("/usr/sbin/spctl --status"));
    if (contains(gk, "disabled"))
        ctx.add(Severity::Warning, "Gatekeeper is off", "Unsigned apps run without a prompt.", trim(gk));
    if (!ctx.admin)
        ctx.add(Severity::Warning, "The scan is not running with sudo",
                "Without sudo the scanner cannot see the environment or open files of the game if it "
                "runs as another user, and some folders are unreadable.");
    if (game_procs().empty())
        ctx.add(Severity::Warning, "No running Minecraft was found",
                "The in-game checks need the game open. Have the player open the game they were playing on, then scan again.");
}

// ---------------------------------------------------------------------------
SCAN_CHECK(100, game_cmdline, Scope::InGame, "Java agents and cheat names on the game's launch command") {
    for (const Proc& p : game_procs()) {
        std::string low = lower(p.cmd);
        ctx.add(Severity::Integrity, "Game process found (PID " + p.pid + ")", "", cut(p.cmd, 600));
        for (const char* flag : kAgentFlags)
            if (contains(low, flag))
                ctx.add(Severity::Warning, "Java agent/boot flag on PID " + p.pid,
                        std::string("The launch command uses ") + flag + " which loads code into the game. Some "
                        "clients use their own agent, so check which file it points at.", cut(p.cmd, 1500));
        std::vector<std::string> strong = ctx.match_names(p.cmd);
        if (!strong.empty())
            ctx.add(Severity::Detection, "Known cheat name in the game command (PID " + p.pid + ")",
                    "Matched: " + join(strong) + ".", cut(p.cmd, 1500));
    }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(110, game_environment, Scope::InGame, "DYLD_INSERT_LIBRARIES and Java option injection") {
    static const char* const vars[] = {"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
                                       "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"};
    for (const Proc& p : game_procs()) {
        if (!std::all_of(p.pid.begin(), p.pid.end(), ::isdigit)) continue;
        std::string line = " " + trim(run_cmd("/bin/ps eww -o command= -p " + p.pid));
        for (const char* var : vars) {
            std::string val = env_value(line, var);
            if (val.empty()) continue;
            std::string lv = lower(val), v = var;
            bool dyld_insert = v == "DYLD_INSERT_LIBRARIES";
            bool java_agent = !starts_with(v, "DYLD") && (contains(lv, "-javaagent") || contains(lv, "-agentpath") || contains(lv, "-agentlib"));
            Severity sev = (dyld_insert && !known_lib(lv)) || java_agent ? Severity::Detection : Severity::Warning;
            if (!dyld_insert && !java_agent && starts_with(v, "DYLD") && known_lib(lv)) sev = Severity::Integrity;
            ctx.add(sev, v + " is set for the game (PID " + p.pid + ")",
                    dyld_insert ? "This variable makes the listed library load into the game when it starts. It is the "
                                  "standard way to inject a library on macOS."
                                : "This variable changes what the game loads at start.",
                    v + "=" + cut(val, 400));
        }
    }
    // Variables set for every app the user starts.
    for (const char* var : vars) {
        std::string val = trim(run_cmd(std::string("/bin/launchctl getenv ") + var));
        if (val.empty()) continue;
        std::string lv = lower(val), v = var;
        bool bad = v == "DYLD_INSERT_LIBRARIES" || contains(lv, "-javaagent") || contains(lv, "-agentpath") || contains(lv, "-agentlib");
        ctx.add(bad ? Severity::Detection : Severity::Warning, v + " is set for every app (launchctl)",
                "Set with launchctl setenv, so every app started after it inherits it, the game included.",
                v + "=" + cut(val, 400), Scope::Boot);
    }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(120, game_libraries, Scope::InGame, "Libraries and jars the game has open from unusual places") {
    for (const Proc& p : game_procs()) {
        if (!std::all_of(p.pid.begin(), p.pid.end(), ::isdigit)) continue;
        std::string out = run_cmd("/usr/sbin/lsof -p " + p.pid + " -Fn");
        if (out.empty()) {
            ctx.note("could not list open files of PID " + p.pid + " (run with sudo)");
            continue;
        }
        std::set<std::string> seen;
        size_t libs = 0, flagged = 0;
        bool instrument = false;
        for (const std::string& raw : split(out, '\n')) {
            if (raw.size() < 2 || raw[0] != 'n') continue;
            std::string path = raw.substr(1), l = lower(path);
            std::string ext = ext_of(l);
            if (ext != ".dylib" && ext != ".jar" && ext != ".jnilib" && ext != ".so" && ext != ".bundle") continue;
            if (!seen.insert(l).second) continue;
            ++libs;
            if (ends_with(l, "/libinstrument.dylib")) instrument = true;
            std::vector<std::string> strong = ctx.match_names(base_name(path));
            if (!strong.empty()) {
                ++flagged;
                ctx.add(Severity::Detection, "Known cheat file open in the game (PID " + p.pid + ")", "Matched: " + join(strong) + ".", path);
            } else if (!file_exists(path) && path[0] == '/') {
                ++flagged;
                ctx.add(Severity::Warning, "The game has a library or jar open that is gone from disk (PID " + p.pid + ")",
                        "The file was deleted or moved after the game loaded it.", path);
            } else if (risky_path(l) && !known_lib(l)) {
                ++flagged;
                ctx.add(Severity::Warning, "The game loaded a library or jar from a user or temp folder (PID " + p.pid + ")",
                        "Launchers load from their own folders. A file from Downloads, Desktop, Documents or /tmp should be checked.", path);
            }
        }
        std::string low = lower(p.cmd);
        if (instrument && !contains(low, "-javaagent"))
            ctx.add(Severity::Detection, "A Java agent was attached to the running game (PID " + p.pid + ")",
                    "Java's instrument library is loaded but the game was not started with an agent, so one was "
                    "attached while it was running. That is how injectable Java cheats load. A few mods attach to "
                    "themselves.");
        ctx.add(Severity::Integrity, "Game libraries checked (PID " + p.pid + ")", strf("%zu libraries and jars open, %zu flagged.", libs, flagged),
                "", Scope::None);
    }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(400, downloads_quarantine, Scope::OutOfInstance, "Cheat sites in the download quarantine records") {
    if (ctx.sigs.domains.empty()) return;
    size_t read = 0;
    for (const std::string& h : user_homes()) {
        std::string path = h + "/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2";
        std::string data;
        if (!read_file(path, data, 64u << 20) || data.empty()) continue;
        ++read;
        lower_inplace(data);
        std::vector<std::string> hit;
        for (const Sig& s : ctx.sigs.domains)
            if (data.find(s.value) != std::string::npos) hit.push_back(s.label + " (" + s.value + ")");
        if (!hit.empty())
            ctx.add(Severity::Warning, "A file was downloaded from a cheat site",
                    "macOS records where every downloaded file came from. These addresses are in that record: " + join(hit) +
                        ". It shows a download at some point, not that the file was used.", path);
    }
    if (read) ctx.add(Severity::Integrity, "Download records checked", strf("%zu quarantine database(s) searched.", read), "", Scope::None);
    else ctx.note("download quarantine records could not be read (Terminal may need Full Disk Access)");
}

// ---------------------------------------------------------------------------
SCAN_CHECK(410, trash, Scope::Boot, "Files in the Trash") {
    for (const std::string& h : user_homes()) {
        std::string dir = h + "/.Trash";
        std::vector<std::string> recent;
        for (const std::string& f : list_dir(dir)) {
            if (f == ".DS_Store") continue;
            std::string path = dir + "/" + f;
            double mt = file_mtime(path);
            std::vector<std::string> strong = ctx.match_names(f);
            bool since = ctx.since_boot(mt);
            if (!strong.empty())
                ctx.add(Severity::Warning, "Known cheat name in the Trash: " + f,
                        "Matched: " + join(strong) + ". Modified " + fmt_time(mt) + ".", path, since ? Scope::Boot : Scope::OutOfInstance);
            std::string ext = ext_of(f);
            if (since && (ext == ".jar" || ext == ".dylib" || ext == ".app" || ext == ".dmg" || ext == ".zip" || ext == ".command") && recent.size() < 15)
                recent.push_back(f);
        }
        if (!recent.empty())
            ctx.add(Severity::Warning, "Programs or jars in the Trash were changed this boot",
                    "The modified time is from before the file was trashed, so this is a lead only. Empty Trash "
                    "cannot be seen at all.", join(recent) + " in " + dir);
    }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(420, shell_history, Scope::OutOfInstance, "Shell history cleared or turned off, and cheat names in it") {
    for (const std::string& h : user_homes()) {
        for (const char* name : {".zsh_history", ".bash_history"}) {
            std::string path = h + "/" + name;
            char link[1024];
            ssize_t n = readlink(path.c_str(), link, sizeof link - 1);
            if (n > 0 && std::string(link, static_cast<size_t>(n)) == "/dev/null") {
                ctx.add(Severity::Detection, std::string(name) + " points at /dev/null", "Commands are thrown away instead of saved.", path);
                continue;
            }
            std::string text;
            if (!read_file(path, text, 16u << 20)) continue;
            std::vector<std::string> hits;
            for (const std::string& raw : split(text, '\n')) {
                std::string l = lower(raw);
                if (contains(l, "dyld_insert_libraries") || contains(l, "history -c") || contains(l, "unset histfile") ||
                    contains(l, "-javaagent") || contains(l, "csrutil disable") || !ctx.match_names(l).empty())
                    if (hits.size() < 12) hits.push_back(trim(cut(raw, 200)));
            }
            if (!hits.empty())
                ctx.add(Severity::Warning, std::string("Commands worth reading in ") + name,
                        "These lines mention injection variables, history clearing or a known cheat name.", join(hits, " | "));
        }
        for (const char* rc : {".zshrc", ".zprofile", ".bash_profile", ".bashrc", ".zshenv"}) {
            std::string text;
            if (!read_file(h + "/" + rc, text, 1u << 20)) continue;
            std::string l = lower(text);
            if (contains(l, "dyld_insert_libraries") || contains(l, "java_tool_options") || contains(l, "_java_options"))
                ctx.add(Severity::Warning, std::string(rc) + " sets an injection variable",
                        "The shell start-up file sets DYLD_INSERT_LIBRARIES or Java options for everything started from Terminal.",
                        h + "/" + rc);
            if (contains(l, "histsize=0") || contains(l, "histfile=/dev/null") || contains(l, "unset histfile") || contains(l, "savehist=0"))
                ctx.add(Severity::Warning, std::string(rc) + " turns shell history off", "", h + "/" + rc);
        }
    }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(500, launch_items, Scope::OutOfInstance, "Launch agents and daemons that start by themselves") {
    std::vector<std::string> dirs = {"/Library/LaunchAgents", "/Library/LaunchDaemons"};
    for (const std::string& h : user_homes()) dirs.push_back(h + "/Library/LaunchAgents");
    size_t count = 0;
    for (const std::string& dir : dirs)
        for (const std::string& f : list_dir(dir)) {
            if (ext_of(f) != ".plist") continue;
            ++count;
            std::string path = dir + "/" + f, data;
            if (!read_file(path, data, 1u << 20)) continue;
            std::vector<std::string> strs;
            extract_strings(data.data(), data.size(), 4, strs);   // works for XML and binary plists
            std::string joined = lower(join(strs, " "));
            double mt = file_mtime(path);
            Scope sc = ctx.since_boot(mt) ? Scope::Boot : Scope::OutOfInstance;
            std::vector<std::string> strong = ctx.match_names(f + " " + joined);
            if (!strong.empty())
                ctx.add(Severity::Detection, "Launch item with a known cheat name: " + f, "Matched: " + join(strong) + ".", path, sc);
            else if (contains(joined, "dyld_insert_libraries") || contains(joined, "java_tool_options") || contains(joined, "-javaagent"))
                ctx.add(Severity::Detection, "Launch item sets an injection variable: " + f,
                        "It sets DYLD_INSERT_LIBRARIES or Java agent options when it runs.", path, sc);
            else if (contains(joined, "/tmp/") || contains(joined, "/users/shared/") || contains(joined, "/downloads/") ||
                     contains(joined, "curl ") || contains(joined, "base64") || contains(joined, "osascript"))
                ctx.add(Severity::Warning, "Launch item runs from a temp or user folder, or runs a script: " + f,
                        "Modified " + fmt_time(mt) + ". Check what it starts.", path, sc);
            else if (ctx.since_boot(mt))
                ctx.add(Severity::Integrity, "Launch item changed this boot: " + f, "Modified " + fmt_time(mt) + ".", path, Scope::Boot);
        }
    ctx.add(Severity::Integrity, "Launch items checked", strf("%zu plist files.", count), "", Scope::None);
}

}  // namespace scan
#endif

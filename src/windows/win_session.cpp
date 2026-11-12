// Injection evidence that outlives the moment of injection: when each DLL was
// loaded into the game, Java agent state, debuggers, game crashes that list
// loaded modules, code integrity and Defender events.
#ifdef _WIN32
#include "win_util.hpp"

#include <algorithm>
#include <map>
#include <set>

#include "../util.hpp"

namespace scan {
using namespace win;

namespace {

struct Opened {
    ProcInfo info;
    HANDLE h;
};
std::vector<Opened> open_games() {
    std::vector<Opened> out;
    for (const ProcInfo& p : game_processes()) {
        HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, p.pid);
        if (h) out.push_back({p, h});
    }
    return out;
}

struct LdrMod {
    uint64_t base = 0;
    std::string path;
    double load_time = 0;
};

// Walks the loader's module list in the game and reads each entry's LoadTime.
std::vector<LdrMod> ldr_modules(HANDLE h) {
    std::vector<LdrMod> out;
    BOOL wow = FALSE;
    if (IsWow64Process(h, &wow) && wow) return out;   // 32-bit Java: different layout, skipped
    typedef LONG(NTAPI * QueryProc)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    QueryProc query = reinterpret_cast<QueryProc>(nt_proc("NtQueryInformationProcess"));
    if (!query) return out;
    struct { uint64_t exit_status, peb, affinity, priority, pid, parent; } pbi{};
    if (query(h, 0, &pbi, sizeof(pbi), nullptr) < 0 || !pbi.peb) return out;
    uint64_t ldr = 0;
    if (!read_mem(h, pbi.peb + 0x18, &ldr, 8) || !ldr) return out;
    uint64_t head = ldr + 0x10, cur = 0;
    if (!read_mem(h, head, &cur, 8)) return out;
    for (int guard = 0; cur && cur != head && guard < 4096; ++guard) {
        unsigned char e[0x110];
        if (!read_mem(h, cur, e, sizeof e)) break;
        LdrMod m;
        memcpy(&m.base, e + 0x30, 8);
        uint16_t len = 0;
        uint64_t buf = 0, lt = 0;
        memcpy(&len, e + 0x48, 2);
        memcpy(&buf, e + 0x50, 8);
        memcpy(&lt, e + 0x100, 8);
        if (len && len < 2048 && buf) {
            std::vector<wchar_t> w(len / 2);
            if (read_mem(h, buf, w.data(), len)) m.path = narrow(w.data(), w.size());
        }
        m.load_time = ft_to_epoch(lt);
        if (m.base) out.push_back(std::move(m));
        memcpy(&cur, e, 8);
    }
    return out;
}

bool lazy_native(const std::string& l) {
    for (const char* k : {"lwjgl", "natives", "jna", "jinput", "openal", "glfw", "netty", "sqlite", "jansi", "oshi",
                          "sodium", "iris", "voicechat", "opus", "rnnoise", "webrtc", "jcef", "skija", "imgui",
                          "zstd", "lz4", "\\jre", "\\jdk", "\\runtime\\", "\\java\\"})
        if (contains(l, k)) return true;
    return false;
}

// All <Data> values of an event, in order.
std::vector<std::string> data_values(const std::string& xml) {
    std::vector<std::string> out;
    size_t p = 0;
    while ((p = xml.find("<Data", p)) != std::string::npos) {
        size_t gt = xml.find('>', p);
        if (gt == std::string::npos) break;
        if (xml[gt - 1] == '/') { out.emplace_back(); p = gt; continue; }
        size_t lt = xml.find("</Data>", gt);
        if (lt == std::string::npos) break;
        out.push_back(xml.substr(gt + 1, lt - gt - 1));
        p = lt;
    }
    return out;
}

std::wstring recent_xpath(const Context& ctx, const char* ids, double max_age_days) {
    double ms = max_age_days * 86400000.0;
    (void)ctx;
    return widen(strf("*[System[(%s) and TimeCreated[timediff(@SystemTime) <= %.0f]]]", ids, ms));
}

bool java_name(const std::string& l) {
    return contains(l, "javaw.exe") || contains(l, "java.exe") || contains(l, "minecraft") || contains(l, "lunar client");
}

std::string read_utf16_file(const std::string& path, size_t max) {
    std::string raw;
    if (!read_file(path, raw, max)) return std::string();
    if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xFF && static_cast<unsigned char>(raw[1]) == 0xFE)
        return narrow(reinterpret_cast<const wchar_t*>(raw.data() + 2), (raw.size() - 2) / 2);
    return raw;
}

}  // namespace

// ---------------------------------------------------------------------------
SCAN_CHECK(105, game_agents, Scope::InGame, "Java agents, debuggers and attach state of the running game") {
    typedef LONG(NTAPI * QueryProc)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    QueryProc query = reinterpret_cast<QueryProc>(nt_proc("NtQueryInformationProcess"));
    for (Opened& g : open_games()) {
        std::string cmd = lower(remote_cmdline(g.h));
        bool cmd_agent = contains(cmd, "-javaagent") || contains(cmd, "-agentpath") || contains(cmd, "-agentlib");
        bool cmd_debug = contains(cmd, "jdwp") || contains(cmd, "-xdebug");
        bool instrument = false, jdwp = false, attach = false;
        std::string instrument_path;
        double instrument_time = 0;
        for (const LdrMod& m : ldr_modules(g.h)) {
            std::string b = lower(base_name(m.path));
            if (b == "instrument.dll") { instrument = true; instrument_path = m.path; instrument_time = m.load_time; }
            if (b == "jdwp.dll" || b == "dt_socket.dll" || b == "dt_shmem.dll") jdwp = true;
            if (b == "attach.dll") attach = true;
        }
        if (instrument && !cmd_agent) {
            double after = instrument_time - g.info.start;
            ctx.add(Severity::Detection, strf("A Java agent was attached to the running game (PID %lu)", g.info.pid),
                    "Java's instrument library is loaded, which only happens when a Java agent is used, but "
                    "the game was not started with one. So an agent was attached while the game was running. "
                    "That is how most injectable Java cheats get in. Some launchers and mods that reload "
                    "classes also do it." +
                        (instrument_time > 0 && after >= 0 && after < 86400 * 30
                             ? " Loaded " + fmt_time(instrument_time) + strf(", %.0f seconds after the game started.", after)
                             : std::string()),
                    instrument_path);
        } else if (instrument) {
            ctx.add(Severity::Integrity, strf("Java agent library is loaded (PID %lu)", g.info.pid),
                    "The game was started with an agent flag, so this is expected. The agent itself is listed "
                    "under the game launch check.", instrument_path);
        }
        if (jdwp && !cmd_debug)
            ctx.add(Severity::Detection, strf("Java debugger library loaded without a debug flag (PID %lu)", g.info.pid),
                    "The JDWP debug agent is in the game but the game was not started in debug mode. A debugger "
                    "can read and change anything in the game.");
        else if (jdwp)
            ctx.add(Severity::Warning, strf("The game is running in Java debug mode (PID %lu)", g.info.pid),
                    "It was started with a debug flag. A debugger can change the game while it runs.");
        if (attach)
            ctx.add(Severity::Warning, strf("The game loaded Java's attach library (PID %lu)", g.info.pid),
                    "attach.dll is used by a Java program to attach to another Java program, or to itself to "
                    "load an agent. Some mods (self-attaching agents) do this.");
        if (contains(cmd, "-xx:+enabledynamicagentloading"))
            ctx.add(Severity::Integrity, strf("Dynamic agent loading is switched on by flag (PID %lu)", g.info.pid),
                    "The launch flags allow agents to be attached without a warning in the log.");
        if (query) {
            uint64_t port = 0;
            HANDLE dbg = nullptr;
            if (query(g.h, 7, &port, sizeof(port), nullptr) >= 0 && port != 0)
                ctx.add(Severity::Detection, strf("A native debugger is attached to the game (PID %lu)", g.info.pid),
                        "A debugger has full control of the game's memory and threads. Players do not debug "
                        "their game during normal play.");
            else if (query(g.h, 30, &dbg, sizeof(dbg), nullptr) >= 0 && dbg) {
                CloseHandle(dbg);
                ctx.add(Severity::Detection, strf("A debug object is attached to the game (PID %lu)", g.info.pid),
                        "Something opened the game for debugging.");
            }
        }
        CloseHandle(g.h);
    }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(165, game_load_times, Scope::InGame, "DLLs loaded into the game long after it started") {
    for (Opened& g : open_games()) {
        std::vector<LdrMod> mods = ldr_modules(g.h);
        if (mods.empty()) {
            ctx.note(strf("module load times could not be read for PID %lu", g.info.pid));
            CloseHandle(g.h);
            continue;
        }
        double now = now_epoch();
        size_t timed = 0, late = 0;
        std::vector<std::string> signed_late;
        for (const LdrMod& m : mods) {
            if (m.load_time < g.info.start - 5 || m.load_time > now + 60) continue;   // not a valid time
            ++timed;
            double after = m.load_time - g.info.start;
            if (after < 90) continue;
            ++late;
            std::string l = lower(m.path), name = base_name(m.path);
            std::string when = fmt_time(m.load_time) + strf(" (%.0f min after the game started)", after / 60);
            std::vector<std::string> strong = ctx.match_names(name);
            const SigInfo& si = verify_file(m.path);
            if (!strong.empty())
                ctx.add(Severity::Detection, "Known cheat DLL loaded into the running game: " + name,
                        "Loaded " + when + ". Matched: " + join(strong) + ".", m.path);
            else if (!si.trusted && !lazy_native(l))
                ctx.add(Severity::Warning, "Unsigned DLL loaded into the game after it started: " + name,
                        "Loaded " + when + ". The game loads its own libraries in the first minute. An unsigned "
                        "DLL showing up later was loaded by a mod, by Windows, or by an injector. Compare the time "
                        "with what the player was doing.", m.path);
            else if (signed_late.size() < 30)
                signed_late.push_back(name + strf(" +%.0fm", after / 60) + (si.trusted ? "" : " (unsigned game library)"));
        }
        ctx.add(Severity::Integrity, strf("Module load times read (PID %lu)", g.info.pid),
                strf("%zu modules, %zu with a load time, %zu loaded more than 90 seconds after the game started. "
                     "Overlays from Discord, OBS and GPU software inject signed DLLs late, which is normal.",
                     mods.size(), timed, late),
                signed_late.empty() ? "" : "late but signed or known: " + join(signed_late));
        CloseHandle(g.h);
    }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(270, injection_history, Scope::Boot, "Game crashes, crash reports and system events that name what was loaded into Java") {
    std::string win_l = lower(windows_dir());
    // 1. Application Error (1000) and Hang (1002): the faulting module of a Java crash.
    size_t crashes = 0;
    for (const Event& e : query_events(L"Application", recent_xpath(ctx, "EventID=1000 or EventID=1002", 14), 300)) {
        if (!java_name(lower(e.xml))) continue;
        std::vector<std::string> d = data_values(e.xml);
        std::string app = xml_data(e.xml, "AppName"), mod = xml_data(e.xml, "ModuleName"), mod_path = xml_data(e.xml, "ModulePath");
        if (app.empty() && !d.empty()) app = d[0];
        if (mod.empty() && d.size() > 3) mod = d[3];
        if (mod_path.empty() && d.size() > 11) mod_path = d[11];
        if (!java_name(lower(app))) continue;
        ++crashes;
        bool since = ctx.since_boot(e.time);
        Scope sc = since ? Scope::Boot : Scope::OutOfInstance;
        std::string lm = lower(mod_path.empty() ? mod : mod_path);
        std::vector<std::string> strong = ctx.match_names(base_name(lm));
        bool system_mod = starts_with(lm, win_l) || lazy_native(lm) || lm == "unknown" || lm.empty() ||
                          contains(lm, "jvm.dll") || contains(lm, "ntdll") || contains(lm, "nvoglv") || contains(lm, "atio") || contains(lm, "icd64") || contains(lm, "igxe") || contains(lm, "opengl32");
        if (e.id == 1000 && !strong.empty())
            ctx.add(Severity::Detection, "Java crashed inside a known cheat module: " + mod,
                    "Windows logged a game crash at " + fmt_time(e.time) + " and the crashing module matches: " + join(strong) + ".",
                    mod_path.empty() ? mod : mod_path, sc);
        else if (e.id == 1000 && !system_mod)
            ctx.add(Severity::Warning, "Java crashed inside an unusual module: " + mod,
                    "Windows logged a game crash at " + fmt_time(e.time) + (since ? " (since this boot)." : " (before this boot).") +
                        " The crash happened inside a module that is not part of Java, Windows or the graphics "
                        "driver. Badly made injected DLLs crash the game like this.",
                    mod_path.empty() ? mod : mod_path, sc);
    }
    // 2. Windows Error Reporting keeps a report per crash with the full list of loaded modules.
    size_t reports = 0;
    std::vector<std::string> roots = {"C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive", "C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue"};
    for (const std::string& h : user_homes()) {
        roots.push_back(h + "\\AppData\\Local\\Microsoft\\Windows\\WER\\ReportArchive");
        roots.push_back(h + "\\AppData\\Local\\Microsoft\\Windows\\WER\\ReportQueue");
    }
    std::set<std::string> reported;
    for (const std::string& root : roots)
        for (const std::string& dir : list_dir(root)) {
            if (!java_name(lower(dir))) continue;
            std::string file = root + "\\" + dir + "\\Report.wer";
            std::string text = read_utf16_file(file, 4u << 20);
            if (text.empty()) continue;
            ++reports;
            double t = file_mtime(file);
            bool since = ctx.since_boot(t);
            Scope sc = since ? Scope::Boot : Scope::OutOfInstance;
            for (const std::string& raw : split(text, '\n')) {
                std::string line = trim(raw);
                if (!starts_with(line, "LoadedModule[")) continue;
                size_t eq = line.find('=');
                if (eq == std::string::npos) continue;
                std::string path = line.substr(eq + 1), l = lower(path);
                if (starts_with(l, win_l)) continue;
                std::vector<std::string> strong = ctx.match_names(base_name(path));
                if (!strong.empty() && reported.insert(l + dir).second)
                    ctx.add(since ? Severity::Detection : Severity::Warning, "Crash report shows a known cheat module was loaded in Java",
                            "A Windows crash report for the game from " + fmt_time(t) + " lists every module that was "
                            "loaded when it crashed. Matched: " + join(strong) + ".", path + " (in " + file + ")", sc);
                else if (strong.empty() && user_writable_path(path) && !lazy_native(l) && reported.insert(l).second && reported.size() < 40)
                    ctx.add(Severity::Warning, "Crash report shows a DLL from a user folder was loaded in Java",
                            "From the game crash report dated " + fmt_time(t) + ". The file was in Downloads, Desktop, "
                            "Documents or Temp." + (file_exists(path) ? "" : " It is no longer on disk."),
                            path + " (in " + file + ")", sc);
            }
        }
    // 3. Code Integrity: Windows refusing or auditing an image load into Java.
    for (const Event& e : query_events(L"Microsoft-Windows-CodeIntegrity/Operational",
                                       recent_xpath(ctx, "EventID=3033 or EventID=3034 or EventID=3076 or EventID=3077 or EventID=3089", 14), 300)) {
        std::string l = lower(e.xml);
        if (!java_name(l)) continue;
        bool since = ctx.since_boot(e.time);
        std::string file = xml_data(e.xml, "FileNameBuffer");
        if (file.empty()) file = xml_data(e.xml, "File Name");
        ctx.add(Severity::Warning, "Windows flagged a file loading into Java",
                strf("Code Integrity event %d at ", e.id) + fmt_time(e.time) + ". Windows logs this when an image that "
                "does not meet signing rules is loaded into a process.", file.empty() ? cut(e.xml, 300) : device_to_dos(file),
                since ? Scope::Boot : Scope::OutOfInstance);
    }
    // 4. Sysmon, if the PC has it: remote threads and process access aimed at Java.
    size_t sysmon = 0;
    for (const Event& e : query_events(L"Microsoft-Windows-Sysmon/Operational", recent_xpath(ctx, "EventID=8 or EventID=10", 3), 2000)) {
        ++sysmon;
        std::string target = xml_data(e.xml, "TargetImage"), source = xml_data(e.xml, "SourceImage");
        if (!java_name(lower(target)) || java_name(lower(source))) continue;
        if (e.id == 10) {
            std::string access = lower(xml_data(e.xml, "GrantedAccess"));
            unsigned long mask = strtoul(access.c_str(), nullptr, 16);
            if (!(mask & (0x0002 | 0x0008 | 0x0020))) continue;   // thread create, vm operation, vm write
            if (starts_with(lower(source), win_l)) continue;
        }
        bool since = ctx.since_boot(e.time);
        ctx.add(e.id == 8 ? Severity::Detection : Severity::Warning,
                e.id == 8 ? "Sysmon: a program created a thread inside Java" : "Sysmon: a program opened Java with write access",
                "Logged " + fmt_time(e.time) + ". Creating a thread in another process is the classic DLL injection step.",
                source + " -> " + target, since ? Scope::Boot : Scope::OutOfInstance);
    }
    ctx.add(Severity::Integrity, "Crash and system event history read",
            strf("%zu Java crash/hang events in the last 14 days, %zu Java crash reports on disk, Sysmon %s.", crashes, reports,
                 sysmon ? "is installed and was searched" : "is not installed (normal)"),
            "", Scope::None);
}

// ---------------------------------------------------------------------------
SCAN_CHECK(280, defender, Scope::Boot, "Defender detections, exclusions and protection switched off") {
    const wchar_t* ch = L"Microsoft-Windows-Windows Defender/Operational";
    std::set<std::string> seen;
    for (const Event& e : query_events(ch, recent_xpath(ctx, "EventID=1116 or EventID=1117", 30), 200)) {
        std::string threat = xml_data(e.xml, "Threat Name"), path = xml_data(e.xml, "Path"), proc = xml_data(e.xml, "Process Name");
        if (!seen.insert(threat + "|" + path).second) continue;
        std::string l = lower(threat + " " + path);
        bool since = ctx.since_boot(e.time);
        std::vector<std::string> strong = ctx.match_names(path);
        bool tool = contains(l, "hacktool") || contains(l, "gamehack") || contains(l, "inject") || contains(l, "cheat") || contains(l, "keygen");
        if (strong.empty() && !tool && !since) continue;
        ctx.add(!strong.empty() ? Severity::Detection : Severity::Warning, "Defender flagged a file: " + (threat.empty() ? "unknown threat" : threat),
                "Detected " + fmt_time(e.time) + (since ? " (since this boot)." : " (before this boot).") +
                    " Defender labels many cheats and injectors as HackTool. Other malware shows up here too." +
                    (strong.empty() ? "" : " Matched: " + join(strong) + "."),
                cut(path, 300) + (proc.empty() ? "" : " | by " + proc), since ? Scope::Boot : Scope::OutOfInstance);
    }
    for (const Event& e : query_events(ch, recent_xpath(ctx, "EventID=5001 or EventID=5010 or EventID=5012", 7), 20)) {
        bool since = ctx.since_boot(e.time);
        ctx.add(Severity::Warning, "Defender protection was switched off",
                strf("Event %d at ", e.id) + fmt_time(e.time) + (since ? " (since this boot)." : " (before this boot).") +
                    " People turn it off to run a cheat or loader it would delete. Other antivirus products also turn it off.",
                "", since ? Scope::Boot : Scope::OutOfInstance);
    }
    size_t shown = 0;
    for (const Event& e : query_events(ch, recent_xpath(ctx, "EventID=5007", 7), 200)) {
        std::string nv = xml_data(e.xml, "New Value");
        if (!contains(lower(nv), "exclusions\\") || nv.empty()) continue;
        bool since = ctx.since_boot(e.time);
        if (shown++ < 10)
            ctx.add(Severity::Warning, "A Defender exclusion was added",
                    "Added " + fmt_time(e.time) + (since ? " (since this boot)." : " (before this boot).") +
                        " Files in an excluded place are never scanned.", cut(nv, 300), since ? Scope::Boot : Scope::OutOfInstance);
    }
    std::vector<std::string> ex;
    for (const wchar_t* k : {L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths", L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes",
                             L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths"})
        for (const RegValue& v : reg_values(HKEY_LOCAL_MACHINE, k)) ex.push_back(v.name);
    if (!ex.empty()) {
        bool user = false, strong = false;
        for (const std::string& p : ex) {
            user = user || user_writable_path(p + "\\") || lower(p).size() <= 3;
            strong = strong || !ctx.match_names(p).empty();
        }
        ctx.add(strong ? Severity::Detection : user ? Severity::Warning : Severity::Integrity, "Defender exclusions are set",
                user ? "At least one excluded place is a user folder or a whole drive." : "Listed for review.", join(ex, " | "),
                Scope::OutOfInstance);
    }
    RegValue v;
    if (reg_get(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"DisableAntiSpyware", v) && v.dword())
        ctx.add(Severity::Warning, "Defender is disabled by policy", "DisableAntiSpyware=1.", "", Scope::OutOfInstance);
}

}  // namespace scan
#endif

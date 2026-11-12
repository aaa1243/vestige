// Integrity checks: is the evidence the other checks rely on still intact?
// Boot state, services that record activity, cleared logs, clock changes,
// blocked tools and loaded drivers.
#ifdef _WIN32
#include "win_util.hpp"

#include <psapi.h>

#include <algorithm>
#include <cmath>
#include <ctime>
#include <set>

#include "../util.hpp"

namespace scan {
using namespace win;

namespace {

double iso_to_epoch(const std::string& s) {
    struct tm t{};
    int y, mo, d, h, mi;
    double sec = 0;
    if (sscanf(s.c_str(), "%d-%d-%dT%d:%d:%lf", &y, &mo, &d, &h, &mi, &sec) != 6) return 0;
    t.tm_year = y - 1900; t.tm_mon = mo - 1; t.tm_mday = d;
    t.tm_hour = h; t.tm_min = mi; t.tm_sec = 0;
    return static_cast<double>(_mkgmtime(&t)) + sec;
}

std::string span(double seconds) {
    seconds = std::fabs(seconds);
    if (seconds < 120) return strf("%.0f seconds", seconds);
    if (seconds < 7200) return strf("%.0f minutes", seconds / 60);
    if (seconds < 172800) return strf("%.1f hours", seconds / 3600);
    return strf("%.1f days", seconds / 86400);
}

std::wstring since_boot_xpath(const Context& ctx, const char* ids) {
    // TimeCreated uses milliseconds back from now
    double ms = (now_epoch() - ctx.boot_time + 120) * 1000.0;
    if (ctx.boot_time <= 0) ms = 7 * 86400000.0;
    return widen(strf("*[System[(%s) and TimeCreated[timediff(@SystemTime) <= %.0f]]]", ids, ms));
}

}  // namespace

// ---------------------------------------------------------------------------
SCAN_CHECK(10, integrity_boot, Scope::None, "Boot time, logon time and code integrity state") {
    double up = now_epoch() - ctx.boot_time;
    ctx.add(Severity::Integrity, "Last boot: " + fmt_time(ctx.boot_time),
            "Up for " + span(up) + ". Fast Startup keeps the kernel session across a shutdown, so this can be "
            "older than the last time the PC was turned on. Findings tagged Boot happened after this time.");
    if (up < 15 * 60)
        ctx.add(Severity::Warning, "The PC was restarted " + span(up) + " ago",
                "A restart right before a screenshare wipes everything held in memory: injected code, "
                "service memory, the DNS cache. Ask when and why.", fmt_time(ctx.boot_time));

    double explorer = 0, game = 0;
    for (const ProcInfo& p : processes())
        if (lower(p.name) == "explorer.exe" && (explorer == 0 || p.start < explorer)) explorer = p.start;
    for (const ProcInfo& p : game_processes())
        if (game == 0 || p.start < game) game = p.start;
    if (explorer > 0) {
        ctx.add(Severity::Integrity, "Explorer started: " + fmt_time(explorer),
                "Explorer starts at logon. A start time well after logon means it was restarted, which "
                "clears what it holds in memory.");
        if (game > 0 && explorer > game)
            ctx.add(Severity::Warning, "Explorer was restarted while the game was running",
                    "Explorer started " + span(explorer - game) + " after the game. Killing explorer is a "
                    "known way to clear its memory before a screenshare. It can also just crash.",
                    "explorer " + fmt_time(explorer) + ", game " + fmt_time(game));
    }
    if (game > 0)
        ctx.add(Severity::Integrity, "Game started: " + fmt_time(game),
                "Findings tagged In game are about this running game. If the game was restarted after "
                "the screenshare was called, in-memory injection evidence from the earlier game is gone.");
    else
        ctx.add(Severity::Warning, "No running Minecraft was found",
                "The in-game checks need the game open. Have the player open the game they were "
                "playing on, then scan again.");

    typedef LONG(NTAPI * QuerySys)(ULONG, PVOID, ULONG, PULONG);
    QuerySys query = reinterpret_cast<QuerySys>(nt_proc("NtQuerySystemInformation"));
    if (query) {
        struct { ULONG Length, Options; } ci = {8, 0};
        if (query(103, &ci, sizeof(ci), nullptr) >= 0) {
            if (ci.Options & 0x02)
                ctx.add(Severity::Detection, "Test signing is on",
                        "Windows is set to load drivers that are not properly signed. That is how "
                        "self-made kernel drivers get loaded.", strf("CodeIntegrityOptions=0x%lX", ci.Options));
            if (!(ci.Options & 0x01))
                ctx.add(Severity::Detection, "Driver signature enforcement is off",
                        "Code integrity is disabled, so any driver can load.", strf("CodeIntegrityOptions=0x%lX", ci.Options));
            if (ci.Options & 0x80)
                ctx.add(Severity::Warning, "Kernel debug mode is on", "Windows booted with kernel debugging enabled.",
                        strf("CodeIntegrityOptions=0x%lX", ci.Options));
            ctx.add(Severity::Integrity, (ci.Options & 0x400) ? "Memory Integrity (HVCI) is on" : "Memory Integrity (HVCI) is off",
                    "With it on, unsigned and known vulnerable drivers are much harder to load.");
        }
        struct { BOOLEAN Enabled, NotPresent; } kd = {0, 1};
        if (query(35, &kd, sizeof(kd), nullptr) >= 0 && kd.Enabled && !kd.NotPresent)
            ctx.add(Severity::Warning, "A kernel debugger is attached", "A kernel debugger can read and change any memory.");
    }
    RegValue v;
    if (reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", L"UEFISecureBootEnabled", v))
        ctx.add(Severity::Integrity, v.dword() ? "Secure Boot is on" : "Secure Boot is off",
                "Secure Boot off is common on older or custom PCs. It matters together with other driver findings.");
    if (reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config", L"VulnerableDriverBlocklistEnable", v) &&
        v.dword() == 0)
        ctx.add(Severity::Warning, "The vulnerable driver blocklist is turned off",
                "Windows blocks drivers that are known to be abused to load kernel cheats. That block was disabled.",
                "VulnerableDriverBlocklistEnable=0");
    if (!ctx.admin)
        ctx.add(Severity::Warning, "The scan is not running as administrator",
                "Most checks need administrator rights. Results from this run are incomplete.");
}

// ---------------------------------------------------------------------------
SCAN_CHECK(20, integrity_services, Scope::Boot, "Services that record activity are running since boot") {
    struct S { const wchar_t* name; const char* what; bool must; };
    static const S list[] = {
        {L"SysMain", "writes Prefetch files", true},
        {L"DPS", "keeps program names in memory", true},
        {L"PcaSvc", "records program launches", true},
        {L"EventLog", "writes the event logs", true},
        {L"DiagTrack", "records program activity", false},
        {L"Schedule", "runs scheduled tasks", true},
        {L"Dnscache", "keeps the DNS cache", true},
        {L"Appinfo", "handles administrator prompts", false},
        {L"bam", "records program runs (BAM)", true},
        {L"CDPUserSvc", "records activity history", false},
    };
    for (const S& s : list) {
        DWORD state = 0, start_type = 0;
        DWORD pid = service_pid(s.name, &state, &start_type);
        std::string name = narrow(s.name);
        if (state == 0) {
            if (s.must && name != "CDPUserSvc")
                ctx.add(Severity::Warning, "Service not found: " + name, std::string("This service ") + s.what + ". It is missing.");
            continue;
        }
        if (start_type == SERVICE_DISABLED)
            ctx.add(s.must ? Severity::Detection : Severity::Warning, "Service is disabled: " + name,
                    std::string("This service ") + s.what + ". Windows does not disable it by itself.", name);
        else if (state != SERVICE_RUNNING && s.must)
            ctx.add(Severity::Detection, "Service is stopped: " + name,
                    std::string("This service ") + s.what + " and normally runs the whole session. It is not running now.", name);
        if (state == SERVICE_RUNNING && pid > 4) {
            double started = process_start(pid);
            if (started > 0 && ctx.boot_time > 0 && started - ctx.boot_time > 15 * 60 && s.must)
                ctx.add(Severity::Warning, "Service was restarted after boot: " + name,
                        std::string("This service ") + s.what + ". Its process started " + span(started - ctx.boot_time) +
                            " after boot, so it was stopped or restarted and anything it held in memory before "
                            "that is gone. Several services share one process on PCs with little RAM.",
                        name + " process started " + fmt_time(started));
        }
    }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(30, integrity_logs, Scope::Boot, "Cleared logs, deleted USN journal and clock changes") {
    for (const Event& e : query_events(L"Security", L"*[System[(EventID=1102)]]", 5)) {
        bool since = ctx.since_boot(e.time);
        ctx.add(since ? Severity::Detection : Severity::Warning, "The Security log was cleared",
                "Cleared " + fmt_time(e.time) + (since ? ", since this boot." : ", before this boot."),
                "Event 1102, by " + xml_data(e.xml, "SubjectUserName"), since ? Scope::Boot : Scope::OutOfInstance);
    }
    for (const Event& e : query_events(L"System", L"*[System[(EventID=104)]]", 10)) {
        bool since = ctx.since_boot(e.time);
        std::string which = xml_data(e.xml, "Channel");
        ctx.add(since ? Severity::Detection : Severity::Warning, "An event log was cleared: " + (which.empty() ? "unknown" : which),
                "Cleared " + fmt_time(e.time) + (since ? ", since this boot." : ", before this boot."),
                "Event 104, by " + xml_data(e.xml, "SubjectUserName"), since ? Scope::Boot : Scope::OutOfInstance);
    }
    for (const Event& e : query_events(L"Microsoft-Windows-Ntfs/Operational", L"*[System[(EventID=3079)]]", 5)) {
        bool since = ctx.since_boot(e.time);
        ctx.add(since ? Severity::Detection : Severity::Warning, "The USN journal was deleted",
                "Deleted " + fmt_time(e.time) + (since ? ", since this boot." : ", before this boot.") +
                    " The journal is the record of created, renamed and deleted files.",
                "Ntfs event 3079", since ? Scope::Boot : Scope::OutOfInstance);
    }
    // Clock changes: Kernel-General event 1. Small corrections are normal time sync.
    size_t shown = 0;
    for (const Event& e : query_events(L"System",
             since_boot_xpath(ctx, "EventID=1").c_str(), 400)) {
        if (!contains(e.xml, "Kernel-General")) continue;
        double new_t = iso_to_epoch(xml_data(e.xml, "NewTime")), old_t = iso_to_epoch(xml_data(e.xml, "OldTime"));
        if (new_t == 0 || old_t == 0) continue;
        double delta = new_t - old_t;
        if (std::fabs(delta) < 300) continue;
        // waking from sleep reports a jump forward with reason 2; only user changes count
        std::string reason = xml_data(e.xml, "Reason");
        if (reason != "1" && !(reason.empty() && delta < 0)) continue;
        if (shown++ < 6)
            ctx.add(Severity::Warning, std::string("The clock was changed ") + (delta < 0 ? "back" : "forward") + " by " + span(delta),
                    "Changing the clock makes new activity look old, or old activity look new, in every "
                    "time-based check. Logged at " + fmt_time(e.time) + ".",
                    "from " + fmt_time(old_t) + " to " + fmt_time(new_t));
    }
    // Was the event log service itself restarted / does the System log cover this boot?
    std::vector<Event> oldest = query_events(L"System", since_boot_xpath(ctx, "EventID=12 or EventID=6005 or EventID=6009"), 20);
    if (oldest.empty() && ctx.admin && ctx.boot_time > 0)
        ctx.add(Severity::Warning, "The System log has no start-up events for this boot",
                "Windows writes several events at every boot. None were found for this boot, so the "
                "log was cleared, is too small, or logging was off.", "", Scope::Boot);
    // Service start-type changes since boot
    for (const Event& e : query_events(L"System", since_boot_xpath(ctx, "EventID=7040"), 100)) {
        std::string svc = xml_data(e.xml, "param1"), to = xml_data(e.xml, "param3");
        std::string l = lower(svc + " " + xml_data(e.xml, "param4"));
        bool watched = false;
        for (const char* k : {"sysmain", "diagnostic policy", "dps", "program compatibility", "pcasvc", "event log",
                              "eventlog", "dns client", "dnscache", "diagtrack", "connected user experiences"})
            watched = watched || contains(l, k);
        if (!watched || !contains(lower(to), "disabled")) continue;
        ctx.add(Severity::Detection, "A recording service was set to disabled this boot: " + svc,
                "Changed at " + fmt_time(e.time) + ".", "Event 7040: " + xml_data(e.xml, "param2") + " -> " + to);
    }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(40, integrity_tamper, Scope::None, "Settings that block tools or hide activity") {
    if (reg_key_exists(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\MiniNt"))
        ctx.add(Severity::Detection, "MiniNt key is present",
                "This key makes Windows think it is a recovery environment, which stops the event logs "
                "from recording. It does not exist on a normal install.",
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\MiniNt");
    RegValue v;
    if (reg_get(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
                L"EnableScriptBlockLogging", v) && v.dword() == 0)
        ctx.add(Severity::Warning, "PowerShell script logging was turned off by policy",
                "Someone set the policy to 0 on purpose. The default is simply not set.", "EnableScriptBlockLogging=0");

    std::vector<std::pair<HKEY, std::wstring>> roots = {{HKEY_LOCAL_MACHINE, L""}};
    for (const std::string& sid : user_sids()) roots.push_back({HKEY_USERS, widen(sid) + L"\\"});
    for (const auto& r : roots) {
        std::string where = r.first == HKEY_LOCAL_MACHINE ? "HKLM" : "HKU\\" + narrow(r.second);
        std::wstring pol = r.second + L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\";
        std::vector<RegValue> blocked = reg_values(r.first, pol + L"Explorer\\DisallowRun");
        if (!blocked.empty()) {
            std::vector<std::string> names;
            for (const RegValue& b : blocked) names.push_back(b.text());
            bool on = reg_get(r.first, pol + L"Explorer", L"DisallowRun", v) && v.dword() != 0;
            ctx.add(on ? Severity::Detection : Severity::Warning,
                    on ? "Programs are blocked from running (DisallowRun)" : "A DisallowRun list exists but is switched off",
                    "This policy stops the listed programs from starting. It is used to block screenshare "
                    "tools. The list only applies when the DisallowRun value next to it is 1.",
                    where + ": " + join(names));
        }
        struct P { const wchar_t* sub; const wchar_t* value; const char* what; };
        for (const P& p : {P{L"System", L"DisableTaskMgr", "Task Manager is disabled"},
                           P{L"System", L"DisableRegistryTools", "Registry tools are disabled"},
                           P{L"Explorer", L"NoRun", "The Run box is disabled"}})
            if (reg_get(r.first, pol + p.sub, p.value, v) && v.dword() != 0)
                ctx.add(Severity::Warning, p.what, "Set by policy. It gets in the way of a screenshare.",
                        where + "\\..\\Policies\\" + narrow(p.sub) + "\\" + narrow(p.value) + "=1");
        if (reg_get(r.first, r.second + L"Software\\Policies\\Microsoft\\Windows\\System", L"DisableCMD", v) && v.dword() != 0)
            ctx.add(Severity::Warning, "Command Prompt is disabled", "Set by policy.", where + " DisableCMD=" + strf("%lu", v.dword()));
    }
    if (reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\FileSystem", L"NtfsDisableLastAccessUpdate", v)) {
        // informational only; value differs by Windows version
    }
    std::string hosts = windows_dir() + "\\System32\\drivers\\etc\\hosts";
    double mt = file_mtime(hosts);
    if (ctx.since_boot(mt))
        ctx.add(Severity::Warning, "The hosts file was changed this boot",
                "The hosts file can block or redirect sites, for example an anticheat or a tool download.",
                hosts + " modified " + fmt_time(mt), Scope::Boot);
    std::string text;
    if (read_file(hosts, text, 1 << 20)) {
        std::vector<std::string> odd;
        for (const std::string& raw : split(text, '\n')) {
            std::string line = lower(trim(raw));
            if (line.empty() || line[0] == '#') continue;
            for (const char* k : {"echo", "anticheat", "github", "nirsoft", "ericzimmerman", "lunarclient", "badlion", "virustotal"})
                if (contains(line, k) && odd.size() < 8) { odd.push_back(trim(raw)); break; }
        }
        if (!odd.empty())
            ctx.add(Severity::Warning, "The hosts file redirects tool or anticheat sites", "These lines stand out.", join(odd, " | "));
    }
    // Recycle Bin emptied this boot (folder time changes when items are removed)
    for (const std::string& sid : user_sids()) {
        if (sid.size() < 20 || contains(sid, "_Classes")) continue;
        std::string bin = windows_dir().substr(0, 3) + "$Recycle.Bin\\" + sid;
        double t = file_mtime(bin);
        if (ctx.since_boot(t) && list_dir(bin).size() <= 1)
            ctx.add(Severity::Integrity, "The Recycle Bin is empty and changed this boot",
                    "It was emptied or something was restored at about " + fmt_time(t) + ".", bin, Scope::Boot);
    }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(50, drivers, Scope::Boot, "Loaded kernel drivers: known cheat loaders and unsigned drivers") {
    std::vector<LPVOID> bases(4096);
    DWORD needed = 0;
    if (!EnumDeviceDrivers(bases.data(), static_cast<DWORD>(bases.size() * sizeof(LPVOID)), &needed)) {
        ctx.note("could not list kernel drivers");
        return;
    }
    size_t n = std::min<size_t>(needed / sizeof(LPVOID), bases.size()), unsigned_shown = 0;
    std::string win = windows_dir();
    for (size_t i = 0; i < n; ++i) {
        wchar_t wpath[1024];
        if (!GetDeviceDriverFileNameW(bases[i], wpath, 1024)) continue;
        std::string path = narrow(wpath);
        std::string l = lower(path);
        if (starts_with(l, "\\systemroot\\")) path = win + path.substr(11);
        else if (starts_with(l, "\\??\\")) path = path.substr(4);
        else if (starts_with(l, "\\windows\\")) path = win.substr(0, 2) + path;
        else if (starts_with(l, "\\device\\")) path = device_to_dos(path);
        std::string name = base_name(path);
        std::vector<std::string> hit = match_list(ctx.sigs.drivers, lower(name), false);
        if (!hit.empty()) {
            ctx.add(Severity::Warning, "Driver known to be abused is loaded: " + name,
                    "This signed driver has a flaw that lets programs run their own kernel code, and "
                    "cheat loaders use it. Some hardware tools install it for real reasons. Matched: " + join(hit) + ".", path);
            continue;
        }
        if (!file_exists(path)) {
            if (path.size() > 2 && path[1] == ':')
                ctx.add(Severity::Warning, "A loaded driver's file is gone: " + name,
                        "The driver is running in the kernel but its file is no longer on disk.", path);
            continue;
        }
        const SigInfo& sig = verify_file(path);
        if (!sig.trusted && unsigned_shown++ < 10)
            ctx.add(Severity::Warning, "Unsigned driver is loaded: " + name,
                    "Windows normally refuses unsigned drivers, so this one got in through test signing, "
                    "a boot option or an exploit.", path);
    }
    // Drivers that were loaded and unloaded leave service entries; list recent kernel services in user folders.
    for (const std::string& svc : reg_subkeys(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services")) {
        std::wstring key = L"SYSTEM\\CurrentControlSet\\Services\\" + widen(svc);
        RegValue type, image;
        if (!reg_get(HKEY_LOCAL_MACHINE, key, L"Type", type) || type.dword() != 1) continue;
        if (!reg_get(HKEY_LOCAL_MACHINE, key, L"ImagePath", image)) continue;
        std::string path = image.text();
        std::string l = lower(path);
        if (starts_with(l, "\\??\\")) path = path.substr(4);
        std::vector<std::string> hit = match_list(ctx.sigs.drivers, lower(base_name(path)), false);
        double t = reg_key_time(HKEY_LOCAL_MACHINE, key);
        bool since = ctx.since_boot(t);
        if (user_writable_path(path) || contains(l, "\\appdata\\"))
            ctx.add(since ? Severity::Detection : Severity::Warning, "Kernel driver registered from a user folder: " + svc,
                    "Real drivers live in System32\\drivers. Service key last changed " + fmt_time(t) + ".", path,
                    since ? Scope::Boot : Scope::OutOfInstance);
        else if (!hit.empty() && since)
            ctx.add(Severity::Warning, "Abusable driver was registered this boot: " + svc,
                    "Service key last changed " + fmt_time(t) + ". Matched: " + join(hit) + ".", path);
    }
    ctx.add(Severity::Integrity, "Drivers checked", strf("%zu loaded drivers.", n), "", Scope::None);
}

}  // namespace scan
#endif

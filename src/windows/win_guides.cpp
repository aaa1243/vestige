// Checks that automate manual screenshare steps: Temp and Recent traces,
// PowerShell history, mouse software macros, programs hidden under another
// extension or in alternate data streams, suspended service threads, the
// game's network connections and removable drives.
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include "win_util.hpp"

#include <iphlpapi.h>

#include <algorithm>
#include <map>
#include <set>

#include "../util.hpp"

namespace scan {
using namespace win;

namespace {

std::wstring boot_xpath(const Context& ctx, const char* ids) {
    double ms = ctx.boot_time > 0 ? (now_epoch() - ctx.boot_time + 120) * 1000.0 : 7 * 86400000.0;
    return widen(strf("*[System[(%s) and TimeCreated[timediff(@SystemTime) <= %.0f]]]", ids, ms));
}

std::string when(const Context& ctx, double t) {
    return fmt_time(t) + (ctx.since_boot(t) ? " (since this boot)" : " (before this boot)");
}

Scope scope_of(const Context& ctx, double t) { return ctx.since_boot(t) ? Scope::Boot : Scope::OutOfInstance; }

bool pe_header(const std::string& head) {
    if (head.size() < 0x40 || head[0] != 'M' || head[1] != 'Z') return false;
    uint32_t off = 0;
    memcpy(&off, head.data() + 0x3C, 4);
    return off + 4 <= head.size() && head.compare(off, 4, std::string("PE\0\0", 4)) == 0;
}

std::string read_head(const std::wstring& wpath, size_t n) {
    std::string out;
    HANDLE h = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return out;
    out.resize(n);
    DWORD got = 0;
    if (!ReadFile(h, &out[0], static_cast<DWORD>(n), &got, nullptr)) got = 0;
    out.resize(got);
    CloseHandle(h);
    return out;
}

// Invisible or direction-changing characters used to disguise file names (UTF-8).
const char* odd_unicode(const std::string& name) {
    static const struct { const char* bytes; const char* what; } list[] = {
        {"\xE2\x80\xAE", "right-to-left override"}, {"\xE2\x80\xAD", "left-to-right override"},
        {"\xE2\x80\x8B", "zero-width space"},       {"\xE2\x80\x8C", "zero-width non-joiner"},
        {"\xE2\x80\x8D", "zero-width joiner"},      {"\xE2\x80\x8E", "left-to-right mark"},
        {"\xE2\x80\x8F", "right-to-left mark"},     {"\xE2\x81\xA0", "word joiner"},
        {"\xEF\xBB\xBF", "zero-width no-break space"}, {"\xE3\x85\xA4", "Hangul filler (blank)"},
        {"\xE2\xA0\x80", "Braille blank"},          {"\xC2\xA0", "non-breaking space"},
        {"\xE2\x80\x80", "en quad (blank)"},        {"\xE2\x80\x83", "em space (blank)"},
    };
    for (const auto& e : list)
        if (name.find(e.bytes) != std::string::npos) return e.what;
    return nullptr;
}

std::vector<std::string> user_roots(bool with_roaming) {
    std::vector<std::string> roots;
    for (const std::string& h : user_homes()) {
        for (const char* sub : {"\\Downloads", "\\Desktop", "\\Documents", "\\AppData\\Local\\Temp", "\\Music", "\\Pictures", "\\Videos"})
            roots.push_back(h + sub);
        if (with_roaming) {
            roots.push_back(h + "\\AppData\\Roaming");
            roots.push_back(h + "\\AppData\\Roaming\\.minecraft");
        }
    }
    roots.push_back("C:\\Users\\Public");
    return roots;
}

}  // namespace

// ---------------------------------------------------------------------------
SCAN_CHECK(25, service_threads, Scope::Boot, "Recording services with suspended threads") {
    typedef LONG(NTAPI * QuerySys)(ULONG, PVOID, ULONG, PULONG);
    QuerySys query = reinterpret_cast<QuerySys>(nt_proc("NtQuerySystemInformation"));
    if (!query) return;
    std::vector<unsigned char> buf(1 << 20);
    ULONG need = 0;
    LONG st;
    for (int i = 0; i < 6 && (st = query(5, buf.data(), static_cast<ULONG>(buf.size()), &need)) == static_cast<LONG>(0xC0000004); ++i)
        buf.resize(std::max<size_t>(buf.size() * 2, need + 65536));
    if (st < 0) {
        ctx.note("thread states could not be read");
        return;
    }
    struct Counts { unsigned total = 0, suspended = 0; };
    std::map<DWORD, Counts> by_pid;
    size_t off = 0;
    for (;;) {
        if (off + 0x100 > buf.size()) break;
        const unsigned char* p = buf.data() + off;
        uint32_t next = 0, threads = 0;
        uint64_t pid = 0;
        memcpy(&next, p, 4);
        memcpy(&threads, p + 4, 4);
        memcpy(&pid, p + 0x50, 8);
        Counts c;
        for (uint32_t t = 0; t < threads && off + 0x100 + (t + 1) * 0x50ull <= buf.size(); ++t) {
            const unsigned char* th = p + 0x100 + t * 0x50ull;
            uint32_t state = 0, reason = 0;
            memcpy(&state, th + 0x44, 4);
            memcpy(&reason, th + 0x48, 4);
            ++c.total;
            if (state == 5 && reason == 5) ++c.suspended;   // Waiting, Suspended
        }
        by_pid[static_cast<DWORD>(pid)] = c;
        if (!next) break;
        off += next;
    }
    struct S { const wchar_t* name; const char* what; };
    size_t checked = 0;
    for (const S& s : {S{L"DPS", "keeps program names in memory"}, S{L"PcaSvc", "records program launches"},
                       S{L"SysMain", "writes Prefetch files"}, S{L"EventLog", "writes the event logs"},
                       S{L"DiagTrack", "records program activity"}, S{L"Dnscache", "keeps the DNS cache"},
                       S{L"Schedule", "runs scheduled tasks"}, S{L"DcomLaunch", "starts COM programs"}}) {
        DWORD state = 0;
        DWORD pid = service_pid(s.name, &state);
        if (!pid || state != SERVICE_RUNNING) continue;
        auto it = by_pid.find(pid);
        if (it == by_pid.end() || !it->second.total) continue;
        ++checked;
        const Counts& c = it->second;
        std::string name = narrow(s.name);
        if (c.suspended == c.total)
            ctx.add(Severity::Detection, "Service is frozen: " + name,
                    std::string("Every thread of the process that hosts this service is suspended. The service ") + s.what +
                        ". It still shows as running, but it records nothing while frozen. Windows does not do this itself.",
                    strf("%s, PID %lu, %u of %u threads suspended", name.c_str(), pid, c.suspended, c.total));
        else if (c.suspended)
            ctx.add(Severity::Warning, "Service has suspended threads: " + name,
                    std::string("Some threads of the process that hosts this service are suspended. The service ") + s.what +
                        ". Suspending single threads is a way to stop a service recording without stopping it.",
                    strf("%s, PID %lu, %u of %u threads suspended", name.c_str(), pid, c.suspended, c.total));
    }
    ctx.add(Severity::Integrity, "Service threads checked", strf("%zu running recording services looked at.", checked), "", Scope::None);
}

// ---------------------------------------------------------------------------
SCAN_CHECK(45, integrity_policies, Scope::None, "Policies that switch off tracking or hide drives") {
    RegValue v;
    std::vector<std::pair<HKEY, std::wstring>> roots = {{HKEY_LOCAL_MACHINE, L""}};
    for (const std::string& sid : user_sids()) roots.push_back({HKEY_USERS, widen(sid) + L"\\"});
    for (const auto& r : roots) {
        std::string where = r.first == HKEY_LOCAL_MACHINE ? "HKLM" : "HKU\\" + narrow(r.second);
        if (reg_get(r.first, r.second + L"Software\\Policies\\Microsoft\\Windows\\AppCompat", L"DisablePCA", v) && v.dword())
            ctx.add(Severity::Warning, "Program Compatibility Assistant is turned off by policy",
                    "With DisablePCA set, PcaSvc stops recording program launches. It is not set on a normal install.",
                    where + "\\Software\\Policies\\Microsoft\\Windows\\AppCompat\\DisablePCA=1");
        std::wstring pol = r.second + L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";
        for (const wchar_t* name : {L"NoDrives", L"NoViewOnDrive"})
            if (reg_get(r.first, pol, name, v) && v.dword())
                ctx.add(Severity::Warning, "Drives are hidden from Explorer by policy (" + narrow(name) + ")",
                        "This policy hides drive letters in Explorer. The value is a bit mask where A is 1, B is 2, C is 4, D is 8 "
                        "and so on. A hidden drive is a place to keep files out of sight during a screenshare.",
                        where + strf("\\..\\Policies\\Explorer\\%s=0x%lX", narrow(name).c_str(), v.dword()));
        for (const wchar_t* name : {L"NoRecentDocsHistory", L"ClearRecentDocsOnExit"})
            if (reg_get(r.first, pol, name, v) && v.dword())
                ctx.add(Severity::Warning, "Recent files tracking is turned off by policy (" + narrow(name) + ")",
                        "Windows stops keeping the Recent items list, which removes a record of opened files and folders.",
                        where + "\\..\\Policies\\Explorer\\" + narrow(name) + "=1");
        if (r.first == HKEY_USERS &&
            reg_get(r.first, r.second + L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"Start_TrackProgs", v) &&
            v.type == REG_DWORD && v.dword() == 0)
            ctx.add(Severity::Integrity, "Program launch tracking is off for a user (Start_TrackProgs=0)",
                    "UserAssist stops counting program launches. This is also a normal privacy setting in Windows.", where);
    }
    // Prefetch files with odd attributes (read-only is covered by the prefetch check).
    std::string dir = windows_dir() + "\\Prefetch";
    size_t odd = 0;
    for (const std::string& f : list_dir(dir)) {
        if (ext_of(f) != ".pf") continue;
        DWORD a = GetFileAttributesW(widen(dir + "\\" + f).c_str());
        if (a == INVALID_FILE_ATTRIBUTES || !(a & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ENCRYPTED))) continue;
        if (odd++ < 10)
            ctx.add(Severity::Warning, "Prefetch file with unusual attributes: " + f,
                    "The file is marked hidden, system or encrypted. Windows creates prefetch files with none of these, so "
                    "someone changed it to hide it or stop it being read.",
                    dir + "\\" + f + strf(" (attributes 0x%lX)", a));
    }
    // Programs Windows recorded starting at the last logons.
    std::string sdir = windows_dir() + "\\System32\\WDI\\LogFiles\\StartupInfo";
    std::vector<std::pair<double, std::string>> files;
    for (const std::string& f : list_dir(sdir))
        if (ext_of(f) == ".xml") files.push_back({file_mtime(sdir + "\\" + f), sdir + "\\" + f});
    std::sort(files.rbegin(), files.rend());
    std::set<std::string> seen;
    size_t read = 0;
    for (size_t i = 0; i < files.size() && i < 3; ++i) {
        std::string raw, xml;
        if (!read_file(files[i].second, raw, 8u << 20)) continue;
        ++read;
        xml = raw;
        if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xFF && static_cast<unsigned char>(raw[1]) == 0xFE)
            xml = narrow(reinterpret_cast<const wchar_t*>(raw.data() + 2), (raw.size() - 2) / 2);
        size_t p = 0;
        while ((p = xml.find("<CommandLine>", p)) != std::string::npos) {
            size_t e = xml.find("</CommandLine>", p);
            if (e == std::string::npos) break;
            std::string cmd = xml.substr(p + 13, e - p - 13);
            p = e;
            size_t cd = cmd.find("<![CDATA[");
            if (cd != std::string::npos) cmd = cmd.substr(cd + 9, cmd.rfind("]]>") == std::string::npos ? std::string::npos : cmd.rfind("]]>") - cd - 9);
            std::string l = lower(cmd);
            if (!seen.insert(l).second) continue;
            std::vector<std::string> strong = ctx.match_names(cmd);
            Scope sc = scope_of(ctx, files[i].first);
            if (!strong.empty())
                ctx.add(ctx.since_boot(files[i].first) ? Severity::Detection : Severity::Warning, "Known cheat started at logon",
                        "Windows logs what started during each logon. Matched: " + join(strong) + ". Log written " + when(ctx, files[i].first) + ".",
                        cut(cmd, 300) + " | " + files[i].second, sc);
            else if ((contains(l, "\\downloads\\") || contains(l, "\\desktop\\") || contains(l, "\\appdata\\local\\temp\\") ||
                      contains(l, "\\users\\public\\")) && seen.size() < 4000)
                ctx.add(Severity::Warning, "A program from a user folder started at logon",
                        "Started during a recent logon from Downloads, Desktop, Temp or Public. Cheat loaders are set to start "
                        "this way so they are running before the game. Log written " + when(ctx, files[i].first) + ".",
                        cut(cmd, 300), sc);
        }
    }
    if (read) ctx.add(Severity::Integrity, "Startup logs read", strf("%zu of the newest logon startup logs.", read), "", Scope::None);
}

// ---------------------------------------------------------------------------
SCAN_CHECK(155, game_network, Scope::InGame, "Where the game is connected (proxy clients)") {
    std::set<DWORD> game;
    for (const ProcInfo& g : game_processes()) game.insert(g.pid);
    if (game.empty()) return;
    auto table = [](int cls, std::vector<unsigned char>& buf) {
        DWORD size = 0;
        GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, static_cast<TCP_TABLE_CLASS>(cls), 0);
        for (int i = 0; i < 4; ++i) {
            buf.resize(size + 4096);
            size = static_cast<DWORD>(buf.size());
            if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, static_cast<TCP_TABLE_CLASS>(cls), 0) == NO_ERROR) return true;
        }
        return false;
    };
    std::vector<unsigned char> conns, listeners;
    if (!table(TCP_TABLE_OWNER_PID_CONNECTIONS, conns)) {
        ctx.note("the TCP connection table could not be read");
        return;
    }
    std::map<unsigned, DWORD> listen_pid;
    if (table(TCP_TABLE_OWNER_PID_LISTENER, listeners)) {
        auto* lt = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(listeners.data());
        for (DWORD i = 0; i < lt->dwNumEntries; ++i) listen_pid[ntohs(static_cast<u_short>(lt->table[i].dwLocalPort))] = lt->table[i].dwOwningPid;
    }
    auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(conns.data());
    std::vector<std::string> remote;
    std::set<std::string> seen;
    for (DWORD i = 0; i < t->dwNumEntries; ++i) {
        const MIB_TCPROW_OWNER_PID& r = t->table[i];
        if (!game.count(r.dwOwningPid) || r.dwState != MIB_TCP_STATE_ESTAB) continue;
        unsigned char ip[4];
        memcpy(ip, &r.dwRemoteAddr, 4);
        unsigned port = ntohs(static_cast<u_short>(r.dwRemotePort));
        std::string ep = strf("%u.%u.%u.%u:%u", ip[0], ip[1], ip[2], ip[3], port);
        if (!seen.insert(ep).second) continue;
        bool loopback = ip[0] == 127;
        if (loopback) {
            auto lp = listen_pid.find(port);
            const ProcInfo* owner = lp != listen_pid.end() ? find_process(lp->second) : nullptr;
            if (owner && game.count(owner->pid)) continue;   // the game talking to itself
            std::string who = owner ? (owner->path.empty() ? owner->name : owner->path) + strf(" (PID %lu)", owner->pid) : "unknown program";
            std::vector<std::string> strong = owner ? ctx.match_names(owner->name) : std::vector<std::string>();
            bool trusted = owner && !owner->path.empty() && verify_file(owner->path).trusted;
            ctx.add(!strong.empty() ? Severity::Detection : trusted ? Severity::Integrity : Severity::Warning,
                    "The game is connected to a program on this PC",
                    "The game has a network connection to another program on the same PC. Proxy cheats work this way: the game "
                    "joins a local proxy and the proxy joins the server. Launchers and some mods also talk to a local helper, "
                    "so check what the program is." + std::string(trusted ? " The program has a valid signature." : ""),
                    strf("game PID %lu -> %s, listening program: %s", r.dwOwningPid, ep.c_str(), who.c_str()));
        } else if (remote.size() < 12) {
            remote.push_back(ep);
        }
    }
    if (!remote.empty())
        ctx.add(Severity::Integrity, "Addresses the game is connected to",
                "Compare these with your server's real address. A player on your server whose game is not connected to "
                "your server's address is going through a proxy. Launchers also keep a few connections of their own open. "
                "Only IPv4 connections are listed.",
                join(remote));
}

// ---------------------------------------------------------------------------
SCAN_CHECK(290, temp_traces, Scope::Boot, "Temp folder: Java input hooks, programs run from archives, unsigned programs") {
    size_t unsigned_shown = 0, archive_shown = 0, files = 0;
    std::set<std::string> seen_hook;
    for (const std::string& home : user_homes()) {
        std::string temp = home + "\\AppData\\Local\\Temp";
        walk_files(temp, 3, [&](const std::string& path, uint64_t size) {
            ++files;
            std::string name = base_name(path), l = lower(path), ext = ext_of(path);
            double mt = file_mtime(path);
            if (starts_with(lower(name), "jnativehook") && ext == ".dll") {
                if (seen_hook.insert(lower(name)).second)
                    ctx.add(Severity::Warning, "Java input hook library in Temp: " + name,
                            "JNativeHook lets a Java program read and send mouse and keyboard input everywhere. Java "
                            "autoclickers unpack this file into Temp when they start, and its modified time is when "
                            "that program ran. Some normal Java programs with global hotkeys use it too. Modified " + when(ctx, mt) + ".",
                            path, scope_of(ctx, mt));
                return true;
            }
            if (ext != ".exe" && ext != ".dll" && ext != ".jar" && ext != ".bat" && ext != ".ps1") return true;
            if (!ctx.since_boot(mt) || size < 4096) return true;
            bool from_archive = contains(l, "\\rar$") || contains(l, "\\7z") || contains(l, ".zip\\") || contains(l, "\\temp1_");
            if (from_archive && ext != ".dll" && archive_shown < 10) {
                ++archive_shown;
                ctx.add(Severity::Warning, "Program run straight out of an archive this boot: " + name,
                        "WinRAR, 7-Zip and Explorer unpack a file here when you double-click it inside an archive. It shows "
                        "something was run without being extracted to a normal folder. Modified " + fmt_time(mt) + ".", path);
            } else if ((ext == ".exe" || ext == ".dll") && unsigned_shown < 12 && !verify_file(path).trusted) {
                ++unsigned_shown;
                ctx.add(Severity::Warning, "Unsigned program file in Temp changed this boot: " + name,
                        "Injectable cheats have been kept in Temp because it is full of DLLs nobody looks at. Installers "
                        "and updaters also leave unsigned files here. Modified " + fmt_time(mt) + ".", path);
            }
            return files < 60000;
        });
    }
    ctx.add(Severity::Integrity, "Temp folders checked", strf("%zu files looked at.", files), "", Scope::None);
}

// ---------------------------------------------------------------------------
SCAN_CHECK(295, recent_items, Scope::Boot, "Recent items and PowerShell history") {
    static const char* const bad_cmds[] = {
        "usn deletejournal", "wevtutil cl", "wevtutil clear", "clear-eventlog", "remove-eventlog", "\\prefetch", "sc stop", "sc config",
        "net stop", "stop-service", "set-service", "services\\bam", "cipher /w", "sdelete", "attrib +", "vssadmin delete",
        "clear-recyclebin", "remove-item", "reg delete", "schtasks /create", "register-scheduledtask", "-encodedcommand", "frombase64string",
        "downloadstring", "invoke-webrequest", "set-mppreference", "add-mppreference", "fsutil behavior", "suspend-process", "pssuspend",
        "taskkill", "stop-process", "bcdedit", "set-date", "psexec", "streams.exe", "set-content -stream", "forfiles"};
    for (const std::string& home : user_homes()) {
        std::string recent = home + "\\AppData\\Roaming\\Microsoft\\Windows\\Recent";
        if (!is_dir(recent)) continue;
        size_t links = 0;
        std::vector<std::string> opened;
        for (const std::string& f : list_dir(recent)) {
            if (ext_of(f) != ".lnk") continue;
            ++links;
            std::string target = f.substr(0, f.size() - 4);   // "cheat.dll.lnk" -> "cheat.dll"
            std::string path = recent + "\\" + f;
            double mt = file_mtime(path);
            std::vector<std::string> strong = ctx.match_names(target);
            if (!strong.empty())
                ctx.add(ctx.since_boot(mt) ? Severity::Detection : Severity::Warning, "Known cheat name in Recent items: " + target,
                        "Windows adds a shortcut here when a file or folder is opened from Explorer. Matched: " + join(strong) +
                            ". Last opened " + when(ctx, mt) + ".", path, scope_of(ctx, mt));
            else if (odd_unicode(target))
                ctx.add(Severity::Warning, "Recent item with a hidden Unicode character in its name",
                        std::string("The name contains a ") + odd_unicode(target) + ". These characters make a file look like "
                        "something else or look like it has no name. Last opened " + when(ctx, mt) + ".", path, scope_of(ctx, mt));
            std::string ext = ext_of(target);
            if (ctx.since_boot(mt) && (ext == ".exe" || ext == ".dll" || ext == ".jar" || ext == ".bat" || ext == ".ps1" || ext == ".vhd" ||
                                       ext == ".vhdx" || ext == ".iso" || ext == ".ahk" || ext == ".zip" || ext == ".rar" || ext == ".7z") &&
                opened.size() < 20)
                opened.push_back(target + " at " + fmt_time(mt));
        }
        if (!opened.empty())
            ctx.add(Severity::Integrity, "Programs, archives and disk images opened this boot (Recent items)",
                    "Opened from Explorer since boot. Use it for your timeline.", join(opened, " | "));
        size_t jump = list_dir(recent + "\\AutomaticDestinations").size();
        double up = now_epoch() - ctx.boot_time;
        if (links < 3 && up > 3600)
            ctx.add(jump < 3 ? Severity::Warning : Severity::Integrity, "Recent items is almost empty",
                    strf("%zu shortcuts and %zu jump list files. On a PC that is used daily this folder fills up quickly, so "
                         "an empty one usually means it was cleared or tracking is off. Jump lists often survive a clear, so "
                         "open them with JumpList Explorer.", links, jump), recent);
        // PowerShell keeps every command typed in the console in a text file.
        std::string hist = home + "\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";
        std::string text;
        double hmt = file_mtime(hist);
        if (hmt > 0 && read_file(hist, text, 8u << 20)) {
            std::vector<std::string> lines = split(text, '\n');
            std::vector<std::string> hits;
            // only the tail can be from this session
            size_t start = lines.size() > 400 ? lines.size() - 400 : 0;
            for (size_t i = start; i < lines.size(); ++i) {
                std::string l = lower(lines[i]);
                bool hit = !ctx.match_names(l).empty();
                for (const char* k : bad_cmds) hit = hit || contains(l, k);
                if (hit && hits.size() < 12) hits.push_back(trim(cut(lines[i], 220)));
            }
            if (!hits.empty())
                ctx.add(Severity::Warning, "PowerShell history has commands worth reading",
                        "These typed commands stop services, clear logs or the journal, delete files, download code or name a "
                        "known cheat. The file was last written " + when(ctx, hmt) + ", which is when the last command was "
                        "typed. Lines are not dated one by one, so older commands can be in here too.",
                        join(hits, " | "), scope_of(ctx, hmt));
            else if (ctx.since_boot(hmt))
                ctx.add(Severity::Integrity, "PowerShell was used by hand this boot",
                        "The command history file was written " + fmt_time(hmt) + ". Only commands typed by a person land in it.", hist);
        }
    }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(615, hidden_programs, Scope::OutOfInstance, "Programs under another extension, hidden Unicode names and alternate data streams") {
    static const std::set<std::string> disguise = {"", ".txt", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".cfg", ".ini", ".log", ".json",
                                                   ".xml", ".html", ".csv", ".pdf", ".mp3", ".mp4", ".wav", ".doc", ".docx", ".zip", ".rar",
                                                   ".7z", ".dat", ".db", ".ttf", ".md", ".yml", ".yaml", ".properties", ".nbt", ".mcmeta"};
    static const char* const ok_streams[] = {":zone.identifier:$data", ":smartscreen:$data", ":com.dropbox.attrs:$data", ":com.dropbox.attributes:$data",
                                             ":ms-properties:$data", ":oecustomproperty:$data", ":encryptable:$data", ":favicon:$data",
                                             ":afp_afpinfo:$data", ":afp_resource:$data", ":wofcompresseddata:$data", ":$citadel_ads:$data"};
    size_t files = 0, renamed = 0, uni = 0, streams = 0, stream_hits = 0;
    uint64_t budget = ctx.deep ? 400000 : 60000;
    auto check_streams = [&](const std::string& path) {
        WIN32_FIND_STREAM_DATA sd;
        std::wstring w = widen(path);
        HANDLE h = FindFirstStreamW(w.c_str(), FindStreamInfoStandard, &sd, 0);
        if (h == INVALID_HANDLE_VALUE) return;
        do {
            std::string sname = narrow(sd.cStreamName, wcsnlen(sd.cStreamName, MAX_PATH + 36));
            std::string sl = lower(sname);
            if (sl == "::$data") continue;
            ++streams;
            bool zone = sl == ":zone.identifier:$data";
            bool known = false;
            for (const char* k : ok_streams) known = known || sl == k;
            uint64_t ssize = static_cast<uint64_t>(sd.StreamSize.QuadPart);
            if (zone && ssize <= 4096) continue;
            if (known && !zone && ssize < 65536) continue;
            std::string head = ssize >= 0x40 ? read_head(w + sd.cStreamName, 4096) : std::string();
            bool pe = pe_header(head) || (head.size() >= 2 && head[0] == 'M' && head[1] == 'Z');
            if (!pe && ssize < 20480) continue;
            if (stream_hits++ >= 20) continue;
            double mt = file_mtime(path);
            ctx.add(pe ? Severity::Detection : Severity::Warning,
                    pe ? "Program hidden in an alternate data stream" : "Large alternate data stream on a file",
                    std::string(pe ? "A Windows program is stored inside a hidden stream attached to this file or folder. Explorer does "
                                     "not show streams and the visible file looks normal. It can still be run from the command line."
                                   : "This file or folder has a hidden extra stream holding data. Streams are invisible in Explorer.") +
                        (zone ? " It is using the Zone.Identifier name, which is normally a few lines of text." : "") +
                        " Host last changed " + when(ctx, mt) + ".",
                    path + sname + strf(" (%llu bytes)", static_cast<unsigned long long>(ssize)), scope_of(ctx, mt));
        } while (FindNextStreamW(h, &sd));
        FindClose(h);
    };
    for (const std::string& root : user_roots(true)) {
        bool roaming = ends_with(lower(root), "\\appdata\\roaming");
        // folders can carry streams too
        for (const std::string& d : list_dir(root))
            if (is_dir(root + "\\" + d)) check_streams(root + "\\" + d);
        walk_files(root, roaming ? 1 : 3, [&](const std::string& path, uint64_t size) {
            if (++files > budget) return false;
            std::string name = base_name(path), ext = ext_of(path);
            if (const char* what = odd_unicode(name)) {
                bool prog = ext == ".exe" || ext == ".dll" || ext == ".jar" || ext == ".bat" || ext == ".scr" || ext == ".lnk" || ext.empty();
                bool override_char = contains(what, "override");
                // blanks and joiners turn up in ordinary document and emoji names, so only programs count for those
                if ((prog || override_char) && uni++ < 15) {
                    double mt = file_mtime(path);
                    ctx.add(prog ? Severity::Detection : Severity::Warning, "File name contains a hidden Unicode character",
                            std::string("The name contains a ") + what + ". These characters are used to make a program look like "
                            "another file type, to break tools that search by name, or to make a name look empty. Modified " + when(ctx, mt) + ".",
                            path, scope_of(ctx, mt));
                }
            }
            check_streams(path);
            if (size < 8192 || size > (80u << 20) || !disguise.count(ext)) return true;
            std::string head = read_head(widen(path), 4096);
            if (!pe_header(head)) return true;
            if (renamed++ < 20) {
                double mt = file_mtime(path);
                bool in_temp = contains(lower(path), "\\appdata\\local\\temp\\");   // installers unpack odd names there
                ctx.add(ctx.since_boot(mt) && !in_temp ? Severity::Detection : Severity::Warning,
                        ext.empty() ? "Windows program with no file extension: " + name : "Windows program saved as " + ext + ": " + name,
                        "The file starts with a real program header but is not named like a program. Renaming an .exe or .dll is "
                        "a common way to hide a cheat as a picture, text or config file. It can still be run or loaded under "
                        "the fake name. Modified " + when(ctx, mt) + ".",
                        path + strf(" (%.1f MB)", size / 1048576.0), scope_of(ctx, mt));
            }
            return true;
        });
    }
    ctx.add(Severity::Integrity, "Hidden program checks done",
            strf("%zu files looked at, %zu extra data streams, %zu disguised programs, %zu odd names.%s", files, streams, renamed, uni,
                 files > budget ? " Stopped at the file limit; use --deep to go further." : ""),
            "", Scope::None);
}

// ---------------------------------------------------------------------------
SCAN_CHECK(710, drives, Scope::Boot, "USB and virtual drives used this boot, and drives without a journal") {
    wchar_t letters[512];
    DWORD len = GetLogicalDriveStringsW(511, letters);
    std::vector<std::string> now_list;
    for (const wchar_t* d = letters; len && *d; d += wcslen(d) + 1) {
        UINT type = GetDriveTypeW(d);
        if (type != DRIVE_REMOVABLE && type != DRIVE_FIXED) continue;
        wchar_t fs[32] = {0}, label[128] = {0};
        if (!GetVolumeInformationW(d, label, 128, nullptr, nullptr, nullptr, fs, 32)) continue;
        std::string drive = narrow(d, 2), fsn = narrow(fs, wcsnlen(fs, 32));
        now_list.push_back(drive + " " + fsn + (type == DRIVE_REMOVABLE ? " removable" : ""));
        if (fsn != "NTFS" && fsn != "ReFS")
            ctx.add(Severity::Warning, "Drive " + drive + " is " + fsn + " and keeps no journal",
                    "FAT32 and exFAT drives have no USN journal, so files deleted or swapped on them leave no record there. "
                    "Check this drive for deleted files with FTK Imager, and check what was run from it in Prefetch and BAM.",
                    drive + " label \"" + narrow(label, wcsnlen(label, 128)) + "\"", Scope::None);
    }
    std::set<std::string> seen;
    size_t usb = 0;
    for (const Event& e : query_events(L"Microsoft-Windows-Partition/Diagnostic", boot_xpath(ctx, "EventID=1006"), 200)) {
        std::string bus = xml_data(e.xml, "BusType"), model = trim(xml_data(e.xml, "Manufacturer") + " " + xml_data(e.xml, "Model"));
        std::string serial = xml_data(e.xml, "SerialNumber"), cap = xml_data(e.xml, "Capacity");
        bool usb_bus = bus == "7", virt = bus == "14" || bus == "15";   // USB; virtual / file-backed virtual
        if (!usb_bus && !virt) continue;
        bool removed = cap == "0";
        std::string key = model + serial + (removed ? "-" : "+");
        if (!seen.insert(key).second) continue;
        if (usb++ < 12)
            ctx.add(Severity::Warning,
                    std::string(virt ? "Virtual disk " : "USB drive ") + (removed ? "removed this boot" : "connected this boot") + ": " +
                        (model.empty() ? "unknown model" : model),
                    std::string("Logged at ") + fmt_time(e.time) + ". A drive pulled out or unmounted right before a screenshare can "
                    "hold the cheat. Ask for it to be plugged back in and check it.",
                    "serial " + (serial.empty() ? "none" : serial));
    }
    for (const Event& e : query_events(L"Microsoft-Windows-VHDMP-Operational", boot_xpath(ctx, "EventID=1 or EventID=2 or EventID=12"), 60)) {
        std::string file = xml_data(e.xml, "VhdFileName");
        if (file.empty()) file = xml_data(e.xml, "VhdFile");
        if (file.empty() || !seen.insert("vhd" + lower(file) + strf("%d", e.id)).second) continue;
        ctx.add(Severity::Warning, std::string("Virtual disk file ") + (e.id == 2 ? "detached" : "mounted") + " this boot",
                "A .vhd, .vhdx or .iso file was mounted as a drive. Files run from it disappear with the drive when it is "
                "unmounted. Logged at " + fmt_time(e.time) + ".", device_to_dos(file));
    }
    ctx.add(Severity::Integrity, "Drives checked", "Connected now: " + join(now_list), "", Scope::None);
}

// ---------------------------------------------------------------------------
SCAN_CHECK(720, mouse_macros, Scope::Boot, "Mouse software macro and settings files changed this boot") {
    struct M { const char* label; const char* rel; bool home; const char* needle; const char* needle_what; };
    static const M list[] = {
        {"Logitech G HUB", "\\AppData\\Local\\LGHUB\\settings.db", true, nullptr, nullptr},
        {"Logitech Gaming Software", "\\AppData\\Local\\Logitech\\Logitech Gaming Software", true, nullptr, nullptr},
        {"Razer Synapse 2 macros", "\\AppData\\Local\\Razer\\Synapse\\log\\macros", true, "macroclient:delete", "a macro was deleted"},
        {"Razer Synapse 3", "C:\\ProgramData\\Razer\\Synapse3\\Log\\SynapseService.log", false, "turbo: true", "turbo (rapid fire) mode was on"},
        {"Roccat Swarm macros", "\\AppData\\Roaming\\ROCCAT\\SWARM\\macro", true, nullptr, nullptr},
        {"Roccat Swarm preset macros", "\\AppData\\Roaming\\ROCCAT\\SWARM\\preset_macro", true, nullptr, nullptr},
        {"Corsair iCUE", "\\AppData\\Roaming\\Corsair\\CUE\\Config.cuecfg", true, "recmouseclicksenable", "mouse click recording is on in macros"},
        {"Corsair iCUE 4", "\\AppData\\Roaming\\Corsair\\CUE4\\Config.cuecfg", true, "recmouseclicksenable", "mouse click recording is on in macros"},
        {"Glorious / Ajazz", "\\AppData\\Local\\BYCOMBO-2", true, nullptr, nullptr},
        {"Glorious / Ajazz", "\\AppData\\Roaming\\BYCOMBO-2", true, nullptr, nullptr},
        {"ASUS ROG Armoury", "\\Documents\\ASUS\\ROG\\ROG Armoury\\common", true, nullptr, nullptr},
        {"Bloody7", "C:\\Program Files (x86)\\Bloody7\\Bloody7\\Data\\Mouse\\English\\ScriptsMacros\\GunLib", false, nullptr, nullptr},
        {"Blackweb", "C:\\Blackweb Gaming AP\\config", false, nullptr, nullptr},
        {"AYAX", "C:\\Program Files\\AYAX GamingMouse\\record.ini", false, nullptr, nullptr},
        {"X-Mouse Button Control", "\\AppData\\Roaming\\Highresolution Enterprises\\XMouseButtonControl", true, nullptr, nullptr},
        {"SteelSeries GG", "C:\\ProgramData\\SteelSeries\\GG\\apps\\engine\\db", false, nullptr, nullptr},
    };
    std::vector<std::string> homes = user_homes();
    size_t found = 0;
    for (const M& m : list) {
        std::vector<std::string> paths;
        if (m.home) for (const std::string& h : homes) paths.push_back(h + m.rel);
        else paths.push_back(m.rel);
        for (const std::string& p : paths) {
            std::vector<std::pair<double, std::string>> files;
            if (is_dir(p)) walk_files(p, 2, [&](const std::string& f, uint64_t) { files.push_back({file_mtime(f), f}); return files.size() < 400; });
            else if (file_mtime(p) > 0) files.push_back({file_mtime(p), p});
            if (files.empty()) continue;
            ++found;
            std::sort(files.rbegin(), files.rend());
            std::vector<std::string> changed;
            for (const auto& f : files)
                if (ctx.since_boot(f.first) && changed.size() < 6) changed.push_back(base_name(f.second) + " at " + fmt_time(f.first));
            std::string extra;
            if (m.needle) {
                std::string text;
                const std::string& newest = files[0].second;
                if (read_file(newest, text, 16u << 20)) {
                    lower_inplace(text);
                    if (text.find(m.needle) != std::string::npos) extra = std::string(" The file also shows ") + m.needle_what + ".";
                }
            }
            if (!changed.empty())
                ctx.add(Severity::Warning, std::string("Mouse software files changed this boot: ") + m.label,
                        "Macro or settings files for this mouse software were written since boot. Editing or deleting a macro right "
                        "before a screenshare shows up as a change here. The software also saves settings by itself sometimes, so "
                        "open it and look at the macros." + extra, p + ": " + join(changed, " | "));
            else if (!extra.empty())
                ctx.add(Severity::Warning, std::string("Mouse software setting to check: ") + m.label,
                        "Nothing changed this boot." + extra + " Newest file is from " + fmt_time(files[0].first) + ".", p, Scope::OutOfInstance);
        }
    }
    // Redragon keeps macros in Documents\<model> Gaming Mouse\MacroDB
    for (const std::string& h : homes)
        for (const std::string& d : list_dir(h + "\\Documents")) {
            std::string macro = h + "\\Documents\\" + d + "\\MacroDB";
            if (!contains(lower(d), "gaming mouse") || !is_dir(macro)) continue;
            ++found;
            double newest = file_mtime(macro);
            for (const std::string& f : list_dir(macro)) newest = std::max(newest, file_mtime(macro + "\\" + f));
            if (ctx.since_boot(newest))
                ctx.add(Severity::Warning, "Mouse macro folder changed this boot: " + d,
                        "The macro folder was written at " + fmt_time(newest) + ".", macro);
        }
    for (const ProcInfo& p : processes()) {
        std::string l = lower(p.name);
        if (starts_with(l, "autohotkey") || l == "xmousebuttoncontrol.exe" || l == "tinytask.exe" || l == "macrorecorder.exe")
            ctx.add(Severity::Warning, "Macro tool is running: " + p.name,
                    "This program can replay or generate clicks and key presses. Check what script or profile it has loaded.",
                    (p.path.empty() ? p.name : p.path) + strf(" (PID %lu, started %s)", p.pid, fmt_time(p.start).c_str()));
    }
    ctx.add(Severity::Integrity, "Mouse software checked",
            strf("%zu known macro or settings locations exist on this PC. Mouse software not on the list is not covered.", found), "", Scope::None);
}

}  // namespace scan
#endif

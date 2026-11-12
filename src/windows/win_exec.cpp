// What ran on this PC: running processes, BAM, Prefetch, PCA, service memory,
// DNS cache and file dialogs. Each finding is tagged Boot when it happened
// since the last boot, otherwise Out of instance.
#ifdef _WIN32
#include "win_util.hpp"

#include <algorithm>
#include <ctime>
#include <map>
#include <set>

#include "../util.hpp"

namespace scan {
using namespace win;

namespace {

bool gone(const std::string& path) {
    if (path.size() < 3 || path[1] != ':') return false;
    DWORD a = GetFileAttributesW(widen(path).c_str());
    if (a != INVALID_FILE_ATTRIBUTES) return false;
    DWORD e = GetLastError();
    return e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND;
}

double parse_utc(const std::string& s) {
    struct tm t{};
    int y, mo, d, h, mi, se;
    if (sscanf(s.c_str(), "%d-%d-%d %d:%d:%d", &y, &mo, &d, &h, &mi, &se) != 6) return 0;
    t.tm_year = y - 1900; t.tm_mon = mo - 1; t.tm_mday = d;
    t.tm_hour = h; t.tm_min = mi; t.tm_sec = se;
    return static_cast<double>(_mkgmtime(&t));
}

// Text files that may be UTF-16LE or plain 8-bit.
std::string read_text_any(const std::string& path) {
    std::string raw;
    if (!read_file(path, raw, 32u << 20)) return std::string();
    size_t zeros = 0, sample = std::min<size_t>(raw.size(), 4096);
    for (size_t i = 0; i < sample; ++i) zeros += raw[i] == 0;
    if (sample && zeros > sample / 4) {
        size_t skip = (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xFF) ? 2 : 0;
        return narrow(reinterpret_cast<const wchar_t*>(raw.data() + skip), (raw.size() - skip) / 2);
    }
    return raw;
}

struct Prefetch {
    bool ok = false;
    std::string exe;
    double last_run = 0;
    std::vector<std::string> files;
};

Prefetch parse_prefetch(const std::string& path) {
    Prefetch pf;
    std::string raw;
    if (!read_file(path, raw, 16u << 20) || raw.size() < 0x100) return pf;
    std::string data;
    if (raw.compare(0, 3, "MAM") == 0) {
        typedef LONG(NTAPI * WsSize)(USHORT, PULONG, PULONG);
        typedef LONG(NTAPI * Decomp)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID);
        static WsSize ws_size = reinterpret_cast<WsSize>(nt_proc("RtlGetCompressionWorkSpaceSize"));
        static Decomp decomp = reinterpret_cast<Decomp>(nt_proc("RtlDecompressBufferEx"));
        if (!ws_size || !decomp) return pf;
        uint32_t out_size = 0;
        memcpy(&out_size, raw.data() + 4, 4);
        if (out_size < 0x100 || out_size > (64u << 20)) return pf;
        size_t hdr = (static_cast<unsigned char>(raw[3]) & 0x80) ? 12 : 8;
        ULONG ws1 = 0, ws2 = 0;
        if (ws_size(4 /*XPRESS_HUFF*/, &ws1, &ws2) < 0) return pf;
        std::vector<unsigned char> ws(ws1 + 16);
        data.resize(out_size);
        ULONG final_size = 0;
        if (decomp(4, reinterpret_cast<PUCHAR>(&data[0]), out_size,
                   reinterpret_cast<PUCHAR>(&raw[hdr]), static_cast<ULONG>(raw.size() - hdr), &final_size, ws.data()) < 0)
            return pf;
        data.resize(final_size);
    } else {
        data.swap(raw);
    }
    if (data.size() < 0x100 || data.compare(4, 4, "SCCA") != 0) return pf;
    uint32_t version = 0, str_off = 0, str_size = 0;
    memcpy(&version, data.data(), 4);
    wchar_t name[30] = {0};
    memcpy(name, data.data() + 0x10, 58);
    pf.exe = narrow(name, wcsnlen(name, 29));
    memcpy(&str_off, data.data() + 0x64, 4);
    memcpy(&str_size, data.data() + 0x68, 4);
    int times = version >= 26 ? 8 : 1;
    size_t toff = version == 17 ? 0x78 : 0x80;
    for (int i = 0; i < times && toff + 8 * (i + 1) <= data.size(); ++i) {
        uint64_t ft = 0;
        memcpy(&ft, data.data() + toff + 8 * i, 8);
        pf.last_run = std::max(pf.last_run, ft_to_epoch(ft));
    }
    if (uint64_t(str_off) + str_size <= data.size() && str_size >= 2) {
        const wchar_t* w = reinterpret_cast<const wchar_t*>(data.data() + str_off);
        size_t chars = str_size / 2, i = 0;
        while (i < chars) {
            size_t j = i;
            while (j < chars && w[j]) ++j;
            if (j > i) pf.files.push_back(narrow(w + i, j - i));
            i = j + 1;
        }
    }
    pf.ok = true;
    return pf;
}

// "\VOLUME{01d9...-ABCD1234}\USERS\X\A.DLL" -> "\USERS\X\A.DLL"
std::string strip_volume(const std::string& p) {
    if (starts_with(p, "\\VOLUME{") || starts_with(p, "\\volume{")) {
        size_t e = p.find('}');
        if (e != std::string::npos) return p.substr(e + 1);
    }
    return p;
}

bool known_native(const std::string& l) {
    for (const char* k : {"lwjgl", "natives", "jna", "jinput", "openal", "glfw", "discord", "netty", "sqlite",
                          "lunar", "badlion", "feather", "labymod", "jcef", "oshi", "jansi"})
        if (contains(l, k)) return true;
    return false;
}

}  // namespace

// ---------------------------------------------------------------------------
SCAN_CHECK(200, running_processes, Scope::Boot, "Known cheats and clickers running right now") {
    for (const ProcInfo& p : processes()) {
        std::vector<std::string> strong = ctx.match_names(p.name);
        std::string ev = (p.path.empty() ? p.name : p.path) + strf(" (PID %lu, started %s)", p.pid, fmt_time(p.start).c_str());
        if (!strong.empty()) {
            ctx.add(Severity::Detection, "Known cheat running: " + p.name, "Matched: " + join(strong) + ". It is running right now.", ev);
            continue;
        }
        std::vector<std::string> weak = ctx.match_weak(p.name);
        if (!weak.empty())
            ctx.add(Severity::Warning, "Suspicious process name: " + p.name,
                    "Matched a generic word: " + join(weak) + ". Check what the program is.", ev);
    }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(210, bam, Scope::Boot, "BAM: programs each user ran and when") {
    std::wstring base = L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";
    std::vector<std::string> sids = reg_subkeys(HKEY_LOCAL_MACHINE, base);
    if (sids.empty()) {
        base = L"SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings";
        sids = reg_subkeys(HKEY_LOCAL_MACHINE, base);
    }
    if (sids.empty()) {
        ctx.add(Severity::Warning, "No BAM user data",
                "The BAM key has no user entries. If the scan ran as administrator, BAM was cleared or "
                "is disabled.", narrow(base), Scope::None);
        return;
    }
    size_t total = 0, deleted_recent = 0;
    double oldest = 0;
    for (const std::string& sid : sids) {
        for (const RegValue& v : reg_values(HKEY_LOCAL_MACHINE, base + L"\\" + widen(sid))) {
            if (v.data.size() < 8 || !starts_with(lower(v.name), "\\device\\")) continue;
            ++total;
            uint64_t ft = 0;
            memcpy(&ft, v.data.data(), 8);
            double ts = ft_to_epoch(ft);
            if (ts > 0 && (oldest == 0 || ts < oldest)) oldest = ts;
            std::string path = device_to_dos(v.name);
            std::string name = base_name(path);
            bool since = ctx.since_boot(ts);
            bool missing = gone(path);
            std::vector<std::string> strong = ctx.match_names(name);
            std::vector<std::string> weak = strong.empty() ? ctx.match_weak(name) : std::vector<std::string>();
            std::string when = "Last run " + fmt_time(ts) + (since ? " (since this boot)." : " (before this boot).") +
                               (missing ? " The file is no longer on disk." : "");
            Scope sc = since ? Scope::Boot : Scope::OutOfInstance;
            if (!strong.empty())
                ctx.add(since ? Severity::Detection : Severity::Warning, "Known cheat in BAM: " + name,
                        when + " Matched: " + join(strong) + ".", path, sc);
            else if (!weak.empty())
                ctx.add(Severity::Warning, "Suspicious program in BAM: " + name,
                        when + " Matched a generic word: " + join(weak) + ".", path, sc);
            else if (since && missing && user_writable_path(path) && deleted_recent++ < 10)
                ctx.add(Severity::Warning, "Program ran this boot and was deleted: " + name,
                        when + " It ran from a user folder and is gone now.", path, Scope::Boot);
        }
    }
    if (total && oldest > 0 && ctx.since_boot(oldest) && now_epoch() - ctx.boot_time < 48 * 3600)
        ctx.add(Severity::Warning, "Every BAM entry is from this boot",
                "BAM normally holds about a week of history. Nothing older than the last boot can mean "
                "it was cleared. A new Windows install or a first login looks the same.",
                strf("%zu entries, oldest %s", total, fmt_time(oldest).c_str()));
    ctx.add(Severity::Integrity, "BAM read", strf("%zu entries for %zu user(s). BAM does not record every run.", total, sids.size()),
            "", Scope::None);
}

// ---------------------------------------------------------------------------
SCAN_CHECK(220, prefetch, Scope::Boot, "Prefetch: state, tampering, what ran and what the game loaded") {
    RegValue v;
    const wchar_t* pp = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters";
    if (!reg_get(HKEY_LOCAL_MACHINE, pp, L"EnablePrefetcher", v))
        ctx.add(Severity::Warning, "EnablePrefetcher setting is missing", "The setting that turns Prefetch on is gone.", "", Scope::None);
    else if (v.dword() == 0)
        ctx.add(Severity::Detection, "Prefetch is turned off",
                "EnablePrefetcher is 0, so Windows records no program runs. Windows does not set this "
                "by itself.", "EnablePrefetcher=0", Scope::None);
    else if (v.dword() != 3)
        ctx.add(Severity::Warning, "Prefetch is partly turned off", "EnablePrefetcher should be 3.",
                strf("EnablePrefetcher=%lu", v.dword()), Scope::None);

    std::string dir = windows_dir() + "\\Prefetch";
    if (!is_dir(dir)) {
        ctx.add(Severity::Detection, "Prefetch folder is missing", "The Prefetch folder does not exist.", dir, Scope::None);
        return;
    }
    size_t count = 0, parsed = 0, user_loads = 0;
    for (const std::string& f : list_dir(dir)) {
        if (ext_of(f) != ".pf") continue;
        ++count;
        std::string path = dir + "\\" + f;
        DWORD attr = GetFileAttributesW(widen(path).c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_READONLY))
            ctx.add(Severity::Detection, "Read-only prefetch file: " + f,
                    "A .pf file was set read-only, which stops Windows updating it. A known way to "
                    "freeze a program's run count and time.", path, Scope::None);
        Prefetch pf = parse_prefetch(path);
        std::string exe = pf.ok && !pf.exe.empty() ? pf.exe : f.substr(0, f.rfind('-'));
        double ts = pf.ok && pf.last_run > 0 ? pf.last_run : file_mtime(path);
        if (pf.ok) ++parsed;
        bool since = ctx.since_boot(ts);
        Scope sc = since ? Scope::Boot : Scope::OutOfInstance;
        std::string when = "Last run " + fmt_time(ts) + (since ? " (since this boot)." : " (before this boot).");

        std::vector<std::string> strong = ctx.match_names(exe);
        std::vector<std::string> weak = strong.empty() ? ctx.match_weak(exe) : std::vector<std::string>();
        if (!strong.empty())
            ctx.add(since ? Severity::Detection : Severity::Warning, "Known cheat in Prefetch: " + exe,
                    when + " Matched: " + join(strong) + ".", path, sc);
        else if (!weak.empty())
            ctx.add(Severity::Warning, "Suspicious name in Prefetch: " + exe,
                    when + " Matched a generic word: " + join(weak) + ".", path, sc);
        if (!pf.ok) continue;

        std::string exe_l = lower(exe);
        bool is_game = exe_l == "javaw.exe" || exe_l == "java.exe";
        for (const std::string& raw : pf.files) {
            std::string file = strip_volume(raw);
            std::string fl = lower(file);
            std::string ext = ext_of(fl);
            if (ext != ".dll" && ext != ".jar" && ext != ".exe" && ext != ".sys") continue;
            std::vector<std::string> hit = ctx.match_names(base_name(file));
            if (!hit.empty() && lower(base_name(file)) != exe_l) {
                ctx.add(since ? Severity::Detection : Severity::Warning,
                        exe + " loaded a known cheat file",
                        when + " Prefetch lists the files a program opened in its first seconds. Matched: " + join(hit) + ".",
                        file, sc);
            } else if (is_game && ext != ".exe" && user_writable_path(fl) && !known_native(fl) && user_loads < 10) {
                ++user_loads;
                ctx.add(Severity::Warning, "The game loaded a file from a user folder at startup",
                        when + " Launchers load from their own folders, so a DLL or jar from Downloads, "
                        "Desktop, Documents or Temp should be checked.", file, sc);
            }
        }
    }
    ctx.add(Severity::Integrity, "Prefetch read",
            strf("%zu .pf files, %zu parsed. Windows keeps up to 1024. A very low count on a PC in daily "
                 "use can mean files were deleted; the USN check lists deleted .pf files.", count, parsed),
            "", Scope::None);
}

// ---------------------------------------------------------------------------
SCAN_CHECK(230, pca, Scope::Boot, "Program Compatibility Assistant launch records") {
    std::string dir = windows_dir() + "\\appcompat\\pca\\";
    size_t lines = 0;
    for (const char* file : {"PcaAppLaunchDic.txt", "PcaGeneralDb0.txt", "PcaGeneralDb1.txt"}) {
        std::string text = read_text_any(dir + file);
        if (text.empty()) continue;
        bool dic = std::string(file) == "PcaAppLaunchDic.txt";
        for (const std::string& raw : split(text, '\n')) {
            std::vector<std::string> parts = split(trim(raw), '|');
            if (parts.size() < 2) continue;
            ++lines;
            std::string path = dic ? parts[0] : (parts.size() > 2 ? parts[2] : std::string());
            double ts = parse_utc(dic ? parts[1] : parts[0]);
            if (path.empty()) continue;
            std::string name = base_name(path);
            std::vector<std::string> strong = ctx.match_names(name);
            if (strong.empty()) continue;
            bool since = ctx.since_boot(ts);
            ctx.add(since ? Severity::Detection : Severity::Warning, "Known cheat in PCA records: " + name,
                    "Windows logged this program starting at " + fmt_time(ts) +
                        (since ? " (since this boot)." : " (before this boot).") + " Matched: " + join(strong) + "." +
                        (gone(path) ? " The file is no longer on disk." : ""),
                    path, since ? Scope::Boot : Scope::OutOfInstance);
        }
    }
    if (lines) ctx.add(Severity::Integrity, "PCA records read", strf("%zu launch records.", lines), "", Scope::None);
    else ctx.note("no PCA launch files found (they exist on Windows 11 22H2 and newer)");
}

// ---------------------------------------------------------------------------
namespace {

// Pulls "X:\...\name.ext" style paths out of a string.
void paths_in(const std::string& s, std::set<std::string>& out) {
    static const char* const exts[] = {".exe", ".dll", ".jar", ".bat", ".ps1", ".sys"};
    std::string l = lower(s);
    size_t pos = 0;
    while ((pos = l.find(":\\", pos)) != std::string::npos) {
        if (pos == 0 || !isalpha(static_cast<unsigned char>(l[pos - 1]))) { pos += 2; continue; }
        size_t start = pos - 1, best = std::string::npos;
        for (const char* e : exts) {
            size_t p = l.find(e, pos);
            if (p == std::string::npos) continue;
            size_t end = p + strlen(e);
            if (end < l.size() && isalnum(static_cast<unsigned char>(l[end]))) continue;
            if (end < best) best = end;
        }
        if (best == std::string::npos || best - start > 300) { pos += 2; continue; }
        std::string path = s.substr(start, best - start);
        if (path.find_first_of("\"<>|*?") == std::string::npos && out.size() < 50000) out.insert(path);
        pos = best;
    }
}

}  // namespace

SCAN_CHECK(240, service_memory, Scope::Boot, "Programs recorded in service memory since boot (DPS, PcaSvc)") {
    struct Svc { const wchar_t* name; const char* label; };
    for (const Svc& svc : {Svc{L"DPS", "DPS"}, Svc{L"PcaSvc", "PcaSvc"}}) {
        DWORD state = 0;
        DWORD pid = service_pid(svc.name, &state);
        if (!pid) {
            ctx.note(std::string(svc.label) + " service is not running, its memory could not be searched");
            continue;
        }
        HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!h) {
            ctx.note(std::string("could not open the ") + svc.label + " service process (run as administrator)");
            continue;
        }
        std::set<std::string> paths, dps_names;
        std::string buf;
        std::vector<std::string> strings;
        uint64_t scanned = 0;
        for (const Region& r : regions(h)) {
            if (r.type != MEM_PRIVATE || (r.protect & (PAGE_GUARD | PAGE_NOACCESS)) || scanned > (1ull << 30)) continue;
            for (uint64_t off = 0; off < r.size; off += (4u << 20)) {
                size_t want = static_cast<size_t>(std::min<uint64_t>(4u << 20, r.size - off));
                buf.resize(want);
                SIZE_T got = 0;
                ReadProcessMemory(h, reinterpret_cast<LPCVOID>(r.base + off), &buf[0], want, &got);
                if (!got) break;
                scanned += got;
                strings.clear();
                extract_strings(buf.data(), got, 8, strings);
                for (const std::string& s : strings) {
                    if (s.find(":\\") != std::string::npos) paths_in(s, paths);
                    // DPS keeps "!!name.exe!2024/01/31:12:00:00!..." for programs it watched
                    size_t b = s.find("!!");
                    if (b != std::string::npos) {
                        size_t e = s.find('!', b + 2);
                        if (e != std::string::npos && e - b < 80 && contains(lower(s.substr(b, e - b)), ".exe"))
                            dps_names.insert(s.substr(b + 2, e - b - 2));
                    }
                }
            }
        }
        CloseHandle(h);
        double started = process_start(pid);
        size_t deleted = 0;
        std::set<std::string> reported;
        for (const std::string& name : dps_names) {
            std::vector<std::string> strong = ctx.match_names(name);
            if (!strong.empty() && reported.insert(lower(name)).second)
                ctx.add(Severity::Detection, std::string("Known cheat in ") + svc.label + " memory: " + name,
                        "This service keeps the names of programs it saw running. Its memory starts empty "
                        "at boot, so this ran since boot even if the file is gone. Matched: " + join(strong) + ".",
                        name);
        }
        for (const std::string& path : paths) {
            std::string name = base_name(path);
            std::vector<std::string> strong = ctx.match_names(name);
            if (!strong.empty()) {
                if (reported.insert(lower(name)).second)
                    ctx.add(Severity::Detection, std::string("Known cheat in ") + svc.label + " memory: " + name,
                            "The path of this file is in the service's memory, which starts empty at boot. "
                            "Matched: " + join(strong) + "." + (gone(path) ? " The file is no longer on disk." : ""),
                            path);
            } else if (ext_of(path) != ".dll" && user_writable_path(path) && gone(path) && deleted < 12 &&
                       reported.insert(lower(path)).second) {
                ++deleted;
                ctx.add(Severity::Warning, "Program seen since boot is gone now: " + name,
                        std::string("Its path is in ") + svc.label + " memory, so it existed since boot, and it "
                        "was in a user folder. The file is not there any more.", path);
            }
        }
        ctx.add(Severity::Integrity, std::string(svc.label) + " memory searched",
                strf("%.0f MB, %zu file paths and %zu watched program names found. Service started %s.",
                     scanned / 1048576.0, paths.size(), dps_names.size(), fmt_time(started).c_str()),
                "", Scope::None);
    }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(250, dns_cache, Scope::Boot, "Cheat sites looked up since boot (DNS cache)") {
    if (ctx.sigs.domains.empty()) return;
    struct Entry {
        Entry* next;
        wchar_t* name;
        unsigned short type, data_len;
        unsigned long flags;
    };
    HMODULE dns = LoadLibraryW(L"dnsapi.dll");
    if (!dns) return;
    typedef int(WINAPI * GetTable)(Entry*);
    GetTable get = reinterpret_cast<GetTable>(reinterpret_cast<void*>(GetProcAddress(dns, "DnsGetCacheDataTable")));
    if (!get) return;
    Entry head{};
    if (!get(&head)) {
        ctx.note("the DNS cache could not be read (the DNS Client service may be off)");
        return;
    }
    size_t n = 0;
    std::set<std::string> seen;
    for (Entry* e = head.next; e && n < 100000; e = e->next, ++n) {
        if (!e->name) continue;
        std::string name = narrow(e->name, wcsnlen(e->name, 512));
        std::vector<std::string> hit = ctx.match_domains(name);
        if (!hit.empty() && seen.insert(lower(name)).second)
            ctx.add(Severity::Warning, "Cheat site in the DNS cache: " + name,
                    "This address was looked up recently on this PC. The cache empties on reboot and "
                    "entries expire, so it is from this boot. A lookup can also come from a link "
                    "preview or an ad, so it is a lead. Matched: " + join(hit) + ".", name);
    }
    ctx.add(Severity::Integrity, "DNS cache read", strf("%zu cached names.", n), "", Scope::None);
}

// ---------------------------------------------------------------------------
SCAN_CHECK(260, file_dialogs, Scope::OutOfInstance, "DLLs and programs picked in file windows") {
    for (const std::string& sid : user_sids()) {
        std::wstring base = widen(sid) + L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\";
        for (const wchar_t* ext : {L"dll", L"jar", L"exe"}) {
            std::wstring key = base + L"OpenSavePidlMRU\\" + ext;
            std::vector<RegValue> vals = reg_values(HKEY_USERS, key);
            if (vals.empty()) continue;
            double changed = reg_key_time(HKEY_USERS, key);
            bool since = ctx.since_boot(changed);
            std::vector<std::string> names;
            for (const RegValue& v : vals) {
                if (v.type != REG_BINARY || lower(v.name) == "mrulistex") continue;
                std::vector<std::string> strs;
                extract_strings(reinterpret_cast<const char*>(v.data.data()), v.data.size(), 5, strs);
                for (const std::string& s : strs)
                    if (ext_of(s) == "." + narrow(ext) && std::find(names.begin(), names.end(), s) == names.end())
                        names.push_back(s);
            }
            if (names.empty()) continue;
            std::vector<std::string> strong;
            for (const std::string& n : names)
                for (const std::string& h : ctx.match_names(n)) strong.push_back(n + " (" + h + ")");
            std::string e = narrow(ext);
            if (!strong.empty())
                ctx.add(since ? Severity::Detection : Severity::Warning, "Known cheat file was picked in a file window",
                        "Windows remembers files chosen in open/save windows. List last changed " + fmt_time(changed) + ".",
                        join(strong), since ? Scope::Boot : Scope::OutOfInstance);
            else if (e == "dll" && since)
                ctx.add(Severity::Warning, "A DLL was picked in a file window this boot",
                        "Injector programs ask you to pick the DLL in a file window, and Windows remembers "
                        "those picks. The list changed at " + fmt_time(changed) + ". It does not prove the "
                        "DLL was loaded into anything.", join(names), Scope::Boot);
            else if (e == "dll")
                ctx.add(Severity::Integrity, "DLLs picked in file windows before this boot",
                        "List last changed " + fmt_time(changed) + ".", join(names));
        }
        // programs that showed a file window (injector GUIs end up here)
        for (const RegValue& v : reg_values(HKEY_USERS, base + L"LastVisitedPidlMRU")) {
            if (v.type != REG_BINARY) continue;
            std::vector<std::string> strs;
            extract_strings(reinterpret_cast<const char*>(v.data.data()), v.data.size(), 5, strs);
            for (const std::string& s : strs) {
                if (ext_of(s) != ".exe") continue;
                std::vector<std::string> strong = ctx.match_names(s);
                if (!strong.empty())
                    ctx.add(Severity::Warning, "Known cheat tool used a file window: " + s,
                            "Windows remembers which programs opened a file window. Matched: " + join(strong) + ".", s);
            }
        }
    }
}

}  // namespace scan
#endif

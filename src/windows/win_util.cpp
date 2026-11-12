#ifdef _WIN32
#include "win_util.hpp"

#include <psapi.h>
#include <softpub.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <winevt.h>
#include <wintrust.h>

#include <ctime>
#include <unordered_map>

#include "../util.hpp"

namespace scan {

// ---- platform entry points ----
bool platform_is_admin() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION el{};
    DWORD len = 0;
    BOOL ok = GetTokenInformation(tok, TokenElevation, &el, sizeof el, &len);
    CloseHandle(tok);
    return ok && el.TokenIsElevated;
}

double platform_boot_time() { return now_epoch() - static_cast<double>(GetTickCount64()) / 1000.0; }

void platform_prepare(Context&) {
    SetConsoleOutputCP(CP_UTF8);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(out, &mode)) SetConsoleMode(out, mode | 0x0004 /*VT processing*/);
    win::enable_privilege(L"SeDebugPrivilege");
    win::enable_privilege(L"SeBackupPrivilege");
    win::enable_privilege(L"SeSecurityPrivilege");
    win::enable_privilege(L"SeManageVolumePrivilege");
}

namespace win {

std::wstring widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n > 0 ? n : 0), L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), &w[0], n);
    return w;
}

std::string narrow(const wchar_t* w, size_t len) {
    if (!w || !len) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(len), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n > 0 ? n : 0), '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(len), &s[0], n, nullptr, nullptr);
    return s;
}

std::string narrow(const std::wstring& w) { return narrow(w.data(), w.size()); }

bool enable_privilege(const wchar_t* name) {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid) &&
              AdjustTokenPrivileges(tok, FALSE, &tp, sizeof tp, nullptr, nullptr) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(tok);
    return ok;
}

double ft_to_epoch(uint64_t ft) {
    if (ft == 0) return 0;
    return static_cast<double>(ft) / 1e7 - 11644473600.0;
}
double ft_to_epoch(const FILETIME& ft) {
    return ft_to_epoch((uint64_t(ft.dwHighDateTime) << 32) | ft.dwLowDateTime);
}
uint64_t ms_since_boot() { return GetTickCount64(); }

void* nt_proc(const char* name) {
    static HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    return nt ? reinterpret_cast<void*>(GetProcAddress(nt, name)) : nullptr;
}

double process_start(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return 0;
    FILETIME c, e, k, u;
    double t = GetProcessTimes(h, &c, &e, &k, &u) ? ft_to_epoch(c) : 0;
    CloseHandle(h);
    return t;
}

const std::vector<ProcInfo>& processes() {
    static std::vector<ProcInfo> cache;
    static bool done = false;
    if (done) return cache;
    done = true;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return cache;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof pe;
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcInfo p;
            p.pid = pe.th32ProcessID;
            p.ppid = pe.th32ParentProcessID;
            p.name = narrow(pe.szExeFile, wcslen(pe.szExeFile));
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
            if (h) {
                wchar_t buf[1024];
                DWORD n = 1024;
                if (QueryFullProcessImageNameW(h, 0, buf, &n)) p.path = narrow(buf, n);
                FILETIME c, e, k, u;
                if (GetProcessTimes(h, &c, &e, &k, &u)) p.start = ft_to_epoch(c);
                CloseHandle(h);
            }
            cache.push_back(std::move(p));
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return cache;
}

const ProcInfo* find_process(DWORD pid) {
    for (const ProcInfo& p : processes())
        if (p.pid == pid) return &p;
    return nullptr;
}

std::vector<ProcInfo> game_processes() {
    static std::vector<ProcInfo> cache;
    static bool done = false;
    if (done) return cache;
    done = true;
    std::vector<ProcInfo> java, minecraft;
    for (const ProcInfo& p : processes()) {
        std::string n = lower(p.name);
        if (n != "javaw.exe" && n != "java.exe") continue;
        java.push_back(p);
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
        if (!h) continue;
        std::string cmd = lower(remote_cmdline(h));
        CloseHandle(h);
        for (const char* k : {"minecraft", "lunar", "badlion", "feather", "labymod", "fabric", "forge",
                              "optifine", "lwjgl", "mojang", "tlauncher", "prism", "multimc"})
            if (contains(cmd, k) || contains(lower(p.path), k)) {
                minecraft.push_back(p);
                break;
            }
    }
    // If nothing looks like Minecraft, fall back to every Java process.
    cache = minecraft.empty() ? java : minecraft;
    return cache;
}

std::string device_to_dos(const std::string& path) {
    static std::vector<std::pair<std::string, std::string>> map;
    static bool done = false;
    if (!done) {
        done = true;
        wchar_t dev[512];
        for (wchar_t l = L'A'; l <= L'Z'; ++l) {
            wchar_t drive[3] = {l, L':', 0};
            if (QueryDosDeviceW(drive, dev, 512))
                map.push_back({lower(narrow(dev, wcslen(dev))), narrow(drive, 2)});
        }
    }
    std::string low = lower(path);
    for (const auto& m : map)
        if (low.size() > m.first.size() && low.compare(0, m.first.size(), m.first) == 0 &&
            low[m.first.size()] == '\\')
            return m.second + path.substr(m.first.size());
    return path;
}

std::string windows_dir() {
    wchar_t buf[MAX_PATH];
    UINT n = GetWindowsDirectoryW(buf, MAX_PATH);
    return n ? narrow(buf, n) : std::string("C:\\Windows");
}

bool user_writable_path(const std::string& path) {
    std::string l = lower(path);
    if (contains(l, "\\users\\public\\") || contains(l, "\\windows\\temp\\")) return true;
    if (!contains(l, "\\users\\")) return false;
    return contains(l, "\\downloads\\") || contains(l, "\\desktop\\") || contains(l, "\\documents\\") ||
           contains(l, "\\appdata\\local\\temp\\") || contains(l, "\\onedrive") ||
           contains(l, "\\pictures\\") || contains(l, "\\videos\\") || contains(l, "\\music\\");
}

// ---- signatures ----
static bool catalog_signed(const std::wstring& wpath) {
    typedef BOOL(WINAPI * Acquire2)(HANDLE*, const GUID*, PCWSTR, void*, DWORD);
    typedef BOOL(WINAPI * Calc2)(HANDLE, HANDLE, DWORD*, BYTE*, DWORD);
    typedef HANDLE(WINAPI * EnumCat)(HANDLE, BYTE*, DWORD, DWORD, HANDLE*);
    typedef BOOL(WINAPI * RelCat)(HANDLE, HANDLE, DWORD);
    typedef BOOL(WINAPI * RelCtx)(HANDLE, DWORD);
    static HMODULE wt = LoadLibraryW(L"wintrust.dll");
    if (!wt) return false;
    static Acquire2 acquire = reinterpret_cast<Acquire2>(reinterpret_cast<void*>(GetProcAddress(wt, "CryptCATAdminAcquireContext2")));
    static Calc2 calc = reinterpret_cast<Calc2>(reinterpret_cast<void*>(GetProcAddress(wt, "CryptCATAdminCalcHashFromFileHandle2")));
    static EnumCat enumcat = reinterpret_cast<EnumCat>(reinterpret_cast<void*>(GetProcAddress(wt, "CryptCATAdminEnumCatalogFromHash")));
    static RelCat relcat = reinterpret_cast<RelCat>(reinterpret_cast<void*>(GetProcAddress(wt, "CryptCATAdminReleaseCatalogContext")));
    static RelCtx relctx = reinterpret_cast<RelCtx>(reinterpret_cast<void*>(GetProcAddress(wt, "CryptCATAdminReleaseContext")));
    if (!acquire || !calc || !enumcat || !relcat || !relctx) return false;

    bool found = false;
    for (const wchar_t* alg : {L"SHA256", L"SHA1"}) {
        HANDLE admin = nullptr;
        if (!acquire(&admin, nullptr, alg, nullptr, 0)) continue;
        HANDLE f = CreateFileW(wpath.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD len = 0;
            calc(admin, f, &len, nullptr, 0);
            if (len > 0 && len <= 64) {
                BYTE hash[64];
                if (calc(admin, f, &len, hash, 0)) {
                    HANDLE ci = enumcat(admin, hash, len, 0, nullptr);
                    if (ci) {
                        found = true;
                        relcat(admin, ci, 0);
                    }
                }
            }
            CloseHandle(f);
        }
        relctx(admin, 0);
        if (found) break;
    }
    return found;
}

const SigInfo& verify_file(const std::string& path) {
    static std::unordered_map<std::string, SigInfo> cache;
    std::string key = lower(path);
    auto it = cache.find(key);
    if (it != cache.end()) return it->second;
    SigInfo info;
    std::wstring wpath = widen(path);
    if (GetFileAttributesW(wpath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_FILE_INFO fi{};
        fi.cbStruct = sizeof fi;
        fi.pcwszFilePath = wpath.c_str();
        WINTRUST_DATA wd{};
        wd.cbStruct = sizeof wd;
        wd.dwUIChoice = WTD_UI_NONE;
        wd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wd.dwUnionChoice = WTD_CHOICE_FILE;
        wd.pFile = &fi;
        wd.dwStateAction = WTD_STATEACTION_VERIFY;
        wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        LONG r = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
        if (r == ERROR_SUCCESS) {
            info.trusted = true;
            CRYPT_PROVIDER_DATA* pd = WTHelperProvDataFromStateData(wd.hWVTStateData);
            CRYPT_PROVIDER_SGNR* sg = pd ? WTHelperGetProvSignerFromChain(pd, 0, FALSE, 0) : nullptr;
            CRYPT_PROVIDER_CERT* cert = sg ? WTHelperGetProvCertFromChain(sg, 0) : nullptr;
            if (cert && cert->pCert) {
                wchar_t name[256];
                DWORD n = CertGetNameStringW(cert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, 256);
                if (n > 1) info.signer = narrow(name, n - 1);
            }
        }
        wd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
        if (!info.trusted && catalog_signed(wpath)) {
            info.trusted = true;
            info.catalog = true;
            info.signer = "Windows catalog";
        }
    }
    return cache.emplace(key, info).first->second;
}

// ---- registry ----
static HKEY open_key(HKEY root, const std::wstring& path) {
    HKEY k = nullptr;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) return nullptr;
    return k;
}

std::string RegValue::text() const {
    if (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ) {
        if (type == REG_DWORD && data.size() >= 4) return std::to_string(dword());
        return std::string();
    }
    size_t chars = data.size() / 2;
    const wchar_t* w = reinterpret_cast<const wchar_t*>(data.data());
    while (chars && w[chars - 1] == 0) --chars;
    std::string s = narrow(w, chars);
    for (char& c : s)
        if (c == '\0') c = ';';
    return s;
}

DWORD RegValue::dword() const {
    DWORD d = 0;
    if (data.size() >= 4) memcpy(&d, data.data(), 4);
    return d;
}

std::vector<std::string> reg_subkeys(HKEY root, const std::wstring& path) {
    std::vector<std::string> out;
    HKEY k = open_key(root, path);
    if (!k) return out;
    wchar_t name[512];
    for (DWORD i = 0;; ++i) {
        DWORD n = 512;
        if (RegEnumKeyExW(k, i, name, &n, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        out.push_back(narrow(name, n));
    }
    RegCloseKey(k);
    return out;
}

std::vector<RegValue> reg_values(HKEY root, const std::wstring& path) {
    std::vector<RegValue> out;
    HKEY k = open_key(root, path);
    if (!k) return out;
    DWORD max_name = 0, max_data = 0;
    RegQueryInfoKeyW(k, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &max_name, &max_data, nullptr, nullptr);
    std::vector<wchar_t> name(static_cast<size_t>(max_name) + 2);
    std::vector<uint8_t> data(static_cast<size_t>(max_data) + 2);
    for (DWORD i = 0;; ++i) {
        DWORD nn = static_cast<DWORD>(name.size()), dn = static_cast<DWORD>(data.size()), type = 0;
        LONG r = RegEnumValueW(k, i, name.data(), &nn, nullptr, &type, data.data(), &dn);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        RegValue v;
        v.name = narrow(name.data(), nn);
        v.type = type;
        v.data.assign(data.begin(), data.begin() + dn);
        out.push_back(std::move(v));
    }
    RegCloseKey(k);
    return out;
}

bool reg_get(HKEY root, const std::wstring& path, const std::wstring& name, RegValue& out) {
    HKEY k = open_key(root, path);
    if (!k) return false;
    DWORD type = 0, size = 0;
    bool ok = false;
    if (RegQueryValueExW(k, name.c_str(), nullptr, &type, nullptr, &size) == ERROR_SUCCESS) {
        out.data.assign(static_cast<size_t>(size) + 2, 0);
        DWORD s2 = size;
        if (RegQueryValueExW(k, name.c_str(), nullptr, &type, out.data.data(), &s2) == ERROR_SUCCESS) {
            out.data.resize(s2);
            out.type = type;
            out.name = narrow(name);
            ok = true;
        }
    }
    RegCloseKey(k);
    return ok;
}

bool reg_key_exists(HKEY root, const std::wstring& path) {
    HKEY k = open_key(root, path);
    if (!k) return false;
    RegCloseKey(k);
    return true;
}

double reg_key_time(HKEY root, const std::wstring& path) {
    HKEY k = open_key(root, path);
    if (!k) return 0;
    FILETIME ft{};
    double t = 0;
    if (RegQueryInfoKeyW(k, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &ft) == ERROR_SUCCESS)
        t = ft_to_epoch(ft);
    RegCloseKey(k);
    return t;
}

std::vector<std::string> user_sids() {
    std::vector<std::string> out;
    for (const std::string& s : reg_subkeys(HKEY_USERS, L""))
        if (starts_with(s, "S-1-5-21-") && !ends_with(s, "_Classes")) out.push_back(s);
    return out;
}

// ---- remote memory ----
bool read_mem(HANDLE h, uint64_t addr, void* buf, size_t n) {
    SIZE_T got = 0;
    return ReadProcessMemory(h, reinterpret_cast<LPCVOID>(addr), buf, n, &got) && got == n;
}

std::string mapped_path(HANDLE h, uint64_t addr) {
    wchar_t buf[1024];
    DWORD n = GetMappedFileNameW(h, reinterpret_cast<LPVOID>(addr), buf, 1024);
    return n ? device_to_dos(narrow(buf, n)) : std::string();
}

bool query_region(HANDLE h, uint64_t addr, Region& out) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQueryEx(h, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof mbi)) return false;
    out.base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
    out.alloc_base = reinterpret_cast<uint64_t>(mbi.AllocationBase);
    out.size = mbi.RegionSize;
    out.state = mbi.State;
    out.protect = mbi.Protect;
    out.type = mbi.Type;
    return true;
}

std::vector<Region> regions(HANDLE h) {
    std::vector<Region> out;
    uint64_t addr = 0;
    Region r;
    while (addr < 0x7FFFFFFF0000ull && query_region(h, addr, r)) {
        if (r.size == 0) break;
        if (r.state == MEM_COMMIT) out.push_back(r);
        addr = r.base + r.size;
    }
    return out;
}

typedef LONG(NTAPI * NtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);

std::string remote_cmdline(HANDLE h) {
    NtQIP q = reinterpret_cast<NtQIP>(nt_proc("NtQueryInformationProcess"));
    if (!q) return std::string();
    std::vector<uint8_t> buf(0x10000);
    ULONG ret = 0;
    if (q(h, 60 /*ProcessCommandLineInformation*/, buf.data(), static_cast<ULONG>(buf.size()), &ret) < 0)
        return std::string();
    struct US { USHORT Length, MaximumLength; ULONG pad; wchar_t* Buffer; };
    US* us = reinterpret_cast<US*>(buf.data());
    const uint8_t* b = reinterpret_cast<const uint8_t*>(us->Buffer);
    if (b < buf.data() || b + us->Length > buf.data() + buf.size()) return std::string();
    return narrow(us->Buffer, us->Length / 2);
}

std::vector<std::pair<std::string, std::string>> remote_env(HANDLE h) {
    std::vector<std::pair<std::string, std::string>> out;
    NtQIP q = reinterpret_cast<NtQIP>(nt_proc("NtQueryInformationProcess"));
    if (!q) return out;
    struct PBI { LONG status; ULONG pad; uint64_t peb; uint64_t a, b, c, d; } pbi{};
    ULONG ret = 0;
    if (q(h, 0, &pbi, sizeof pbi, &ret) < 0 || !pbi.peb) return out;
    uint64_t params = 0, env = 0, env_size = 0;
    if (!read_mem(h, pbi.peb + 0x20, &params, 8) || !params) return out;
    if (!read_mem(h, params + 0x80, &env, 8) || !env) return out;
    if (!read_mem(h, params + 0x3F0, &env_size, 8) || env_size == 0 || env_size > (4u << 20)) env_size = 0x8000;
    std::vector<wchar_t> block(static_cast<size_t>(env_size / 2) + 1, 0);
    SIZE_T got = 0;
    ReadProcessMemory(h, reinterpret_cast<LPCVOID>(env), block.data(), static_cast<SIZE_T>(env_size), &got);
    size_t chars = got / 2, i = 0;
    while (i < chars && block[i]) {
        size_t j = i;
        while (j < chars && block[j]) ++j;
        std::string kv = narrow(&block[i], j - i);
        size_t eq = kv.find('=', 1);
        if (eq != std::string::npos) out.push_back({kv.substr(0, eq), kv.substr(eq + 1)});
        i = j + 1;
    }
    return out;
}

// ---- event log ----
static double parse_iso_utc(const std::string& s) {
    struct tm t{};
    int y, mo, d, h, mi, se;
    if (sscanf(s.c_str(), "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &se) != 6) return 0;
    t.tm_year = y - 1900; t.tm_mon = mo - 1; t.tm_mday = d;
    t.tm_hour = h; t.tm_min = mi; t.tm_sec = se;
    return static_cast<double>(_mkgmtime(&t));
}

std::vector<Event> query_events(const std::wstring& channel, const std::wstring& xpath, size_t max_events) {
    std::vector<Event> out;
    EVT_HANDLE q = EvtQuery(nullptr, channel.c_str(), xpath.c_str(), EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!q) return out;
    EVT_HANDLE ev[16];
    DWORD got = 0;
    std::vector<wchar_t> buf(1 << 15);
    while (out.size() < max_events && EvtNext(q, 16, ev, 3000, 0, &got)) {
        for (DWORD i = 0; i < got; ++i) {
            if (out.size() < max_events) {
                DWORD used = 0, props = 0;
                if (!EvtRender(nullptr, ev[i], EvtRenderEventXml, static_cast<DWORD>(buf.size() * 2), buf.data(), &used, &props) &&
                    GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    buf.resize(used / 2 + 2);
                    EvtRender(nullptr, ev[i], EvtRenderEventXml, static_cast<DWORD>(buf.size() * 2), buf.data(), &used, &props);
                }
                Event e;
                e.xml = narrow(buf.data(), wcsnlen(buf.data(), buf.size()));
                size_t t = e.xml.find("SystemTime=");
                if (t != std::string::npos && t + 12 < e.xml.size()) e.time = parse_iso_utc(e.xml.substr(t + 12, 19));
                size_t idp = e.xml.find("<EventID");
                if (idp != std::string::npos) {
                    size_t gt = e.xml.find('>', idp);
                    if (gt != std::string::npos) e.id = atoi(e.xml.c_str() + gt + 1);
                }
                out.push_back(std::move(e));
            }
            EvtClose(ev[i]);
        }
    }
    EvtClose(q);
    return out;
}

std::string xml_data(const std::string& xml, const std::string& name) {
    for (const char* quote : {"'", "\""}) {
        std::string key = "Name=" + std::string(quote) + name + quote;
        size_t p = xml.find(key);
        if (p == std::string::npos) continue;
        size_t gt = xml.find('>', p);
        if (gt == std::string::npos) continue;
        if (gt > 0 && xml[gt - 1] == '/') return std::string();
        size_t lt = xml.find('<', gt);
        if (lt == std::string::npos) continue;
        return xml.substr(gt + 1, lt - gt - 1);
    }
    return std::string();
}

DWORD service_pid(const wchar_t* name, DWORD* state, DWORD* start_type) {
    DWORD pid = 0;
    if (state) *state = 0;
    if (start_type) *start_type = 0xFFFFFFFF;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return 0;
    SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (svc) {
        SERVICE_STATUS_PROCESS ssp{};
        DWORD need = 0;
        if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof ssp, &need)) {
            pid = ssp.dwProcessId;
            if (state) *state = ssp.dwCurrentState;
        }
        if (start_type) {
            std::vector<uint8_t> cfg(8192);
            if (QueryServiceConfigW(svc, reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(cfg.data()), static_cast<DWORD>(cfg.size()), &need))
                *start_type = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(cfg.data())->dwStartType;
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return pid;
}

}  // namespace win
}  // namespace scan
#endif

// Things that start by themselves or load into other programs: Run keys,
// IFEO, AppInit, shims, WMI consumers, Java options set for every JVM, and
// scheduled tasks.
#ifdef _WIN32
#include "win_util.hpp"

#include <wbemidl.h>

#include <set>

#include "../util.hpp"

namespace scan {
using namespace win;

namespace {

// First path-looking token of a command line.
std::string command_target(const std::string& cmd) {
    std::string s = trim(cmd);
    if (s.empty()) return s;
    if (s[0] == '"') {
        size_t e = s.find('"', 1);
        return e == std::string::npos ? s.substr(1) : s.substr(1, e - 1);
    }
    std::string l = lower(s);
    for (const char* ext : {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".dll", ".jar"}) {
        size_t p = l.find(ext);
        if (p != std::string::npos) return s.substr(0, p + strlen(ext));
    }
    size_t sp = s.find(' ');
    return sp == std::string::npos ? s : s.substr(0, sp);
}

std::string expand(const std::string& s) {
    wchar_t buf[2048];
    DWORD n = ExpandEnvironmentStringsW(widen(s).c_str(), buf, 2048);
    return n && n < 2048 ? narrow(buf, n - 1) : s;
}

bool script_host(const std::string& l) {
    for (const char* k : {"powershell", "pwsh", "cmd.exe", "cmd /", "wscript", "cscript", "mshta", "rundll32", "regsvr32",
                          "bitsadmin", "certutil", "javaw", "java.exe", "curl ", "msiexec"})
        if (contains(l, k)) return true;
    return false;
}

void check_autorun(Context& ctx, const std::string& where, const std::string& name, const std::string& cmd, double key_time) {
    std::string l = lower(cmd);
    std::string target = expand(command_target(cmd));
    std::vector<std::string> strong = ctx.match_names(name + " " + cmd);
    bool since = ctx.since_boot(key_time);
    Scope sc = since ? Scope::Boot : Scope::OutOfInstance;
    std::string ev = where + "\\" + name + " = " + cut(cmd, 300);
    if (!strong.empty()) {
        ctx.add(Severity::Detection, "Known cheat starts with Windows: " + name, "Matched: " + join(strong) + ".", ev, sc);
        return;
    }
    bool user_path = user_writable_path(target) || contains(l, "\\appdata\\local\\temp\\");
    bool encoded = contains(l, "-enc") || contains(l, "frombase64string") || contains(l, "downloadstring") ||
                   contains(l, "iex ") || contains(l, "-w hidden") || contains(l, "-windowstyle hidden");
    if (encoded)
        ctx.add(Severity::Warning, "Autorun runs a hidden or encoded script: " + name,
                "The command hides its window, decodes text or downloads code when Windows starts.", ev, sc);
    else if (user_path && script_host(l))
        ctx.add(Severity::Warning, "Autorun runs a script from a user folder: " + name, "Check what it starts.", ev, sc);
    else if (user_path && target.size() > 3 && target[1] == ':' && file_exists(target) && !verify_file(target).trusted)
        ctx.add(Severity::Warning, "Unsigned autorun from a user folder: " + name,
                "It starts with Windows from Downloads, Desktop, Documents or Temp and has no valid signature.", ev, sc);
    else if (target.size() > 3 && target[1] == ':' && !file_exists(target) && since)
        ctx.add(Severity::Warning, "Autorun added this boot points at a missing file: " + name, "The file it starts is gone.", ev, sc);
}

std::string bstr(const VARIANT& v) {
    if (v.vt == VT_BSTR && v.bstrVal) return narrow(v.bstrVal, SysStringLen(v.bstrVal));
    return std::string();
}

void wmi_consumers(Context& ctx) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool uninit = SUCCEEDED(hr);
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                         nullptr, EOAC_NONE, nullptr);
    IWbemLocator* loc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, reinterpret_cast<void**>(&loc))) || !loc) {
        ctx.note("WMI could not be opened, event consumers were not checked");
        if (uninit) CoUninitialize();
        return;
    }
    IWbemServices* svc = nullptr;
    BSTR ns = SysAllocString(L"ROOT\\subscription");
    hr = loc->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc);
    SysFreeString(ns);
    if (SUCCEEDED(hr) && svc) {
        CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
                          RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
        struct Q { const wchar_t* cls; const wchar_t* prop; const char* what; };
        for (const Q& q : {Q{L"CommandLineEventConsumer", L"CommandLineTemplate", "runs a command"},
                           Q{L"ActiveScriptEventConsumer", L"ScriptText", "runs a script"}}) {
            BSTR lang = SysAllocString(L"WQL");
            BSTR query = SysAllocString((std::wstring(L"SELECT * FROM ") + q.cls).c_str());
            IEnumWbemClassObject* en = nullptr;
            if (SUCCEEDED(svc->ExecQuery(lang, query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &en)) && en) {
                for (;;) {
                    IWbemClassObject* obj = nullptr;
                    ULONG got = 0;
                    if (en->Next(5000, 1, &obj, &got) != S_OK || !got) break;
                    VARIANT name, body;
                    VariantInit(&name);
                    VariantInit(&body);
                    obj->Get(L"Name", 0, &name, nullptr, nullptr);
                    obj->Get(q.prop, 0, &body, nullptr, nullptr);
                    std::string n = bstr(name), b = bstr(body);
                    // "SCM Event Log Consumer" style built-ins are NTEventLogEventConsumer, not these classes.
                    bool known = contains(lower(b), "\\dell\\") || contains(lower(b), "\\hp\\") || contains(lower(n), "bvtconsumer");
                    std::vector<std::string> strong = ctx.match_names(n + " " + b);
                    ctx.add(!strong.empty() ? Severity::Detection : known ? Severity::Integrity : Severity::Warning,
                            "WMI event consumer " + std::string(q.what) + ": " + n,
                            "WMI consumers run a command or script when something happens (a logon, a timer, "
                            "a program starting). Almost nothing normal on a home PC uses them, and they do "
                            "not show in Task Manager's startup list.", cut(b, 400), Scope::OutOfInstance);
                    VariantClear(&name);
                    VariantClear(&body);
                    obj->Release();
                }
                en->Release();
            }
            SysFreeString(lang);
            SysFreeString(query);
        }
        svc->Release();
    } else {
        ctx.note("the WMI subscription namespace could not be opened (run as administrator)");
    }
    loc->Release();
    if (uninit) CoUninitialize();
}

}  // namespace

// ---------------------------------------------------------------------------
SCAN_CHECK(500, autoruns, Scope::OutOfInstance, "Run keys, startup folder and WMI consumers") {
    static const wchar_t* const keys[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    };
    size_t total = 0;
    for (const wchar_t* k : keys) {
        double t = reg_key_time(HKEY_LOCAL_MACHINE, k);
        for (const RegValue& v : reg_values(HKEY_LOCAL_MACHINE, k)) {
            ++total;
            check_autorun(ctx, "HKLM\\" + narrow(k), v.name, v.text(), t);
        }
        for (const std::string& sid : user_sids()) {
            std::wstring full = widen(sid) + L"\\" + k;
            double ut = reg_key_time(HKEY_USERS, full);
            for (const RegValue& v : reg_values(HKEY_USERS, full)) {
                ++total;
                check_autorun(ctx, "HKU\\" + sid + "\\" + narrow(k), v.name, v.text(), ut);
            }
        }
    }
    for (const std::string& home : user_homes()) {
        std::string dir = home + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
        for (const std::string& f : list_dir(dir)) {
            if (lower(f) == "desktop.ini") continue;
            ++total;
            std::string path = dir + "\\" + f;
            std::vector<std::string> strong = ctx.match_names(f);
            std::string ext = ext_of(f);
            double mt = file_mtime(path);
            Scope sc = ctx.since_boot(mt) ? Scope::Boot : Scope::OutOfInstance;
            if (!strong.empty())
                ctx.add(Severity::Detection, "Known cheat in the Startup folder: " + f, "Matched: " + join(strong) + ".", path, sc);
            else if (ext == ".bat" || ext == ".cmd" || ext == ".ps1" || ext == ".vbs" || ext == ".js" || ext == ".jar" || ext == ".ahk")
                ctx.add(Severity::Warning, "Script in the Startup folder: " + f, "It runs at every logon. Modified " + fmt_time(mt) + ".", path, sc);
            else if (ext == ".exe" && !verify_file(path).trusted)
                ctx.add(Severity::Warning, "Unsigned program in the Startup folder: " + f, "Modified " + fmt_time(mt) + ".", path, sc);
        }
    }
    wmi_consumers(ctx);
    ctx.add(Severity::Integrity, "Autoruns checked", strf("%zu Run and Startup entries.", total), "", Scope::None);
}

// ---------------------------------------------------------------------------
SCAN_CHECK(510, load_hijacks, Scope::OutOfInstance, "IFEO, AppInit, AppCert, shims and Java options for every JVM") {
    for (const wchar_t* base : {L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                                L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"}) {
        for (const std::string& exe : reg_subkeys(HKEY_LOCAL_MACHINE, base)) {
            std::wstring key = std::wstring(base) + L"\\" + widen(exe);
            RegValue v;
            double t = reg_key_time(HKEY_LOCAL_MACHINE, key);
            Scope sc = ctx.since_boot(t) ? Scope::Boot : Scope::OutOfInstance;
            std::string le = lower(exe);
            bool java = le == "javaw.exe" || le == "java.exe" || contains(le, "minecraft") || contains(le, "lunar");
            if (reg_get(HKEY_LOCAL_MACHINE, key, L"Debugger", v) && !v.text().empty())
                ctx.add(java ? Severity::Detection : Severity::Warning, "IFEO debugger set for " + exe,
                        "Whenever this program starts, Windows starts the listed program instead. It is used "
                        "to block screenshare tools and to wrap the game in a loader. Key changed " + fmt_time(t) + ".",
                        v.text(), sc);
            if (reg_get(HKEY_LOCAL_MACHINE, key, L"VerifierDlls", v) && !v.text().empty())
                ctx.add(java ? Severity::Detection : Severity::Warning, "IFEO verifier DLL set for " + exe,
                        "Windows loads this DLL into the program every time it starts. Key changed " + fmt_time(t) + ".",
                        v.text(), sc);
            if (java && reg_get(HKEY_LOCAL_MACHINE, key, L"GlobalFlag", v) && v.dword() != 0)
                ctx.add(Severity::Warning, "IFEO GlobalFlag set for " + exe, "Debug flags are set for the game's program.",
                        strf("GlobalFlag=0x%lX", v.dword()), sc);
            if (reg_get(HKEY_LOCAL_MACHINE, key, L"MitigationOptions", v) && java) {
                // informational: mitigations on java are unusual but not harmful
            }
        }
    }
    for (const wchar_t* key : {L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                               L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"}) {
        RegValue dlls, load;
        if (reg_get(HKEY_LOCAL_MACHINE, key, L"AppInit_DLLs", dlls) && !trim(dlls.text()).empty()) {
            bool on = reg_get(HKEY_LOCAL_MACHINE, key, L"LoadAppInit_DLLs", load) && load.dword() != 0;
            ctx.add(on ? Severity::Detection : Severity::Warning, "AppInit_DLLs is set",
                    std::string("DLLs listed here load into every program that uses user32.dll, the game included. ") +
                        (on ? "Loading is switched on." : "Loading is switched off right now (LoadAppInit_DLLs=0)."),
                    dlls.text());
        }
    }
    std::vector<RegValue> certs = reg_values(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls");
    for (const RegValue& v : certs)
        ctx.add(Severity::Detection, "AppCertDlls entry: " + v.name,
                "DLLs listed here load into every process that starts another process. Normal installs have none.", v.text());

    for (const std::string& exe : reg_subkeys(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom")) {
        std::string le = lower(exe);
        bool java = le == "javaw.exe" || le == "java.exe";
        ctx.add(java ? Severity::Detection : Severity::Warning, "Custom compatibility shim for " + exe,
                "A custom shim database is applied to this program. Shims can load a DLL into it at start.",
                "AppCompatFlags\\Custom\\" + exe);
    }
    for (const std::string& sdb : reg_subkeys(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB")) {
        RegValue path;
        std::wstring key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB\\" + widen(sdb);
        reg_get(HKEY_LOCAL_MACHINE, key, L"DatabasePath", path);
        ctx.add(Severity::Integrity, "Installed shim database", "Changed " + fmt_time(reg_key_time(HKEY_LOCAL_MACHINE, key)) + ".",
                path.text().empty() ? sdb : path.text());
    }

    // Java options that apply to every JVM started later. An agent here is
    // injected into the game at every launch without touching the launcher.
    std::vector<std::pair<std::string, std::vector<RegValue>>> envs;
    envs.push_back({"system", reg_values(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment")});
    for (const std::string& sid : user_sids()) envs.push_back({"user " + sid, reg_values(HKEY_USERS, widen(sid) + L"\\Environment")});
    for (const auto& e : envs)
        for (const RegValue& v : e.second) {
            std::string n = lower(v.name), val = v.text(), lv = lower(val);
            if (n != "java_tool_options" && n != "_java_options" && n != "jdk_java_options") continue;
            bool agent = contains(lv, "-javaagent") || contains(lv, "-agentpath") || contains(lv, "-agentlib") ||
                         contains(lv, "-xbootclasspath") || contains(lv, "-djava.system.class.loader");
            ctx.add(agent ? Severity::Detection : Severity::Warning, "Java options are set for every Java program: " + v.name,
                    agent ? "This saved environment variable makes every Java program, the game included, load an "
                            "agent or extra classes at start. It survives relaunching the game."
                          : "This saved environment variable adds options to every Java program. No agent is in it.",
                    e.first + ": " + v.name + "=" + cut(val, 300));
        }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(520, scheduled_tasks, Scope::OutOfInstance, "Scheduled tasks with cheat names or hidden scripts (quick pass)") {
    std::string root = windows_dir() + "\\System32\\Tasks";
    size_t count = 0, shown = 0;
    walk_files(root, 6, [&](const std::string& path, uint64_t size) {
        if (size > (1u << 20)) return true;
        ++count;
        std::string rel = path.substr(root.size());
        bool microsoft = starts_with(lower(rel), "\\microsoft\\");
        std::string raw;
        if (!read_file(path, raw, 1u << 20)) return true;
        std::string xml = raw;
        if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xFF && static_cast<unsigned char>(raw[1]) == 0xFE)
            xml = narrow(reinterpret_cast<const wchar_t*>(raw.data() + 2), (raw.size() - 2) / 2);
        std::string cmd = xml_data(xml, "Command"), args = xml_data(xml, "Arguments");
        if (cmd.empty()) {
            size_t a = xml.find("<Command>"), b = xml.find("</Command>");
            if (a != std::string::npos && b != std::string::npos && b > a) cmd = xml.substr(a + 9, b - a - 9);
            a = xml.find("<Arguments>"); b = xml.find("</Arguments>");
            if (a != std::string::npos && b != std::string::npos && b > a) args = xml.substr(a + 11, b - a - 11);
        }
        if (cmd.empty()) return true;
        std::string l = lower(cmd + " " + args);
        std::vector<std::string> strong = ctx.match_names(base_name(rel) + " " + cmd + " " + args);
        double mt = file_mtime(path);
        Scope sc = ctx.since_boot(mt) ? Scope::Boot : Scope::OutOfInstance;
        std::string ev = "Task " + rel + ": " + cut(cmd + " " + args, 300);
        if (!strong.empty())
            ctx.add(Severity::Detection, "Scheduled task runs a known cheat: " + base_name(rel), "Matched: " + join(strong) + ".", ev, sc);
        else if (!microsoft && shown < 15 &&
                 (contains(l, "-enc") || contains(l, "frombase64string") || contains(l, "downloadstring") ||
                  contains(l, "-w hidden") || contains(l, "-windowstyle hidden") ||
                  (script_host(l) && (user_writable_path(expand(cmd)) || contains(l, "\\appdata\\local\\temp\\") ||
                                      contains(l, "\\users\\public\\"))))) {
            ++shown;
            ctx.add(Severity::Warning, "Scheduled task runs a hidden script or from a user folder: " + base_name(rel),
                    "Task file modified " + fmt_time(mt) + ". Use the Combined Task Parser for the full check.", ev, sc);
        }
        return true;
    });
    ctx.add(Severity::Integrity, "Scheduled tasks read",
            strf("%zu task files. This is a quick pass; the Combined Task Parser also finds tasks hidden from disk.", count),
            "", Scope::None);
}

}  // namespace scan
#endif

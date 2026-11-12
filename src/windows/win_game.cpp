// In-game checks: what is inside the running Minecraft (Java) process, and
// what was loaded into it since it started.
#ifdef _WIN32
#include "win_util.hpp"

#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <map>
#include <set>

#include "../util.hpp"

namespace scan {
using namespace win;

namespace {

struct Game {
    ProcInfo info;
    HANDLE h = nullptr;
};

struct GameSet {
    std::vector<Game> games;
    explicit GameSet(Context& ctx, bool notes = false) {
        std::vector<ProcInfo> procs = game_processes();
        if (procs.empty() && notes)
            ctx.note("no Minecraft (javaw.exe) process is running, so in-game checks were skipped. "
                     "Have the player open the game and scan again.");
        for (const ProcInfo& p : procs) {
            HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, p.pid);
            if (!h) {
                if (notes) ctx.note(strf("could not open game PID %lu (run as administrator)", p.pid));
                continue;
            }
            games.push_back({p, h});
        }
    }
    ~GameSet() {
        for (Game& g : games) CloseHandle(g.h);
    }
};

struct Mod {
    uint64_t base = 0, size = 0;
    std::string path;
};

std::vector<Mod> loader_modules(HANDLE h) {
    std::vector<Mod> out;
    std::vector<HMODULE> mods(2048);
    DWORD need = 0;
    if (!EnumProcessModulesEx(h, mods.data(), static_cast<DWORD>(mods.size() * sizeof(HMODULE)), &need, LIST_MODULES_ALL))
        return out;
    size_t n = std::min<size_t>(need / sizeof(HMODULE), mods.size());
    for (size_t i = 0; i < n; ++i) {
        Mod m;
        m.base = reinterpret_cast<uint64_t>(mods[i]);
        wchar_t buf[1024];
        DWORD len = GetModuleFileNameExW(h, mods[i], buf, 1024);
        if (len) m.path = narrow(buf, len);
        MODULEINFO mi{};
        if (GetModuleInformation(h, mods[i], &mi, sizeof mi)) m.size = mi.SizeOfImage;
        out.push_back(std::move(m));
    }
    return out;
}

bool exec_protect(DWORD p) {
    if (p & PAGE_GUARD) return false;
    DWORD b = p & 0xFF;
    return b == PAGE_EXECUTE || b == PAGE_EXECUTE_READ || b == PAGE_EXECUTE_READWRITE || b == PAGE_EXECUTE_WRITECOPY;
}

bool readable_protect(DWORD p) {
    if (p & (PAGE_GUARD | PAGE_NOACCESS)) return false;
    return (p & 0xFF) != 0;
}

bool is_pe_at(HANDLE h, uint64_t addr) {
    unsigned char buf[0x1000];
    if (!read_mem(h, addr, buf, sizeof buf)) return false;
    if (buf[0] != 'M' || buf[1] != 'Z') return false;
    uint32_t lfanew = 0;
    memcpy(&lfanew, buf + 0x3C, 4);
    return lfanew < 0xF00 && memcmp(buf + lfanew, "PE\0\0", 4) == 0;
}

bool definitely_missing(const std::string& path) {
    if (path.empty()) return false;
    DWORD a = GetFileAttributesW(widen(path).c_str());
    if (a != INVALID_FILE_ATTRIBUTES) return false;
    DWORD e = GetLastError();
    return e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND;
}

bool under_windows(const std::string& path) {
    static std::string w = lower(windows_dir()) + "\\";
    return starts_with(lower(path), w);
}

// Libraries games and launchers unpack into temp or user folders themselves.
bool known_native(const std::string& lower_path) {
    for (const char* k : {"lwjgl", "natives", "jna", "jinput", "openal", "glfw", "discord", "netty",
                          "sqlite", "jansi", "oshi", "lunar", "badlion", "feather", "labymod", "sodium",
                          "iris", "voicechat", "opus", "rnnoise", "webrtc", "jcef", "chromium", "skija",
                          "imgui-java", "saturn", "zstd", "lz4", "steam", "overwolf", "medal", "nvidia",
                          "amd", "obs", "rtss", "msi afterburner"})
        if (contains(lower_path, k)) return true;
    return false;
}

std::string describe_target(HANDLE h, uint64_t target, bool& trusted, bool& in_image) {
    Region r;
    trusted = false;
    in_image = false;
    if (!query_region(h, target, r)) return strf("0x%llX (unreadable)", static_cast<unsigned long long>(target));
    if (r.type == MEM_IMAGE) {
        in_image = true;
        std::string path = mapped_path(h, target);
        if (path.empty()) return strf("0x%llX in an image with no file name", static_cast<unsigned long long>(target));
        const SigInfo& si = verify_file(path);
        trusted = si.trusted;
        return path + (si.trusted ? " (signed: " + si.signer + ")" : " (NOT signed)");
    }
    return strf("0x%llX in private memory with no file behind it", static_cast<unsigned long long>(target));
}

}  // namespace

// ---------------------------------------------------------------------------
SCAN_CHECK(100, game_launch, Scope::InGame, "Game process, Java agents and injected Java options") {
    GameSet gs(ctx, true);
    static const char* const flags[] = {"-javaagent:", "-agentpath:", "-agentlib:", "-xbootclasspath"};
    for (Game& g : gs.games) {
        const ProcInfo* parent = find_process(g.info.ppid);
        ctx.add(Severity::Integrity, strf("Game process found (PID %lu)", g.info.pid),
                "Started " + fmt_time(g.info.start) + ", launched by " +
                    (parent ? parent->name : std::string("a process that has exited")) +
                    ". In-game checks only see what happened since the game started, so a game "
                    "restart right before the SS is worth noting.",
                g.info.path);
        std::string cmd = remote_cmdline(g.h);
        std::string low = lower(cmd);
        for (const char* f : flags)
            if (contains(low, f))
                ctx.add(Severity::Warning, strf("Java agent/boot flag on the game (PID %lu)", g.info.pid),
                        std::string("The launch command uses ") + f +
                            " which loads code into the game. Some clients use their own agent, so "
                            "check which file it points at.",
                        cut(cmd, 2000));
        std::vector<std::string> strong = ctx.match_names(cmd);
        if (!strong.empty())
            ctx.add(Severity::Detection, strf("Known cheat name in the game command (PID %lu)", g.info.pid),
                    "Matched: " + join(strong) + ".", cut(cmd, 2000));
        for (const auto& kv : remote_env(g.h)) {
            std::string k = lower(kv.first);
            if (k != "java_tool_options" && k != "_java_options" && k != "jdk_java_options") continue;
            std::string v = lower(kv.second);
            bool agent = false;
            for (const char* f : flags) agent = agent || contains(v, f);
            ctx.add(agent ? Severity::Detection : Severity::Warning,
                    kv.first + strf(" is set inside the game (PID %lu)", g.info.pid),
                    agent ? "This variable loads a Java agent into the game without it showing in "
                            "the launcher settings."
                          : "This variable adds hidden options to the game. No agent in it, but it "
                            "is unusual on a gaming PC.",
                    kv.first + "=" + kv.second);
        }
    }
    // the same variables set for future launches
    std::vector<std::pair<HKEY, std::wstring>> keys = {
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"}};
    for (const std::string& sid : user_sids()) keys.push_back({HKEY_USERS, widen(sid) + L"\\Environment"});
    for (const auto& k : keys)
        for (const wchar_t* var : {L"JAVA_TOOL_OPTIONS", L"_JAVA_OPTIONS", L"JDK_JAVA_OPTIONS"}) {
            RegValue v;
            if (!reg_get(k.first, k.second, var, v) || v.text().empty()) continue;
            std::string val = lower(v.text());
            bool agent = contains(val, "-javaagent") || contains(val, "-agentpath") || contains(val, "-agentlib");
            ctx.add(agent ? Severity::Detection : Severity::Warning,
                    narrow(var) + " is set in the Windows environment",
                    agent ? "Every Java program, including the game, loads this agent at start."
                          : "Adds options to every Java program. No agent in it right now.",
                    narrow(var) + "=" + v.text(), Scope::OutOfInstance);
        }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(110, game_modules, Scope::InGame,
           "Injected images, hidden modules and unsigned DLLs in the game") {
    GameSet gs(ctx);
    for (Game& g : gs.games) {
        std::vector<Region> regs = regions(g.h);
        std::vector<Mod> mods = loader_modules(g.h);
        std::set<uint64_t> loader_bases;
        for (const Mod& m : mods) loader_bases.insert(m.base);

        // 1. program images in private executable memory (manual mapping)
        std::set<uint64_t> checked;
        size_t pe_hits = 0, rwx = 0, private_exec = 0;
        for (const Region& r : regs) {
            if (r.type != MEM_PRIVATE || !exec_protect(r.protect)) continue;
            ++private_exec;
            if ((r.protect & 0xFF) == PAGE_EXECUTE_READWRITE) ++rwx;
            for (uint64_t at : {r.base, r.alloc_base}) {
                if (!at || !checked.insert(at).second) continue;
                if (is_pe_at(g.h, at)) {
                    ++pe_hits;
                    if (pe_hits <= 10)
                        ctx.add(Severity::Detection, strf("Injected program image in game memory (PID %lu)", g.info.pid),
                                "A DLL-style image sits in private executable memory instead of being a "
                                "normal file-backed module. That is what a manually mapped cheat looks like.",
                                strf("address 0x%llX, region size %llu bytes, protection 0x%lX",
                                     static_cast<unsigned long long>(at), static_cast<unsigned long long>(r.size), r.protect));
                }
            }
        }

        // 2. images mapped in memory that the loader does not list
        std::map<uint64_t, bool> image_allocs;
        for (const Region& r : regs)
            if (r.type == MEM_IMAGE) image_allocs[r.alloc_base] = true;
        size_t hidden = 0;
        for (const auto& kv : image_allocs) {
            if (loader_bases.count(kv.first)) continue;
            std::string path = mapped_path(g.h, kv.first);
            std::string low = lower(path);
            if (ends_with(low, ".mui")) continue;
            std::vector<std::string> strong = ctx.match_names(base_name(path));
            const SigInfo* si = path.empty() ? nullptr : &verify_file(path);
            if (!strong.empty()) {
                ctx.add(Severity::Detection, strf("Hidden cheat module in the game (PID %lu)", g.info.pid),
                        "This image is mapped in the game but missing from its module list. Matched: " +
                            join(strong) + ".", path);
                ++hidden;
            } else if (!si || !si->trusted) {
                ctx.add(Severity::Warning, strf("Module hidden from the game's module list (PID %lu)", g.info.pid),
                        "An unsigned image is mapped in the game but is not in the loader's module "
                        "list. Cheats unlink themselves this way. Windows also maps some files like "
                        "this for icons, so check what the file is.",
                        path.empty() ? strf("base 0x%llX, no file name", static_cast<unsigned long long>(kv.first)) : path);
                ++hidden;
            }
        }

        // 3. listed modules: known names, deleted files, unsigned from user folders
        size_t unsigned_count = 0;
        std::vector<std::string> unsigned_names;
        for (const Mod& m : mods) {
            if (m.path.empty()) continue;
            std::string low = lower(m.path);
            std::vector<std::string> strong = ctx.match_names(base_name(m.path));
            if (!strong.empty()) {
                ctx.add(Severity::Detection, strf("Known cheat module loaded in the game (PID %lu)", g.info.pid),
                        "Matched: " + join(strong) + ".", m.path);
                continue;
            }
            if (definitely_missing(m.path)) {
                ctx.add(Severity::Detection, strf("Loaded module's file is gone (PID %lu)", g.info.pid),
                        "This DLL is loaded in the game but its file no longer exists at that path. "
                        "Windows locks loaded DLLs, so it was renamed, moved, or was on a drive that "
                        "has been removed.", m.path);
                continue;
            }
            if (under_windows(m.path)) continue;
            const SigInfo& si = verify_file(m.path);
            if (si.trusted) continue;
            ++unsigned_count;
            if (user_writable_path(m.path) && !known_native(low)) {
                ctx.add(Severity::Warning, strf("Unsigned DLL from a user folder loaded in the game (PID %lu)", g.info.pid),
                        "Launchers load their libraries from their own folders. An unsigned DLL from "
                        "Downloads, Desktop, Documents or Temp should be checked by hand.", m.path);
            } else if (unsigned_names.size() < 15) {
                unsigned_names.push_back(base_name(m.path));
            }
        }
        ctx.add(Severity::Integrity, strf("Game modules checked (PID %lu)", g.info.pid),
                strf("%zu modules, %zu unsigned, %zu hidden. %zu private executable regions (%zu RWX, "
                     "normal for Java's JIT), %zu with a program image in them.",
                     mods.size(), unsigned_count, hidden, private_exec, rwx, pe_hits),
                unsigned_names.empty() ? "" : "unsigned (usually game natives): " + join(unsigned_names));
    }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(120, game_threads, Scope::InGame, "Game threads started from injected memory") {
    GameSet gs(ctx);
    if (gs.games.empty()) return;
    typedef LONG(NTAPI * NtQIT)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    NtQIT q = reinterpret_cast<NtQIT>(nt_proc("NtQueryInformationThread"));
    if (!q) return;
    typedef HRESULT(WINAPI * GetDesc)(HANDLE, PWSTR*);
    HMODULE kb = GetModuleHandleW(L"kernelbase.dll");
    GetDesc get_desc = kb ? reinterpret_cast<GetDesc>(reinterpret_cast<void*>(GetProcAddress(kb, "GetThreadDescription"))) : nullptr;

    // LoadLibrary lives at the same address in every process for this boot.
    std::map<uint64_t, std::string> loaders;
    for (const wchar_t* mod : {L"kernel32.dll", L"kernelbase.dll"}) {
        HMODULE m = GetModuleHandleW(mod);
        if (!m) continue;
        for (const char* fn : {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"}) {
            void* p = reinterpret_cast<void*>(GetProcAddress(m, fn));
            if (p) loaders[reinterpret_cast<uint64_t>(p)] = fn;
        }
    }
    if (void* p = nt_proc("LdrLoadDll")) loaders[reinterpret_cast<uint64_t>(p)] = "LdrLoadDll";

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    for (Game& g : gs.games) {
        size_t total = 0, bad = 0;
        THREADENTRY32 te{};
        te.dwSize = sizeof te;
        if (!Thread32First(snap, &te)) continue;
        do {
            if (te.th32OwnerProcessID != g.info.pid) continue;
            ++total;
            HANDLE th = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!th) continue;
            uint64_t start = 0;
            if (q(th, 9 /*ThreadQuerySetWin32StartAddress*/, &start, sizeof start, nullptr) >= 0 && start) {
                Region r;
                if (query_region(g.h, start, r) && r.state == MEM_COMMIT && r.type != MEM_IMAGE) {
                    ++bad;
                    if (bad <= 8)
                        ctx.add(Severity::Detection, strf("Game thread started in injected memory (PID %lu)", g.info.pid),
                                "Every normal game thread starts inside a DLL. This one starts in memory "
                                "with no file behind it, which is how injected code runs.",
                                strf("thread %lu, start address 0x%llX", te.th32ThreadID, static_cast<unsigned long long>(start)));
                }
                auto it = loaders.find(start);
                if (it != loaders.end())
                    ctx.add(Severity::Warning, strf("Game thread started at %s (PID %lu)", it->second.c_str(), g.info.pid),
                            "A thread whose first instruction is the DLL loading function. That is the "
                            "classic remote-thread DLL injection, caught while still running.",
                            strf("thread %lu", te.th32ThreadID));
            }
            if (get_desc) {
                PWSTR d = nullptr;
                if (SUCCEEDED(get_desc(th, &d)) && d) {
                    std::string name = narrow(d, wcslen(d));
                    LocalFree(d);
                    if (name == "Attach Listener")
                        ctx.add(Severity::Warning, strf("Something attached to the game's Java VM (PID %lu)", g.info.pid),
                                "The Java 'Attach Listener' thread exists. It only starts when another "
                                "program attaches to the running game, which is how agents are loaded "
                                "after launch. Profilers do this too.",
                                strf("thread %lu", te.th32ThreadID));
                }
            }
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
        ctx.add(Severity::Integrity, strf("Game threads checked (PID %lu)", g.info.pid),
                strf("%zu threads, %zu started outside any DLL.", total, bad));
    }
    CloseHandle(snap);
}

// ---------------------------------------------------------------------------
namespace {

struct PeFile {
    std::string data;
    bool ok = false;
    struct Sec { uint32_t va, vsize, raw, rawsize; };
    std::vector<Sec> secs;

    explicit PeFile(const std::string& path) {
        if (!read_file(path, data, 256u << 20) || data.size() < 0x200) return;
        uint32_t lf = 0;
        memcpy(&lf, data.data() + 0x3C, 4);
        if (lf + 0x108 > data.size() || memcmp(data.data() + lf, "PE\0\0", 4) != 0) return;
        uint16_t nsec = 0, optsize = 0;
        memcpy(&nsec, data.data() + lf + 6, 2);
        memcpy(&optsize, data.data() + lf + 20, 2);
        size_t tbl = lf + 24 + optsize;
        for (uint16_t i = 0; i < nsec && tbl + 40 <= data.size(); ++i, tbl += 40) {
            Sec s{};
            memcpy(&s.vsize, data.data() + tbl + 8, 4);
            memcpy(&s.va, data.data() + tbl + 12, 4);
            memcpy(&s.rawsize, data.data() + tbl + 16, 4);
            memcpy(&s.raw, data.data() + tbl + 20, 4);
            secs.push_back(s);
        }
        ok = !secs.empty();
    }
    bool bytes_at(uint32_t rva, unsigned char* out, size_t n) const {
        for (const Sec& s : secs)
            if (rva >= s.va && rva < s.va + std::max(s.vsize, s.rawsize)) {
                uint64_t off = uint64_t(s.raw) + (rva - s.va);
                if (rva - s.va + n > s.rawsize || off + n > data.size()) return false;
                memcpy(out, data.data() + off, n);
                return true;
            }
        return false;
    }
};

// name -> RVA of every named export of a module in the target process
std::map<std::string, uint32_t> remote_exports(HANDLE h, uint64_t base) {
    std::map<std::string, uint32_t> out;
    unsigned char hdr[0x1000];
    if (!read_mem(h, base, hdr, sizeof hdr)) return out;
    uint32_t lf = 0;
    memcpy(&lf, hdr + 0x3C, 4);
    if (lf > 0xE00 || memcmp(hdr + lf, "PE\0\0", 4) != 0) return out;
    uint16_t magic = 0;
    memcpy(&magic, hdr + lf + 24, 2);
    if (magic != 0x20B) return out;
    uint32_t exp_rva = 0, exp_size = 0;
    memcpy(&exp_rva, hdr + lf + 24 + 112, 4);
    memcpy(&exp_size, hdr + lf + 24 + 116, 4);
    if (!exp_rva || exp_size < 40 || exp_size > (8u << 20)) return out;
    std::vector<unsigned char> blob(exp_size);
    if (!read_mem(h, base + exp_rva, blob.data(), blob.size())) return out;
    auto u32 = [&](uint32_t rva, uint32_t& v) {
        if (rva < exp_rva || uint64_t(rva) + 4 > uint64_t(exp_rva) + exp_size) return false;
        memcpy(&v, blob.data() + (rva - exp_rva), 4);
        return true;
    };
    uint32_t nfuncs = 0, nnames = 0, afuncs = 0, anames = 0, aords = 0;
    memcpy(&nfuncs, blob.data() + 20, 4);
    memcpy(&nnames, blob.data() + 24, 4);
    memcpy(&afuncs, blob.data() + 28, 4);
    memcpy(&anames, blob.data() + 32, 4);
    memcpy(&aords, blob.data() + 36, 4);
    if (nnames > 100000) return out;
    for (uint32_t i = 0; i < nnames; ++i) {
        uint32_t name_rva = 0, func_rva = 0;
        if (!u32(anames + i * 4, name_rva)) break;
        uint32_t ord_rva = aords + i * 2;
        if (ord_rva < exp_rva || uint64_t(ord_rva) + 2 > uint64_t(exp_rva) + exp_size) break;
        uint16_t ord = 0;
        memcpy(&ord, blob.data() + (ord_rva - exp_rva), 2);
        if (ord >= nfuncs || !u32(afuncs + uint32_t(ord) * 4, func_rva)) continue;
        if (name_rva < exp_rva || name_rva >= exp_rva + exp_size) continue;
        const char* nm = reinterpret_cast<const char*>(blob.data() + (name_rva - exp_rva));
        size_t maxlen = exp_rva + exp_size - name_rva;
        size_t len = strnlen(nm, std::min<size_t>(maxlen, 256));
        if (len == 0 || len == 256) continue;
        if (func_rva >= exp_rva && func_rva < exp_rva + exp_size) continue;   // forwarder
        out[std::string(nm, len)] = func_rva;
    }
    return out;
}

// Follows a jump at addr. Returns false if the bytes are not a jump.
bool decode_jump(HANDLE h, uint64_t addr, uint64_t& target) {
    unsigned char b[16];
    if (!read_mem(h, addr, b, sizeof b)) return false;
    if (b[0] == 0xE9) {
        int32_t rel;
        memcpy(&rel, b + 1, 4);
        target = addr + 5 + static_cast<int64_t>(rel);
        return true;
    }
    if (b[0] == 0xEB) {
        target = addr + 2 + static_cast<int8_t>(b[1]);
        return true;
    }
    if (b[0] == 0xFF && b[1] == 0x25) {
        int32_t rel;
        memcpy(&rel, b + 2, 4);
        uint64_t slot = addr + 6 + static_cast<int64_t>(rel);
        return read_mem(h, slot, &target, 8);
    }
    if (b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0) {   // mov rax, imm64; jmp rax
        memcpy(&target, b + 2, 8);
        return true;
    }
    if (b[0] == 0x49 && b[1] == 0xBB && b[10] == 0x41 && b[11] == 0xFF && b[12] == 0xE3) {   // mov r11; jmp r11
        memcpy(&target, b + 2, 8);
        return true;
    }
    if (b[0] == 0x68 && b[5] == 0xC3) {   // push imm32; ret
        uint32_t t;
        memcpy(&t, b + 1, 4);
        target = t;
        return true;
    }
    return false;
}

struct HookTarget {
    const char* module;
    const char* function;
    bool key;   // render / input / network functions cheats care about most
};
const HookTarget kHookTargets[] = {
    {"opengl32.dll", "wglSwapBuffers", true}, {"opengl32.dll", "wglSwapLayerBuffers", true},
    {"opengl32.dll", "glReadPixels", true},   {"gdi32.dll", "SwapBuffers", true},
    {"gdi32full.dll", "SwapBuffers", true},   {"user32.dll", "GetAsyncKeyState", true},
    {"user32.dll", "GetKeyState", true},      {"user32.dll", "GetCursorPos", true},
    {"user32.dll", "SetCursorPos", true},     {"user32.dll", "SendInput", true},
    {"user32.dll", "mouse_event", true},      {"user32.dll", "GetRawInputData", true},
    {"user32.dll", "PeekMessageW", true},     {"user32.dll", "GetMessageW", true},
    {"user32.dll", "CallWindowProcW", true},  {"ws2_32.dll", "send", true},
    {"ws2_32.dll", "recv", true},             {"ws2_32.dll", "WSASend", true},
    {"ws2_32.dll", "WSARecv", true},          {"ws2_32.dll", "connect", true},
    {"kernelbase.dll", "LoadLibraryExW", false}, {"kernelbase.dll", "VirtualProtect", false},
    {"kernelbase.dll", "ReadProcessMemory", false},
    {"ntdll.dll", "LdrLoadDll", false},       {"ntdll.dll", "NtReadVirtualMemory", false},
    {"ntdll.dll", "NtQueryVirtualMemory", false}, {"ntdll.dll", "NtProtectVirtualMemory", false},
    {"ntdll.dll", "NtCreateThreadEx", false}, {"ntdll.dll", "NtQueryInformationProcess", false},
    {"ntdll.dll", "NtQuerySystemInformation", false}, {"ntdll.dll", "NtOpenProcess", false},
    {"jvm.dll", "JNI_GetCreatedJavaVMs", true}, {"jvm.dll", "JVM_DefineClass", true},
    {"jvm.dll", "JVM_DefineClassWithSource", true}, {"jvm.dll", "JVM_FindLoadedClass", true},
};

}  // namespace

SCAN_CHECK(130, game_hooks, Scope::InGame,
           "Hooks on the game's render, input, network and loader functions") {
    GameSet gs(ctx);
    for (Game& g : gs.games) {
        std::vector<Mod> mods = loader_modules(g.h);
        std::map<std::string, const Mod*> by_name;
        for (const Mod& m : mods) by_name.emplace(lower(base_name(m.path)), &m);
        std::map<std::string, std::map<std::string, uint32_t>> exports;
        std::map<std::string, PeFile*> files;
        size_t checked = 0, hooked = 0;
        for (const HookTarget& t : kHookTargets) {
            auto mi = by_name.find(t.module);
            if (mi == by_name.end()) continue;
            const Mod& m = *mi->second;
            if (!exports.count(t.module)) exports[t.module] = remote_exports(g.h, m.base);
            auto fi = exports[t.module].find(t.function);
            if (fi == exports[t.module].end()) continue;
            if (!files.count(t.module)) files[t.module] = new PeFile(m.path);
            PeFile* pf = files[t.module];
            unsigned char disk[16], mem[16];
            uint64_t addr = m.base + fi->second;
            if (!pf->ok || !pf->bytes_at(fi->second, disk, 16) || !read_mem(g.h, addr, mem, 16)) continue;
            ++checked;
            if (memcmp(disk, mem, 16) == 0) continue;
            uint64_t target = 0;
            std::string what = std::string(t.module) + "!" + t.function;
            if (!decode_jump(g.h, addr, target)) {
                std::string hex;
                for (int i = 0; i < 16; ++i) hex += strf("%02X ", mem[i]);
                ctx.add(Severity::Integrity, "Function bytes differ from the file: " + what,
                        "The start of this function in the game does not match the DLL on disk, but it "
                        "is not a plain jump. Can be a Windows patch or a different hook style.", hex);
                continue;
            }
            ++hooked;
            for (int hop = 0; hop < 3; ++hop) {   // follow trampolines
                uint64_t next = 0;
                Region r;
                if (!query_region(g.h, target, r) || r.type == MEM_IMAGE) break;
                if (!decode_jump(g.h, target, next)) break;
                target = next;
            }
            bool trusted = false, in_image = false;
            std::string where = describe_target(g.h, target, trusted, in_image);
            std::vector<std::string> strong = ctx.match_names(where);
            Severity sev = !strong.empty() ? Severity::Detection
                           : trusted ? Severity::Integrity
                           : (t.key ? Severity::Detection : Severity::Warning);
            ctx.add(sev, "Hooked function in the game: " + what,
                    trusted ? "This function was redirected to a signed module. Overlays (Discord, Steam, "
                              "OBS, NVIDIA) and antivirus do this."
                            : "This function was redirected to code that is not a signed module. Internal "
                              "cheats hook these functions to draw their menu, read input or change "
                              "packets.",
                    "jumps to " + where);
        }
        for (auto& kv : files) delete kv.second;
        ctx.add(Severity::Integrity, strf("Game functions checked for hooks (PID %lu)", g.info.pid),
                strf("%zu functions compared with the DLL files on disk, %zu redirected.", checked, hooked));
    }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(140, game_unloaded, Scope::InGame, "DLLs that were loaded into the game and unloaded again") {
    GameSet gs(ctx);
    if (gs.games.empty()) return;
    typedef void(NTAPI * GetTrace)(PULONG*, PULONG*, PVOID*);
    GetTrace gt = reinterpret_cast<GetTrace>(nt_proc("RtlGetUnloadEventTraceEx"));
    if (!gt) return;
    PULONG p_size = nullptr, p_count = nullptr;
    PVOID p_trace = nullptr;
    gt(&p_size, &p_count, &p_trace);   // addresses are the same in every process this boot
    if (!p_size || !p_count || !p_trace) return;
    static const char* const overlays[] = {"discordhook", "graphics-hook", "gameoverlayrenderer", "nvspcap",
                                           "medal", "overwolf", "owclient", "rtsshooks", "fraps", "bdcam",
                                           "action_x64", "igo64", "gamebar", "obs"};
    for (Game& g : gs.games) {
        ULONG esize = 0, ecount = 0;
        uint64_t arr = 0;
        if (!read_mem(g.h, reinterpret_cast<uint64_t>(p_size), &esize, 4) ||
            !read_mem(g.h, reinterpret_cast<uint64_t>(p_count), &ecount, 4) ||
            !read_mem(g.h, reinterpret_cast<uint64_t>(p_trace), &arr, 8))
            continue;
        if (esize < 0x5C || esize > 0x100 || ecount == 0 || ecount > 512) continue;
        if (!arr) {
            ctx.add(Severity::Integrity, strf("No DLL has been unloaded from the game (PID %lu)", g.info.pid), "");
            continue;
        }
        std::vector<unsigned char> buf(size_t(esize) * ecount);
        if (!read_mem(g.h, arr, buf.data(), buf.size())) continue;
        std::vector<Mod> mods = loader_modules(g.h);
        std::set<std::string> loaded_now, module_dirs;
        for (const Mod& m : mods) {
            loaded_now.insert(lower(base_name(m.path)));
            module_dirs.insert(dir_name(m.path));
        }
        std::set<std::string> seen;
        std::vector<std::string> benign;
        for (ULONG i = 0; i < ecount; ++i) {
            const unsigned char* e = buf.data() + size_t(i) * esize;
            uint64_t base = 0;
            memcpy(&base, e, 8);
            if (!base) continue;
            wchar_t wname[33] = {0};
            memcpy(wname, e + 28, 64);
            std::string name = narrow(wname, wcsnlen(wname, 32));
            std::string low = lower(name);
            if (name.empty() || !seen.insert(low).second) continue;
            std::vector<std::string> strong = ctx.match_names(name);
            if (!strong.empty()) {
                ctx.add(Severity::Detection, "Known cheat DLL was loaded into the game and unloaded: " + name,
                        "Windows keeps a short list of DLLs each program has unloaded. Matched: " + join(strong) + ".",
                        strf("PID %lu, was at 0x%llX", g.info.pid, static_cast<unsigned long long>(base)));
                continue;
            }
            bool known = loaded_now.count(low) > 0;
            for (const char* o : overlays) known = known || contains(low, o);
            if (!known && file_exists(windows_dir() + "\\System32\\" + name)) known = true;
            if (!known)
                for (const std::string& d : module_dirs)
                    if (!d.empty() && file_exists(d + "\\" + name)) { known = true; break; }
            if (known) {
                if (benign.size() < 20) benign.push_back(name);
            } else {
                ctx.add(Severity::Warning, "Unknown DLL was loaded into the game and unloaded: " + name,
                        "This DLL was in the game earlier and is gone now. It is not a Windows file and "
                        "not in any folder the game loads from. Injected DLLs that unload themselves "
                        "look like this. The list only holds the name, cut to 31 letters.",
                        strf("PID %lu, was at 0x%llX", g.info.pid, static_cast<unsigned long long>(base)));
            }
        }
        ctx.add(Severity::Integrity, strf("Unloaded DLL history read (PID %lu)", g.info.pid),
                strf("%zu different DLLs unloaded since the game started.", seen.size()),
                benign.empty() ? "" : "known ones: " + join(benign));
    }
}

// ---------------------------------------------------------------------------
namespace {
struct HandleEntry {
    void* Object;
    ULONG_PTR Pid;
    ULONG_PTR Handle;
    ULONG Access;
    USHORT BackTrace;
    USHORT TypeIndex;
    ULONG Attributes;
    ULONG Reserved;
};
}  // namespace

SCAN_CHECK(150, game_handles, Scope::InGame, "Other programs that can write to the game's memory") {
    GameSet gs(ctx);
    if (gs.games.empty()) return;
    typedef LONG(NTAPI * NtQSI)(ULONG, PVOID, ULONG, PULONG);
    NtQSI q = reinterpret_cast<NtQSI>(nt_proc("NtQuerySystemInformation"));
    if (!q) return;
    std::vector<unsigned char> buf(8u << 20);
    LONG st = 0;
    for (int tries = 0; tries < 8; ++tries) {
        ULONG ret = 0;
        st = q(64 /*SystemExtendedHandleInformation*/, buf.data(), static_cast<ULONG>(buf.size()), &ret);
        if (st != static_cast<LONG>(0xC0000004)) break;
        buf.resize(std::max<size_t>(buf.size() * 2, size_t(ret) + (1u << 20)));
    }
    if (st < 0) {
        ctx.note("could not list system handles");
        return;
    }
    ULONG_PTR count = 0;
    memcpy(&count, buf.data(), sizeof count);
    const HandleEntry* entries = reinterpret_cast<const HandleEntry*>(buf.data() + 2 * sizeof(ULONG_PTR));
    if (count > (buf.size() - 2 * sizeof(ULONG_PTR)) / sizeof(HandleEntry)) return;
    DWORD self = GetCurrentProcessId();
    const DWORD kWrite = PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION;

    for (Game& g : gs.games) {
        void* obj = nullptr;
        USHORT type = 0;
        bool found = false;
        for (ULONG_PTR i = 0; i < count; ++i)
            if (entries[i].Pid == self && entries[i].Handle == reinterpret_cast<ULONG_PTR>(g.h)) {
                obj = entries[i].Object;
                type = entries[i].TypeIndex;
                found = true;
                break;
            }
        if (!found) continue;
        std::map<DWORD, ULONG> holders;   // pid -> combined access
        std::map<DWORD, HANDLE> sources;
        for (ULONG_PTR i = 0; i < count; ++i) {
            const HandleEntry& e = entries[i];
            DWORD pid = static_cast<DWORD>(e.Pid);
            if (e.TypeIndex != type || pid == self || pid == g.info.pid || !(e.Access & kWrite)) continue;
            bool match = false;
            if (obj) {
                match = e.Object == obj;
            } else {   // object addresses hidden: compare by duplicating the handle
                if (!sources.count(pid)) sources[pid] = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
                HANDLE src = sources[pid], dup = nullptr;
                if (src && DuplicateHandle(src, reinterpret_cast<HANDLE>(e.Handle), GetCurrentProcess(), &dup,
                                           PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0)) {
                    match = GetProcessId(dup) == g.info.pid;
                    CloseHandle(dup);
                }
            }
            if (match) holders[pid] |= e.Access;
        }
        for (auto& kv : sources)
            if (kv.second) CloseHandle(kv.second);

        std::vector<std::string> ordinary;
        for (const auto& kv : holders) {
            const ProcInfo* p = find_process(kv.first);
            std::string name = p ? p->name : strf("PID %lu", kv.first);
            std::string path = p ? p->path : std::string();
            std::string ev = strf("%s (PID %lu) access 0x%lX", path.empty() ? name.c_str() : path.c_str(), kv.first, kv.second);
            std::vector<std::string> strong = ctx.match_names(name);
            if (!strong.empty()) {
                ctx.add(Severity::Detection, "Known cheat tool has the game open for writing: " + name,
                        "Matched: " + join(strong) + ". It holds a handle that lets it write memory or "
                        "start threads in the game.", ev);
                continue;
            }
            if (kv.first == g.info.ppid || path.empty()) {   // launcher, or a protected system process
                ordinary.push_back(name);
                continue;
            }
            const SigInfo& si = verify_file(path);
            if (!si.trusted || user_writable_path(path)) {
                ctx.add(Severity::Warning, "Unsigned program has the game open for writing: " + name,
                        "It holds a handle that lets it write memory or start threads in the game. "
                        "Injectors and external cheats need exactly this. Check what the program is.",
                        ev + (si.trusted ? " signed: " + si.signer : " NOT signed"));
            } else {
                ordinary.push_back(name + " [" + si.signer + "]");
            }
        }
        ctx.add(Severity::Integrity, strf("Programs holding the game open checked (PID %lu)", g.info.pid),
                strf("%zu other program(s) can write to the game's memory.", holders.size()),
                ordinary.empty() ? "" : "signed or system: " + join(ordinary));
    }
}

// ---------------------------------------------------------------------------
SCAN_CHECK(160, game_strings, Scope::InGame, "Known cheat text in the game's memory") {
    if (ctx.sigs.memory.empty()) return;
    GameSet gs(ctx);
    MultiSearch ms;
    size_t maxlen = 0;
    for (size_t i = 0; i < ctx.sigs.memory.size(); ++i) {
        ms.add(ctx.sigs.memory[i].value, static_cast<int>(i));
        ms.add(utf16le(ctx.sigs.memory[i].value), static_cast<int>(i));
        maxlen = std::max(maxlen, ctx.sigs.memory[i].value.size() * 2);
    }
    const uint64_t budget = ctx.deep ? ~0ull : (2ull << 30);
    const size_t chunk = 8u << 20;
    for (Game& g : gs.games) {
        std::vector<Region> regs;
        for (const Region& r : regions(g.h))
            if (r.type == MEM_PRIVATE && readable_protect(r.protect)) regs.push_back(r);
        // small regions first: class metadata lives there, the big ones are the Java heap
        std::sort(regs.begin(), regs.end(), [](const Region& a, const Region& b) { return a.size < b.size; });
        std::vector<char> found(ctx.sigs.memory.size(), 0);
        std::string buf;
        uint64_t scanned = 0, skipped = 0;
        for (const Region& r : regs) {
            if (scanned >= budget) { skipped += r.size; continue; }
            for (uint64_t off = 0; off < r.size;) {
                size_t want = static_cast<size_t>(std::min<uint64_t>(chunk, r.size - off));
                buf.resize(want);
                SIZE_T got = 0;
                ReadProcessMemory(g.h, reinterpret_cast<LPCVOID>(r.base + off), &buf[0], want, &got);
                if (got == 0) break;
                buf.resize(got);
                lower_inplace(buf);
                ms.search(buf.data(), buf.size(), found);
                scanned += got;
                if (got < want) break;
                off += want > maxlen ? want - maxlen : want;   // overlap so a match on the edge is not lost
                if (want <= maxlen) break;
            }
        }
        std::vector<std::string> labels;
        for (size_t i = 0; i < found.size(); ++i)
            if (found[i] && std::find(labels.begin(), labels.end(), ctx.sigs.memory[i].label) == labels.end())
                labels.push_back(ctx.sigs.memory[i].label);
        if (!labels.empty())
            ctx.add(Severity::Detection, strf("Cheat code text in the game's memory (PID %lu)", g.info.pid),
                    "Class names that belong to a known cheat are in the game's memory. They are there "
                    "when the cheat's code is loaded into the game.", join(labels));
        ctx.add(Severity::Integrity, strf("Game memory searched (PID %lu)", g.info.pid),
                strf("%.0f MB searched for %zu cheat strings.%s", scanned / 1048576.0, ctx.sigs.memory.size(),
                     skipped ? strf(" %.0f MB of the largest regions skipped; use --deep to search all of it.",
                                    skipped / 1048576.0).c_str() : ""));
    }
}

}  // namespace scan
#endif

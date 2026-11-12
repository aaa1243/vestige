#pragma once
#ifdef _WIN32
#include <windows.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "../core.hpp"

namespace scan {
namespace win {

std::wstring widen(const std::string& s);
std::string narrow(const wchar_t* w, size_t len);
std::string narrow(const std::wstring& w);

bool enable_privilege(const wchar_t* name);
double ft_to_epoch(uint64_t ft);
double ft_to_epoch(const FILETIME& ft);
uint64_t ms_since_boot();
void* nt_proc(const char* name);            // function from ntdll.dll, or null

struct ProcInfo {
    DWORD pid = 0, ppid = 0;
    std::string name, path;
    double start = 0;
};
const std::vector<ProcInfo>& processes();    // snapshot, cached for the run
const ProcInfo* find_process(DWORD pid);
std::vector<ProcInfo> game_processes();      // javaw.exe / java.exe

std::string device_to_dos(const std::string& path);   // \Device\HarddiskVolume3\x -> C:\x
std::string windows_dir();

struct SigInfo {
    bool trusted = false;    // valid signature (embedded or catalog)
    bool catalog = false;
    std::string signer;      // empty if unknown
};
const SigInfo& verify_file(const std::string& path);   // cached
// Folders a normal user can drop files into (Downloads, Desktop, Temp ...).
bool user_writable_path(const std::string& path);

struct RegValue {
    std::string name;
    DWORD type = 0;
    std::vector<uint8_t> data;
    std::string text() const;      // REG_SZ / EXPAND_SZ / MULTI_SZ as UTF-8
    DWORD dword() const;
};
std::vector<std::string> reg_subkeys(HKEY root, const std::wstring& path);
std::vector<RegValue> reg_values(HKEY root, const std::wstring& path);
bool reg_get(HKEY root, const std::wstring& path, const std::wstring& name, RegValue& out);
bool reg_key_exists(HKEY root, const std::wstring& path);
double reg_key_time(HKEY root, const std::wstring& path);   // last write, 0 on error
std::vector<std::string> user_sids();        // loaded user hives under HKEY_USERS

bool read_mem(HANDLE h, uint64_t addr, void* buf, size_t n);
std::string mapped_path(HANDLE h, uint64_t addr);
std::string remote_cmdline(HANDLE h);
std::vector<std::pair<std::string, std::string>> remote_env(HANDLE h);

struct Region {
    uint64_t base = 0, alloc_base = 0, size = 0;
    DWORD state = 0, protect = 0, type = 0;
};
std::vector<Region> regions(HANDLE h);
bool query_region(HANDLE h, uint64_t addr, Region& out);

struct Event {
    double time = 0;
    int id = 0;
    std::string xml;
};
// Newest first.
std::vector<Event> query_events(const std::wstring& channel, const std::wstring& xpath,
                                size_t max_events);
std::string xml_data(const std::string& xml, const std::string& name);

DWORD service_pid(const wchar_t* name, DWORD* state = nullptr, DWORD* start_type = nullptr);
double process_start(DWORD pid);

}  // namespace win
}  // namespace scan
#endif

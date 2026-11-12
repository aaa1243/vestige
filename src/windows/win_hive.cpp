// Deleted BAM entries. The live registry only shows what is there now. When a
// BAM value is deleted, its record stays in the free space of the SYSTEM hive
// file until something overwrites it. The hive is locked while Windows runs,
// so its clusters are read straight from the volume (read-only).
#ifdef _WIN32
#include "win_util.hpp"

#include <winioctl.h>

#include <algorithm>
#include <map>
#include <set>

#include "../util.hpp"

namespace scan {
using namespace win;

namespace {

bool read_locked_file(const std::string& path, std::string& out, uint64_t max_bytes, std::string& why) {
    HANDLE f = CreateFileW(widen(path).c_str(), FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (f == INVALID_HANDLE_VALUE) { why = strf("could not open the file (error %lu)", GetLastError()); return false; }
    LARGE_INTEGER size{};
    GetFileSizeEx(f, &size);
    if (size.QuadPart <= 0x1000 || static_cast<uint64_t>(size.QuadPart) > max_bytes) {
        CloseHandle(f);
        why = "unexpected file size";
        return false;
    }
    std::string root = path.substr(0, 3);
    DWORD spc = 0, bps = 0, free_c = 0, total_c = 0;
    if (!GetDiskFreeSpaceW(widen(root).c_str(), &spc, &bps, &free_c, &total_c) || !spc || !bps) {
        CloseHandle(f);
        why = "could not get the cluster size";
        return false;
    }
    uint64_t cluster = static_cast<uint64_t>(spc) * bps;

    struct Extent { int64_t vcn, next_vcn, lcn; };
    std::vector<Extent> extents;
    STARTING_VCN_INPUT_BUFFER in{};
    std::vector<char> buf(64 * 1024);
    for (;;) {
        DWORD got = 0;
        BOOL ok = DeviceIoControl(f, FSCTL_GET_RETRIEVAL_POINTERS, &in, sizeof(in), buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr);
        DWORD err = ok ? 0 : GetLastError();
        if (!ok && err != ERROR_MORE_DATA) {
            if (extents.empty()) {
                CloseHandle(f);
                why = strf("could not get the file layout (error %lu)", err);
                return false;
            }
            break;
        }
        auto* rp = reinterpret_cast<RETRIEVAL_POINTERS_BUFFER*>(buf.data());
        int64_t vcn = rp->StartingVcn.QuadPart;
        for (DWORD i = 0; i < rp->ExtentCount; ++i) {
            extents.push_back({vcn, rp->Extents[i].NextVcn.QuadPart, rp->Extents[i].Lcn.QuadPart});
            vcn = rp->Extents[i].NextVcn.QuadPart;
        }
        if (ok || rp->ExtentCount == 0) break;
        in.StartingVcn.QuadPart = vcn;
    }
    CloseHandle(f);

    std::wstring dev = L"\\\\.\\" + widen(path.substr(0, 2));
    HANDLE vol = CreateFileW(dev.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (vol == INVALID_HANDLE_VALUE) { why = strf("could not open the volume (error %lu)", GetLastError()); return false; }
    out.assign(static_cast<size_t>(size.QuadPart), '\0');
    std::vector<char> chunk(1 << 20);
    bool any = false;
    for (const Extent& e : extents) {
        if (e.lcn < 0) continue;   // sparse
        uint64_t file_off = static_cast<uint64_t>(e.vcn) * cluster;
        uint64_t bytes = static_cast<uint64_t>(e.next_vcn - e.vcn) * cluster;
        uint64_t disk_off = static_cast<uint64_t>(e.lcn) * cluster;
        while (bytes && file_off < out.size()) {
            DWORD want = static_cast<DWORD>(std::min<uint64_t>(bytes, chunk.size())), got = 0;
            LARGE_INTEGER pos;
            pos.QuadPart = static_cast<LONGLONG>(disk_off);
            if (!SetFilePointerEx(vol, pos, nullptr, FILE_BEGIN) || !ReadFile(vol, chunk.data(), want, &got, nullptr) || !got) break;
            size_t copy = static_cast<size_t>(std::min<uint64_t>(got, out.size() - file_off));
            memcpy(&out[static_cast<size_t>(file_off)], chunk.data(), copy);
            any = true;
            file_off += got;
            disk_off += got;
            bytes -= std::min<uint64_t>(bytes, got);
        }
    }
    CloseHandle(vol);
    if (!any) { why = "no data could be read from the volume"; return false; }
    return true;
}

template <typename T>
T rd(const std::string& s, size_t off) {
    T v{};
    if (off + sizeof(T) <= s.size()) memcpy(&v, s.data() + off, sizeof(T));
    return v;
}

bool is_device_path(const std::string& l) { return starts_with(l, "\\device\\harddiskvolume"); }

}  // namespace

SCAN_CHECK(320, bam_deleted, Scope::Boot, "Deleted BAM entries recovered from the SYSTEM hive file") {
    if (!ctx.admin) {
        ctx.note("deleted BAM entries need administrator rights");
        return;
    }
    std::string path = windows_dir() + "\\System32\\config\\SYSTEM";
    std::string hive, why;
    if (!read_locked_file(path, hive, 512ull << 20, why)) {
        ctx.note("SYSTEM hive could not be read for deleted BAM entries: " + why);
        return;
    }
    if (hive.compare(0, 4, "regf") != 0) {
        ctx.note("SYSTEM hive did not have a registry header (the volume may be encrypted at a layer below the file system)");
        return;
    }
    // Names that are in the live BAM right now.
    std::set<std::string> live;
    for (const wchar_t* base : {L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
                                L"SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings"})
        for (const std::string& sid : reg_subkeys(HKEY_LOCAL_MACHINE, base))
            for (const RegValue& v : reg_values(HKEY_LOCAL_MACHINE, std::wstring(base) + L"\\" + widen(sid)))
                live.insert(lower(v.name));

    uint32_t bins_size = rd<uint32_t>(hive, 0x28);
    size_t end = std::min<size_t>(hive.size(), 0x1000 + static_cast<size_t>(bins_size));
    double now = now_epoch();
    std::map<std::string, double> found;   // lowercased device path -> newest plausible time
    std::map<std::string, std::string> display;
    size_t free_cells = 0;

    auto scan_free = [&](size_t a, size_t b) {
        for (size_t q = a; q + 24 < b; ++q) {
            if (hive[q] != 'v' || hive[q + 1] != 'k') continue;
            uint16_t name_len = rd<uint16_t>(hive, q + 2);
            uint32_t data_size = rd<uint32_t>(hive, q + 4), data_off = rd<uint32_t>(hive, q + 8);
            uint16_t flags = rd<uint16_t>(hive, q + 16);
            if (name_len < 24 || name_len > 1040 || q + 20 + name_len > hive.size()) continue;
            std::string name = (flags & 1) ? hive.substr(q + 20, name_len)
                                           : narrow(reinterpret_cast<const wchar_t*>(hive.data() + q + 20), name_len / 2);
            std::string l = lower(name);
            if (!is_device_path(l) || l.find('\0') != std::string::npos) continue;
            double ts = 0;
            if (!(data_size & 0x80000000u) && (data_size & 0x7FFFFFFF) >= 8 && (data_size & 0x7FFFFFFF) <= 64) {
                size_t d = 0x1000 + static_cast<size_t>(data_off) + 4;
                if (d + 8 <= hive.size()) {
                    double t = ft_to_epoch(rd<uint64_t>(hive, d));
                    if (t > 1420070400.0 && t < now + 86400) ts = t;
                }
            }
            auto it = found.find(l);
            if (it == found.end() || ts > it->second) found[l] = ts;
            display[l] = name;
        }
    };

    size_t off = 0x1000;
    while (off + 0x20 <= end && hive.compare(off, 4, "hbin") == 0) {
        uint32_t bin_size = rd<uint32_t>(hive, off + 8);
        if (bin_size < 0x1000 || off + bin_size > hive.size()) break;
        size_t c = off + 0x20, bin_end = off + bin_size;
        while (c + 4 <= bin_end) {
            int32_t sz = rd<int32_t>(hive, c);
            size_t abs = static_cast<size_t>(sz < 0 ? -static_cast<int64_t>(sz) : sz);
            if (abs < 8 || c + abs > bin_end) break;
            if (sz > 0) {
                ++free_cells;
                scan_free(c + 4, c + abs);
            }
            c += abs;
        }
        off += bin_size;
    }

    size_t recovered = 0, shown = 0;
    for (const auto& f : found) {
        if (live.count(f.first)) continue;
        ++recovered;
        std::string dos = device_to_dos(display[f.first]);
        std::string name = base_name(dos);
        std::vector<std::string> strong = ctx.match_names(name);
        bool since = ctx.since_boot(f.second);
        std::string when = f.second > 0 ? "Last run time in the deleted record: " + fmt_time(f.second) + (since ? " (since this boot)." : " (before this boot).")
                                        : "The time in the record was already overwritten.";
        Scope sc = since ? Scope::Boot : Scope::OutOfInstance;
        if (!strong.empty())
            ctx.add(since ? Severity::Detection : Severity::Warning, "Deleted BAM entry for a known cheat: " + name,
                    "This entry is not in the live BAM any more but its record is still in the hive file. " + when +
                        " Matched: " + join(strong) + ".", dos, sc);
        else if (since && shown++ < 15)
            ctx.add(Severity::Warning, "BAM entry from this boot was removed: " + name,
                    "A program that ran since boot is no longer listed in the live BAM. Windows only prunes "
                    "entries older than about a week, and only at boot. " + when, dos, sc);
    }
    ctx.add(Severity::Integrity, "SYSTEM hive free space searched",
            strf("%.1f MB hive, %zu free cells, %zu old BAM records found, %zu not in the live BAM. Old entries "
                 "Windows pruned itself also show up here. Windows writes registry changes to a log first, so very "
                 "recent deletes may not be in the hive file yet.",
                 hive.size() / 1048576.0, free_cells, found.size(), recovered),
            "", Scope::None);
}

}  // namespace scan
#endif

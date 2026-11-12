// USN journal: created, renamed and deleted files since boot, and whether the
// journal itself was reset.
#ifdef _WIN32
#include "win_util.hpp"

#include <winioctl.h>

#include <algorithm>
#include <map>
#include <set>
#include <unordered_map>

#include "../util.hpp"

namespace scan {
using namespace win;

namespace {

// Own copies of the V0 structures so the layout does not depend on the SDK.
#pragma pack(push, 8)
struct JournalData {
    uint64_t UsnJournalID;
    int64_t FirstUsn, NextUsn, LowestValidUsn, MaxUsn;
    uint64_t MaximumSize, AllocationDelta;
    uint64_t pad[4];     // room for the V1/V2 fields newer systems may return
};
struct ReadJournal {
    int64_t StartUsn;
    uint32_t ReasonMask, ReturnOnlyOnClose;
    uint64_t Timeout, BytesToWaitFor, UsnJournalID;
};
#pragma pack(pop)

struct Rec {
    uint64_t frn = 0, parent = 0;
    double time = 0;
    uint32_t reason = 0, attrs = 0;
    std::string name;
};

// Resolves a directory's file reference number to a path, cached.
struct Resolver {
    HANDLE vol;
    std::string drive;   // "C:"
    std::unordered_map<uint64_t, std::string> cache;
    std::string path(uint64_t frn) {
        auto it = cache.find(frn);
        if (it != cache.end()) return it->second;
        std::string out;
        FILE_ID_DESCRIPTOR id{};
        id.dwSize = sizeof(id);
        id.Type = FileIdType;
        id.FileId.QuadPart = static_cast<LONGLONG>(frn);
        HANDLE h = OpenFileById(vol, &id, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                FILE_FLAG_BACKUP_SEMANTICS);
        if (h != INVALID_HANDLE_VALUE) {
            wchar_t buf[1024];
            DWORD n = GetFinalPathNameByHandleW(h, buf, 1024, FILE_NAME_NORMALIZED | VOLUME_NAME_NONE);
            if (n && n < 1024) out = drive + narrow(buf, n);
            CloseHandle(h);
        }
        cache[frn] = out;
        return out;
    }
};

bool exec_ext(const std::string& e) { return e == ".exe" || e == ".dll" || e == ".jar" || e == ".sys"; }

bool harmless_new_ext(const std::string& e) {
    for (const char* k : {".old", ".bak", ".tmp", ".del", ".delete", ".temp", ".orig", ".partial", ".crdownload", ".exe", ".dll", ".jar", ".sys", ".mui", ".disabled"})
        if (e == k) return true;
    return false;
}

std::string reasons(uint32_t r) {
    std::vector<std::string> v;
    if (r & USN_REASON_FILE_CREATE) v.push_back("created");
    if (r & (USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND | USN_REASON_DATA_TRUNCATION)) v.push_back("written");
    if (r & USN_REASON_RENAME_OLD_NAME) v.push_back("renamed from this name");
    if (r & USN_REASON_RENAME_NEW_NAME) v.push_back("renamed to this name");
    if (r & USN_REASON_FILE_DELETE) v.push_back("deleted");
    if (r & USN_REASON_BASIC_INFO_CHANGE) v.push_back("attributes or times changed");
    return join(v);
}

}  // namespace

SCAN_CHECK(300, usn_journal, Scope::Boot, "USN journal: files created, renamed and deleted since boot") {
    wchar_t drives[512];
    DWORD len = GetLogicalDriveStringsW(511, drives);
    size_t volumes = 0;
    for (const wchar_t* d = drives; len && *d; d += wcslen(d) + 1) {
        if (GetDriveTypeW(d) != DRIVE_FIXED) continue;
        wchar_t fs[32] = {0};
        if (!GetVolumeInformationW(d, nullptr, 0, nullptr, nullptr, nullptr, fs, 32) || wcscmp(fs, L"NTFS") != 0) continue;
        std::string drive = narrow(d, 2);
        std::wstring dev = L"\\\\.\\" + std::wstring(d, 2);
        HANDLE vol = CreateFileW(dev.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (vol == INVALID_HANDLE_VALUE) {
            ctx.note("could not open volume " + drive + " for the USN journal (run as administrator)");
            continue;
        }
        ++volumes;
        JournalData jd{};
        DWORD got = 0;
        if (!DeviceIoControl(vol, FSCTL_QUERY_USN_JOURNAL, nullptr, 0, &jd, sizeof(jd), &got, nullptr)) {
            DWORD err = GetLastError();
            if (err == ERROR_JOURNAL_NOT_ACTIVE || err == ERROR_JOURNAL_DELETE_IN_PROGRESS)
                ctx.add(Severity::Detection, "USN journal is off on " + drive,
                        "The journal that records created, renamed and deleted files does not exist on this "
                        "drive. On the Windows drive it is always on unless someone deleted it.", drive);
            else
                ctx.note(strf("USN journal query failed on %s (error %lu)", drive.c_str(), err));
            CloseHandle(vol);
            continue;
        }
        double created = ft_to_epoch(static_cast<uint64_t>(jd.UsnJournalID));
        if (ctx.since_boot(created))
            ctx.add(Severity::Detection, "USN journal on " + drive + " was created this boot",
                    "The journal's ID is the time it was created: " + fmt_time(created) + ". A journal newer "
                    "than the last boot means the old one was deleted (fsutil usn deletejournal), which wipes "
                    "the record of deleted and renamed files.", drive);
        else
            ctx.add(Severity::Integrity, "USN journal on " + drive + " created " + fmt_time(created),
                    strf("Size limit %.0f MB.", jd.MaximumSize / 1048576.0), "", Scope::None);

        Resolver res{vol, drive, {}};
        std::vector<char> buf(1 << 20);
        ReadJournal rd{};
        rd.StartUsn = jd.FirstUsn;
        rd.ReasonMask = 0xFFFFFFFF;
        rd.UsnJournalID = jd.UsnJournalID;

        double first_time = 0;
        size_t records = 0, since_boot = 0;
        std::vector<std::string> pf_deleted;
        size_t pf_deleted_count = 0;
        std::map<std::string, std::pair<uint32_t, double>> named;      // name -> reasons, last time
        std::unordered_map<uint64_t, Rec> rename_old;                    // frn -> old name record
        std::vector<std::string> ext_changes;
        std::vector<Rec> deleted_exec, deleted_mods;
        size_t deleted_exec_total = 0;
        uint64_t budget = ctx.deep ? (4ull << 30) : (1ull << 30), read_total = 0;

        while (rd.StartUsn < jd.NextUsn && read_total < budget) {
            if (!DeviceIoControl(vol, FSCTL_READ_USN_JOURNAL, &rd, sizeof(rd), buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr) ||
                got <= sizeof(USN))
                break;
            read_total += got;
            int64_t next = 0;
            memcpy(&next, buf.data(), 8);
            if (next <= rd.StartUsn) break;
            size_t off = sizeof(USN);
            while (off + 60 <= got) {
                const char* p = buf.data() + off;
                uint32_t rec_len;
                uint16_t major;
                memcpy(&rec_len, p, 4);
                memcpy(&major, p + 4, 2);
                if (rec_len < 60 || off + rec_len > got) break;
                Rec r;
                uint64_t ft = 0;
                uint16_t name_len = 0, name_off = 0;
                if (major == 2) {
                    memcpy(&r.frn, p + 8, 8);
                    memcpy(&r.parent, p + 16, 8);
                    memcpy(&ft, p + 32, 8);
                    memcpy(&r.reason, p + 40, 4);
                    memcpy(&r.attrs, p + 52, 4);
                    memcpy(&name_len, p + 56, 2);
                    memcpy(&name_off, p + 58, 2);
                } else if (major == 3 && rec_len >= 76) {
                    memcpy(&r.frn, p + 8, 8);        // low 64 bits of the 128-bit id
                    memcpy(&r.parent, p + 24, 8);
                    memcpy(&ft, p + 48, 8);
                    memcpy(&r.reason, p + 56, 4);
                    memcpy(&r.attrs, p + 68, 4);
                    memcpy(&name_len, p + 72, 2);
                    memcpy(&name_off, p + 74, 2);
                } else {
                    off += rec_len;
                    continue;
                }
                off += rec_len;
                ++records;
                r.time = ft_to_epoch(ft);
                if (first_time == 0) first_time = r.time;
                if (!ctx.since_boot(r.time)) continue;
                ++since_boot;
                if (name_off + name_len > rec_len || (r.attrs & FILE_ATTRIBUTE_DIRECTORY)) continue;
                r.name = narrow(reinterpret_cast<const wchar_t*>(p + name_off), name_len / 2);
                std::string ext = ext_of(r.name);

                if (ext == ".pf" && (r.reason & USN_REASON_FILE_DELETE)) {
                    ++pf_deleted_count;
                    if (pf_deleted.size() < 25 && std::find(pf_deleted.begin(), pf_deleted.end(), r.name) == pf_deleted.end())
                        pf_deleted.push_back(r.name);
                }
                if (r.reason & USN_REASON_RENAME_OLD_NAME) rename_old[r.frn] = r;
                if (r.reason & USN_REASON_RENAME_NEW_NAME) {
                    auto it = rename_old.find(r.frn);
                    if (it != rename_old.end()) {
                        std::string old_ext = ext_of(it->second.name);
                        if (exec_ext(old_ext) && old_ext != ext && !harmless_new_ext(ext) && ext_changes.size() < 40) {
                            std::string dir = res.path(r.parent);
                            if (dir.empty() || user_writable_path(dir + "\\") || contains(lower(dir), "\\.minecraft") ||
                                contains(lower(dir), "\\appdata\\roaming"))
                                ext_changes.push_back((dir.empty() ? std::string() : dir + "\\") + it->second.name + " -> " + r.name +
                                                      " at " + fmt_time(r.time));
                        }
                        rename_old.erase(it);
                    }
                }
                bool interesting_ext = exec_ext(ext) || ext == ".pf" || ext == ".bat" || ext == ".ps1" || ext == ".ahk" || ext == ".zip" || ext == ".rar";
                if (interesting_ext && (r.reason & (USN_REASON_FILE_CREATE | USN_REASON_FILE_DELETE | USN_REASON_RENAME_OLD_NAME |
                                                    USN_REASON_RENAME_NEW_NAME))) {
                    if (!ctx.match_names(r.name).empty()) {
                        auto& e = named[r.name];
                        e.first |= r.reason;
                        e.second = r.time;
                    }
                }
                if ((r.reason & USN_REASON_FILE_DELETE) && (ext == ".exe" || ext == ".dll" || ext == ".jar")) {
                    ++deleted_exec_total;
                    if (deleted_exec.size() < 4000) deleted_exec.push_back(r);
                }
            }
            rd.StartUsn = next;
        }

        if (first_time > 0 && ctx.since_boot(first_time) && !ctx.since_boot(created))
            ctx.add(Severity::Integrity, "USN journal on " + drive + " does not reach back to boot",
                    "The oldest record is from " + fmt_time(first_time) + ". Older records were pushed out by "
                    "newer ones, so early parts of this session are not covered.", "", Scope::None);

        for (const auto& n : named) {
            bool del = (n.second.first & USN_REASON_FILE_DELETE) != 0;
            ctx.add(Severity::Detection, std::string("Known cheat file ") + (del ? "deleted" : "touched") + " this boot: " + n.first,
                    "The journal on " + drive + " shows this file was " + reasons(n.second.first) + ". Last record " +
                        fmt_time(n.second.second) + ". Matched: " + join(ctx.match_names(n.first)) + ".", n.first);
        }
        if (pf_deleted_count) {
            bool java = false;
            for (const std::string& n : pf_deleted) java = java || starts_with(lower(n), "java");
            ctx.add((java || pf_deleted_count >= 8) ? Severity::Detection : Severity::Warning,
                    strf("%zu prefetch file delete record(s) this boot on %s", pf_deleted_count, drive.c_str()),
                    "Prefetch files record program runs. Windows only removes them itself when the folder is "
                    "full (1024 files), so deletes during a session usually mean someone cleaned them.",
                    join(pf_deleted));
        }
        if (!ext_changes.empty())
            ctx.add(Severity::Warning, strf("%zu program file(s) renamed to another file type this boot", ext_changes.size()),
                    "An .exe, .dll or .jar was renamed to a different extension. That is done to hide a cheat as "
                    "a picture or text file.", join(ext_changes, " | "));

        // Deleted executables: resolve the folder only now, and only for these.
        std::vector<std::string> user_deleted;
        size_t user_deleted_count = 0;
        std::set<std::string> dedupe;
        for (const Rec& r : deleted_exec) {
            std::string dir = res.path(r.parent);
            if (dir.empty()) continue;
            std::string full = dir + "\\" + r.name;
            std::string l = lower(full);
            if (!dedupe.insert(l).second) continue;
            bool mods = contains(l, "\\mods\\") && (contains(l, "minecraft") || contains(l, "lunar") || contains(l, "\\instances\\") ||
                                                     contains(l, "prism") || contains(l, "multimc") || contains(l, "modrinth") || contains(l, "curseforge"));
            if (mods && ext_of(l) == ".jar") {
                deleted_mods.push_back(r);
                ctx.add(Severity::Warning, "Mod jar deleted this boot: " + r.name,
                        "A jar was deleted from a mods folder at " + fmt_time(r.time) + ". Removing a mod right "
                        "before a screenshare is a common way to hide a cheat mod. Launchers also delete jars when "
                        "they update mods.", full);
            } else if (user_writable_path(full) && !contains(l, "\\appdata\\local\\temp\\")) {
                ++user_deleted_count;
                if (user_deleted.size() < 15) user_deleted.push_back(full + " at " + fmt_time(r.time));
            }
        }
        if (user_deleted_count)
            ctx.add(Severity::Warning, strf("%zu program file(s) deleted from user folders this boot on %s", user_deleted_count, drive.c_str()),
                    "Executables, DLLs or jars were deleted from Downloads, Desktop, Documents or similar. "
                    "Compare the times with when the screenshare was called.", join(user_deleted, " | "));
        ctx.add(Severity::Integrity, "USN journal read on " + drive,
                strf("%zu records, %zu since boot, %zu program-file deletes since boot.%s", records, since_boot, deleted_exec_total,
                     read_total >= budget ? " Stopped at the read limit; use --deep for the whole journal." : ""),
                "", Scope::None);
        CloseHandle(vol);
    }
    if (!volumes) ctx.note("no NTFS volume could be opened for the USN journal");
}

}  // namespace scan
#endif

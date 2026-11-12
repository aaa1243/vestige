// Checks that work the same on every system: signature scan of files on disk
// and cheat sites in browser history.
#include <algorithm>

#include "core.hpp"
#include "util.hpp"

namespace scan {

static bool exec_ext(const std::string& e) {
    return e == ".exe" || e == ".dll" || e == ".jar" || e == ".sys" || e == ".so" || e == ".dylib" ||
           e == ".bat" || e == ".ps1" || e == ".ahk";
}

SCAN_CHECK(600, file_signatures, Scope::OutOfInstance,
           "Known cheat files on disk by name, hash and content") {
    struct Root { std::string path; int depth; };
    std::vector<Root> roots;
    for (const std::string& h : user_homes()) {
#if defined(_WIN32)
        roots.push_back({h + "\\Downloads", 3});
        roots.push_back({h + "\\Desktop", 3});
        roots.push_back({h + "\\Documents", 2});
        roots.push_back({h + "\\AppData\\Local\\Temp", 2});
        roots.push_back({h + "\\AppData\\Roaming\\.minecraft\\mods", 2});
        roots.push_back({h + "\\AppData\\Roaming\\.minecraft\\versions", 2});
        roots.push_back({h + "\\.lunarclient\\offline", 4});
        if (ctx.deep) roots.push_back({h + "\\AppData\\Roaming", 4});
#elif defined(__APPLE__)
        roots.push_back({h + "/Downloads", 3});
        roots.push_back({h + "/Desktop", 3});
        roots.push_back({h + "/Documents", 2});
        roots.push_back({h + "/Library/Application Support/minecraft/mods", 2});
        roots.push_back({h + "/Library/Application Support/minecraft/versions", 2});
        roots.push_back({h + "/.lunarclient/offline", 4});
#else
        roots.push_back({h + "/Downloads", 3});
        roots.push_back({h + "/Desktop", 3});
        roots.push_back({h + "/Documents", 2});
        roots.push_back({h + "/.minecraft/mods", 2});
        roots.push_back({h + "/.minecraft/versions", 2});
        roots.push_back({h + "/.lunarclient/offline", 4});
#endif
    }
#if !defined(_WIN32)
    roots.push_back({"/tmp", 2});
#endif

    const size_t max_files = ctx.deep ? 20000 : 4000;
    const uint64_t max_file = ctx.deep ? (256ull << 20) : (64ull << 20);
    const uint64_t max_total = ctx.deep ? (8ull << 30) : (2ull << 30);
    size_t files = 0, hits = 0;
    uint64_t total = 0;
    bool capped = false;

    MultiSearch needles;   // id = index into ctx.sigs.content
    for (size_t i = 0; i < ctx.sigs.content.size(); ++i) {
        needles.add(ctx.sigs.content[i].value, static_cast<int>(i));
        needles.add(utf16le(ctx.sigs.content[i].value), static_cast<int>(i));
    }

    for (const Root& r : roots) {
        walk_files(r.path, r.depth, [&](const std::string& path, uint64_t size) {
            std::string ext = ext_of(path);
            if (!exec_ext(ext)) return true;
            if (files >= max_files || total >= max_total) { capped = true; return false; }
            ++files;
            std::string name = base_name(path);
            double mt = file_mtime(path);
            Scope sc = ctx.since_boot(mt) ? Scope::Boot : Scope::OutOfInstance;
            std::string when = " Modified " + fmt_time(mt) + ".";

            std::vector<std::string> strong = ctx.match_names(name);
            bool content_hit = false;
            if (size <= max_file && (!ctx.sigs.hashes.empty() || !needles.empty())) {
                std::string data;
                if (read_file(path, data, static_cast<size_t>(max_file))) {
                    total += data.size();
                    if (!ctx.sigs.hashes.empty()) {
                        auto it = ctx.sigs.hashes.find(sha256_hex(data));
                        if (it != ctx.sigs.hashes.end()) {
                            ctx.add(Severity::Detection, "Known cheat file (hash match): " + it->second,
                                    "The file's SHA-256 is in the signature list, so this is that "
                                    "exact file whatever it is named." + when, path, sc);
                            ++hits;
                            content_hit = true;
                        }
                    }
                    if (!content_hit && !needles.empty()) {
                        lower_inplace(data);
                        std::vector<std::string> labels;
                        std::vector<char> found(ctx.sigs.content.size(), 0);
                        needles.search(data.data(), data.size(), found);
                        for (size_t i = 0; i < found.size(); ++i)
                            if (found[i] && std::find(labels.begin(), labels.end(),
                                                      ctx.sigs.content[i].label) == labels.end())
                                labels.push_back(ctx.sigs.content[i].label);
                        if (!labels.empty()) {
                            ctx.add(Severity::Detection, "Cheat code inside file: " + join(labels),
                                    "The file contains text that belongs to a known cheat. A file on "
                                    "disk shows it was downloaded or built, not that it was used." + when,
                                    path, sc);
                            ++hits;
                            content_hit = true;
                        }
                    }
                }
            }
            if (!content_hit && !strong.empty()) {
                ctx.add(Severity::Warning, "File named like a known cheat: " + join(strong),
                        "Matched by name only. Names can be coincidence, so check the file." + when,
                        path, sc);
                ++hits;
            }
            return true;
        });
        if (capped) break;
    }
    ctx.add(Severity::Integrity, "Files checked against signatures",
            strf("%zu program, library and jar files in user folders, %zu flagged. %zu hash and %zu "
                 "content signatures loaded.%s",
                 files, hits, ctx.sigs.hashes.size(), ctx.sigs.content.size(),
                 capped ? " Stopped at the file limit; use --deep for more." : ""),
            "", Scope::None);
}

// ---------------------------------------------------------------------------
// Game and launcher logs. They are written by the game itself, so they keep
// evidence from earlier in the session even after the game was restarted.
SCAN_CHECK(170, game_logs, Scope::Boot, "Game logs and Java crash logs: attached agents and cheat class names") {
#if defined(_WIN32)
    const char sep = '\\';
#else
    const char sep = '/';
#endif
    struct Root { std::string path; int depth; };
    std::vector<Root> roots;
    for (const std::string& h : user_homes()) {
#if defined(_WIN32)
        std::string r = h + "\\AppData\\Roaming\\";
        roots.push_back({r + ".minecraft", 1});
        roots.push_back({r + ".minecraft\\logs", 1});
        roots.push_back({r + ".minecraft\\crash-reports", 1});
        roots.push_back({h + "\\.lunarclient\\logs", 3});
        roots.push_back({h + "\\.lunarclient\\offline\\multiver\\logs", 1});
        roots.push_back({r + "PrismLauncher\\instances", 4});
        roots.push_back({r + "com.modrinth.theseus\\profiles", 3});
        roots.push_back({r + "ModrinthApp\\profiles", 3});
        roots.push_back({h + "\\curseforge\\minecraft\\Instances", 3});
        roots.push_back({r + ".feather\\logs", 2});
        roots.push_back({r + "Badlion Client\\logs", 2});
#elif defined(__APPLE__)
        std::string a = h + "/Library/Application Support/";
        roots.push_back({a + "minecraft", 1});
        roots.push_back({a + "minecraft/logs", 1});
        roots.push_back({a + "minecraft/crash-reports", 1});
        roots.push_back({h + "/.lunarclient/logs", 3});
        roots.push_back({h + "/.lunarclient/offline/multiver/logs", 1});
        roots.push_back({a + "PrismLauncher/instances", 4});
        roots.push_back({a + "com.modrinth.theseus/profiles", 3});
#else
        roots.push_back({h + "/.minecraft", 1});
        roots.push_back({h + "/.minecraft/logs", 1});
        roots.push_back({h + "/.minecraft/crash-reports", 1});
        roots.push_back({h + "/.lunarclient/logs", 3});
        roots.push_back({h + "/.lunarclient/offline/multiver/logs", 1});
        roots.push_back({h + "/.local/share/PrismLauncher/instances", 4});
        roots.push_back({h + "/.local/share/com.modrinth.theseus/profiles", 3});
        roots.push_back({h + "/.var/app/org.prismlauncher.PrismLauncher/data/PrismLauncher/instances", 4});
#endif
    }
    (void)sep;
    double now = now_epoch();
    size_t files = 0, findings = 0;
    for (const Root& root : roots) {
        walk_files(root.path, root.depth, [&](const std::string& path, uint64_t size) {
            std::string name = lower(base_name(path));
            bool hs_err = starts_with(name, "hs_err_pid");
            bool crash = starts_with(name, "crash-") && ends_with(name, ".txt");
            bool log = ends_with(name, ".log") || name == "launcher_log.txt";
            if (!(hs_err || crash || log) || size > (48u << 20) || size == 0) return true;
            double mt = file_mtime(path);
            if (now - mt > 14 * 86400.0) return true;
            std::string text;
            if (!read_file(path, text, 48u << 20)) return true;
            ++files;
            bool since = ctx.since_boot(mt);
            Scope sc = since ? Scope::Boot : Scope::OutOfInstance;
            std::string when = " File last written " + fmt_time(mt) + (since ? " (since this boot)." : " (before this boot).");
            bool agent_seen = false;
            std::vector<std::string> cls_hits, lib_hits, mod_hits;
            for (const std::string& raw : split(text, '\n')) {
                if (raw.size() > 4000) continue;
                std::string l = lower(raw);
                if (contains(l, "[chat]")) continue;   // what other players typed proves nothing
                if (!agent_seen && contains(l, "a java agent has been loaded dynamically")) {
                    agent_seen = true;
                    ctx.add(since ? Severity::Detection : Severity::Warning, "Log shows a Java agent was attached while the game ran",
                            "Java 21 and newer print this warning when an agent is attached to a running "
                            "game. That is how injectable Java cheats load. A few mods attach an agent to "
                            "themselves, and the line names the jar when it can." + when,
                            trim(cut(raw, 300)) + " | " + path, sc);
                    ++findings;
                }
                for (const Sig& s : ctx.sigs.memory)
                    if (l.find(s.value) != std::string::npos) {
                        std::string label = s.label.empty() ? s.value : s.label;
                        if (std::find(cls_hits.begin(), cls_hits.end(), label) == cls_hits.end()) cls_hits.push_back(label);
                    }
                bool lib_line = contains(l, ".dll") || contains(l, ".so") || contains(l, ".dylib") || contains(l, ".jar");
                bool mod_line = contains(l, "mod") || contains(l, "agent") || contains(l, "tweak") || contains(l, "loading");
                if (lib_line || mod_line) {
                    for (const std::string& hit : ctx.match_names(l)) {
                        std::vector<std::string>& dst = (hs_err || crash) && lib_line ? lib_hits : mod_hits;
                        if (std::find(dst.begin(), dst.end(), hit) == dst.end()) dst.push_back(hit);
                    }
                }
            }
            if (!cls_hits.empty()) {
                ctx.add(since ? Severity::Detection : Severity::Warning, "Cheat code named in a game log",
                        "The log contains class names that belong to: " + join(cls_hits) +
                            ". Those only get printed if the code was loaded in the game." + when, path, sc);
                ++findings;
            }
            if (!lib_hits.empty()) {
                ctx.add(since ? Severity::Detection : Severity::Warning, "Crash log lists a known cheat file as loaded",
                        "Java crash logs list every library and jar that was loaded at the time. Matched: " +
                            join(lib_hits) + "." + when, path, sc);
                ++findings;
            }
            if (!mod_hits.empty()) {
                ctx.add(Severity::Warning, "Known cheat name in a game or launcher log",
                        "Matched: " + join(mod_hits) + ". Chat lines are skipped, but a name can still be a "
                        "coincidence, so open the log and read the line." + when, path, sc);
                ++findings;
            }
            return true;
        });
    }
    if (files)
        ctx.add(Severity::Integrity, "Game logs read",
                strf("%zu log and crash files from the last 14 days, %zu flagged. Old logs are zipped by the "
                     "game (.log.gz) and are not opened.", files, findings),
                "", Scope::None);
    else
        ctx.note("no recent game logs were found in the usual launcher folders");
}

SCAN_CHECK(620, browser_history, Scope::OutOfInstance, "Cheat sites in browser history") {
    if (ctx.sigs.domains.empty()) return;
    struct Cand { std::string browser, dir; bool chromium; };
    std::vector<Cand> cands;
    for (const std::string& h : user_homes()) {
#if defined(_WIN32)
        std::string l = h + "\\AppData\\Local\\", r = h + "\\AppData\\Roaming\\";
        cands.push_back({"Chrome", l + "Google\\Chrome\\User Data", true});
        cands.push_back({"Edge", l + "Microsoft\\Edge\\User Data", true});
        cands.push_back({"Brave", l + "BraveSoftware\\Brave-Browser\\User Data", true});
        cands.push_back({"Vivaldi", l + "Vivaldi\\User Data", true});
        cands.push_back({"Opera", r + "Opera Software\\Opera Stable", true});
        cands.push_back({"Opera GX", r + "Opera Software\\Opera GX Stable", true});
        cands.push_back({"Firefox", r + "Mozilla\\Firefox\\Profiles", false});
#elif defined(__APPLE__)
        std::string a = h + "/Library/Application Support/";
        cands.push_back({"Chrome", a + "Google/Chrome", true});
        cands.push_back({"Edge", a + "Microsoft Edge", true});
        cands.push_back({"Brave", a + "BraveSoftware/Brave-Browser", true});
        cands.push_back({"Vivaldi", a + "Vivaldi", true});
        cands.push_back({"Opera", a + "com.operasoftware.Opera", true});
        cands.push_back({"Firefox", a + "Firefox/Profiles", false});
        cands.push_back({"Safari", h + "/Library/Safari", true});
#else
        cands.push_back({"Chrome", h + "/.config/google-chrome", true});
        cands.push_back({"Chromium", h + "/.config/chromium", true});
        cands.push_back({"Brave", h + "/.config/BraveSoftware/Brave-Browser", true});
        cands.push_back({"Vivaldi", h + "/.config/vivaldi", true});
        cands.push_back({"Firefox", h + "/.mozilla/firefox", false});
#endif
    }
    size_t read = 0;
    auto scan_file = [&](const std::string& browser, const std::string& path) {
        std::string data;
        if (!read_file(path, data, 128u << 20) || data.empty()) return;
        ++read;
        lower_inplace(data);
        std::vector<std::string> hit;
        for (const Sig& s : ctx.sigs.domains)
            if (data.find(s.value) != std::string::npos) hit.push_back(s.label + " (" + s.value + ")");
        if (!hit.empty())
            ctx.add(Severity::Warning, "Cheat site in " + browser + " history",
                    "The history file contains these addresses: " + join(hit) +
                    ". It shows a visit at some point, not when, and not that anything was "
                    "downloaded or used.", path);
    };
    for (const Cand& c : cands) {
        if (!is_dir(c.dir)) continue;
        if (c.chromium) {
            for (const char* f : {"History", "History.db"})
                if (file_exists(c.dir + "/" + f)) scan_file(c.browser, c.dir + "/" + f);
            for (const std::string& prof : list_dir(c.dir)) {
                std::string l = lower(prof);
                if (l == "default" || starts_with(l, "profile ") || l == "guest profile")
                    if (file_exists(c.dir + "/" + prof + "/History"))
                        scan_file(c.browser + " (" + prof + ")", c.dir + "/" + prof + "/History");
            }
        } else {
            for (const std::string& prof : list_dir(c.dir))
                for (const char* f : {"places.sqlite", "places.sqlite-wal"})
                    if (file_exists(c.dir + "/" + prof + "/" + f))
                        scan_file(c.browser + " (" + prof + ")", c.dir + "/" + prof + "/" + f);
        }
    }
    if (read == 0) ctx.note("no browser history files could be read");
    else
        ctx.add(Severity::Integrity, "Browser history checked",
                strf("%zu history file(s) searched for %zu cheat site addresses. Only matches are "
                     "shown; nothing else from the history is read out.", read, ctx.sigs.domains.size()),
                "", Scope::None);
}

}  // namespace scan

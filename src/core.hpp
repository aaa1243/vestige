// Core types shared by every platform: findings, signatures, the check
// registry and the scan context. Read-only tool: nothing in here or in any
// check writes to the scanned machine except the report files.
#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace scan {

enum class Severity { Integrity = 0, Warning = 1, Detection = 2 };
// Default = use the check's own default scope.
enum class Scope { Default, None, InGame, Boot, OutOfInstance };

const char* severity_name(Severity s);
const char* scope_name(Scope s);   // "" for None

struct Finding {
    std::string module;
    Severity severity = Severity::Integrity;
    std::string title, detail, evidence;
    Scope scope = Scope::None;
};

struct Sig {
    std::string value;   // lowercase
    std::string label;   // human name, may be empty
};

struct Signatures {
    std::vector<Sig> names;     // known cheat / tool file names
    std::vector<Sig> weak;      // generic words, lead only
    std::vector<Sig> content;   // byte strings inside files (class paths etc.)
    std::vector<Sig> memory;    // strings searched in game memory
    std::vector<Sig> domains;   // cheat sites
    std::vector<Sig> drivers;   // driver file names used to load kernel cheats
    std::unordered_map<std::string, std::string> hashes;  // sha256 hex -> label

    // Lines: type|value|label   ('#' starts a comment)
    void load_text(const std::string& text, std::vector<std::string>* errors);
    size_t total() const;
};

struct Context;
using CheckFn = void (*)(Context&);

struct CheckInfo {
    int order;
    const char* name;
    const char* summary;
    Scope scope;
    CheckFn fn;
};

std::vector<CheckInfo>& registry();
struct Registrar {
    Registrar(int order, const char* name, const char* summary, Scope scope, CheckFn fn);
};

#define SCAN_CHECK(order, id, scope, summary)                                   \
    static void check_##id(scan::Context& ctx);                                 \
    static scan::Registrar registrar_##id(order, #id, summary, scope, check_##id); \
    static void check_##id(scan::Context& ctx)

struct Context {
    std::string os;            // "windows", "macos", "linux"
    bool admin = false;
    bool deep = false;         // --deep: slower, wider scans
    double boot_time = 0;      // epoch seconds, 0 = unknown
    Signatures sigs;
    std::vector<Finding> findings;
    std::vector<std::string> notes;

    // set by the runner while a check executes
    std::string current;
    Scope current_scope = Scope::None;

    void add(Severity sev, std::string title, std::string detail,
             std::string evidence = "", Scope scope = Scope::Default);
    void note(const std::string& msg);

    bool since_boot(double t) const { return boot_time > 0 && t >= boot_time; }

    // Labels of known-cheat names found in `text` (case-insensitive).
    std::vector<std::string> match_names(const std::string& text) const;
    std::vector<std::string> match_weak(const std::string& text) const;
    std::vector<std::string> match_domains(const std::string& text) const;
};

// Returns labels of signatures in `list` whose value occurs in `lowered`.
// With `boundary`, short values must not sit inside a longer word.
std::vector<std::string> match_list(const std::vector<Sig>& list, const std::string& lowered,
                                    bool boundary);

std::string join(const std::vector<std::string>& v, const char* sep = ", ");

// Reports
void print_console(const Context& ctx, double seconds);
std::string to_json(const Context& ctx, double started);
std::string to_html(const Context& ctx, double started);

// Built-in signature text (sigs_default.cpp)
extern const char* const kDefaultSignatures;

// Platform entry points (each platform file set defines these)
bool platform_is_admin();
double platform_boot_time();
void platform_prepare(Context& ctx);   // privileges etc. before checks run

}  // namespace scan

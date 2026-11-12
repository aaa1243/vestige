#include "core.hpp"

#include <algorithm>

#include "util.hpp"

namespace scan {

const char* severity_name(Severity s) {
    switch (s) {
        case Severity::Detection: return "DETECTION";
        case Severity::Warning: return "WARNING";
        default: return "INTEGRITY";
    }
}

const char* scope_name(Scope s) {
    switch (s) {
        case Scope::InGame: return "In game";
        case Scope::Boot: return "Boot";
        case Scope::OutOfInstance: return "Out of instance";
        default: return "";
    }
}

std::vector<CheckInfo>& registry() {
    static std::vector<CheckInfo> r;
    return r;
}

Registrar::Registrar(int order, const char* name, const char* summary, Scope scope, CheckFn fn) {
    registry().push_back(CheckInfo{order, name, summary, scope, fn});
}

void Signatures::load_text(const std::string& text, std::vector<std::string>* errors) {
    size_t line_no = 0;
    for (const std::string& raw : split(text, '\n')) {
        ++line_no;
        std::string line = trim(raw);
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> parts = split(line, '|');
        if (parts.size() < 2) {
            if (errors) errors->push_back(strf("line %zu: expected type|value|label", line_no));
            continue;
        }
        std::string type = lower(trim(parts[0]));
        std::string value = lower(trim(parts[1]));
        std::string label = parts.size() > 2 ? trim(parts[2]) : std::string();
        if (value.size() < 3) {
            if (errors) errors->push_back(strf("line %zu: value too short", line_no));
            continue;
        }
        Sig s{value, label.empty() ? value : label};
        if (type == "name") names.push_back(s);
        else if (type == "weak") weak.push_back(s);
        else if (type == "content") content.push_back(s);
        else if (type == "memory") memory.push_back(s);
        else if (type == "domain") domains.push_back(s);
        else if (type == "driver") drivers.push_back(s);
        else if (type == "hash") {
            if (value.size() == 64) hashes[value] = s.label;
            else if (errors) errors->push_back(strf("line %zu: hash must be 64 hex chars (SHA-256)", line_no));
        } else if (errors) {
            errors->push_back(strf("line %zu: unknown type '%s'", line_no, type.c_str()));
        }
    }
}

size_t Signatures::total() const {
    return names.size() + weak.size() + content.size() + memory.size() + domains.size() +
           drivers.size() + hashes.size();
}

static inline bool is_letter(char c) { return c >= 'a' && c <= 'z'; }

std::vector<std::string> match_list(const std::vector<Sig>& list, const std::string& lowered,
                                    bool boundary) {
    std::vector<std::string> out;
    for (const Sig& s : list) {
        size_t pos = 0;
        bool hit = false;
        while ((pos = lowered.find(s.value, pos)) != std::string::npos) {
            if (!boundary || s.value.size() > 6) { hit = true; break; }
            // short names must stand alone: "vape.exe" yes, "evaporate" no
            bool left = pos == 0 || !is_letter(lowered[pos - 1]);
            size_t end = pos + s.value.size();
            bool right = end >= lowered.size() || !is_letter(lowered[end]);
            if (left && right) { hit = true; break; }
            ++pos;
        }
        if (hit && std::find(out.begin(), out.end(), s.label) == out.end()) out.push_back(s.label);
    }
    return out;
}

std::vector<std::string> Context::match_names(const std::string& text) const {
    return match_list(sigs.names, lower(text), true);
}
std::vector<std::string> Context::match_weak(const std::string& text) const {
    return match_list(sigs.weak, lower(text), false);
}
std::vector<std::string> Context::match_domains(const std::string& text) const {
    return match_list(sigs.domains, lower(text), false);
}

void Context::add(Severity sev, std::string title, std::string detail, std::string evidence,
                  Scope scope) {
    Finding f;
    f.module = current;
    f.severity = sev;
    f.title = std::move(title);
    f.detail = std::move(detail);
    f.evidence = std::move(evidence);
    f.scope = scope == Scope::Default ? current_scope : scope;
    findings.push_back(std::move(f));
}

void Context::note(const std::string& msg) { notes.push_back(current.empty() ? msg : current + ": " + msg); }

std::string join(const std::vector<std::string>& v, const char* sep) {
    std::string o;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) o += sep;
        o += v[i];
    }
    return o;
}

}  // namespace scan

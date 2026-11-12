// The scan worker thread and everything the GUI draws.
//
// Threading: run_scan() runs on a worker thread and owns its Context. After
// every check the progress callback copies the new findings and notes into
// Shared under a mutex. The UI thread copies from Shared once per frame, so
// it never touches the Context and the window never waits on a check.
#ifdef _WIN32
#include "gui.hpp"

#include <algorithm>
#include <cstring>
#include <mutex>
#include <thread>

#include "imgui.h"

#include "../core.hpp"
#include "../scan_run.hpp"
#include "../util.hpp"
#include "../windows/win_util.hpp"

namespace scan {
namespace gui {

namespace {

// ---- palette (same as the HTML report) -------------------------------------
const ImU32 kBg = IM_COL32(0x0b, 0x0c, 0x0f, 255);
const ImU32 kCard = IM_COL32(0x14, 0x16, 0x1b, 255);
const ImU32 kCardHover = IM_COL32(0x1a, 0x1d, 0x24, 255);
const ImU32 kChip = IM_COL32(0x1a, 0x1d, 0x24, 255);
const ImU32 kChipHover = IM_COL32(0x23, 0x27, 0x33, 255);
const ImU32 kAccent = IM_COL32(0x3d, 0x5a, 0xfe, 255);
const ImU32 kAccentHover = IM_COL32(0x53, 0x6d, 0xfe, 255);
const ImU32 kAccentDown = IM_COL32(0x30, 0x4a, 0xe0, 255);
const ImU32 kSelected = IM_COL32(0x1f, 0x2a, 0x52, 255);
const ImU32 kText = IM_COL32(0xe6, 0xe7, 0xea, 255);
const ImU32 kTextBody = IM_COL32(0xc9, 0xcc, 0xd3, 255);
const ImU32 kTextDim = IM_COL32(0x9a, 0xa0, 0xaa, 255);
const ImU32 kTextFaint = IM_COL32(0x8b, 0x8f, 0x99, 255);
const ImU32 kRed = IM_COL32(0xef, 0x53, 0x50, 255);
const ImU32 kAmber = IM_COL32(0xff, 0xb3, 0x00, 255);
const ImU32 kBlueGrey = IM_COL32(0x78, 0x90, 0x9c, 255);
const ImU32 kTrack = IM_COL32(0x2a, 0x2e, 0x38, 255);

ImVec4 v4(ImU32 c) { return ImGui::ColorConvertU32ToFloat4(c); }

ImU32 sev_color(Severity s) {
    return s == Severity::Detection ? kRed : s == Severity::Warning ? kAmber : kBlueGrey;
}
ImU32 tag_bg(Severity s) {
    return s == Severity::Detection ? IM_COL32(0x3a, 0x1f, 0x22, 255)
         : s == Severity::Warning ? IM_COL32(0x3a, 0x31, 0x17, 255) : IM_COL32(0x1f, 0x2a, 0x30, 255);
}
ImU32 tag_fg(Severity s) {
    return s == Severity::Detection ? IM_COL32(0xff, 0x8a, 0x80, 255)
         : s == Severity::Warning ? IM_COL32(0xff, 0xd5, 0x4f, 255) : IM_COL32(0xb0, 0xbe, 0xc5, 255);
}

// ---- state -----------------------------------------------------------------
enum class State { Idle, Scanning, Done };

struct Row {
    Finding f;
    std::string hay;    // lowercase title + detail + evidence + check name, for the search box
};

// Written by the worker, read by the UI. Always under mu.
struct Shared {
    std::mutex mu;
    std::vector<Finding> findings;
    std::vector<std::string> notes;
    size_t index = 0, total = 0;
    std::string check;
    bool check_running = false;
    bool saving = false;      // report files are being written
    bool finished = false;
    double seconds = 0;
    double game_start = 0;
    bool saved_html = false, saved_json = false;
};

struct App {
    Settings settings;
    State state = State::Idle;
    std::thread worker;
    Shared sh;

    // UI thread copies
    std::vector<Row> rows;
    std::vector<std::string> notes;
    size_t index = 0, total = 0;
    std::string check;
    bool check_running = false;
    double seconds = 0, game_start = 0;
    bool saved_html = false, saved_json = false;

    bool admin = false;
    double boot_time = 0;

    // filters
    int sev_filter = -1;               // -1 = all, else a Severity value
    Scope scope_filter = Scope::Default;   // Default = all
    char search[128] = "";
    std::vector<size_t> view;          // row indexes that pass the filters, detections first
    bool view_dirty = true;

    std::set<size_t> expanded;
    size_t copied_row = static_cast<size_t>(-1);
    double copied_at = 0;
    bool notes_open = false;

    float s = 1.0f;                    // DPI scale
    Fonts fonts;
};

App* g_app = nullptr;

float S(float px) { return px * g_app->s; }

size_t count_sev(const App& a, Severity sev) {
    return static_cast<size_t>(std::count_if(a.rows.begin(), a.rows.end(),
                                             [sev](const Row& r) { return r.f.severity == sev; }));
}

// ---- worker ----------------------------------------------------------------
void scan_thread(App* a) {
    Context ctx;
    ScanOptions opt;
    opt.deep = a->settings.deep;
    opt.sig_path = a->settings.sig_path;
    opt.skip = a->settings.skip;

    size_t sent = 0;
    double started = run_scan(ctx, opt, [&](const ScanProgress& p) {
        std::lock_guard<std::mutex> lock(a->sh.mu);
        a->sh.index = p.index;
        a->sh.total = p.total;
        a->sh.check = p.name;
        a->sh.check_running = !p.done;
        if (p.done) {
            for (; sent < ctx.findings.size(); ++sent) a->sh.findings.push_back(ctx.findings[sent]);
            a->sh.notes = ctx.notes;
        }
    });
    double seconds = now_epoch() - started;
    for (const std::string& name : opt.skip)
        ctx.notes.push_back(name + ": skipped because it crashed in an earlier scan");

    // Same snapshot the checks used (it is cached for the run).
    double game = 0;
    for (const win::ProcInfo& p : win::game_processes())
        if (game == 0 || p.start < game) game = p.start;

    {
        std::lock_guard<std::mutex> lock(a->sh.mu);
        a->sh.saving = true;
    }
    std::string dir = default_report_dir();
    make_dirs(dir);
    bool json_ok = write_file(dir + "\\report.json", to_json(ctx, started));
    bool html_ok = write_file(dir + "\\report.html", to_html(ctx, started));

    std::lock_guard<std::mutex> lock(a->sh.mu);
    for (; sent < ctx.findings.size(); ++sent) a->sh.findings.push_back(ctx.findings[sent]);
    a->sh.notes = ctx.notes;
    a->sh.seconds = seconds;
    a->sh.game_start = game;
    a->sh.saved_json = json_ok;
    a->sh.saved_html = html_ok;
    a->sh.saving = false;
    a->sh.check_running = false;
    a->sh.finished = true;
}

void start_scan(App& a) {
    if (a.state != State::Idle) return;
    a.state = State::Scanning;
    a.worker = std::thread(scan_thread, &a);
}

// Copies whatever the worker produced since the last frame.
void sync(App& a) {
    if (a.state != State::Scanning) return;
    bool finished;
    {
        std::lock_guard<std::mutex> lock(a.sh.mu);
        for (size_t i = a.rows.size(); i < a.sh.findings.size(); ++i) {
            Row r;
            r.f = a.sh.findings[i];
            r.hay = lower(r.f.title + "\n" + r.f.detail + "\n" + r.f.evidence + "\n" + r.f.module);
            a.rows.push_back(std::move(r));
            a.view_dirty = true;
        }
        if (a.notes.size() != a.sh.notes.size()) a.notes = a.sh.notes;
        a.index = a.sh.index;
        a.total = a.sh.total;
        a.check = a.sh.check;
        a.check_running = a.sh.check_running;
        finished = a.sh.finished;
        if (finished) {
            a.seconds = a.sh.seconds;
            a.game_start = a.sh.game_start;
            a.saved_html = a.sh.saved_html;
            a.saved_json = a.sh.saved_json;
        }
    }
    if (finished) {
        a.worker.join();
        a.state = State::Done;
    }
}

void rebuild_view(App& a) {
    a.view.clear();
    std::string needle = lower(trim(a.search));
    for (size_t i = 0; i < a.rows.size(); ++i) {
        const Row& r = a.rows[i];
        if (a.sev_filter >= 0 && static_cast<int>(r.f.severity) != a.sev_filter) continue;
        if (a.scope_filter != Scope::Default && r.f.scope != a.scope_filter) continue;
        if (!needle.empty() && r.hay.find(needle) == std::string::npos) continue;
        a.view.push_back(i);
    }
    // Detections first, then warnings, then integrity. Scan order inside each group.
    std::stable_sort(a.view.begin(), a.view.end(), [&a](size_t x, size_t y) {
        return static_cast<int>(a.rows[x].f.severity) > static_cast<int>(a.rows[y].f.severity);
    });
    a.view_dirty = false;
}

// ---- small widgets ---------------------------------------------------------
void text_colored(ImU32 col, const std::string& t) {
    ImGui::PushStyleColor(ImGuiCol_Text, col);
    ImGui::TextUnformatted(t.c_str(), t.c_str() + t.size());
    ImGui::PopStyleColor();
}

bool accent_button(const char* label, ImVec2 size) {
    ImGui::PushStyleColor(ImGuiCol_Button, kAccent);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kAccentHover);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, kAccentDown);
    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 255, 255, 255));
    bool hit = ImGui::Button(label, size);
    ImGui::PopStyleColor(4);
    return hit;
}

bool chip(const char* label, bool on) {
    if (on) {
        ImGui::PushStyleColor(ImGuiCol_Button, kAccent);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kAccentHover);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, kAccentDown);
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 255, 255, 255));
    } else {
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0xb9, 0xbc, 0xc4, 255));
    }
    bool hit = ImGui::Button(label, ImVec2(0, S(34)));
    ImGui::PopStyleColor(on ? 4 : 1);
    return hit;
}

// On/off switch with a label, as tall as `height` so it lines up with buttons.
bool toggle(const char* label, bool* value, float height) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImVec2 ts = ImGui::CalcTextSize(label);
    float tw = S(40), th = S(22);
    bool hit = ImGui::InvisibleButton(label, ImVec2(tw + S(10) + ts.x, height));
    if (hit) *value = !*value;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float cy = p.y + height * 0.5f;
    float alpha = ImGui::GetStyle().Alpha;
    auto fade = [alpha](ImU32 c) { return ImGui::GetColorU32(c, alpha); };
    dl->AddRectFilled(ImVec2(p.x, cy - th * 0.5f), ImVec2(p.x + tw, cy + th * 0.5f),
                      fade(*value ? kAccent : kTrack), th * 0.5f);
    float kx = *value ? p.x + tw - th * 0.5f : p.x + th * 0.5f;
    dl->AddCircleFilled(ImVec2(kx, cy), th * 0.5f - S(3), fade(IM_COL32(255, 255, 255, 255)));
    dl->AddText(ImVec2(p.x + tw + S(10), cy - ts.y * 0.5f), fade(kText), label);
    return hit;
}

std::string plural(size_t n, const char* one, const char* many) {
    return strf("%zu %s", n, n == 1 ? one : many);
}

// ---- sidebar ---------------------------------------------------------------
void category(App& a, const char* label, Severity sev) {
    bool on = a.sev_filter == static_cast<int>(sev);
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x, h = S(44);
    ImGui::PushID(label);
    if (ImGui::InvisibleButton("cat", ImVec2(w, h))) {
        a.sev_filter = on ? -1 : static_cast<int>(sev);
        a.view_dirty = true;
    }
    bool hovered = ImGui::IsItemHovered();
    ImGui::PopID();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    if (on || hovered)
        dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), on ? kSelected : kCardHover, S(8));
    float cy = p.y + h * 0.5f;
    float th = ImGui::GetFontSize();
    dl->AddCircleFilled(ImVec2(p.x + S(16), cy), S(4.5f), sev_color(sev));
    dl->AddText(ImVec2(p.x + S(30), cy - th * 0.5f), on ? IM_COL32(255, 255, 255, 255) : IM_COL32(0xb9, 0xbc, 0xc4, 255), label);
    std::string n = strf("%zu", count_sev(a, sev));
    float nw = ImGui::CalcTextSize(n.c_str()).x;
    dl->AddText(ImVec2(p.x + w - S(14) - nw, cy - th * 0.5f), on ? IM_COL32(255, 255, 255, 255) : kTextDim, n.c_str());
}

void draw_sidebar(App& a) {
    ImGui::PushFont(a.fonts.bold, 28.0f);
    ImGui::TextUnformatted("Vestige");
    ImGui::PopFont();
    text_colored(kTextFaint, "Read-only screenshare scanner");
    ImGui::Dummy(ImVec2(0, S(12)));

    ImGui::PushStyleColor(ImGuiCol_ChildBg, kCard);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, S(10));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(S(8), S(8)));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, S(2)));
    ImGui::BeginChild("cats", ImVec2(0, 0), ImGuiChildFlags_AutoResizeY | ImGuiChildFlags_AlwaysUseWindowPadding);
    category(a, "Detections", Severity::Detection);
    category(a, "Warnings", Severity::Warning);
    category(a, "Integrity Logs", Severity::Integrity);
    ImGui::EndChild();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor();

    ImGui::Dummy(ImVec2(0, S(8)));
    ImGui::PushFont(nullptr, 13.0f);
    ImGui::PushTextWrapPos(0.0f);
    text_colored(kTextFaint, a.sev_filter < 0 ? "Showing every group. Click one to filter."
                                              : "Click the group again to show everything.");
    ImGui::PopTextWrapPos();
    ImGui::PopFont();
}

// ---- header bar ------------------------------------------------------------
void draw_header(App& a) {
    const float h = S(44);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, kCard);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, S(10));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(S(14), S(14)));
    ImGui::BeginChild("header", ImVec2(0, h + S(28)), ImGuiChildFlags_AlwaysUseWindowPadding,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(S(16), 0));

    // Scan
    ImGui::BeginDisabled(a.state == State::Scanning);
    ImGui::PushFont(a.fonts.bold, 17.0f);
    const char* label = a.state == State::Idle ? "Scan" : a.state == State::Scanning ? "Scanning..." : "Scan again";
    if (accent_button(label, ImVec2(S(150), h))) {
        if (a.state == State::Idle) {
            start_scan(a);
        } else {
            Settings next = a.settings;
            next.autoscan = true;
            if (relaunch(next)) request_close();
        }
    }
    ImGui::PopFont();
    if (a.state == State::Done)
        ImGui::SetItemTooltip("Restarts Vestige and scans again, so nothing from this scan is reused.");
    ImGui::EndDisabled();

    // Deep scan + signature file. Fixed once a scan has started.
    ImGui::BeginDisabled(a.state != State::Idle);
    ImGui::SameLine();
    toggle("Deep scan", &a.settings.deep, h);
    ImGui::SetItemTooltip("Slower, wider scans: whole game memory, whole USN journal, more folders.");

    ImGui::SameLine();
    float by = ImGui::GetCursorPosY();
    ImGui::SetCursorPosY(by + (h - S(34)) * 0.5f);
    std::string sig = a.settings.sig_path.empty() ? std::string("Signature file...")
                                                  : "Signatures: " + cut(base_name(a.settings.sig_path), 24);
    if (ImGui::Button(sig.c_str(), ImVec2(0, S(34)))) {
        std::string picked = pick_signature_file();
        if (!picked.empty()) a.settings.sig_path = picked;
    }
    ImGui::SetItemTooltip("%s", a.settings.sig_path.empty()
                                    ? "Add your own signature list on top of the built-in one (same as --sigs)."
                                    : a.settings.sig_path.c_str());
    if (!a.settings.sig_path.empty()) {
        ImGui::SameLine(0, S(6));
        ImGui::SetCursorPosY(by + (h - S(34)) * 0.5f);
        if (ImGui::Button("Clear", ImVec2(0, S(34)))) a.settings.sig_path.clear();
    }
    ImGui::EndDisabled();

    // Status, right aligned, two lines.
    std::string l1 = std::string("Admin: ") + (a.admin ? "yes" : "NO") + "    Boot: " + fmt_time(a.boot_time);
    std::string l2 = "Game started: " +
                     (a.state != State::Done ? std::string("shown after the scan")
                      : a.game_start > 0 ? fmt_time(a.game_start) : std::string("no running game found"));
    ImGui::PushFont(nullptr, 13.5f);
    float lh = ImGui::GetFontSize();
    float w1 = ImGui::CalcTextSize(l1.c_str()).x, w2 = ImGui::CalcTextSize(l2.c_str()).x;
    ImVec2 wp = ImGui::GetWindowPos();
    float right = wp.x + ImGui::GetWindowWidth() - S(16);
    float top = wp.y + S(14) + (h - lh * 2 - S(4)) * 0.5f;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddText(ImVec2(right - w1, top), a.admin ? kTextDim : kAmber, l1.c_str());
    dl->AddText(ImVec2(right - w2, top + lh + S(4)), kTextDim, l2.c_str());
    ImGui::PopFont();

    ImGui::PopStyleVar();
    ImGui::EndChild();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor();
}

// ---- progress / summary strip ----------------------------------------------
void draw_status(App& a) {
    const float h = S(34);
    ImVec2 start = ImGui::GetCursorPos();
    float text_y = start.y + (h - ImGui::GetFontSize()) * 0.5f;

    if (a.state == State::Idle) {
        ImGui::SetCursorPosY(text_y);
        if (a.admin)
            text_colored(kTextDim, "Have the player open the game they were playing on, then press Scan.");
        else
            text_colored(kAmber, "Not running as administrator. Many checks will be skipped or incomplete.");
    } else if (a.state == State::Scanning) {
        std::string overlay;
        float frac = 0;
        if (a.total == 0) {
            overlay = "starting...";
        } else if (a.check_running) {
            overlay = strf("check %zu of %zu: %s", a.index, a.total, a.check.c_str());
            frac = static_cast<float>(a.index - 1) / static_cast<float>(a.total);
        } else if (a.index >= a.total) {
            overlay = "saving the report...";
            frac = 1.0f;
        } else {
            overlay = strf("check %zu of %zu", a.index + 1, a.total);
            frac = static_cast<float>(a.index) / static_cast<float>(a.total);
        }
        // Bar with the label centered on it.
        ImVec2 p = ImGui::GetCursorScreenPos();
        float w = ImGui::GetContentRegionAvail().x;
        ImDrawList* dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), kChip, S(8));
        if (frac > 0) {
            dl->PushClipRect(p, ImVec2(p.x + w * frac, p.y + h), true);
            dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), kAccent, S(8));
            dl->PopClipRect();
        }
        ImVec2 ts = ImGui::CalcTextSize(overlay.c_str());
        dl->AddText(ImVec2(p.x + (w - ts.x) * 0.5f, p.y + (h - ts.y) * 0.5f), IM_COL32(255, 255, 255, 255), overlay.c_str());
        ImGui::Dummy(ImVec2(w, h));
    } else {
        ImGui::SetCursorPosY(text_y);
        size_t d = count_sev(a, Severity::Detection), w = count_sev(a, Severity::Warning),
               i = count_sev(a, Severity::Integrity);
        text_colored(d ? kRed : kTextDim, plural(d, "detection", "detections"));
        ImGui::SameLine(0, 0);
        text_colored(kTextDim, ",  ");
        ImGui::SameLine(0, 0);
        text_colored(w ? kAmber : kTextDim, plural(w, "warning", "warnings"));
        ImGui::SameLine(0, 0);
        text_colored(kTextDim, strf(",  %zu integrity,  %.1f s", i, a.seconds));
        if (!a.saved_html || !a.saved_json) {
            ImGui::SameLine(0, S(14));
            text_colored(kAmber, "Could not save the report files.");
        }

        const char* b1 = "Open HTML report";
        const char* b2 = "Open report folder";
        const ImGuiStyle& st = ImGui::GetStyle();
        float bw1 = ImGui::CalcTextSize(b1).x + st.FramePadding.x * 2;
        float bw2 = ImGui::CalcTextSize(b2).x + st.FramePadding.x * 2;
        std::string dir = default_report_dir();
        ImGui::SetCursorPos(ImVec2(start.x + ImGui::GetContentRegionAvail().x - bw1 - bw2 - S(8), start.y));
        ImGui::BeginDisabled(!a.saved_html);
        if (ImGui::Button(b1, ImVec2(bw1, h))) open_in_shell(dir + "\\report.html");
        ImGui::EndDisabled();
        ImGui::SameLine(0, S(8));
        if (ImGui::Button(b2, ImVec2(bw2, h))) open_in_shell(dir);
        ImGui::SetItemTooltip("%s", dir.c_str());
    }
    ImGui::SetCursorPos(ImVec2(start.x, start.y + h));
    ImGui::Dummy(ImVec2(0, 0));
}

// ---- filter chips + search -------------------------------------------------
void draw_filters(App& a) {
    struct Chip { const char* label; Scope scope; };
    const Chip chips[] = {{"All", Scope::Default}, {"In game", Scope::InGame}, {"Boot", Scope::Boot},
                          {"Out of instance", Scope::OutOfInstance}};
    float right = ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x;
    for (const Chip& c : chips) {
        if (chip(c.label, a.scope_filter == c.scope)) {
            a.scope_filter = c.scope;
            a.view_dirty = true;
        }
        ImGui::SameLine(0, S(8));
    }
    float sw = S(320);
    ImGui::SetCursorPosX(std::max(ImGui::GetCursorPosX(), right - sw));
    ImGui::SetNextItemWidth(right - ImGui::GetCursorPosX());
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(S(12), (S(34) - ImGui::GetFontSize()) * 0.5f));
    if (ImGui::InputTextWithHint("##search", "Search title, detail, evidence, check", a.search, sizeof a.search))
        a.view_dirty = true;
    ImGui::PopStyleVar();
}

// ---- findings list ---------------------------------------------------------
void draw_row(App& a, size_t idx) {
    const Finding& f = a.rows[idx].f;
    bool open = a.expanded.count(idx) != 0;
    const float h = S(46), gap = S(6);
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x;

    // Closed rows that are scrolled out of view only take up space.
    if (!open && !ImGui::IsRectVisible(p, ImVec2(p.x + w, p.y + h))) {
        ImGui::Dummy(ImVec2(w, h + gap));
        return;
    }

    ImGui::PushID(static_cast<int>(idx));
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->ChannelsSplit(2);
    dl->ChannelsSetCurrent(1);

    if (ImGui::InvisibleButton("row", ImVec2(w, h))) {
        if (open) a.expanded.erase(idx); else a.expanded.insert(idx);
    }
    bool hovered = ImGui::IsItemHovered();
    if (hovered) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);

    float cy = p.y + h * 0.5f;
    dl->AddCircleFilled(ImVec2(p.x + S(20), cy), S(5), sev_color(f.severity));

    // Right side: check name, and the scope tag left of it.
    float fs = ImGui::GetFontSize();
    ImFont* font = ImGui::GetFont();
    float small = fs * (13.0f / 15.0f);
    float x = p.x + w - S(16);
    float mw = font->CalcTextSizeA(small, FLT_MAX, 0, f.module.c_str()).x;
    x -= mw;
    dl->AddText(font, small, ImVec2(x, cy - small * 0.5f), kTextFaint, f.module.c_str());
    const char* sc = scope_name(f.scope);
    if (*sc) {
        float tw = font->CalcTextSizeA(small, FLT_MAX, 0, sc).x;
        float pad = S(9), th = small + S(8);
        x -= S(12) + tw + pad * 2;
        dl->AddRectFilled(ImVec2(x, cy - th * 0.5f), ImVec2(x + tw + pad * 2, cy + th * 0.5f), tag_bg(f.severity), S(6));
        dl->AddText(font, small, ImVec2(x + pad, cy - small * 0.5f), tag_fg(f.severity), sc);
    }

    // Title, cut off where the right side starts.
    ImFont* bold = a.fonts.bold ? a.fonts.bold : font;
    ImVec4 clip(p.x + S(38), p.y, x - S(14), p.y + h);
    dl->AddText(bold, fs, ImVec2(p.x + S(38), cy - fs * 0.5f), kText, f.title.c_str(), nullptr, 0.0f, &clip);

    float bottom = p.y + h;
    if (open) {
        float bw = w - S(38) - S(16);
        ImGui::SetCursorScreenPos(ImVec2(p.x + S(38), p.y + h - S(4)));
        ImGui::BeginGroup();
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + bw);
        if (!f.detail.empty()) text_colored(kTextBody, f.detail);
        if (!f.evidence.empty()) {
            ImGui::Dummy(ImVec2(0, S(12)));
            text_colored(kTextFaint, "Evidence");
            ImGui::SameLine(0, S(10));
            bool copied = a.copied_row == idx && ImGui::GetTime() - a.copied_at < 1.5;
            ImGui::PushFont(nullptr, 13.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(S(10), S(3)));
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() - S(3));
            if (ImGui::Button(copied ? "Copied" : "Copy")) {
                ImGui::SetClipboardText(f.evidence.c_str());
                a.copied_row = idx;
                a.copied_at = ImGui::GetTime();
            }
            ImGui::PopStyleVar();
            ImGui::PopFont();

            ImGui::Dummy(ImVec2(0, S(4)));
            ImGui::PushStyleColor(ImGuiCol_ChildBg, kBg);
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, S(6));
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(S(10), S(10)));
            ImGui::SetNextWindowSizeConstraints(ImVec2(bw, 0), ImVec2(bw, S(300)));
            ImGui::BeginChild("evidence", ImVec2(bw, 0),
                              ImGuiChildFlags_AutoResizeY | ImGuiChildFlags_AlwaysUseWindowPadding);
            ImGui::PushFont(a.fonts.mono, 13.5f);
            ImGui::PushTextWrapPos(0.0f);
            text_colored(kTextBody, f.evidence);
            ImGui::PopTextWrapPos();
            ImGui::PopFont();
            ImGui::EndChild();
            ImGui::PopStyleVar(2);
            ImGui::PopStyleColor();
        }
        ImGui::PopTextWrapPos();
        ImGui::EndGroup();
        bottom = ImGui::GetItemRectMax().y + S(14);
    }

    dl->ChannelsSetCurrent(0);
    dl->AddRectFilled(p, ImVec2(p.x + w, bottom), hovered ? kCardHover : kCard, S(8));
    dl->ChannelsMerge();

    ImGui::SetCursorScreenPos(ImVec2(p.x, bottom));
    ImGui::Dummy(ImVec2(w, gap));
    ImGui::PopID();
}

void draw_list(App& a, float height) {
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
    ImGui::BeginChild("list", ImVec2(0, height));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(S(8), S(6)));
    if (a.view.empty()) {
        ImGui::Dummy(ImVec2(0, S(28)));
        const char* msg = a.rows.empty()
                              ? (a.state == State::Idle ? "Nothing scanned yet."
                                 : a.state == State::Scanning ? "Findings show up here as each check finishes."
                                 : "The scan produced no findings.")
                              : "No findings match the filters.";
        float tw = ImGui::CalcTextSize(msg).x;
        ImGui::SetCursorPosX((ImGui::GetContentRegionAvail().x - tw) * 0.5f);
        text_colored(kTextFaint, msg);
    }
    ImGui::PopStyleVar();
    // Row spacing is handled by draw_row so skipped rows keep an exact height.
    for (size_t idx : a.view) draw_row(a, idx);
    ImGui::EndChild();
    ImGui::PopStyleVar();
}

// ---- notes -----------------------------------------------------------------
float notes_height(const App& a) {
    if (a.notes.empty()) return 0;
    return S(8) + S(34) + (a.notes_open ? S(6) + S(150) : 0);
}

// Caller has set the vertical item spacing to zero, so the heights here add
// up to exactly notes_height().
void draw_notes(App& a) {
    if (a.notes.empty()) return;
    ImGui::Dummy(ImVec2(0, S(8)));
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x, h = S(34);
    if (ImGui::InvisibleButton("notes", ImVec2(w, h))) a.notes_open = !a.notes_open;
    bool hovered = ImGui::IsItemHovered();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), hovered ? kCardHover : kCard, S(8));
    float cx = p.x + S(18), cy = p.y + h * 0.5f, r = S(4.5f);
    if (a.notes_open)
        dl->AddTriangleFilled(ImVec2(cx - r, cy - r * 0.6f), ImVec2(cx + r, cy - r * 0.6f), ImVec2(cx, cy + r * 0.8f), kTextDim);
    else
        dl->AddTriangleFilled(ImVec2(cx - r * 0.6f, cy - r), ImVec2(cx - r * 0.6f, cy + r), ImVec2(cx + r * 0.8f, cy), kTextDim);
    std::string label = strf("Notes (%zu)", a.notes.size());
    float fs = ImGui::GetFontSize();
    dl->AddText(ImVec2(p.x + S(34), cy - fs * 0.5f), kText, label.c_str());
    float lw = ImGui::CalcTextSize(label.c_str()).x;
    dl->AddText(ImVec2(p.x + S(34) + lw + S(12), cy - fs * 0.5f), kTextFaint, "checks that were skipped or limited");

    if (!a.notes_open) return;
    ImGui::Dummy(ImVec2(0, S(6)));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, kCard);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, S(8));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(S(14), S(10)));
    ImGui::BeginChild("notes_body", ImVec2(0, S(150)), ImGuiChildFlags_AlwaysUseWindowPadding);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, S(5)));
    ImGui::PushFont(nullptr, 13.5f);
    ImGui::PushTextWrapPos(0.0f);
    for (const std::string& n : a.notes) text_colored(kTextBody, "-  " + n);
    ImGui::PopTextWrapPos();
    ImGui::PopFont();
    ImGui::PopStyleVar();
    ImGui::EndChild();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor();
}

void draw_main(App& a) {
    draw_header(a);
    ImGui::Dummy(ImVec2(0, S(2)));
    draw_status(a);
    ImGui::Dummy(ImVec2(0, S(2)));
    draw_filters(a);
    ImGui::Dummy(ImVec2(0, S(2)));

    if (a.view_dirty) rebuild_view(a);
    const float footer = S(28);
    float list_h = ImGui::GetContentRegionAvail().y - footer - notes_height(a);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
    draw_list(a, std::max(list_h, S(80)));
    draw_notes(a);
    ImGui::PopStyleVar();

    ImGui::SetCursorPosY(ImGui::GetWindowHeight() - ImGui::GetFontSize() * (13.0f / 15.0f) - S(2));
    ImGui::PushFont(nullptr, 13.0f);
    text_colored(kTextFaint, "Findings are leads. Confirm by hand before any ban.");
    ImGui::PopFont();
}

}  // namespace

// ---- entry points ----------------------------------------------------------
void ui_init(const Settings& s) {
    g_app = new App();
    g_app->settings = s;
    g_app->settings.autoscan = false;
    g_app->admin = platform_is_admin();
    g_app->boot_time = platform_boot_time();
    if (s.autoscan) start_scan(*g_app);
}

Settings ui_settings() { return g_app ? g_app->settings : Settings(); }

void ui_apply_style(float scale) {
    ImGuiStyle& st = ImGui::GetStyle();
    st = ImGuiStyle();
    ImGui::StyleColorsDark(&st);
    st.FontSizeBase = 15.0f;
    st.FontScaleDpi = scale;
    st.WindowPadding = ImVec2(20 * scale, 18 * scale);
    st.WindowRounding = 0;
    st.WindowBorderSize = 0;
    st.ChildBorderSize = 0;
    st.PopupBorderSize = 0;
    st.PopupRounding = 6 * scale;
    st.FrameBorderSize = 0;
    st.FrameRounding = 8 * scale;
    st.FramePadding = ImVec2(14 * scale, 8 * scale);
    st.ItemSpacing = ImVec2(8 * scale, 8 * scale);
    st.ScrollbarSize = 12 * scale;
    st.ScrollbarRounding = 6 * scale;
    st.GrabRounding = 6 * scale;
    st.DisabledAlpha = 0.5f;

    ImVec4* c = st.Colors;
    c[ImGuiCol_WindowBg] = v4(kBg);
    c[ImGuiCol_ChildBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_PopupBg] = v4(IM_COL32(0x1f, 0x22, 0x2a, 255));
    c[ImGuiCol_Text] = v4(kText);
    c[ImGuiCol_TextDisabled] = v4(kTextFaint);
    c[ImGuiCol_Border] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_FrameBg] = v4(kChip);
    c[ImGuiCol_FrameBgHovered] = v4(kChipHover);
    c[ImGuiCol_FrameBgActive] = v4(kChipHover);
    c[ImGuiCol_Button] = v4(kChip);
    c[ImGuiCol_ButtonHovered] = v4(kChipHover);
    c[ImGuiCol_ButtonActive] = v4(kTrack);
    c[ImGuiCol_ScrollbarBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ScrollbarGrab] = v4(kTrack);
    c[ImGuiCol_ScrollbarGrabHovered] = v4(IM_COL32(0x3a, 0x3f, 0x4c, 255));
    c[ImGuiCol_ScrollbarGrabActive] = v4(IM_COL32(0x4a, 0x50, 0x60, 255));
    c[ImGuiCol_TextSelectedBg] = v4(IM_COL32(0x3d, 0x5a, 0xfe, 110));
    c[ImGuiCol_NavCursor] = v4(kAccentHover);
}

void ui_frame(const Fonts& fonts, float scale) {
    App& a = *g_app;
    a.fonts = fonts;
    a.s = scale;
    sync(a);

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("##root", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
                     ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::BeginChild("side", ImVec2(S(240), 0), 0, ImGuiWindowFlags_NoScrollbar);
    draw_sidebar(a);
    ImGui::EndChild();
    ImGui::SameLine(0, S(20));
    ImGui::BeginChild("main", ImVec2(0, 0), 0, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    draw_main(a);
    ImGui::EndChild();
    ImGui::End();
}

void ui_shutdown() {
    App& a = *g_app;
    if (!a.worker.joinable()) return;
    {
        // A check can't be interrupted. Checks only read, so if the window is
        // closed mid-scan the process just ends. The one thing worth waiting
        // for is a report file that is being written right now.
        std::lock_guard<std::mutex> lock(a.sh.mu);
        if (!a.sh.saving && !a.sh.finished) TerminateProcess(GetCurrentProcess(), 0);
    }
    a.worker.join();
}

}  // namespace gui
}  // namespace scan
#endif

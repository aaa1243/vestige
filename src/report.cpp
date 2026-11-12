#include <algorithm>
#include <cstdio>

#include "core.hpp"
#include "util.hpp"

#ifdef _WIN32
#include <io.h>
#define ISATTY _isatty
#define FILENO _fileno
#else
#include <unistd.h>
#define ISATTY isatty
#define FILENO fileno
#endif

namespace scan {

static size_t count_sev(const Context& ctx, Severity s) {
    return static_cast<size_t>(std::count_if(ctx.findings.begin(), ctx.findings.end(),
                                             [s](const Finding& f) { return f.severity == s; }));
}

void print_console(const Context& ctx, double seconds) {
    bool color = ISATTY(FILENO(stdout)) != 0;
    auto col = [color](Severity s) -> const char* {
        if (!color) return "";
        return s == Severity::Detection ? "\033[91m" : s == Severity::Warning ? "\033[93m" : "\033[90m";
    };
    const char* reset = color ? "\033[0m" : "";

    printf("============================================================\n");
    printf("  Forensic Scanner\n");
    printf("============================================================\n");
    printf("  System: %s   admin/root: %s   boot: %s\n", ctx.os.c_str(), ctx.admin ? "yes" : "NO",
           fmt_time(ctx.boot_time).c_str());
    if (!ctx.admin)
        printf("  [!] Not elevated. Many checks need admin/root and were skipped\n"
               "      or are incomplete. Run it again elevated.\n");
    printf("\n");

    const Severity order[] = {Severity::Detection, Severity::Warning, Severity::Integrity};
    for (Severity sev : order) {
        size_t n = count_sev(ctx, sev);
        if (!n) continue;
        printf("%s----- %s (%zu) -----%s\n", col(sev), severity_name(sev), n, reset);
        for (const Finding& f : ctx.findings) {
            if (f.severity != sev) continue;
            const char* sc = scope_name(f.scope);
            printf("%s[%s]%s%s%s %s: %s%s\n", col(sev), severity_name(sev), *sc ? " [" : "", sc,
                   *sc ? "]" : "", f.module.c_str(), f.title.c_str(), reset);
            if (!f.detail.empty()) printf("        %s\n", f.detail.c_str());
            if (!f.evidence.empty()) printf("        evidence: %s\n", cut(f.evidence, 600).c_str());
        }
        printf("\n");
    }
    printf("------------------------------------------------------------\n");
    printf("  %zu detection, %zu warning, %zu integrity in %.1fs\n", count_sev(ctx, Severity::Detection),
           count_sev(ctx, Severity::Warning), count_sev(ctx, Severity::Integrity), seconds);
    if (!ctx.notes.empty()) {
        printf("\n  Notes (checks that were skipped or limited):\n");
        for (const std::string& n : ctx.notes) printf("   - %s\n", cut(n, 300).c_str());
    }
    printf("\n  Findings are leads. Confirm by hand before any ban.\n");
    fflush(stdout);
}

std::string to_json(const Context& ctx, double started) {
    std::string o = "{\n";
    o += strf("  \"os\": \"%s\",\n  \"admin\": %s,\n  \"scanned_at\": %.0f,\n  \"boot_time\": %.0f,\n",
              json_escape(ctx.os).c_str(), ctx.admin ? "true" : "false", started, ctx.boot_time);
    o += "  \"notes\": [";
    for (size_t i = 0; i < ctx.notes.size(); ++i)
        o += std::string(i ? ", " : "") + "\"" + json_escape(ctx.notes[i]) + "\"";
    o += "],\n  \"findings\": [\n";
    for (size_t i = 0; i < ctx.findings.size(); ++i) {
        const Finding& f = ctx.findings[i];
        o += strf("    {\"module\": \"%s\", \"severity\": \"%s\", \"scope\": \"%s\", \"title\": \"%s\", "
                  "\"detail\": \"%s\", \"evidence\": \"%s\"}%s\n",
                  json_escape(f.module).c_str(), severity_name(f.severity), scope_name(f.scope),
                  json_escape(f.title).c_str(), json_escape(f.detail).c_str(),
                  json_escape(f.evidence).c_str(), i + 1 < ctx.findings.size() ? "," : "");
    }
    o += "  ]\n}\n";
    return o;
}

std::string to_html(const Context& ctx, double started) {
    std::string rows;
    for (const Finding& f : ctx.findings) {
        const char* sev = f.severity == Severity::Detection ? "det" : f.severity == Severity::Warning ? "warn" : "integ";
        const char* sc = scope_name(f.scope);
        rows += strf("<details class=\"row %s\" data-sev=\"%s\" data-scope=\"%s\"><summary>"
                     "<span class=\"dot\"></span><span class=\"t\">%s</span>"
                     "<span class=\"e\">%s</span>%s</summary><div class=\"body\"><p>%s</p>%s"
                     "<p class=\"m\">check: %s</p></div></details>\n",
                     sev, sev, html_escape(sc).c_str(), html_escape(f.title).c_str(),
                     html_escape(cut(f.evidence, 90)).c_str(),
                     *sc ? strf("<span class=\"tag\">%s</span>", html_escape(sc).c_str()).c_str() : "",
                     html_escape(f.detail).c_str(),
                     f.evidence.empty() ? "" : strf("<pre>%s</pre>", html_escape(f.evidence).c_str()).c_str(),
                     html_escape(f.module).c_str());
    }
    std::string notes;
    for (const std::string& n : ctx.notes) notes += "<li>" + html_escape(n) + "</li>";

    std::string h = R"HTML(<!DOCTYPE html><html><head><meta charset="utf-8"><title>Forensic Scanner report</title>
<style>
body{margin:0;background:#0b0c0f;color:#e6e7ea;font:15px/1.45 system-ui,Segoe UI,sans-serif}
.wrap{display:flex;gap:28px;max-width:1280px;margin:0 auto;padding:28px}
.side{width:270px;flex:none}.main{flex:1;min-width:0}
.card{background:#14161b;border-radius:10px;padding:14px}
.cat{display:flex;justify-content:space-between;padding:12px 14px;border-radius:8px;cursor:pointer;color:#b9bcc4}
.cat.on{background:#1f2a52;color:#fff}.cat:hover{background:#1a1d24}
h1{font-size:26px;margin:0 0 4px}.sub{color:#8b8f99;margin:0 0 18px}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.chip{background:#1a1d24;border:0;color:#b9bcc4;padding:8px 14px;border-radius:8px;cursor:pointer;font:inherit}
.chip.on{background:#3d5afe;color:#fff}
.row{background:#14161b;border-radius:8px;margin-bottom:6px}
.row summary{display:flex;align-items:center;gap:14px;padding:14px 16px;cursor:pointer;list-style:none}
.row summary::-webkit-details-marker{display:none}
.dot{width:10px;height:10px;border-radius:50%;flex:none}
.det .dot{background:#ef5350}.warn .dot{background:#ffb300}.integ .dot{background:#66bb6a}
.t{font-weight:600;flex:0 0 34%}.e{flex:1;color:#9aa0aa;font-family:Consolas,monospace;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tag{background:#3a1f22;color:#ff8a80;padding:4px 10px;border-radius:6px;font-size:13px;white-space:nowrap}
.warn .tag{background:#3a3117;color:#ffd54f}.integ .tag{background:#1b2a1e;color:#a5d6a7}
.body{padding:0 16px 14px 40px;color:#c9ccd3}.body pre{background:#0b0c0f;padding:10px;border-radius:6px;white-space:pre-wrap;word-break:break-all;font-size:13px}
.m{color:#6f7480;font-size:13px;margin:6px 0 0}.meta{color:#8b8f99;font-size:13px;margin-top:14px}
.hide{display:none}ul{color:#9aa0aa;font-size:13px;padding-left:18px}
</style></head><body><div class="wrap"><div class="side"><div class="card">
)HTML";
    h += strf("<div class=\"cat on\" data-sev=\"det\"><span>Detections</span><span>%zu</span></div>"
              "<div class=\"cat\" data-sev=\"warn\"><span>Warnings</span><span>%zu</span></div>"
              "<div class=\"cat\" data-sev=\"integ\"><span>Integrity logs</span><span>%zu</span></div>",
              count_sev(ctx, Severity::Detection), count_sev(ctx, Severity::Warning),
              count_sev(ctx, Severity::Integrity));
    h += strf("</div><div class=\"meta\">System: %s<br>Admin: %s<br>Scanned: %s<br>Booted: %s</div>",
              html_escape(ctx.os).c_str(), ctx.admin ? "yes" : "no", fmt_time(started).c_str(),
              fmt_time(ctx.boot_time).c_str());
    if (!notes.empty()) h += "<div class=\"meta\">Skipped or limited checks:<ul>" + notes + "</ul></div>";
    h += R"HTML(</div><div class="main"><h1 id="ttl">Detections</h1>
<p class="sub">Findings are leads. Confirm by hand before any ban.</p>
<div class="chips"><button class="chip on" data-scope="*">All</button><button class="chip" data-scope="In game">In game</button><button class="chip" data-scope="Boot">Boot</button><button class="chip" data-scope="Out of instance">Out of instance</button></div>
<div id="rows">
)HTML";
    h += rows;
    h += R"HTML(</div></div></div><script>
var sev='det',scope='*',names={det:'Detections',warn:'Warnings',integ:'Integrity logs'};
function draw(){document.querySelectorAll('.row').forEach(function(r){
var ok=r.dataset.sev==sev&&(scope=='*'||r.dataset.scope==scope);r.classList.toggle('hide',!ok);});
document.getElementById('ttl').textContent=names[sev];}
document.querySelectorAll('.cat').forEach(function(c){c.onclick=function(){
document.querySelectorAll('.cat').forEach(function(x){x.classList.remove('on')});c.classList.add('on');sev=c.dataset.sev;draw();}});
document.querySelectorAll('.chip').forEach(function(c){c.onclick=function(){
document.querySelectorAll('.chip').forEach(function(x){x.classList.remove('on')});c.classList.add('on');scope=c.dataset.scope;draw();}});
draw();
</script></body></html>
)HTML";
    return h;
}

}  // namespace scan

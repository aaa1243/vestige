#include "util.hpp"

#include <algorithm>
#include <chrono>
#include <cstdarg>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace scan {

namespace fs = std::filesystem;

// All paths in this program are UTF-8. On Windows the narrow file APIs use
// the ANSI code page, so always go through a filesystem::path.
static fs::path P(const std::string& utf8) {
#ifdef _WIN32
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n > 0 ? n : 0), L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), &w[0], n);
    return fs::path(w);
#else
    return fs::path(utf8);
#endif
}

static std::string U(const fs::path& p) {
#ifdef _WIN32
    const std::wstring& w = p.native();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n > 0 ? n : 0), '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), &s[0], n, nullptr, nullptr);
    return s;
#else
    return p.string();
#endif
}

static bool cloud_placeholder(const fs::path& p) {
#ifdef _WIN32
    DWORD a = GetFileAttributesW(p.c_str());
    if (a == INVALID_FILE_ATTRIBUTES) return true;
    // OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS: reading would download it
    return (a & (0x1000 | 0x40000 | 0x400000)) != 0;
#else
    (void)p;
    return false;
#endif
}

bool is_dir(const std::string& path) {
    std::error_code ec;
    return fs::is_directory(P(path), ec);
}

double file_mtime(const std::string& path) {
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (!GetFileAttributesExW(P(path).c_str(), GetFileExInfoStandard, &d)) return 0;
    uint64_t ft = (uint64_t(d.ftLastWriteTime.dwHighDateTime) << 32) | d.ftLastWriteTime.dwLowDateTime;
    return static_cast<double>(ft) / 1e7 - 11644473600.0;
#else
    std::error_code ec;
    auto t = fs::last_write_time(P(path), ec);
    if (ec) return 0;
    auto sys = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        t - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
    return static_cast<double>(std::chrono::system_clock::to_time_t(sys));
#endif
}

std::vector<std::string> list_dir(const std::string& dir) {
    std::vector<std::string> out;
    std::error_code ec;
    fs::directory_iterator it(P(dir), fs::directory_options::skip_permission_denied, ec), end;
    for (; !ec && it != end; it.increment(ec)) out.push_back(U(it->path().filename()));
    return out;
}

static bool walk_impl(const fs::path& dir, int depth,
                      const std::function<bool(const std::string&, uint64_t)>& fn) {
    std::error_code ec;
    fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end;
    for (; !ec && it != end; it.increment(ec)) {
        std::error_code e2;
        fs::file_status st = it->symlink_status(e2);
        if (e2 || fs::is_symlink(st)) continue;
        if (fs::is_directory(st)) {
            if (depth > 0 && !walk_impl(it->path(), depth - 1, fn)) return false;
        } else if (fs::is_regular_file(st)) {
            if (cloud_placeholder(it->path())) continue;
            uint64_t size = it->file_size(e2);
            if (e2) continue;
            if (!fn(U(it->path()), size)) return false;
        }
    }
    return true;
}

void walk_files(const std::string& root, int max_depth,
                const std::function<bool(const std::string&, uint64_t)>& fn) {
    if (is_dir(root)) walk_impl(P(root), max_depth, fn);
}

std::vector<std::string> user_homes() {
    std::vector<std::string> out;
#if defined(_WIN32)
    wchar_t buf[MAX_PATH];
    std::string users = "C:\\Users";
    if (GetEnvironmentVariableW(L"SystemDrive", buf, MAX_PATH)) users = U(fs::path(buf)) + "\\Users";
    for (const std::string& n : list_dir(users)) {
        std::string l = lower(n);
        if (l == "public" || l == "default" || l == "default user" || l == "all users" ||
            l == "desktop.ini" || starts_with(l, "defaultapppool"))
            continue;
        if (is_dir(users + "\\" + n)) out.push_back(users + "\\" + n);
    }
#else
#if defined(__APPLE__)
    const char* base = "/Users";
#else
    const char* base = "/home";
#endif
    for (const std::string& n : list_dir(base)) {
        if (n == "Shared" || n.empty() || n[0] == '.') continue;
        std::string h = std::string(base) + "/" + n;
        if (is_dir(h)) out.push_back(h);
    }
    const char* home = getenv("HOME");
    if (home && *home && std::find(out.begin(), out.end(), std::string(home)) == out.end() && is_dir(home))
        out.push_back(home);
#endif
    return out;
}

void make_dirs(const std::string& dir) {
    std::error_code ec;
    fs::create_directories(P(dir), ec);
}

bool write_file(const std::string& path, const std::string& data) {
    std::ofstream f(P(path), std::ios::binary);
    if (!f) return false;
    f.write(data.data(), static_cast<std::streamsize>(data.size()));
    return f.good();
}

std::string strf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(nullptr, 0, fmt, ap);
    va_end(ap);
    std::string out;
    if (n > 0) {
        out.resize(static_cast<size_t>(n) + 1);
        vsnprintf(&out[0], out.size(), fmt, ap2);
        out.resize(static_cast<size_t>(n));
    }
    va_end(ap2);
    return out;
}

void lower_inplace(std::string& s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
}

std::string lower(std::string s) {
    lower_inplace(s);
    return s;
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n' || s[a] == '\0')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n' ||
                     s[b - 1] == '\0'))
        --b;
    return s.substr(a, b - a);
}

bool starts_with(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}
bool ends_with(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0;
}
bool contains(const std::string& s, const std::string& sub) {
    return s.find(sub) != std::string::npos;
}

std::string base_name(const std::string& path) {
    size_t p = path.find_last_of("/\\");
    return p == std::string::npos ? path : path.substr(p + 1);
}
std::string dir_name(const std::string& path) {
    size_t p = path.find_last_of("/\\");
    return p == std::string::npos ? std::string() : path.substr(0, p);
}
std::string ext_of(const std::string& path) {
    std::string b = base_name(path);
    size_t p = b.find_last_of('.');
    return p == std::string::npos ? std::string() : lower(b.substr(p));
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    size_t a = 0;
    while (true) {
        size_t b = s.find(sep, a);
        if (b == std::string::npos) {
            out.push_back(s.substr(a));
            break;
        }
        out.push_back(s.substr(a, b - a));
        a = b + 1;
    }
    return out;
}

std::string cut(const std::string& s, size_t max) {
    return s.size() <= max ? s : s.substr(0, max) + " ...";
}

double now_epoch() {
    using namespace std::chrono;
    return duration<double>(system_clock::now().time_since_epoch()).count();
}

std::string fmt_time(double epoch) {
    if (epoch <= 0) return "unknown";
    time_t t = static_cast<time_t>(epoch);
    struct tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char buf[32];
    strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", &tmv);
    return buf;
}

bool file_exists(const std::string& path) {
    std::error_code ec;
    return fs::exists(P(path), ec);
}

bool read_file(const std::string& path, std::string& out, size_t max_bytes) {
    std::ifstream f(P(path), std::ios::binary);
    if (!f) return false;
    out.clear();
    char buf[1 << 16];
    while (f && out.size() < max_bytes) {
        f.read(buf, static_cast<std::streamsize>(std::min(sizeof buf, max_bytes - out.size())));
        std::streamsize got = f.gcount();
        if (got <= 0) break;
        out.append(buf, static_cast<size_t>(got));
    }
    return true;
}

std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) o += strf("\\u%04x", c);
                else o += static_cast<char>(c);
        }
    }
    return o;
}

std::string html_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '&': o += "&amp;"; break;
            case '<': o += "&lt;"; break;
            case '>': o += "&gt;"; break;
            case '"': o += "&quot;"; break;
            default: o += c;
        }
    }
    return o;
}

std::string utf16le(const std::string& ascii) {
    std::string o;
    o.reserve(ascii.size() * 2);
    for (char c : ascii) {
        o += c;
        o += '\0';
    }
    return o;
}

static inline bool printable(unsigned char c) { return c >= 0x20 && c < 0x7f; }

void extract_strings(const char* data, size_t n, size_t min_len, std::vector<std::string>& out) {
    // ASCII
    size_t start = 0;
    bool in = false;
    for (size_t i = 0; i <= n; ++i) {
        bool p = i < n && printable(static_cast<unsigned char>(data[i]));
        if (p && !in) { start = i; in = true; }
        if (!p && in) {
            if (i - start >= min_len) out.emplace_back(data + start, i - start);
            in = false;
        }
    }
    // UTF-16LE, both alignments
    for (size_t off = 0; off < 2; ++off) {
        std::string cur;
        for (size_t i = off; i + 1 < n; i += 2) {
            unsigned char lo = static_cast<unsigned char>(data[i]);
            unsigned char hi = static_cast<unsigned char>(data[i + 1]);
            if (hi == 0 && printable(lo)) {
                cur += static_cast<char>(lo);
            } else {
                if (cur.size() >= min_len) out.push_back(cur);
                cur.clear();
            }
        }
        if (cur.size() >= min_len) out.push_back(cur);
    }
}

void MultiSearch::add(const std::string& needle, int id) {
    if (needle.empty()) return;
    first_[static_cast<unsigned char>(needle[0])].push_back(static_cast<uint32_t>(needles_.size()));
    needles_.push_back({needle, id});
}

void MultiSearch::search(const char* data, size_t n, std::vector<char>& found) const {
    for (size_t i = 0; i < n; ++i) {
        const std::vector<uint32_t>& b = first_[static_cast<unsigned char>(data[i])];
        if (b.empty()) continue;
        for (uint32_t idx : b) {
            const N& nd = needles_[idx];
            if (static_cast<size_t>(nd.id) < found.size() && found[static_cast<size_t>(nd.id)]) continue;
            if (nd.s.size() <= n - i && memcmp(data + i, nd.s.data(), nd.s.size()) == 0) {
                if (static_cast<size_t>(nd.id) >= found.size()) found.resize(static_cast<size_t>(nd.id) + 1, 0);
                found[static_cast<size_t>(nd.id)] = 1;
            }
        }
    }
}

// ---- SHA-256 (public domain style, small) ----
namespace {
struct Sha {
    uint32_t h[8];
    uint64_t len = 0;
    unsigned char buf[64];
    size_t fill = 0;
};
const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
void sha_block(Sha& s, const unsigned char* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (uint32_t(p[i * 4]) << 24) | (uint32_t(p[i * 4 + 1]) << 16) |
               (uint32_t(p[i * 4 + 2]) << 8) | uint32_t(p[i * 4 + 3]);
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = s.h[0], b = s.h[1], c = s.h[2], d = s.h[3], e = s.h[4], f = s.h[5], g = s.h[6],
             h = s.h[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s.h[0] += a; s.h[1] += b; s.h[2] += c; s.h[3] += d;
    s.h[4] += e; s.h[5] += f; s.h[6] += g; s.h[7] += h;
}
void sha_init(Sha& s) {
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(s.h, iv, sizeof iv);
    s.len = 0;
    s.fill = 0;
}
void sha_update(Sha& s, const unsigned char* p, size_t n) {
    s.len += n;
    while (n) {
        size_t take = std::min(n, sizeof(s.buf) - s.fill);
        memcpy(s.buf + s.fill, p, take);
        s.fill += take; p += take; n -= take;
        if (s.fill == 64) { sha_block(s, s.buf); s.fill = 0; }
    }
}
std::string sha_final(Sha& s) {
    uint64_t bits = s.len * 8;
    unsigned char pad = 0x80;
    sha_update(s, &pad, 1);
    unsigned char z = 0;
    while (s.fill != 56) sha_update(s, &z, 1);
    unsigned char lenb[8];
    for (int i = 0; i < 8; ++i) lenb[i] = static_cast<unsigned char>(bits >> (56 - 8 * i));
    sha_update(s, lenb, 8);
    std::string hex;
    for (int i = 0; i < 8; ++i) hex += strf("%08x", s.h[i]);
    return hex;
}
}  // namespace

std::string sha256_hex(const std::string& data) {
    Sha s;
    sha_init(s);
    sha_update(s, reinterpret_cast<const unsigned char*>(data.data()), data.size());
    return sha_final(s);
}

bool sha256_file(const std::string& path, std::string& hex, size_t max_bytes) {
    std::ifstream f(P(path), std::ios::binary);
    if (!f) return false;
    Sha s;
    sha_init(s);
    char buf[1 << 16];
    size_t total = 0;
    while (f) {
        f.read(buf, sizeof buf);
        std::streamsize got = f.gcount();
        if (got <= 0) break;
        total += static_cast<size_t>(got);
        if (total > max_bytes) return false;
        sha_update(s, reinterpret_cast<const unsigned char*>(buf), static_cast<size_t>(got));
    }
    hex = sha_final(s);
    return true;
}

}  // namespace scan

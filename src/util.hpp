#pragma once
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <string>
#include <vector>

namespace scan {

std::string strf(const char* fmt, ...)
#if defined(__MINGW32__)
    __attribute__((format(gnu_printf, 1, 2)))
#elif defined(__GNUC__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;
std::string lower(std::string s);
void lower_inplace(std::string& s);
std::string trim(const std::string& s);
bool starts_with(const std::string& s, const std::string& p);
bool ends_with(const std::string& s, const std::string& p);
bool contains(const std::string& s, const std::string& sub);
std::string base_name(const std::string& path);     // handles / and '\\'
std::string dir_name(const std::string& path);
std::string ext_of(const std::string& path);         // lowercase, with dot, "" if none
std::vector<std::string> split(const std::string& s, char sep);
std::string cut(const std::string& s, size_t max);    // shorten for display

double now_epoch();
std::string fmt_time(double epoch);                   // local time, "unknown" for 0

// Reads up to max_bytes of a file. Returns false if it can't be opened.
bool read_file(const std::string& path, std::string& out, size_t max_bytes = 64u << 20);
bool file_exists(const std::string& path);

// Home folders of every real user on the machine.
std::vector<std::string> user_homes();
bool is_dir(const std::string& path);
double file_mtime(const std::string& path);           // epoch, 0 on error
std::vector<std::string> list_dir(const std::string& dir);   // entry names
// Calls fn(path, size) for regular files under root. Skips links and
// cloud-only placeholder files. fn returns false to stop the walk.
void walk_files(const std::string& root, int max_depth,
                const std::function<bool(const std::string&, uint64_t)>& fn);
void make_dirs(const std::string& dir);
bool write_file(const std::string& path, const std::string& data);

std::string json_escape(const std::string& s);
std::string html_escape(const std::string& s);
std::string utf16le(const std::string& ascii);        // "ab" -> "a\0b\0"

// Pulls printable strings (ASCII and UTF-16LE) of at least min_len out of a
// buffer. UTF-16 strings are returned narrowed.
void extract_strings(const char* data, size_t n, size_t min_len,
                     std::vector<std::string>& out);

// Searches a buffer for many byte strings in one pass.
class MultiSearch {
  public:
    void add(const std::string& needle, int id);   // id is returned on a hit
    // Sets found[id] = true for every needle present. Buffer must already be
    // lowercased if the needles are lowercase.
    void search(const char* data, size_t n, std::vector<char>& found) const;
    bool empty() const { return needles_.empty(); }

  private:
    struct N { std::string s; int id; };
    std::vector<N> needles_;
    std::vector<uint32_t> first_[256];
};

std::string sha256_hex(const std::string& data);
bool sha256_file(const std::string& path, std::string& hex, size_t max_bytes = 256u << 20);

}  // namespace scan

#include "log.h"
#include "string_utils.h"
#include <windows.h>
#include <dbghelp.h>
#include <share.h>
#include <cstring>
#include <cctype>
#include <string>
#include <algorithm>
#include <mutex>
#include <atomic>
#include <cstdio>

#if CERF_DEV_MODE
std::atomic<uint64_t> Log::detail::enabled_mask{Log::MASK_ALL};
#else
std::atomic<uint64_t> Log::detail::enabled_mask{Log::MASK_NONE};
#endif
static FILE* g_logfile = nullptr;
static std::atomic<bool> g_flush{false};
static std::atomic<bool> g_allow_flood{false};
static CRITICAL_SECTION g_log_cs;
static std::once_flag g_cs_once;

static constexpr int    FLOOD_THRESHOLD    = 50;
static constexpr DWORD  FLOOD_WINDOW_MS    = 1000;
static constexpr DWORD  FLOOD_SUPPRESS_MS  = 5000;

struct FloodState {
    DWORD window_start;
    int   count;
    DWORD suppress_until;
    bool  announced;
};
static FloodState g_flood[(size_t)Log::Cat::COUNT] = {};

static bool IsFloodSuppressed(Log::Cat cat) {
    if (cat == Log::Cat::Cerf || cat == Log::Cat::Caution) return false;
    if (g_allow_flood) return false;
    int idx = (int)cat;
    if (idx < 0 || idx >= (int)Log::Cat::COUNT) return false;

    FloodState& fs = g_flood[idx];
    DWORD now = GetTickCount();

    /* Signed compare handles GetTickCount 49-day wrap. */
    if (fs.suppress_until && (int)(now - fs.suppress_until) < 0) {
        return true;
    }

    if (fs.suppress_until && (int)(now - fs.suppress_until) >= 0) {
        fs.suppress_until = 0;
        fs.announced = false;
        fs.count = 0;
        fs.window_start = now;
    }

    if ((int)(now - fs.window_start) > (int)FLOOD_WINDOW_MS) {
        fs.window_start = now;
        fs.count = 0;
    }
    fs.count++;

    if (fs.count > FLOOD_THRESHOLD) {
        fs.suppress_until = now + FLOOD_SUPPRESS_MS;
        if (!fs.announced) {
            fs.announced = true;
            fprintf(stdout, "[LOG] Category %s suppressed on stdout (flood: %d lines/sec). "
                    "Log file unaffected.\n",
                    Log::kCategories[idx].slug, fs.count);
        }
        return true;
    }
    return false;
}

static void EnsureLogCS() {
    std::call_once(g_cs_once, []() { InitializeCriticalSection(&g_log_cs); });
}

void Log::InitDefaultLogFile() {
    EnsureLogCS();
    if (g_logfile) return;
    char path[MAX_PATH] = {};
    DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (len > 0) {
        char* last_sep = strrchr(path, '\\');
        if (!last_sep) last_sep = strrchr(path, '/');
        if (last_sep) {
            size_t prefix_len = (last_sep + 1) - path;
            snprintf(path + prefix_len, MAX_PATH - prefix_len, "cerf.log");
        } else {
            snprintf(path, MAX_PATH, "cerf.log");
        }
        SetFile(path);
    }
}

void Log::SetEnabled(uint64_t mask) {
    detail::enabled_mask.store(mask, std::memory_order_relaxed);
}
void Log::SetAllowFlood(bool allow) { g_allow_flood = allow; }

void Log::SetFile(const char* path) {
    if (g_logfile) { fclose(g_logfile); g_logfile = nullptr; }
    g_logfile = _fsopen(path, "w", _SH_DENYNO);
    if (!g_logfile) {
        fprintf(stderr, "Warning: could not open log file '%s' (errno=%d)\n", path, errno);
        return;
    }
    /* 4 KB buffer caps worst-case data loss to ~20 lines on crash; per-line
       fflush in g_flush mode does the rest. _IONBF is too slow, _IOLBF is
       silently ignored by MSVC. */
    if (g_flush)
        setvbuf(g_logfile, NULL, _IOFBF, 4096);
}

void Log::SetFlush(bool enabled) {
    g_flush = enabled;
    if (enabled && g_logfile)
        setvbuf(g_logfile, NULL, _IOFBF, 4096);
}

void Log::Close() {
    /* Intentionally no fclose: any thread can be mid-vfprintf on g_logfile
       (VEH, fatal handlers, shutdown). fclose+nullify would race them into
       _invalid_parameter_noinfo → __fastfail (0xC0000409). Process exit
       closes the handle for us; we just need a flush. */
    if (g_logfile) fflush(g_logfile);
    fflush(stdout);
    fflush(stderr);
}

static LARGE_INTEGER g_qpf  = {};
static LARGE_INTEGER g_qpc0 = {};
static std::once_flag g_qpc_once;

static void EnsureQpcEpoch() {
    std::call_once(g_qpc_once, []() {
        QueryPerformanceFrequency(&g_qpf);
        QueryPerformanceCounter(&g_qpc0);
    });
}

static void PrintPrefix(FILE* f, DWORD tid, const char* slug) {
    EnsureQpcEpoch();
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    double elapsed = (double)(now.QuadPart - g_qpc0.QuadPart) / (double)g_qpf.QuadPart;
    fprintf(f, "[t+%.6fs][T%lu] [%s] ", elapsed, tid, slug);
}

void Log::Print(Cat cat, const char* fmt, ...) {
    if (!IsEnabled(cat)) return;
    va_list args;
    va_start(args, fmt);
    DWORD tid = GetCurrentThreadId();
    EnsureLogCS();
    EnterCriticalSection(&g_log_cs);

    const char* slug = kCategories[(int)cat].slug;

    if (!IsFloodSuppressed(cat)) {
        PrintPrefix(stdout, tid, slug);
        vprintf(fmt, args);
    }

    bool need_flush = false;
    /* Snapshot g_logfile so a concurrent SetFile/Close can't reload it
       between PrintPrefix and vfprintf. */
    FILE* f_snap = g_logfile;
    if (f_snap) {
        PrintPrefix(f_snap, tid, slug);
        va_list args2;
        va_copy(args2, args);
        vfprintf(f_snap, fmt, args2);
        va_end(args2);
        need_flush = g_flush.load(std::memory_order_relaxed);
    }

    LeaveCriticalSection(&g_log_cs);
    va_end(args);

    /* fflush outside the CS — CRT FILE* is internally locked, so concurrent
       fprintf+fflush is safe. Avoids starving other threads on disk I/O. */
    if (need_flush && g_logfile) fflush(g_logfile);
}

uint64_t Log::ParseCategories(const char* str) {
    std::string s(str);
    ToUpperAscii(s);

    if (s == "ALL")  return MASK_ALL;
    if (s == "NONE") return MASK_NONE;

    uint64_t mask = 0;
    size_t start = 0;
    while (start < s.size()) {
        size_t end = s.find(',', start);
        if (end == std::string::npos) end = s.size();
        std::string token = s.substr(start, end - start);

        if (!token.empty()) {
            bool matched = false;
            for (size_t i = 0; i < (size_t)Cat::COUNT; i++) {
                if (token == kCategories[i].slug) {
                    mask |= 1ULL << i;
                    matched = true;
                    break;
                }
            }
            if (!matched)
                fprintf(stderr, "Warning: unknown log category '%s'\n", token.c_str());
        }

        start = end + 1;
    }
    return mask;
}

void Log::PrintCategoryList() {
    printf("Log categories (use with --log= / --no-log=, comma-separated):\n");
    printf("  %-12s %s\n", "ALL",  "every category");
    printf("  %-12s %s\n", "NONE", "no categories");
    for (size_t i = 0; i < (size_t)Cat::COUNT; i++)
        printf("  %-12s %s\n", kCategories[i].slug, kCategories[i].desc);
}

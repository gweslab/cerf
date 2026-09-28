#include "log.h"
#include "cerf_paths.h"
#include <windows.h>
#include <cstring>
#include <mutex>
#include <atomic>
#include <cstdio>
#include <cstdlib>

#if CERF_DEV_MODE
std::atomic<uint64_t> Log::detail::enabled_mask{Log::MASK_ALL};
#else
std::atomic<uint64_t> Log::detail::enabled_mask{Log::MASK_PRODUCTION_DEFAULT};
#endif
static std::atomic<HANDLE> g_log_handle{INVALID_HANDLE_VALUE};
static std::atomic<bool> g_flush{false};
static std::atomic<bool> g_allow_flood{false};
static CRITICAL_SECTION g_log_cs;
static std::once_flag g_cs_once;

namespace {
constexpr size_t   kRingLines = 4096;
constexpr size_t   kLineMax   = 1152;
constexpr int      kPublishSpin = 4096;

struct LogLine {
    std::atomic<uint64_t> seq{0};
    uint32_t              len        = 0;
    uint8_t               to_console = 0;
    uint8_t               to_file    = 0;
    char                  text[kLineMax];
};

LogLine               g_ring[kRingLines];
std::atomic<uint64_t> g_ring_w{0};
std::atomic<uint64_t> g_ring_r{0};
std::atomic<uint64_t> g_ring_dropped{0};
std::atomic<uint64_t> g_ring_written{0};
std::atomic<uint64_t> g_write_fail{0};
std::atomic<uint64_t> g_write_fail_bytes{0};
std::atomic<uint64_t> g_flush_giveup{0};
std::atomic<uint64_t> g_no_file_lines{0};
std::atomic<bool>     g_emergency_drained{false};
std::atomic<bool>     g_ring_inited{false};
HANDLE                g_ring_event = nullptr;
CRITICAL_SECTION      g_drain_cs;
std::once_flag        g_writer_once;

bool HandleUsable(HANDLE h) {
    return h != nullptr && h != INVALID_HANDLE_VALUE;
}

void WriteRaw(HANDLE h, const char* buf, size_t len) {
    if (!HandleUsable(h) || len == 0) return;
    size_t done = 0;
    while (done < len) {
        DWORD written = 0;
        if (!WriteFile(h, buf + done, (DWORD)(len - done), &written,
                       nullptr) ||
            written == 0) {
            if (h == g_log_handle.load(std::memory_order_acquire)) {
                g_write_fail.fetch_add(1, std::memory_order_relaxed);
                g_write_fail_bytes.fetch_add(len - done,
                                             std::memory_order_relaxed);
            }
            return;
        }
        done += written;
    }
}

LogLine* RingAcquire(uint64_t* out_w) {
    for (;;) {
        const uint64_t w = g_ring_w.load(std::memory_order_relaxed);
        if (w - g_ring_r.load(std::memory_order_acquire) >= kRingLines) {
            g_ring_dropped.fetch_add(1, std::memory_order_relaxed);
            return nullptr;
        }
        uint64_t expected = w;
        if (g_ring_w.compare_exchange_weak(expected, w + 1,
                                           std::memory_order_acq_rel,
                                           std::memory_order_relaxed)) {
            *out_w = w;
            return &g_ring[w % kRingLines];
        }
    }
}

void RingPublish(LogLine* e, uint64_t w, size_t len, bool to_console,
                 bool to_file) {
    e->len        = (uint32_t)len;
    e->to_console = to_console ? 1u : 0u;
    e->to_file    = to_file ? 1u : 0u;
    e->seq.store(w + 1, std::memory_order_release);
    if (w == g_ring_r.load(std::memory_order_relaxed)) {
        SetEvent(g_ring_event);
    }
}

void ReportBothSinks(const char* msg, size_t n) {
    EnterCriticalSection(&g_drain_cs);
    WriteRaw(g_log_handle.load(std::memory_order_acquire), msg, n);
    LeaveCriticalSection(&g_drain_cs);
    WriteRaw(GetStdHandle(STD_OUTPUT_HANDLE), msg, n);
}

void DrainRing() {
    EnterCriticalSection(&g_drain_cs);
    const HANDLE log_h = g_log_handle.load(std::memory_order_acquire);
    static char file_buf[65536];
    for (;;) {
        const uint64_t r0 = g_ring_r.load(std::memory_order_acquire);
        const uint64_t w  = g_ring_w.load(std::memory_order_acquire);
        size_t   file_n = 0;
        uint64_t r      = r0;
        bool     stalled = false;
        while (r < w) {
            LogLine& e = g_ring[r % kRingLines];
            bool published = false;
            for (int i = 0; i < kPublishSpin; ++i) {
                if (e.seq.load(std::memory_order_acquire) == r + 1) {
                    published = true;
                    break;
                }
                YieldProcessor();
            }
            if (!published) {
                stalled = true;
                break;
            }
            if (e.to_file) {
                if (!HandleUsable(log_h)) {
                    g_no_file_lines.fetch_add(1, std::memory_order_relaxed);
                } else {
                    if (file_n + e.len > sizeof(file_buf)) break;
                    memcpy(file_buf + file_n, e.text, e.len);
                    file_n += e.len;
                }
            }
            if (e.to_console) {
                WriteRaw(GetStdHandle(STD_OUTPUT_HANDLE), e.text, e.len);
            }
            ++r;
        }
        if (r == r0) break;
        WriteRaw(log_h, file_buf, file_n);
        g_ring_written.store(r, std::memory_order_release);
        for (uint64_t i = r0; i < r; ++i) {
            g_ring[i % kRingLines].seq.store(0, std::memory_order_release);
        }
        g_ring_r.store(r, std::memory_order_release);
        if (stalled || r == w) break;
    }
    const bool have_sink = HandleUsable(log_h) ||
                           HandleUsable(GetStdHandle(STD_OUTPUT_HANDLE));
    if (have_sink &&
        (g_ring_dropped.load(std::memory_order_relaxed) != 0 ||
         g_write_fail.load(std::memory_order_relaxed) != 0 ||
         g_flush_giveup.load(std::memory_order_relaxed) != 0 ||
         (HandleUsable(log_h) &&
          g_no_file_lines.load(std::memory_order_relaxed) != 0))) {
        const unsigned long dropped = (unsigned long)g_ring_dropped.exchange(0);
        const unsigned long fails   = (unsigned long)g_write_fail.exchange(0);
        const unsigned long bytes =
            (unsigned long)g_write_fail_bytes.exchange(0);
        const unsigned long giveups =
            (unsigned long)g_flush_giveup.exchange(0);
        const unsigned long nofile =
            HandleUsable(log_h)
                ? (unsigned long)g_no_file_lines.exchange(0)
                : 0ul;
        char msg[224];
        const int n = wsprintfA(msg,
                                "[LOG] counters: %lu lines dropped, %lu "
                                "file writes failed (%lu bytes lost), %lu "
                                "flush requests deferred, %lu lines predate "
                                "the log file (console only)\n",
                                dropped, fails, bytes, giveups, nofile);
        if (n > 0) ReportBothSinks(msg, (size_t)n);
    }
    LeaveCriticalSection(&g_drain_cs);
}

void EmergencyDrainRing() {
    bool expected = false;
    if (!g_emergency_drained.compare_exchange_strong(expected, true)) return;
    const bool owned = TryEnterCriticalSection(&g_drain_cs) != 0;
    uint64_t       r  = g_ring_r.load(std::memory_order_acquire);
    const uint64_t wm = g_ring_written.load(std::memory_order_acquire);
    if (wm > r) r = wm;
    const uint64_t w = g_ring_w.load(std::memory_order_acquire);
    uint64_t skipped = 0;
    uint64_t emitted = 0;
    for (uint64_t i = r; i < w; ++i) {
        LogLine& e = g_ring[i % kRingLines];
        if (e.seq.load(std::memory_order_acquire) != i + 1) {
            ++skipped;
            continue;
        }
        if (emitted == 0) {
            Log::Emergency("[LOG] ring tail (%lu slots pending at the crash):\n",
                           (unsigned long)(w - r));
        }
        ++emitted;
        Log::EmergencyWriteBytes(e.text, e.len);
    }
    const unsigned long dropped =
        (unsigned long)g_ring_dropped.load(std::memory_order_relaxed);
    const unsigned long wfails =
        (unsigned long)g_write_fail.load(std::memory_order_relaxed);
    const unsigned long wbytes =
        (unsigned long)g_write_fail_bytes.load(std::memory_order_relaxed);
    Log::Emergency("[LOG] emergency drain: %lu lines recovered here, %lu "
                   "unpublished (producer frozen mid-format), %lu dropped, "
                   "%lu file-write failures (%lu bytes)\n",
                   (unsigned long)emitted, (unsigned long)skipped, dropped,
                   wfails, wbytes);
    if (owned) LeaveCriticalSection(&g_drain_cs);
}

DWORD WINAPI RingWriterThread(LPVOID) {
    for (;;) {
        WaitForSingleObject(g_ring_event, 20);
        DrainRing();
    }
}

void EnsureRingWriter() {
    std::call_once(g_writer_once, []() {
        InitializeCriticalSection(&g_drain_cs);
        g_ring_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        HANDLE t = g_ring_event != nullptr
                       ? CreateThread(nullptr, 0, RingWriterThread, nullptr,
                                      0, nullptr)
                       : nullptr;
        if (t == nullptr) {
            const char msg[] =
                "CERF log: ring writer creation failed; exiting\n";
            WriteRaw(GetStdHandle(STD_ERROR_HANDLE), msg, sizeof(msg) - 1);
            ExitProcess((UINT)CERF_FATAL_RUNTIME_ERROR);
        }
        CloseHandle(t);
        atexit([] { Log::Close(); });
        g_ring_inited.store(true, std::memory_order_release);
    });
}
}

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
            uint64_t w  = 0;
            LogLine* e  = RingAcquire(&w);
            if (e != nullptr) {
                fs.announced = true;
                int n = snprintf(
                    e->text, kLineMax,
                    "[LOG] Category %s suppressed on stdout (flood: %d "
                    "lines/sec). Log file unaffected.\n",
                    Log::kCategories[idx].slug, fs.count);
                if (n < 0) n = 0;
                if ((size_t)n >= kLineMax) n = (int)kLineMax - 1;
                RingPublish(e, w, (size_t)n, true, false);
            }
        }
        return true;
    }
    return false;
}

static constexpr size_t CAUTION_RING_LINES = 12;
static constexpr size_t CAUTION_LINE_MAX   = 256;
static char   g_caution_ring[CAUTION_RING_LINES][CAUTION_LINE_MAX] = {};
static size_t g_caution_next  = 0;
static size_t g_caution_count = 0;

static void EnsureLogCS() {
    std::call_once(g_cs_once, []() { InitializeCriticalSection(&g_log_cs); });
}

static void RecordCautionLocked(const char* fmt, va_list args) {
    char* slot = g_caution_ring[g_caution_next];
    vsnprintf(slot, CAUTION_LINE_MAX, fmt, args);
    slot[CAUTION_LINE_MAX - 1] = '\0';

    size_t len = strlen(slot);
    while (len > 0 && (slot[len - 1] == '\n' || slot[len - 1] == '\r'))
        slot[--len] = '\0';

    g_caution_next = (g_caution_next + 1) % CAUTION_RING_LINES;
    if (g_caution_count < CAUTION_RING_LINES) g_caution_count++;
}

void Log::CopyRecentCautionsPostFreeze(char* out, size_t out_size) {
    if (!out || out_size == 0) return;
    out[0] = '\0';

    EnsureLogCS();
    const bool owned = TryEnterCriticalSection(&g_log_cs) != 0;

    size_t written = 0;
    size_t first = (g_caution_next + CAUTION_RING_LINES - g_caution_count) % CAUTION_RING_LINES;
    for (size_t i = 0; i < g_caution_count && written + 2 < out_size; i++) {
        const char* line = g_caution_ring[(first + i) % CAUTION_RING_LINES];
        if (line[0] == '\0') continue;
        size_t k = 0;
        while (k < CAUTION_LINE_MAX && line[k] != '\0' &&
               written + 2 < out_size) {
            out[written++] = line[k++];
        }
        out[written++] = '\n';
        out[written]   = '\0';
    }

    if (owned) LeaveCriticalSection(&g_log_cs);
}

void Log::InitDefaultLogFile() {
    EnsureLogCS();
    if (g_log_handle.load(std::memory_order_acquire) != INVALID_HANDLE_VALUE) {
        return;
    }
    if (GetCerfExePath().empty()) return;
    SetFile((GetCerfDir() + "cerf.log").c_str());
}

void Log::SetEnabled(uint64_t mask) {
    detail::enabled_mask.store(mask, std::memory_order_relaxed);
}
void Log::SetAllowFlood(bool allow) { g_allow_flood = allow; }

void Log::SetFile(const char* path) {
    EnsureRingWriter();
    EnterCriticalSection(&g_drain_cs);
    HANDLE h = CreateFileW(Utf8ToWide(path).c_str(), GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        const HANDLE old = g_log_handle.exchange(h, std::memory_order_acq_rel);
        if (old != INVALID_HANDLE_VALUE) CloseHandle(old);
    }
    LeaveCriticalSection(&g_drain_cs);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Warning: could not open log file '%s' (gle=%lu)\n",
                path, GetLastError());
    }
}

void Log::SetFlush(bool enabled) {
    g_flush = enabled;
}

void Log::Close() {
    if (IsEmergencyActive()) {
        if (g_ring_inited.load(std::memory_order_acquire)) {
            EmergencyDrainRing();
        }
        return;
    }
    EnsureRingWriter();
    const uint64_t w = g_ring_w.load(std::memory_order_acquire);
    for (int i = 0;
         i < 64 && g_ring_r.load(std::memory_order_acquire) < w; ++i) {
        DrainRing();
    }
    const uint64_t r = g_ring_r.load(std::memory_order_acquire);
    if (r < w) {
        char msg[128];
        const int n = wsprintfA(msg,
                                "[LOG] %lu lines unpublished at close\n",
                                (unsigned long)(w - r));
        if (n > 0) ReportBothSinks(msg, (size_t)n);
    }
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

static int PrefixToBuf(char* buf, size_t cap, DWORD tid, const char* slug) {
    EnsureQpcEpoch();
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    double elapsed = (double)(now.QuadPart - g_qpc0.QuadPart) / (double)g_qpf.QuadPart;
    return snprintf(buf, cap, "[t+%.6fs][T%lu] [%s] ", elapsed, tid, slug);
}

void Log::Print(Cat cat, const char* fmt, ...) {
    if (!IsEnabled(cat)) return;
    va_list args;
    va_start(args, fmt);
    DWORD tid = GetCurrentThreadId();
    EnsureLogCS();
    EnsureRingWriter();

    const char* slug = kCategories[(int)cat].slug;

    bool to_console;
    {
        EnterCriticalSection(&g_log_cs);
        if (cat == Cat::Caution) {
            va_list args_ring;
            va_copy(args_ring, args);
            RecordCautionLocked(fmt, args_ring);
            va_end(args_ring);
        }
        to_console = !IsFloodSuppressed(cat);
        LeaveCriticalSection(&g_log_cs);
    }

    uint64_t w = 0;
    LogLine* e = RingAcquire(&w);
    if (e == nullptr) {
        va_end(args);
        return;
    }
    int n = PrefixToBuf(e->text, kLineMax, tid, slug);
    if (n < 0) n = 0;
    if ((size_t)n >= kLineMax) n = (int)kLineMax - 1;
    int m = vsnprintf(e->text + n, kLineMax - (size_t)n, fmt, args);
    va_end(args);
    if (m < 0) m = 0;
    size_t len = (size_t)n + (size_t)m;
    if (len >= kLineMax) {
        len = kLineMax - 1;
        memcpy(&e->text[kLineMax - 6], " ...\n", 5);
    }
    RingPublish(e, w, len, to_console, true);

    if (g_flush.load(std::memory_order_relaxed)) {
        for (int i = 0;
             i < 64 && g_ring_r.load(std::memory_order_acquire) <= w; ++i) {
            DrainRing();
        }
        if (g_ring_r.load(std::memory_order_acquire) <= w) {
            g_flush_giveup.fetch_add(1, std::memory_order_relaxed);
        }
    }
}


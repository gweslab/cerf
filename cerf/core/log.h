#pragma once

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <mutex>

namespace Log {

    #define LOG_CATEGORIES(X)                                                       \
        X(Cerf,        "CERF",        "generic emulator status (always on)")        \
        X(Caution,     "CAUTION",     "errors / warnings (always on)")              \
        X(Boot,        "BOOT",        "kernel boot / image loader")                 \
        X(Jit,         "JIT",         "ARM JIT runner")                             \
        X(Mem,         "MEM",         "emulated memory regions / telemetry")       \
        X(Net,         "NET",         "slirp backend / NDIS bridge")                \
        X(Periph,      "PERIPH",      "peripheral dispatcher")                      \
        X(Cp15,        "CP15",        "ARM cp15 system control coprocessor")        \
        X(Mmu,         "MMU",         "ARM MMU translation walker")                 \
        X(Tlb,         "TLB",         "ARM JIT page-table cache (GuestTlb)")        \
        X(Board,       "BOARD",       "board detection / BSP setup")                \
        X(Cfg,         "CFG",         "device config loader")                       \
        X(SocIntc,     "SOC_INTC",    "any SoC interrupt controller")               \
        X(SocWdt,      "SOC_WDT",     "any SoC watchdog")                           \
        X(SocClkpwr,   "SOC_CLKPWR",  "any SoC clock / power block")                \
        X(SocIoport,   "SOC_IOPORT",  "any SoC GPIO / I-O port")                    \
        X(SocMemc,     "SOC_MEMC",    "any SoC memory controller")                  \
        X(SocUart,     "SOC_UART",    "any SoC UART / debug serial")                \
        X(SocTimer,    "SOC_TIMER",   "any SoC PWM / system tick timer")            \
        X(SocRtc,      "SOC_RTC",     "any SoC real-time clock")                    \
        X(SocNand,     "SOC_NAND",    "any SoC NAND flash controller")              \
        X(SocReset,    "SOC_RESET",   "any SoC reset controller")                   \
        X(Lcd,         "LCD",         "host display window + per-SoC LCD ctrl")     \
        X(Pcmcia,      "PCMCIA",      "board-level PCMCIA bus controller (PD6710)") \
        X(Trace,       "TRACE",       "TraceManager + device-specific trace files") \
        X(Perf,        "PERF",        "RateProbe — per-second event counters")    \
        X(GuestDriver, "GUEST",       "CERF guest driver runtime output via cerf_debug_tx") \
        X(GuestAdditions, "GUEST_HOST", "CERF guest additions")

    enum class Cat : uint8_t {
    #define X(name, slug, desc) name,
        LOG_CATEGORIES(X)
    #undef X
        COUNT
    };

    struct CatInfo {
        const char* slug;
        const char* desc;
    };

    inline constexpr CatInfo kCategories[] = {
    #define X(name, slug, desc) { slug, desc },
        LOG_CATEGORIES(X)
    #undef X
    };

    static_assert(sizeof(kCategories) / sizeof(CatInfo) == (size_t)Cat::COUNT,
                  "kCategories must match Cat::COUNT — X-macro out of sync");
    static_assert((int)Cat::COUNT <= 64,
                  "Log::Cat exceeds 64 — switch enabled_mask to std::bitset");

    inline constexpr uint64_t MASK_ALL =
        ((int)Cat::COUNT >= 64) ? ~0ULL : ((1ULL << (int)Cat::COUNT) - 1);
    inline constexpr uint64_t MASK_NONE = 0;

    void InitDefaultLogFile();

    namespace detail {
        extern std::atomic<uint64_t> enabled_mask;
    }

    inline uint64_t GetEnabled() {
        return detail::enabled_mask.load(std::memory_order_relaxed);
    }
    inline bool IsEnabled(Cat cat) {
        /* Cerf and Caution are hardcoded always-on — they describe events
           the user must see regardless of --log= / --no-log= / --quiet. */
        if (cat == Cat::Cerf || cat == Cat::Caution) return true;
        return (GetEnabled() & (1ULL << (int)cat)) != 0;
    }

    void SetEnabled(uint64_t mask);
    void SetFile(const char* path);
    void SetFlush(bool enabled);
    void SetAllowFlood(bool allow);
    void Close();

    void Print(Cat cat, const char* fmt, ...);

    /* Comma-separated slugs, plus the special tokens "ALL" and "NONE".
       Unknown tokens warn on stderr and contribute nothing to the mask. */
    uint64_t ParseCategories(const char* str);

    /* Print every category and its description to stdout — used by --help. */
    void PrintCategoryList();

    void EmergencyStart();
    void Emergency(const char* fmt, ...);
    void EmergencyPrintNativeStack(const char* tag);
    void EmergencyDumpAllThreadStacks();

}  // namespace Log

/* LOG(name, fmt, ...) — `name` is an unqualified Cat identifier (e.g. Boot,
   SocIntc). The macro qualifies it as Log::Cat::name; a typo is a compile
   error. The slug "[NAME]" is auto-prepended by Log::Print from the
   registry — never put it in the format string. */
#define LOG(name, ...) do {                                                         \
    if (Log::IsEnabled(Log::Cat::name))                                             \
        Log::Print(Log::Cat::name, __VA_ARGS__);                                    \
} while (0)

inline constexpr int CERF_FATAL_RUNTIME_ERROR = 1;
/* User/environment condition (unsupported board, no ROM installed), not a
   CERF bug: CerfFatalExit skips the crash-dump path for this code. */
inline constexpr int CERF_FATAL_USER_ERROR    = 2;

[[noreturn]] void CerfFatalExit(int code = CERF_FATAL_RUNTIME_ERROR);

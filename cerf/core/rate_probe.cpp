#include "rate_probe.h"

#include "cerf_emulator.h"
#include "log.h"

#include <chrono>
#include <intrin.h>

REGISTER_SERVICE(RateProbe);

RateProbe::~RateProbe() {
    stop_.store(true, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lk(cv_mtx_);
    }
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

void RateProbe::CalibrateTscPerSec() {
    using namespace std::chrono;
    const uint64_t tsc0 = __rdtsc();
    const auto     w0   = steady_clock::now();
    std::this_thread::sleep_for(milliseconds(50));
    const uint64_t tsc1 = __rdtsc();
    const auto     w1   = steady_clock::now();
    const uint64_t wall_ns = static_cast<uint64_t>(
        duration_cast<nanoseconds>(w1 - w0).count());
    tsc_per_sec_ = (wall_ns == 0) ? 1ull
                                  : ((tsc1 - tsc0) * 1'000'000'000ull) / wall_ns;
    LOG(Perf, "TSC calibrated: %llu ticks/sec (~%llu MHz)\n",
        (unsigned long long)tsc_per_sec_,
        (unsigned long long)(tsc_per_sec_ / 1'000'000ull));
}

void RateProbe::OnReady() {
#if CERF_DEV_MODE
    CalibrateTscPerSec();
    thread_ = std::thread([this] { LogLoop(); });
#endif
}

void RateProbe::LogTopMmioPcs() {
    struct Entry { uint32_t pc; uint32_t addr; uint64_t count; };
    Entry snap[kMmioHistSize];
    uint32_t live = 0;
    for (uint32_t i = 0; i < kMmioHistSize; ++i) {
        const uint64_t c = mmio_count_[i].exchange(0, std::memory_order_relaxed);
        if (c == 0) continue;
        snap[live].pc    = mmio_pc_[i].load(std::memory_order_relaxed);
        snap[live].addr  = mmio_addr_[i].load(std::memory_order_relaxed);
        snap[live].count = c;
        ++live;
    }
    /* Partial sort top 10 by count. */
    constexpr uint32_t kTop = 10;
    const uint32_t n = (live < kTop) ? live : kTop;
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t best = i;
        for (uint32_t j = i + 1; j < live; ++j) {
            if (snap[j].count > snap[best].count) best = j;
        }
        if (best != i) {
            Entry tmp = snap[i]; snap[i] = snap[best]; snap[best] = tmp;
        }
        LOG(Perf, "  mmio_pc top%u: pc=0x%08X addr=0x%08X count=%llu\n",
            i + 1, snap[i].pc, snap[i].addr,
            (unsigned long long)snap[i].count);
    }
}

void RateProbe::LogLoop() {
    using namespace std::chrono;
    auto next_tick = steady_clock::now() + seconds(1);

    while (!stop_.load(std::memory_order_acquire)) {
        {
            std::unique_lock<std::mutex> lk(cv_mtx_);
            cv_.wait_until(lk, next_tick, [this] {
                return stop_.load(std::memory_order_acquire);
            });
        }
        if (stop_.load(std::memory_order_acquire)) break;
        next_tick += seconds(1);

        uint64_t s[kCount];
        for (uint8_t i = 0; i < kCount; ++i) {
            s[i] = counters_[i].exchange(0, std::memory_order_relaxed);
        }
        uint64_t t[kTimeCount];
        for (uint8_t i = 0; i < kTimeCount; ++i) {
            t[i] = time_counters_[i].exchange(0, std::memory_order_relaxed);
        }

        const uint64_t rd = s[static_cast<uint8_t>(Counter::OstReadOscr)];
        const uint64_t jr = s[static_cast<uint8_t>(Counter::JitRuns)];
        const uint64_t rd_per_run = jr ? rd / jr : 0;
        const uint64_t ticks_per_ms = tsc_per_sec_ / 1000ull;
        const uint64_t run_ms = ticks_per_ms ?
            t[static_cast<uint8_t>(TimeCounter::JitRun)]   / ticks_per_ms : 0;
        const uint64_t ost_ms = ticks_per_ms ?
            t[static_cast<uint8_t>(TimeCounter::OstMmio)]  / ticks_per_ms : 0;
        const uint64_t io_ms  = ticks_per_ms ?
            t[static_cast<uint8_t>(TimeCounter::JitIo)]    / ticks_per_ms : 0;
        const uint64_t mmu_ms = ticks_per_ms ?
            t[static_cast<uint8_t>(TimeCounter::MmuXlate)] / ticks_per_ms : 0;
        const uint64_t native_ms =
            (run_ms > io_ms + mmu_ms) ? run_ms - io_ms - mmu_ms : 0;
        LogTopMmioPcs();
        LOG(Perf,
            "jit_runs=%llu ost_rd=%llu ost_poll=%llu ost_fire=%llu "
            "intc_assert=%llu intc_deassert=%llu jit_pend_set=%llu "
            "jit_pend_clr=%llu dma_w=%llu audio_msg=%llu rd_per_run=%llu "
            "run_ms=%llu ost_ms=%llu io_ms=%llu mmu_ms=%llu native_ms=%llu "
            "mmu_calls=%llu\n",
            (unsigned long long)s[static_cast<uint8_t>(Counter::JitRuns)],
            (unsigned long long)s[static_cast<uint8_t>(Counter::OstReadOscr)],
            (unsigned long long)s[static_cast<uint8_t>(Counter::OstPolls)],
            (unsigned long long)s[static_cast<uint8_t>(Counter::OstFires)],
            (unsigned long long)s[static_cast<uint8_t>(Counter::IntcAsserts)],
            (unsigned long long)s[static_cast<uint8_t>(Counter::IntcDeasserts)],
            (unsigned long long)s[static_cast<uint8_t>(Counter::JitPendSet)],
            (unsigned long long)s[static_cast<uint8_t>(Counter::JitPendClr)],
            (unsigned long long)s[static_cast<uint8_t>(Counter::DmaWrites)],
            (unsigned long long)s[static_cast<uint8_t>(Counter::AudioMsgs)],
            (unsigned long long)rd_per_run,
            (unsigned long long)run_ms,
            (unsigned long long)ost_ms,
            (unsigned long long)io_ms,
            (unsigned long long)mmu_ms,
            (unsigned long long)native_ms,
            (unsigned long long)s[static_cast<uint8_t>(Counter::MmuXlateCalls)]);
    }
}

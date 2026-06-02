#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../cpu/arm_processor_config.h"
#include "../../jit/arm_jit.h"
#include "../../jit/cpu_state.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "imx31_avic.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

namespace {

/* MCIMX31RM §34.3.1 Table 34-3 (PDF p1474). */
constexpr uint32_t kBase   = 0x53F90000u;
constexpr uint32_t kSize   = 0x00004000u;
constexpr uint32_t kRegEnd = 0x28u;

constexpr uint32_t kOffGptcr   = 0x00u;
constexpr uint32_t kOffGptpr   = 0x04u;
constexpr uint32_t kOffGptsr   = 0x08u;
constexpr uint32_t kOffGptir   = 0x0Cu;
constexpr uint32_t kOffGptocr1 = 0x10u;
constexpr uint32_t kOffGptocr2 = 0x14u;
constexpr uint32_t kOffGptocr3 = 0x18u;
constexpr uint32_t kOffGpticr1 = 0x1Cu;
constexpr uint32_t kOffGpticr2 = 0x20u;
constexpr uint32_t kOffGptcnt  = 0x24u;

/* MCIMX31RM §34.3.3.1 Table 34-6 GPTCR bits (PDF p1477..1480). */
constexpr uint32_t kGptcrEn        = 1u << 0;
constexpr uint32_t kGptcrEnmod     = 1u << 1;
constexpr uint32_t kGptcrClksrcSh  = 6;
constexpr uint32_t kGptcrClksrcM   = 7u << kGptcrClksrcSh;
constexpr uint32_t kGptcrFrr       = 1u << 9;
constexpr uint32_t kGptcrSwr       = 1u << 15;
constexpr uint32_t kGptcrFo1       = 1u << 29;
constexpr uint32_t kGptcrFo2       = 1u << 30;
constexpr uint32_t kGptcrFo3       = 1u << 31;
constexpr uint32_t kGptcrSelfClear = kGptcrSwr | kGptcrFo1 | kGptcrFo2 | kGptcrFo3;
/* SWR preserves EN/ENMOD/DBGEN/WAITEN/DOZEN/STOPEN/CLKSRC (§34.4.1[15]). */
constexpr uint32_t kGptcrSwrPreserve = 0x000003FFu;

/* MCIMX31RM §34.3.3.3 Table 34-8 GPTSR (PDF p1481) — w1c bits. */
constexpr uint32_t kGptOf1 = 1u << 0;
constexpr uint32_t kGptOf2 = 1u << 1;
constexpr uint32_t kGptOf3 = 1u << 2;
constexpr uint32_t kGptIf1 = 1u << 3;
constexpr uint32_t kGptIf2 = 1u << 4;
constexpr uint32_t kGptRov = 1u << 5;
constexpr uint32_t kGptStatusMask = 0x3Fu;

constexpr uint32_t kClksrcNone   = 0u;
constexpr uint32_t kClksrcIpgClk = 1u;

/* MCIMX31RM §2.2 Table 2-3 (PDF p190): AVIC source 29 = GPT. */
constexpr uint32_t kAvicSourceGpt = 29u;

constexpr auto kPollInterval = std::chrono::microseconds(100);
constexpr uint32_t kNotifyForwardLimit = 10000u;

class Imx31Gpt : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }

    void OnReady() override {
        cpu_to_ipg_ = emu_.Get<ArmProcessorConfig>().CpuToOscrDivider();
        if (cpu_to_ipg_ == 0) cpu_to_ipg_ = 1;
        gptocr_[0].store(0xFFFFFFFFu, std::memory_order_release);
        gptocr_[1].store(0xFFFFFFFFu, std::memory_order_release);
        gptocr_[2].store(0xFFFFFFFFu, std::memory_order_release);
        for (int n = 0; n < 3; ++n) {
            ocr_anchor_[n].store(PackPair(0xFFFFFFFFu, 0u),
                                 std::memory_order_release);
        }
        baseline_packed_.store(PackPair(0u, GuestCycles()),
                               std::memory_order_release);

        emu_.Get<PeripheralDispatcher>().Register(this);
        match_thread_ = std::thread([this] { MatchLoop(); });
    }

    ~Imx31Gpt() override {
        stop_.store(true, std::memory_order_release);
        cv_.notify_all();
        if (match_thread_.joinable()) match_thread_.join();
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    FastReadFn  FastReader() override { return &Imx31Gpt::FastReadThunk; }
    FastWriteFn FastWriter() override { return &Imx31Gpt::FastWriteThunk; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    static uint32_t FastReadThunk(void* ctx, uint32_t off, uint32_t width) {
        return static_cast<Imx31Gpt*>(ctx)->FastRead(off, width);
    }
    static void FastWriteThunk(void* ctx, uint32_t off, uint32_t value, uint32_t width) {
        static_cast<Imx31Gpt*>(ctx)->FastWrite(off, value, width);
    }

    uint32_t FastRead(uint32_t off, uint32_t width) {
        if (width != 4 || (off & 0x3u) != 0u || off >= kRegEnd) {
            HaltUnsupportedAccess("FastRead", kBase + off, 0);
        }
        return ReadReg(off);
    }
    void FastWrite(uint32_t off, uint32_t value, uint32_t width) {
        if (width != 4 || (off & 0x3u) != 0u || off >= kRegEnd) {
            HaltUnsupportedAccess("FastWrite", kBase + off, value);
        }
        WriteReg(off, value);
    }

private:
    std::mutex              cv_mtx_;
    std::condition_variable cv_;
    std::thread             match_thread_;
    std::atomic<bool>       stop_{false};

    std::atomic<uint64_t> baseline_packed_{0};
    std::atomic<uint64_t> ocr_anchor_[3]{};
    std::atomic<uint32_t> frozen_count_{0};

    std::atomic<uint32_t> gptcr_{0};
    std::atomic<uint32_t> gptpr_{0};
    std::atomic<uint32_t> gptsr_{0};
    std::atomic<uint32_t> gptir_{0};
    std::atomic<uint32_t> gptocr_[3]{};
    std::atomic<uint32_t> gpticr_[2]{};

    uint32_t last_seen_count_{0};
    uint32_t cpu_to_ipg_{1};

    static uint64_t PackPair(uint32_t hi, uint32_t lo) {
        return (static_cast<uint64_t>(hi) << 32) | lo;
    }
    static uint32_t HiOf(uint64_t p) { return static_cast<uint32_t>(p >> 32); }
    static uint32_t LoOf(uint64_t p) { return static_cast<uint32_t>(p); }

    uint32_t GuestCycles() const {
        return emu_.Get<ArmJit>().CpuState()->guest_cycle_counter;
    }

    uint32_t EffectiveDivider() const {
        const uint32_t cr = gptcr_.load(std::memory_order_acquire);
        if ((cr & kGptcrEn) == 0) return 0;
        const uint32_t clksrc = (cr & kGptcrClksrcM) >> kGptcrClksrcSh;
        if (clksrc != kClksrcIpgClk) return 0;
        const uint32_t pre = gptpr_.load(std::memory_order_acquire) & 0xFFFu;
        return cpu_to_ipg_ * (pre + 1u);
    }

    uint32_t ReadCounter() const {
        const uint32_t div = EffectiveDivider();
        if (div == 0) return frozen_count_.load(std::memory_order_acquire);
        const uint64_t packed = baseline_packed_.load(std::memory_order_acquire);
        const uint32_t cycles_now = GuestCycles();
        const uint32_t delta = cycles_now - LoOf(packed);
        return HiOf(packed) + (delta / div);
    }

    /* Without periodic rebase, 32-bit (cycles_now - base_cycles)
       unsigned-wraps every ~2^32 emit cycles (~43 s) and the counter
       jumps backwards. */
    void RebaseToCurrent() {
        const uint32_t div = EffectiveDivider();
        if (div == 0) return;
        const uint64_t old_packed = baseline_packed_.load(std::memory_order_acquire);
        const uint32_t cycles_now = GuestCycles();
        const uint32_t delta = cycles_now - LoOf(old_packed);
        const uint32_t new_count = HiOf(old_packed) + (delta / div);
        baseline_packed_.store(PackPair(new_count, cycles_now),
                               std::memory_order_release);
    }

    /* Anchored forward-crossing: without the per-channel anchor, an OCR
       value far behind current counter would fire spuriously every poll. */
    static bool MatchHasFired(uint32_t ocr_at_anchor,
                              uint32_t ocr_val,
                              uint32_t count_now) {
        const uint32_t fwd_target = ocr_val   - ocr_at_anchor;
        const uint32_t fwd_now    = count_now - ocr_at_anchor;
        return fwd_now >= fwd_target;
    }

    void WriteOcr(int n, uint32_t value) {
        const uint32_t count_now = ReadCounter();
        gptocr_[n].store(value, std::memory_order_release);
        ocr_anchor_[n].store(PackPair(value, count_now),
                             std::memory_order_release);

        /* §34.3.3.5 (PDF p1482): OCR1 write in restart mode resets counter. */
        if (n == 0) {
            const uint32_t cr = gptcr_.load(std::memory_order_acquire);
            if ((cr & kGptcrFrr) == 0 && (cr & kGptcrEn) != 0) {
                baseline_packed_.store(PackPair(0u, GuestCycles()),
                                       std::memory_order_release);
                last_seen_count_ = 0u;
                ocr_anchor_[0].store(PackPair(value, 0u),
                                     std::memory_order_release);
            }
        }

        const uint32_t fwd = value - count_now;
        if (fwd < kNotifyForwardLimit) cv_.notify_all();
    }

    void WriteGptcr(uint32_t value) {
        const uint32_t old_cr = gptcr_.load(std::memory_order_acquire);
        const uint32_t new_cr = value & ~kGptcrSelfClear;

        /* §34.3.3.1[15] SWR: self-clearing; resets all regs except the
           bits in kGptcrSwrPreserve. */
        if (value & kGptcrSwr) {
            const uint32_t preserved = old_cr & kGptcrSwrPreserve;
            gptcr_.store(preserved, std::memory_order_release);
            gptpr_.store(0u, std::memory_order_release);
            gptsr_.store(0u, std::memory_order_release);
            gptir_.store(0u, std::memory_order_release);
            gptocr_[0].store(0xFFFFFFFFu, std::memory_order_release);
            gptocr_[1].store(0xFFFFFFFFu, std::memory_order_release);
            gptocr_[2].store(0xFFFFFFFFu, std::memory_order_release);
            for (int n = 0; n < 3; ++n) {
                ocr_anchor_[n].store(PackPair(0xFFFFFFFFu, 0u),
                                     std::memory_order_release);
            }
            baseline_packed_.store(PackPair(0u, GuestCycles()),
                                   std::memory_order_release);
            frozen_count_.store(0u, std::memory_order_release);
            last_seen_count_ = 0u;
            cv_.notify_all();
            return;
        }

        /* Rebase across every EN / CLKSRC transition so the counter
           never visibly jumps backward or forward — the kernel reads
           GPTCNT mid-write and would compute a negative elapsed-time. */
        const bool was_en = (old_cr & kGptcrEn) != 0;
        const bool now_en = (new_cr & kGptcrEn) != 0;
        const uint32_t old_clksrc = (old_cr & kGptcrClksrcM) >> kGptcrClksrcSh;
        const uint32_t new_clksrc = (new_cr & kGptcrClksrcM) >> kGptcrClksrcSh;

        /* MUST sample before gptcr_.store — if kernel writes
           CLKSRC=000, post-store ReadCounter returns 0 (frozen) and
           the rebase below snapshots 0 instead of the live counter. */
        const uint32_t pre_store_counter =
            (was_en && (now_en != was_en || old_clksrc != new_clksrc))
                ? ReadCounter()
                : 0u;

        if (was_en && !now_en) {
            frozen_count_.store(pre_store_counter, std::memory_order_release);
        }

        gptcr_.store(new_cr, std::memory_order_release);

        if (!was_en && now_en) {
            const uint32_t start =
                (new_cr & kGptcrEnmod) ? 0u
                                       : frozen_count_.load(std::memory_order_acquire);
            baseline_packed_.store(PackPair(start, GuestCycles()),
                                   std::memory_order_release);
            last_seen_count_ = start;
        } else if (was_en && now_en && old_clksrc != new_clksrc) {
            baseline_packed_.store(PackPair(pre_store_counter, GuestCycles()),
                                   std::memory_order_release);
        }

        if (new_clksrc != kClksrcNone && new_clksrc != kClksrcIpgClk) {
            LOG(Periph,
                "[GPT] unsupported CLKSRC=%u; only 000/001 wired\n",
                new_clksrc);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        cv_.notify_all();
    }

    void WriteGptpr(uint32_t value) {
        const uint32_t old_div = EffectiveDivider();
        const uint32_t new_pre = value & 0xFFFu;
        if (old_div != 0) {
            const uint32_t cur = ReadCounter();
            gptpr_.store(new_pre, std::memory_order_release);
            baseline_packed_.store(PackPair(cur, GuestCycles()),
                                   std::memory_order_release);
        } else {
            gptpr_.store(new_pre, std::memory_order_release);
        }
        cv_.notify_all();
    }

    void WriteGptsr(uint32_t value) {
        /* §34.3.3.3 Table 34-8: all bits w1c. */
        const uint32_t mask = value & kGptStatusMask;
        const uint32_t prev = gptsr_.fetch_and(~mask, std::memory_order_acq_rel);
        const uint32_t cleared = prev & mask;
        if (cleared == 0) return;

        /* Re-anchor cleared compare channels so MatchHasFired sees a
           fresh forward-crossing, not the previous one still satisfying
           the test every poll. */
        const uint32_t count_now = ReadCounter();
        for (int n = 0; n < 3; ++n) {
            const uint32_t of_bit = 1u << n;
            if ((cleared & of_bit) == 0) continue;
            uint64_t expected = ocr_anchor_[n].load(std::memory_order_acquire);
            for (;;) {
                const uint32_t ocr = HiOf(expected);
                const uint64_t desired = PackPair(ocr, count_now);
                if (ocr_anchor_[n].compare_exchange_weak(
                        expected, desired,
                        std::memory_order_acq_rel,
                        std::memory_order_acquire)) break;
            }
        }

        const uint32_t ir = gptir_.load(std::memory_order_acquire);
        if ((gptsr_.load(std::memory_order_acquire) & ir) == 0) {
            emu_.Get<Imx31Avic>().DeassertSource(kAvicSourceGpt);
        }
        cv_.notify_all();
    }

    void WriteGptir(uint32_t value) {
        gptir_.store(value & kGptStatusMask, std::memory_order_release);
        const uint32_t pending =
            gptsr_.load(std::memory_order_acquire) &
            gptir_.load(std::memory_order_acquire);
        if (pending != 0) {
            emu_.Get<Imx31Avic>().AssertSource(kAvicSourceGpt);
        } else {
            emu_.Get<Imx31Avic>().DeassertSource(kAvicSourceGpt);
        }
        cv_.notify_all();
    }

    uint32_t ReadReg(uint32_t off) {
        switch (off) {
            case kOffGptcr:   return gptcr_.load(std::memory_order_acquire);
            case kOffGptpr:   return gptpr_.load(std::memory_order_acquire);
            case kOffGptsr:   return gptsr_.load(std::memory_order_acquire);
            case kOffGptir:   return gptir_.load(std::memory_order_acquire);
            case kOffGptocr1: return gptocr_[0].load(std::memory_order_acquire);
            case kOffGptocr2: return gptocr_[1].load(std::memory_order_acquire);
            case kOffGptocr3: return gptocr_[2].load(std::memory_order_acquire);
            case kOffGpticr1: return gpticr_[0].load(std::memory_order_acquire);
            case kOffGpticr2: return gpticr_[1].load(std::memory_order_acquire);
            case kOffGptcnt:  return ReadCounter();
        }
        HaltUnsupportedAccess("ReadReg", kBase + off, 0);
        return 0;
    }

    void WriteReg(uint32_t off, uint32_t value) {
        switch (off) {
            case kOffGptcr:   WriteGptcr(value); return;
            case kOffGptpr:   WriteGptpr(value); return;
            case kOffGptsr:   WriteGptsr(value); return;
            case kOffGptir:   WriteGptir(value); return;
            case kOffGptocr1: WriteOcr(0, value); return;
            case kOffGptocr2: WriteOcr(1, value); return;
            case kOffGptocr3: WriteOcr(2, value); return;
            case kOffGpticr1:
            case kOffGpticr2:
            case kOffGptcnt:
                return;  /* §34.3.3.8/9/10: read-only */
        }
        HaltUnsupportedAccess("WriteReg", kBase + off, value);
    }

    bool CheckRollover(uint32_t count_now) {
        if (count_now < last_seen_count_) {
            const uint32_t cr = gptcr_.load(std::memory_order_acquire);
            const bool free_run = (cr & kGptcrFrr) != 0;
            if (free_run || last_seen_count_ == 0xFFFFFFFFu) {
                last_seen_count_ = count_now;
                return true;
            }
        }
        last_seen_count_ = count_now;
        return false;
    }

    void RestartCounterIfNeeded(uint32_t fired_of_mask) {
        if ((fired_of_mask & kGptOf1) == 0) return;
        const uint32_t cr = gptcr_.load(std::memory_order_acquire);
        if ((cr & kGptcrFrr) != 0) return;
        if ((cr & kGptcrEn) == 0) return;
        baseline_packed_.store(PackPair(0u, GuestCycles()),
                               std::memory_order_release);
        last_seen_count_ = 0u;
        const uint32_t ocr1 = gptocr_[0].load(std::memory_order_acquire);
        ocr_anchor_[0].store(PackPair(ocr1, 0u),
                             std::memory_order_release);
    }

    void CheckAndFire() {
        const uint32_t div = EffectiveDivider();
        if (div == 0) return;

        /* DO NOT hoist ReadCounter above this pair-load — JIT-thread
           WriteOcr re-anchors with a fresher count_at_write, and a
           hoisted ReadCounter would underflow forward_to_now into an
           unsigned wrap that fires the match spuriously. */
        uint64_t pairs[3];
        for (int n = 0; n < 3; ++n) {
            pairs[n] = ocr_anchor_[n].load(std::memory_order_acquire);
        }
        const uint32_t sr_snap = gptsr_.load(std::memory_order_acquire);
        const uint32_t count_now = ReadCounter();

        uint32_t newly = 0;
        for (int n = 0; n < 3; ++n) {
            const uint32_t of_bit = 1u << n;
            if ((sr_snap & of_bit) != 0) continue;
            if (!MatchHasFired(LoOf(pairs[n]), HiOf(pairs[n]), count_now)) continue;
            newly |= of_bit;
        }
        if (CheckRollover(count_now)) newly |= kGptRov;
        if (newly == 0) return;

        gptsr_.fetch_or(newly, std::memory_order_acq_rel);
        RestartCounterIfNeeded(newly);

        const uint32_t ir = gptir_.load(std::memory_order_acquire);
        if ((gptsr_.load(std::memory_order_acquire) & ir) != 0) {
            emu_.Get<Imx31Avic>().AssertSource(kAvicSourceGpt);
        }
    }

    bool AnyChannelArmed() const {
        if (EffectiveDivider() == 0) return false;
        const uint32_t sr = gptsr_.load(std::memory_order_acquire);
        const uint32_t ir = gptir_.load(std::memory_order_acquire);
        return ((~sr) & kGptStatusMask) != 0 || ir != 0;
    }

    void MatchLoop() {
        std::unique_lock<std::mutex> lk(cv_mtx_);
        while (!stop_.load(std::memory_order_acquire)) {
            lk.unlock();
            RebaseToCurrent();
            CheckAndFire();
            lk.lock();
            if (stop_.load(std::memory_order_acquire)) break;
            if (AnyChannelArmed()) {
                cv_.wait_for(lk, kPollInterval);
            } else {
                cv_.wait(lk);
            }
        }
    }
};

uint32_t Imx31Gpt::ReadWord(uint32_t addr) {
    const uint32_t off = addr - kBase;
    if (off >= kRegEnd || (off & 0x3u) != 0u) {
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }
    return ReadReg(off);
}

void Imx31Gpt::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - kBase;
    if (off >= kRegEnd || (off & 0x3u) != 0u) {
        HaltUnsupportedAccess("WriteWord", addr, value);
    }
    WriteReg(off, value);
}

}  /* namespace */

REGISTER_SERVICE(Imx31Gpt);

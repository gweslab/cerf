#pragma once

#include "../peripherals/peripheral_base.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../boards/board_context.h"
#include "../cpu/arm_processor_config.h"
#include "../jit/arm/arm_jit.h"
#include "../jit/arm/cpu_state.h"
#include "../peripherals/peripheral_dispatcher.h"
#include "../state/emulation_freeze.h"
#include "../state/state_stream.h"
#include "freescale_gpt_regs.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

/* Shared Freescale GPT core: counter/compare/SWR model identical on i.MX31 and
   i.MX51; the IRQ line is per-concrete via Assert/DeassertIrqLine. */
namespace cerf_freescale_gpt_detail {

template <uint32_t kBase, const std::string_view& kSoc>
class FreescaleGptBase : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == kSoc;
    }

    void OnReady() override {
        auto& cfg = emu_.Get<ArmProcessorConfig>();
        cpu_to_ipg_      = cfg.CpuToOscrDivider();
        cpu_to_highfreq_ = cfg.CpuToHighfreqClockDivider();
        cpu_to_lowfreq_  = cfg.CpuToLowfreqClockDivider();
        if (cpu_to_ipg_      == 0) cpu_to_ipg_      = 1;
        if (cpu_to_highfreq_ == 0) cpu_to_highfreq_ = 1;
        if (cpu_to_lowfreq_  == 0) cpu_to_lowfreq_  = 1;
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

    ~FreescaleGptBase() override { StopMatchThread(); }

    /* Match thread raises INTC IRQs; stop it before any peer is destroyed. */
    void OnShutdown() override { StopMatchThread(); }

    void StopMatchThread() {
        stop_.store(true, std::memory_order_release);
        cv_.notify_all();
        if (match_thread_.joinable()) match_thread_.join();
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    FastReadFn  FastReader() override { return &FreescaleGptBase::FastReadThunk; }
    FastWriteFn FastWriter() override { return &FreescaleGptBase::FastWriteThunk; }

    static uint32_t FastReadThunk(void* ctx, uint32_t off, uint32_t width) {
        return static_cast<FreescaleGptBase*>(ctx)->FastRead(off, width);
    }
    static void FastWriteThunk(void* ctx, uint32_t off, uint32_t value, uint32_t width) {
        static_cast<FreescaleGptBase*>(ctx)->FastWrite(off, value, width);
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

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        if (off >= kRegEnd || (off & 0x3u) != 0u) {
            HaltUnsupportedAccess("ReadWord", addr, 0);
        }
        return ReadReg(off);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - kBase;
        if (off >= kRegEnd || (off & 0x3u) != 0u) {
            HaltUnsupportedAccess("WriteWord", addr, value);
        }
        WriteReg(off, value);
    }

    void SaveState(StateWriter& w) override {
        w.Write("gptcr", gptcr_.load(std::memory_order_acquire));
        w.Write("gptpr", gptpr_.load(std::memory_order_acquire));
        w.Write("gptsr", gptsr_.load(std::memory_order_acquire));
        w.Write("gptir", gptir_.load(std::memory_order_acquire));
        for (int n = 0; n < 3; ++n) w.Write("gptocr", gptocr_[n].load(std::memory_order_acquire));
        for (int n = 0; n < 2; ++n) w.Write("gpticr", gpticr_[n].load(std::memory_order_acquire));
        for (int n = 0; n < 3; ++n) w.Write("ocr_anchor", ocr_anchor_[n].load(std::memory_order_acquire));
        w.Write("frozen_count", frozen_count_.load(std::memory_order_acquire));
        w.Write("last_seen_count", last_seen_count_);
        w.Write<uint32_t>("counter", ReadCounter());
    }
    void RestoreState(StateReader& r) override {
        uint32_t v = 0;
        uint64_t u = 0;
        r.Read("gptcr", v); gptcr_.store(v, std::memory_order_release);
        r.Read("gptpr", v); gptpr_.store(v, std::memory_order_release);
        r.Read("gptsr", v); gptsr_.store(v, std::memory_order_release);
        r.Read("gptir", v); gptir_.store(v, std::memory_order_release);
        for (int n = 0; n < 3; ++n) { r.Read("gptocr", v); gptocr_[n].store(v, std::memory_order_release); }
        for (int n = 0; n < 2; ++n) { r.Read("gpticr", v); gpticr_[n].store(v, std::memory_order_release); }
        for (int n = 0; n < 3; ++n) { r.Read("ocr_anchor", u); ocr_anchor_[n].store(u, std::memory_order_release); }
        r.Read("frozen_count", v); frozen_count_.store(v, std::memory_order_release);
        r.Read("last_seen_count", last_seen_count_);
        uint32_t cnt = 0;
        r.Read("counter", cnt);
        baseline_packed_.store(PackPair(cnt, GuestCycles()), std::memory_order_release);
        cv_.notify_all();
    }

    /* Re-assert the INTC line from restored GPTSR&GPTIR (a re-driven level). */
    void PostRestore() override {
        const uint32_t pending = gptsr_.load(std::memory_order_acquire) &
                                 gptir_.load(std::memory_order_acquire);
        if (pending != 0) AssertIrqLine();
        else              DeassertIrqLine();
    }

protected:
    /* Per-SoC IRQ line: i.MX31 AVIC src29 / i.MX51 TZIC src39. */
    virtual void AssertIrqLine()   = 0;
    virtual void DeassertIrqLine() = 0;

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
    uint32_t cpu_to_highfreq_{1};
    uint32_t cpu_to_lowfreq_{1};

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
        const uint32_t pre = gptpr_.load(std::memory_order_acquire) & 0xFFFu;
        switch (clksrc) {
            case kClksrcNone:     return 0;
            case kClksrcIpgClk:   return cpu_to_ipg_      * (pre + 1u);
            case kClksrcHighfreq: return cpu_to_highfreq_ * (pre + 1u);
            case kClksrcLowfreq:  return cpu_to_lowfreq_  * (pre + 1u);
        }
        return 0;   /* unsupported CLKSRC is rejected at GPTCR write */
    }

    uint32_t ReadCounter() const {
        const uint32_t div = EffectiveDivider();
        if (div == 0) return frozen_count_.load(std::memory_order_acquire);
        const uint64_t packed = baseline_packed_.load(std::memory_order_acquire);
        const uint32_t cycles_now = GuestCycles();
        const uint32_t delta = cycles_now - LoOf(packed);
        return HiOf(packed) + (delta / div);
    }

    /* Rebase each poll: the 32-bit cycle delta wraps (~43 s) and would jump the counter back. */
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

    /* Anchored forward-crossing: a far-behind OCR would otherwise match every poll. */
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

        /* §34.3.3.5 / §36.3.2.5: OCR1 write in restart mode resets counter. */
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

        /* §34.4.1[15] / §36.3.2.1[15] SWR: self-clearing; resets all regs
           except the bits in kGptcrSwrPreserve. */
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

        /* Rebase across EN/CLKSRC edges: the kernel reads GPTCNT mid-write; a jump reads negative. */
        const bool was_en = (old_cr & kGptcrEn) != 0;
        const bool now_en = (new_cr & kGptcrEn) != 0;
        const uint32_t old_clksrc = (old_cr & kGptcrClksrcM) >> kGptcrClksrcSh;
        const uint32_t new_clksrc = (new_cr & kGptcrClksrcM) >> kGptcrClksrcSh;

        /* Sample before gptcr_.store: a post-store ReadCounter with new CLKSRC=000 reads frozen 0. */
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

        if (new_clksrc != kClksrcNone && new_clksrc != kClksrcIpgClk &&
            new_clksrc != kClksrcHighfreq && new_clksrc != kClksrcLowfreq) {
            LOG(Periph,
                "[GPT] unsupported CLKSRC=%u; only 000/001/010/100 wired\n",
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
        /* §34.3.3.3 Table 34-8 / §36.3.2.3: all bits w1c. */
        const uint32_t mask = value & kGptStatusMask;
        const uint32_t prev = gptsr_.fetch_and(~mask, std::memory_order_acq_rel);
        const uint32_t cleared = prev & mask;
        if (cleared == 0) return;

        /* Re-anchor cleared channels so MatchHasFired sees a fresh crossing. */
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
            DeassertIrqLine();
        }
        cv_.notify_all();
    }

    void WriteGptir(uint32_t value) {
        gptir_.store(value & kGptStatusMask, std::memory_order_release);
        const uint32_t pending =
            gptsr_.load(std::memory_order_acquire) &
            gptir_.load(std::memory_order_acquire);
        if (pending != 0) AssertIrqLine();
        else              DeassertIrqLine();
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

        /* ReadCounter after the ocr_anchor pair-load - a concurrent WriteOcr re-anchors between. */
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
            AssertIrqLine();
        }
    }

    bool AnyChannelArmed() const {
        if (EffectiveDivider() == 0) return false;
        const uint32_t sr = gptsr_.load(std::memory_order_acquire);
        const uint32_t ir = gptir_.load(std::memory_order_acquire);
        return ((~sr) & kGptStatusMask) != 0 || ir != 0;
    }

    void MatchLoop() {
        auto& freeze = emu_.Get<EmulationFreeze>();
        std::unique_lock<std::mutex> lk(cv_mtx_);
        while (!stop_.load(std::memory_order_acquire)) {
            lk.unlock();
            {
                auto frozen = freeze.WorkerSection();
                RebaseToCurrent();
                CheckAndFire();
            }
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

}  /* namespace cerf_freescale_gpt_detail */

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

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

/* Shared EPIT core. The EPIT IP is register-identical on i.MX31 (MCIMX31RM Ch 33)
   and i.MX51 (MCIMX51RM Ch 29) - registers/offsets/reset-values/EPITCR-SWR-mode all
   match (verified MCIMX51RM Table 29-2 + Figure 29-3) - so the model is shared; only
   the IRQ line differs (AVIC vs TZIC source), per-concrete via Assert/DeassertIrqLine. */
namespace cerf_freescale_epit_detail {

constexpr uint32_t kEpitSize = 0x00004000u;
constexpr uint32_t kRegEnd   = 0x14u;

/* MCIMX31RM Table 33-5 / MCIMX51RM Table 29-2. */
constexpr uint32_t kOffCr    = 0x00u;
constexpr uint32_t kOffSr    = 0x04u;
constexpr uint32_t kOffLr    = 0x08u;
constexpr uint32_t kOffCmpr  = 0x0Cu;
constexpr uint32_t kOffCnt   = 0x10u;

/* MCIMX31RM Table 33-6 / MCIMX51RM Table 29-5 EPITCR. */
constexpr uint32_t kCrEnMask         = 1u << 0;
constexpr uint32_t kCrEnmodMask      = 1u << 1;
constexpr uint32_t kCrOcienMask      = 1u << 2;
constexpr uint32_t kCrRldMask        = 1u << 3;
constexpr uint32_t kCrPrescalerShift = 4;
constexpr uint32_t kCrPrescalerMask  = 0xFFFu << kCrPrescalerShift;
constexpr uint32_t kCrSwrMask        = 1u << 16;
constexpr uint32_t kCrIovwMask       = 1u << 17;
constexpr uint32_t kCrClksrcShift    = 24;
constexpr uint32_t kCrClksrcMask     = 0x3u << kCrClksrcShift;
/* SWR description: preserves EN/ENMOD/STOPEN/DOZEN/WAITEN/DBGEN. DOZEN(20) is
   reserved-0 on i.MX51, so preserving it there is a no-op. */
constexpr uint32_t kCrSwrPreserveMask =
    (1u <<  0) |  /* EN     */
    (1u <<  1) |  /* ENMOD  */
    (1u << 18) |  /* DBGEN  */
    (1u << 19) |  /* WAITEN */
    (1u << 20) |  /* DOZEN  (i.MX31 only; reserved on i.MX51) */
    (1u << 21);   /* STOPEN */

/* CLKSRC values (MCIMX31RM §33.6.1.1 / MCIMX51RM Table 29-5). */
constexpr uint32_t kClksrcOff            = 0u;
constexpr uint32_t kClksrcIpgClk         = 1u;
constexpr uint32_t kClksrcIpgClkHighfreq = 2u;
constexpr uint32_t kClksrcIpgClk32k      = 3u;

/* OCIF (bit 0) is w1c (MCIMX31RM Table 33-7 / MCIMX51RM Table 29-6). */
constexpr uint32_t kSrOcifMask = 1u << 0;

/* Reset rows (MCIMX31RM Figure 33-6/33-8 / MCIMX51RM Table 29-2). */
constexpr uint32_t kLrResetValue  = 0xFFFFFFFFu;
constexpr uint32_t kCntResetValue = 0xFFFFFFFFu;

constexpr auto kPollInterval = std::chrono::microseconds(100);

template <uint32_t kBase, const std::string_view& kSoc>
class FreescaleEpitBase : public Peripheral {
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
        baseline_packed_.store(PackPair(kCntResetValue, GuestCycles()),
                               std::memory_order_release);
        anchor_cnt_.store(kCntResetValue, std::memory_order_release);
        emu_.Get<PeripheralDispatcher>().Register(this);
        match_thread_ = std::thread([this] { MatchLoop(); });
    }

    ~FreescaleEpitBase() override { StopMatchThread(); }

    /* Match thread raises INTC IRQs; stop it before any peer is destroyed. */
    void OnShutdown() override { StopMatchThread(); }

    void StopMatchThread() {
        stop_.store(true, std::memory_order_release);
        cv_.notify_all();
        if (match_thread_.joinable()) match_thread_.join();
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kEpitSize; }

    FastReadFn  FastReader() override { return &FreescaleEpitBase::FastReadThunk; }
    FastWriteFn FastWriter() override { return &FreescaleEpitBase::FastWriteThunk; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        if (off < kRegEnd && (off & 0x3u) == 0) return ReadReg(off);
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - kBase;
        if (off < kRegEnd && (off & 0x3u) == 0) { WriteReg(off, value); return; }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    static uint32_t FastReadThunk(void* ctx, uint32_t off, uint32_t width) {
        return static_cast<FreescaleEpitBase*>(ctx)->FastRead(off, width);
    }
    static void FastWriteThunk(void* ctx, uint32_t off, uint32_t value, uint32_t width) {
        static_cast<FreescaleEpitBase*>(ctx)->FastWrite(off, value, width);
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

    void SaveState(StateWriter& w) override {
        w.Write("cr", cr_.load(std::memory_order_acquire));
        w.Write("sr", sr_.load(std::memory_order_acquire));
        w.Write("lr", lr_.load(std::memory_order_acquire));
        w.Write("cmpr", cmpr_.load(std::memory_order_acquire));
        w.Write("anchor_cnt", anchor_cnt_.load(std::memory_order_acquire));
        w.Write("frozen_cnt", frozen_cnt_.load(std::memory_order_acquire));
        w.Write<uint32_t>("counter", ReadCounter());
    }
    void RestoreState(StateReader& r) override {
        uint32_t cr = 0, sr = 0, lr = 0, cmpr = 0, anchor = 0, frozen = 0, cnt = 0;
        r.Read("cr", cr); r.Read("sr", sr); r.Read("lr", lr); r.Read("cmpr", cmpr);
        r.Read("anchor_cnt", anchor); r.Read("frozen_cnt", frozen); r.Read("counter", cnt);
        cr_.store(cr,        std::memory_order_release);
        sr_.store(sr,        std::memory_order_release);
        lr_.store(lr,        std::memory_order_release);
        cmpr_.store(cmpr,    std::memory_order_release);
        anchor_cnt_.store(anchor, std::memory_order_release);
        frozen_cnt_.store(frozen, std::memory_order_release);
        /* Re-anchor so ReadCounter() yields the saved CNT against the
           restored guest_cycle_counter. */
        baseline_packed_.store(PackPair(cnt, GuestCycles()), std::memory_order_release);
        cv_.notify_all();
    }

    /* Re-assert the INTC line from the restored OCIF/OCIEN - the EPIT compare
       output is a level the source re-drives after restore. */
    void PostRestore() override { RefreshIrq(); }

protected:
    /* Per-SoC interrupt line. i.MX31 -> Imx31Avic::Assert/DeassertSource(src);
       i.MX51 -> Imx51Tzic::AssertIrq/DeAssertIrq(src). */
    virtual void AssertIrqLine()    = 0;
    virtual void DeassertIrqLine()  = 0;

private:
    std::mutex              cv_mtx_;
    std::condition_variable cv_;
    std::thread             match_thread_;
    std::atomic<bool>       stop_{false};

    std::atomic<uint32_t> cr_{0};
    std::atomic<uint32_t> sr_{0};
    std::atomic<uint32_t> lr_{kLrResetValue};
    std::atomic<uint32_t> cmpr_{0};
    /* hi = baseline CNT, lo = guest_cycle_counter snapshot. */
    std::atomic<uint64_t> baseline_packed_{0};
    std::atomic<uint32_t> frozen_cnt_{kCntResetValue};
    /* CNT value at the moment the compare channel was last (re)armed
       (EN edge, CMPR write, or OCIF clear). The down-crossing of CMPR
       is measured relative to this so a far-behind CMPR doesn't fire
       every poll. */
    std::atomic<uint32_t> anchor_cnt_{kCntResetValue};

    uint32_t cpu_to_ipg_      = 1;
    uint32_t cpu_to_highfreq_ = 1;
    uint32_t cpu_to_lowfreq_  = 1;

    static uint64_t PackPair(uint32_t hi, uint32_t lo) {
        return (static_cast<uint64_t>(hi) << 32) | lo;
    }
    static uint32_t HiOf(uint64_t p) { return static_cast<uint32_t>(p >> 32); }
    static uint32_t LoOf(uint64_t p) { return static_cast<uint32_t>(p); }

    uint32_t GuestCycles() const {
        return emu_.Get<ArmJit>().CpuState()->guest_cycle_counter;
    }

    uint32_t EffectiveDivider() const {
        const uint32_t cr = cr_.load(std::memory_order_acquire);
        if ((cr & kCrEnMask) == 0) return 0;
        const uint32_t clksrc    = (cr & kCrClksrcMask)    >> kCrClksrcShift;
        const uint32_t prescaler = (cr & kCrPrescalerMask) >> kCrPrescalerShift;
        switch (clksrc) {
            case kClksrcOff:             return 0;
            case kClksrcIpgClk:          return cpu_to_ipg_      * (prescaler + 1);
            case kClksrcIpgClkHighfreq:  return cpu_to_highfreq_ * (prescaler + 1);
            case kClksrcIpgClk32k:       return cpu_to_lowfreq_  * (prescaler + 1);
        }
        return 0;
    }

    uint32_t ReadCounter() const {
        const uint32_t div = EffectiveDivider();
        if (div == 0) return frozen_cnt_.load(std::memory_order_acquire);
        const uint64_t packed = baseline_packed_.load(std::memory_order_acquire);
        const uint32_t delta_cyc     = GuestCycles() - LoOf(packed);
        const uint32_t elapsed_ticks = delta_cyc / div;
        const uint32_t base_cnt      = HiOf(packed);

        if ((cr_.load(std::memory_order_acquire) & kCrRldMask) == 0) {
            /* Free-Running mode: rolls 0 -> 0xFFFFFFFF. */
            return base_cnt - elapsed_ticks;
        }
        /* Set-and-Forget mode: when CNT reaches 0, reload from LR;
           period = LR + 1 ticks. */
        const uint32_t period = lr_.load(std::memory_order_acquire) + 1u;
        if (period == 0) {
            return base_cnt - elapsed_ticks;
        }
        const uint32_t ticks_in_period = elapsed_ticks % period;
        if (ticks_in_period <= base_cnt) {
            return base_cnt - ticks_in_period;
        }
        const uint32_t overshoot = ticks_in_period - base_cnt;
        return lr_.load(std::memory_order_acquire) - (overshoot - 1u);
    }

    /* Anchored down-crossing: the compare has fired once the counter has
       descended from anchor_cnt past cmpr. */
    static bool CompareHasFired(uint32_t anchor_cnt, uint32_t cmpr,
                                uint32_t count_now) {
        const uint32_t descent_target = anchor_cnt - cmpr;
        const uint32_t descent_now    = anchor_cnt - count_now;
        return descent_now >= descent_target;
    }

    void Rearm(uint32_t count_now) {
        anchor_cnt_.store(count_now, std::memory_order_release);
    }

    void RefreshIrq() {
        const bool pending = (sr_.load(std::memory_order_acquire) & kSrOcifMask) != 0 &&
                             (cr_.load(std::memory_order_acquire) & kCrOcienMask) != 0;
        if (pending) AssertIrqLine();
        else         DeassertIrqLine();
    }

    uint32_t ReadReg(uint32_t off) const {
        switch (off) {
            case kOffCr:   return cr_.load(std::memory_order_acquire);
            case kOffSr:   return sr_.load(std::memory_order_acquire);
            case kOffLr:   return lr_.load(std::memory_order_acquire);
            case kOffCmpr: return cmpr_.load(std::memory_order_acquire);
            case kOffCnt:  return ReadCounter();
        }
        const_cast<FreescaleEpitBase*>(this)->HaltUnsupportedAccess(
            "ReadReg", kBase + off, 0);
    }

    void WriteReg(uint32_t off, uint32_t value) {
        switch (off) {
            case kOffCr:   WriteCr(value); return;
            case kOffSr:   WriteSr(value); return;
            case kOffLr:   WriteLr(value); return;
            case kOffCmpr: WriteCmpr(value); return;
        }
        HaltUnsupportedAccess("WriteReg", kBase + off, value);
    }

    void WriteSr(uint32_t value) {
        /* OCIF is write-one-to-clear; re-anchor so the next descent past CMPR
           is detected fresh (the ISR re-arms CMPR for the following tick). */
        if ((value & kSrOcifMask) == 0) return;
        sr_.fetch_and(~kSrOcifMask, std::memory_order_acq_rel);
        Rearm(ReadCounter());
        RefreshIrq();
        cv_.notify_all();
    }

    void WriteCmpr(uint32_t value) {
        cmpr_.store(value, std::memory_order_release);
        Rearm(ReadCounter());
        cv_.notify_all();
    }

    void WriteCr(uint32_t value) {
        if (value & kCrSwrMask) {
            cr_.store(value & kCrSwrPreserveMask, std::memory_order_release);
            sr_.store(0, std::memory_order_release);
            lr_.store(kLrResetValue, std::memory_order_release);
            cmpr_.store(0, std::memory_order_release);
            baseline_packed_.store(PackPair(kCntResetValue, GuestCycles()),
                                   std::memory_order_release);
            frozen_cnt_.store(kCntResetValue, std::memory_order_release);
            anchor_cnt_.store(kCntResetValue, std::memory_order_release);
            RefreshIrq();
            cv_.notify_all();
            return;
        }

        const uint32_t old_cr = cr_.load(std::memory_order_acquire);
        const bool was_en = (old_cr & kCrEnMask) != 0;
        const bool now_en = (value  & kCrEnMask) != 0;
        const uint32_t sampled_cnt =
            was_en ? ReadCounter() : frozen_cnt_.load(std::memory_order_acquire);

        cr_.store(value, std::memory_order_release);

        if (!was_en && now_en) {
            /* ENMOD: when set, EN edge loads CNT from LR (RLD=1) or
               0xFFFFFFFF (RLD=0); when cleared, CNT resumes from frozen. */
            const uint32_t start = (value & kCrEnmodMask)
                                       ? ((value & kCrRldMask)
                                              ? lr_.load(std::memory_order_acquire)
                                              : kCntResetValue)
                                       : sampled_cnt;
            baseline_packed_.store(PackPair(start, GuestCycles()),
                                   std::memory_order_release);
            Rearm(start);
        } else if (was_en && !now_en) {
            frozen_cnt_.store(sampled_cnt, std::memory_order_release);
        } else if (was_en && now_en) {
            baseline_packed_.store(PackPair(sampled_cnt, GuestCycles()),
                                   std::memory_order_release);
            Rearm(sampled_cnt);
        }
        RefreshIrq();
        cv_.notify_all();
    }

    void WriteLr(uint32_t value) {
        lr_.store(value, std::memory_order_release);
        /* IOVW (bit 17) gates LR->CNT propagation. */
        if (cr_.load(std::memory_order_acquire) & kCrIovwMask) {
            baseline_packed_.store(PackPair(value, GuestCycles()),
                                   std::memory_order_release);
            Rearm(value);
        }
        cv_.notify_all();
    }

    /* MUST run every poll: guest_cycle_counter is 32-bit, so the
       GuestCycles()-baseline_cyc delta wraps every ~2^32 cycles and
       ReadCounter jumps backward unless the baseline is slid forward. */
    void RebaseToCurrent() {
        if (EffectiveDivider() == 0) return;
        const uint32_t cnt_now = ReadCounter();
        baseline_packed_.store(PackPair(cnt_now, GuestCycles()),
                               std::memory_order_release);
    }

    void CheckAndFire() {
        if (EffectiveDivider() == 0) return;
        if ((sr_.load(std::memory_order_acquire) & kSrOcifMask) != 0) return;
        const uint32_t anchor    = anchor_cnt_.load(std::memory_order_acquire);
        const uint32_t cmpr      = cmpr_.load(std::memory_order_acquire);
        const uint32_t count_now = ReadCounter();
        if (!CompareHasFired(anchor, cmpr, count_now)) return;
        sr_.fetch_or(kSrOcifMask, std::memory_order_acq_rel);
        RefreshIrq();
    }

    bool Armed() const {
        if (EffectiveDivider() == 0) return false;
        return (sr_.load(std::memory_order_acquire) & kSrOcifMask) == 0;
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
            if (Armed()) cv_.wait_for(lk, kPollInterval);
            else         cv_.wait(lk);
        }
    }
};

}  /* namespace cerf_freescale_epit_detail */

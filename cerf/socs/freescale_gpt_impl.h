#pragma once

#include "../peripherals/peripheral_base.h"

#include "../boards/board_context.h"
#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "../core/log.h"
#include "../jit/guest_cycle_clock.h"
#include "../peripherals/peripheral_dispatcher.h"
#include "../state/state_stream.h"
#include "cycle_anchored_counter.h"
#include "freescale_gpt_count.h"
#include "freescale_gpt_regs.h"
#include "freescale_timer_clocks.h"
#include "guest_cpu_reset.h"

#include <cstdint>
#include <string_view>

namespace cerf_freescale_gpt_detail {

template <uint32_t kBase, const std::string_view& kSoc, typename Traits>
class FreescaleGptBase : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == kSoc;
    }

    void OnReady() override {
        clock_  = &emu_.Get<GuestCycleClock>();
        clocks_ = &emu_.Get<FreescaleTimerClocks>();
        event_  = clock_->Add([this] { OnEvent(); });
        clock_->RegisterRateListener([this] { Retime(); });
        clock_->RegisterIdleListener([this] { OnIdle(); });
        clock_->RegisterIdleExitListener([this] { OnIdleExit(); });
        clocks_->RegisterRateListener([this] { Retime(); });
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            ResetRegisters(0u);
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    FastReadFn  FastReader() override { return &FreescaleGptBase::FastReadThunk; }
    FastWriteFn FastWriter() override { return &FreescaleGptBase::FastWriteThunk; }

    uint32_t ReadWord(uint32_t addr) override { return FastRead(addr - kBase, 4u); }
    void WriteWord(uint32_t addr, uint32_t value) override {
        FastWrite(addr - kBase, value, 4u);
    }

    void SaveState(StateWriter& w) override {
        const uint64_t now = clock_->Cycles();
        w.Write<uint32_t>("gptcr", cr_);
        w.Write<uint32_t>("gptpr", pr_);
        w.Write<uint32_t>("gptsr", sr_);
        w.Write<uint32_t>("gptir", ir_);
        w.WriteBytes("gptocr", ocr_, sizeof(ocr_));
        w.Write<uint32_t>("count", Count(now));
        w.Write<uint64_t>("prescale_phase", counting_ ? counter_.PhaseAt(now) : phase_);
        w.Write<uint64_t>("prescale_phase_den",
                          counting_ ? counter_.PhaseDenominator() : phase_den_);
    }

    void RestoreState(StateReader& r) override {
        uint32_t cr = 0, pr = 0, sr = 0, ir = 0, count = 0;
        uint32_t ocr[3] = {};
        uint64_t phase = 0, den = 0;
        r.Read("gptcr", cr);
        r.Read("gptpr", pr);
        r.Read("gptsr", sr);
        r.Read("gptir", ir);
        r.ReadBytes("gptocr", ocr, sizeof(ocr));
        r.Read("count", count);
        r.Read("prescale_phase", phase);
        r.Read("prescale_phase_den", den);
        clock_->Disarm(event_);
        counting_   = false;
        suspended_  = false;
        pending_sr_ = 0u;
        cr_         = cr;
        pr_         = pr;
        sr_         = sr;
        ir_         = ir;
        for (int n = 0; n < 3; ++n) ocr_[n] = ocr[n];
        base_value_ = count;
        phase_      = phase;
        phase_den_  = den;
    }

    void PostRestore() override {
        Retime();
        RefreshIrq();
    }

protected:
    virtual void AssertIrqLine()   = 0;
    virtual void DeassertIrqLine() = 0;

private:
    static uint32_t FastReadThunk(void* ctx, uint32_t off, uint32_t width) {
        return static_cast<FreescaleGptBase*>(ctx)->FastRead(off, width);
    }
    static void FastWriteThunk(void* ctx, uint32_t off, uint32_t value, uint32_t width) {
        static_cast<FreescaleGptBase*>(ctx)->FastWrite(off, value, width);
    }

    static uint32_t Clksrc(uint32_t cr) { return (cr >> kGptcrClksrcSh) & 0x7u; }

    uint32_t FastRead(uint32_t off, uint32_t width) {
        if (width != 4u) HaltUnsupportedAccess("FastRead", kBase + off, 0);
        switch (off) {
            case kOffGptcr:   return cr_;
            case kOffGptpr:   return pr_;
            case kOffGptsr:   return sr_;
            case kOffGptir:   return ir_;
            case kOffGptocr1: return ocr_[0];
            case kOffGptocr2: return ocr_[1];
            case kOffGptocr3: return ocr_[2];
            case kOffGpticr1:
            case kOffGpticr2: return 0u;
            case kOffGptcnt:  return ReadCount();
            default: break;
        }
        HaltUnsupportedAccess("FastRead", kBase + off, 0);
    }

    /* MCIMX31RM Table 34-4 / MCIMX51RM Table 36-4: writes to read-only bits have no
       effect. */
    void FastWrite(uint32_t off, uint32_t value, uint32_t width) {
        if (width != 4u) HaltUnsupportedAccess("FastWrite", kBase + off, value);
        switch (off) {
            case kOffGptcr:   WriteCr(value); return;
            case kOffGptpr:   WritePr(value); return;
            case kOffGptsr:   WriteSr(value); return;
            case kOffGptir:   WriteIr(value); return;
            case kOffGptocr1: WriteOcr(0, value); return;
            case kOffGptocr2: WriteOcr(1, value); return;
            case kOffGptocr3: WriteOcr(2, value); return;
            case kOffGpticr1:
            case kOffGpticr2:
            case kOffGptcnt:  return;
            default: break;
        }
        HaltUnsupportedAccess("FastWrite", kBase + off, value);
    }

    GptCountSequence Sequence() const {
        return GptCountSequence(base_value_, (cr_ & kGptcrFrr) != 0u, ocr_[0]);
    }

    uint64_t TicksAt(uint64_t now) const { return counter_.TicksSince(now) - base_tick_; }

    uint32_t Count(uint64_t now) const {
        return counting_ ? Sequence().ValueAt(TicksAt(now)) : base_value_;
    }

    /* MCIMX31RM Table 34-6 / MCIMX51RM Table 36-5 ENMOD: the field value says the
       counter resets when disabled, the field text says it resets on enabling. */
    uint32_t ReadCount() {
        if ((cr_ & (kGptcrEn | kGptcrEnmod)) == kGptcrEnmod && base_value_ != 0u) {
            emu_.Get<Fatal>().Die("GPT %08X: GPTCNT read while disabled with ENMOD set and "
                                  "0x%08X frozen; the value is not established", kBase,
                                  base_value_);
        }
        return Count(clock_->Cycles());
    }

    /* MCIMX31RM 34.4.1.3 / MCIMX51RM 36.4.3: OFn sets when GPTOCRn matches GPTCNT;
       Table 34-8 / 36-7 ROV sets on the 0xFFFFFFFF to 0 rollover. */
    uint32_t HitsIn(uint64_t after, uint64_t upto) const {
        const GptCountSequence seq = Sequence();
        uint32_t bits = 0u;
        uint64_t at   = 0u;
        for (int n = 0; n < 3; ++n) {
            if (seq.NextCompare(ocr_[n], after, at) && at <= upto) bits |= kGptOf1 << n;
        }
        if (seq.NextRollover(after, at) && at <= upto) bits |= kGptRov;
        return bits;
    }

    bool NextEvent(uint64_t after, uint64_t& at) const {
        const GptCountSequence seq = Sequence();
        const uint32_t seen = sr_ | pending_sr_;
        bool     found = false;
        uint64_t hit   = 0u;
        for (int n = 0; n < 3; ++n) {
            if ((seen & (kGptOf1 << n)) != 0u || !seq.NextCompare(ocr_[n], after, hit)) continue;
            if (!found || hit < at) at = hit;
            found = true;
        }
        if ((seen & kGptRov) == 0u && seq.NextRollover(after, hit)) {
            if (!found || hit < at) at = hit;
            found = true;
        }
        return found;
    }

    void CaptureDue(uint64_t now) {
        if (!counting_) return;
        const uint64_t t = TicksAt(now);
        if (clock_->IsDue(event_, now)) pending_sr_ |= HitsIn(last_eval_, t);
        last_eval_ = t;
    }

    void Arm(uint64_t now) {
        uint64_t at = 0u;
        if (pending_sr_ != 0u)                         clock_->Arm(event_, now);
        else if (counting_ && NextEvent(last_eval_, at)) clock_->Arm(event_,
                                                             counter_.CycleOfTick(base_tick_ + at));
        else                                           clock_->Disarm(event_);
    }

    void OnEvent() {
        const uint64_t now = clock_->Cycles();
        sr_ |= pending_sr_;
        pending_sr_ = 0u;
        if (counting_) {
            const uint64_t t = TicksAt(now);
            sr_ |= HitsIn(last_eval_, t);
            last_eval_ = t;
        }
        RefreshIrq();
        Arm(now);
    }

    void RefreshIrq() {
        if ((sr_ & ir_ & kGptStatusMask) != 0u) AssertIrqLine();
        else                                    DeassertIrqLine();
    }

    FreescaleTimerInput Input() const {
        switch (Traits::Clksrc(Clksrc(cr_))) {
            case GptClockInput::kIpg:      return FreescaleTimerInput::kIpg;
            case GptClockInput::kHighfreq: return FreescaleTimerInput::kHighfreq;
            default:                       return FreescaleTimerInput::kLowfreq;
        }
    }

    uint64_t EnabledInputHz() const {
        if (suspended_ || (cr_ & kGptcrEn) == 0u ||
            Traits::Clksrc(Clksrc(cr_)) == GptClockInput::kNone) {
            return 0u;
        }
        return clocks_->InputHz(FreescaleTimerUnit::kGpt, Input());
    }

    uint64_t RatioCycles() const { return clock_->CpuHz() * (uint64_t{pr_} + 1u); }

    void RequireScale(bool ok, uint64_t input_hz) const {
        if (!ok) {
            emu_.Get<Fatal>().Die("GPT %08X: %llu Hz input / %u against the %llu Hz core "
                                  "overflows the 64-bit scale", kBase,
                                  static_cast<unsigned long long>(input_hz), pr_ + 1u,
                                  static_cast<unsigned long long>(clock_->CpuHz()));
        }
    }

    void Rebase(uint64_t now) {
        base_value_ = Count(now);
        base_tick_  = counter_.TicksSince(now);
        last_eval_  = 0u;
    }

    void Freeze(uint64_t now, bool keep_phase) {
        base_value_ = Count(now);
        if (keep_phase) {
            phase_     = counter_.PhaseAt(now);
            phase_den_ = counter_.PhaseDenominator();
        } else {
            ResetPrescaler();
        }
        counting_  = false;
        last_eval_ = 0u;
    }

    /* MCIMX51RM Table 36-6 and Figure 36-13, MCIMX31RM Figure 34-15: after a prescaler
       counter reset the next prescaled pulse comes one input clock later. */
    void ResetPrescaler() {
        phase_     = pr_;
        phase_den_ = uint64_t{pr_} + 1u;
    }

    void Resume(uint64_t now, uint64_t input_hz) {
        RequireScale(counter_.SetRatio(RatioCycles(), input_hz), input_hz);
        RequireScale(counter_.AnchorAtPhase(now, 0u, phase_, phase_den_), input_hz);
        base_tick_    = 0u;
        last_eval_    = 0u;
        ratio_cycles_ = RatioCycles();
        ratio_ticks_  = input_hz;
        counting_     = true;
    }

    void Retime() {
        const uint64_t now      = clock_->Cycles();
        const uint64_t input_hz = EnabledInputHz();
        CaptureDue(now);
        if (!counting_) {
            if (input_hz != 0u) Resume(now, input_hz);
        } else if (input_hz == 0u) {
            Freeze(now, true);
        } else if (input_hz != ratio_ticks_ || RatioCycles() != ratio_cycles_) {
            base_value_ = Count(now);
            RequireScale(counter_.Rescale(now, RatioCycles(), input_hz), input_hz);
            base_tick_    = counter_.TicksSince(now);
            last_eval_    = 0u;
            ratio_cycles_ = RatioCycles();
            ratio_ticks_  = input_hz;
        }
        Arm(now);
    }

    void OnIdle() {
        if (!counting_) return;
        const FreescaleLowPowerMode mode = clocks_->WfiMode();
        uint32_t enable = 0u;
        switch (mode) {
            case FreescaleLowPowerMode::kRun:  return;
            case FreescaleLowPowerMode::kWait: enable = kGptcrWaiten; break;
            case FreescaleLowPowerMode::kDoze: enable = Traits::kDozeEnable; break;
            case FreescaleLowPowerMode::kStop:
            case FreescaleLowPowerMode::kStateRetention: enable = kGptcrStopen; break;
        }
        if ((cr_ & enable) != 0u &&
            clocks_->InputRunsIn(FreescaleTimerUnit::kGpt, Input(), mode)) {
            return;
        }
        suspended_ = true;
        Retime();
    }

    void OnIdleExit() {
        if (!suspended_) return;
        suspended_ = false;
        Retime();
    }

    void RequireNoMatchAt(uint32_t count, const char* what) const {
        for (int n = 0; n < 3; ++n) {
            if (ocr_[n] == count) {
                emu_.Get<Fatal>().Die("GPT %08X: %s leaves GPTCNT 0x%08X equal to GPTOCR%d; "
                                      "whether OF%d sets is not established", kBase, what,
                                      count, n + 1, n + 1);
            }
        }
    }

    void WriteCr(uint32_t value) {
        LOG(SocTimer, "GPT %08X: CR <- %08X (was %08X)\n", kBase, value, cr_);
        const uint64_t now = clock_->Cycles();
        CaptureDue(now);
        if ((value & kGptcrSwr) != 0u) {
            if (value != kGptcrSwr) {
                emu_.Get<Fatal>().Die("GPT %08X: SWR write 0x%08X carries other bits; the "
                                      "value those bits take is not modeled", kBase, value);
            }
            ResetRegisters(cr_ & Traits::kCrSwrKeep);
            return;
        }
        if ((value & kGptcrPinModes) != 0u) {
            emu_.Get<Fatal>().Die("GPT %08X: GPTCR 0x%08X drives input capture, output "
                                  "compare or forced compare pins, which are not modeled",
                                  kBase, value);
        }
        const uint32_t      next  = value & kGptcrStored;
        const GptClockInput input = Traits::Clksrc(Clksrc(next));
        if (input == GptClockInput::kPad || input == GptClockInput::kUndefined) {
            emu_.Get<Fatal>().Die("GPT %08X: GPTCR 0x%08X selects CLKSRC %u, which is not a "
                                  "modeled clock", kBase, value, Clksrc(next));
        }
        const bool was_en = (cr_ & kGptcrEn) != 0u;
        const bool now_en = (next & kGptcrEn) != 0u;
        if (was_en && Clksrc(cr_) != Clksrc(next)) {
            emu_.Get<Fatal>().Die("GPT %08X: GPTCR 0x%08X changes CLKSRC of the enabled timer "
                                  "(was 0x%08X); the result is unpredictable", kBase, value,
                                  cr_);
        }
        if (counting_) {
            if (now_en) Rebase(now);
            else        Freeze(now, Traits::kPrescalerHoldsWhenDisabled);
        } else if (was_en && !now_en && !Traits::kPrescalerHoldsWhenDisabled) {
            ResetPrescaler();
        }
        cr_ = next;
        if (!was_en && now_en) {
            if ((next & kGptcrEnmod) != 0u) {
                base_value_ = 0u;
                ResetPrescaler();
            }
            RequireNoMatchAt(base_value_, "enabling the timer");
        }
        Retime();
        RefreshIrq();
    }

    void WritePr(uint32_t value) {
        if ((value & kGptprMask) == pr_) return;
        const uint64_t now = clock_->Cycles();
        CaptureDue(now);
        uint64_t edge_part = 0u;
        uint64_t edge_den  = 1u;
        if (counting_) {
            edge_den = counter_.PhaseDenominator();
            if (edge_den > UINT64_MAX / (uint64_t{kGptprMask} + 1u)) {
                emu_.Get<Fatal>().Die("GPT %08X: prescaler phase denominator %llu overflows the "
                                      "GPTPR write", kBase,
                                      static_cast<unsigned long long>(edge_den));
            }
            edge_part = counter_.PhaseAt(now) * (uint64_t{pr_} + 1u) % edge_den;
            Freeze(now, false);
        }
        pr_        = value & kGptprMask;
        phase_     = uint64_t{pr_} * edge_den + edge_part;
        phase_den_ = (uint64_t{pr_} + 1u) * edge_den;
        Retime();
    }

    void WriteSr(uint32_t value) {
        const uint64_t now = clock_->Cycles();
        CaptureDue(now);
        const uint32_t clear = value & kGptStatusMask;
        sr_         &= ~clear;
        pending_sr_ &= ~clear;
        RefreshIrq();
        Arm(now);
    }

    void WriteIr(uint32_t value) {
        ir_ = value & kGptStatusMask;
        RefreshIrq();
    }

    void WriteOcr(int n, uint32_t value) {
        const uint64_t now     = clock_->Cycles();
        const bool     restart = n == 0 && (cr_ & kGptcrFrr) == 0u;
        CaptureDue(now);
        if (counting_) Rebase(now);
        if (restart) base_value_ = 0u;
        ocr_[n] = value;
        if ((cr_ & kGptcrEn) != 0u) {
            if (restart) {
                RequireNoMatchAt(0u, "the GPTOCR1 restart-mode counter reset");
            } else if (Count(now) == value) {
                emu_.Get<Fatal>().Die("GPT %08X: GPTOCR%d write 0x%08X equals GPTCNT; whether "
                                      "OF%d sets is not established", kBase, n + 1, value,
                                      n + 1);
            }
        }
        Arm(now);
    }

    void ResetRegisters(uint32_t cr) {
        clock_->Disarm(event_);
        counting_   = false;
        suspended_  = false;
        pending_sr_ = 0u;
        cr_         = cr;
        pr_         = 0u;
        sr_         = 0u;
        ir_         = 0u;
        for (int n = 0; n < 3; ++n) ocr_[n] = kOcrReset;
        base_value_ = 0u;
        ResetPrescaler();
        Retime();
        RefreshIrq();
    }

    GuestCycleClock*        clock_  = nullptr;
    FreescaleTimerClocks*   clocks_ = nullptr;
    GuestCycleClock::Event* event_  = nullptr;
    CycleAnchoredCounter    counter_;

    uint32_t cr_     = 0u;
    uint32_t pr_     = 0u;
    uint32_t sr_     = 0u;
    uint32_t ir_     = 0u;
    uint32_t ocr_[3] = {kOcrReset, kOcrReset, kOcrReset};

    bool     counting_     = false;
    bool     suspended_    = false;
    uint32_t pending_sr_   = 0u;
    uint32_t base_value_   = 0u;
    uint64_t base_tick_    = 0u;
    uint64_t last_eval_    = 0u;
    uint64_t phase_        = 0u;
    uint64_t phase_den_    = 1u;
    uint64_t ratio_cycles_ = 0u;
    uint64_t ratio_ticks_  = 0u;
};

}

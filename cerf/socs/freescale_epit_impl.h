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
#include "freescale_timer_clocks.h"
#include "guest_cpu_reset.h"

#include <cstdint>
#include <string_view>

namespace cerf_freescale_epit_detail {

constexpr uint32_t kEpitSize = 0x00004000u;

/* MCIMX31RM Table 33-5 / MCIMX51RM Table 29-2. */
constexpr uint32_t kOffCr   = 0x00u;
constexpr uint32_t kOffSr   = 0x04u;
constexpr uint32_t kOffLr   = 0x08u;
constexpr uint32_t kOffCmpr = 0x0Cu;
constexpr uint32_t kOffCnt  = 0x10u;

/* MCIMX31RM Table 33-6 / MCIMX51RM Table 29-5 EPITCR. */
constexpr uint32_t kCrEn             = 1u << 0;
constexpr uint32_t kCrEnmod          = 1u << 1;
constexpr uint32_t kCrOcien          = 1u << 2;
constexpr uint32_t kCrRld            = 1u << 3;
constexpr uint32_t kCrPrescalerShift = 4u;
constexpr uint32_t kCrPrescalerMask  = 0xFFFu;
constexpr uint32_t kCrSwr            = 1u << 16;
constexpr uint32_t kCrIovw           = 1u << 17;
constexpr uint32_t kCrWaiten         = 1u << 19;
constexpr uint32_t kCrDozen          = 1u << 20;
constexpr uint32_t kCrStopen         = 1u << 21;
constexpr uint32_t kCrOmShift        = 22u;
constexpr uint32_t kCrClksrcShift    = 24u;

/* MCIMX31RM Table 33-6: bits 31-26 reserved; SWR keeps EN, ENMOD, STOPEN, DOZEN,
   WAITEN and DBGEN. */
constexpr uint32_t kCrWritableMx31 = 0x03FFFFFFu;
constexpr uint32_t kCrSwrKeepMx31  = 0x003C0003u;
/* MCIMX51RM Table 29-5: bits 31-26 and 20 reserved; SWR keeps EN, ENMOD, STOPEN,
   WAITEN and DBGEN. */
constexpr uint32_t kCrWritableMx51 = 0x03EFFFFFu;
constexpr uint32_t kCrSwrKeepMx51  = 0x002C0003u;

/* MCIMX31RM Table 33-7 / MCIMX51RM Table 29-6: OCIF is w1c. */
constexpr uint32_t kSrOcif = 1u << 0;

/* MCIMX31RM Figures 33-6 and 33-8 / MCIMX51RM Table 29-2. */
constexpr uint32_t kLrReset  = 0xFFFFFFFFu;
constexpr uint32_t kCntReset = 0xFFFFFFFFu;

template <uint32_t kBase, const std::string_view& kSoc, FreescaleTimerUnit kUnit,
          uint32_t kCrWritable, uint32_t kCrSwrKeep>
class FreescaleEpitBase : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == kSoc;
    }

    void OnReady() override {
        clock_  = &emu_.Get<GuestCycleClock>();
        clocks_ = &emu_.Get<FreescaleTimerClocks>();
        event_  = clock_->Add([this] { OnCompare(); });
        clock_->RegisterRateListener([this] { Retime(); });
        clock_->RegisterIdleListener([this] { OnIdle(); });
        clock_->RegisterIdleExitListener([this] { OnIdleExit(); });
        clocks_->RegisterRateListener([this] { Retime(); });
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            HardwareReset();
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kEpitSize; }

    FastReadFn  FastReader() override { return &FreescaleEpitBase::FastReadThunk; }
    FastWriteFn FastWriter() override { return &FreescaleEpitBase::FastWriteThunk; }

    uint32_t ReadWord(uint32_t addr) override { return FastRead(addr - kBase, 4u); }
    void WriteWord(uint32_t addr, uint32_t value) override {
        FastWrite(addr - kBase, value, 4u);
    }

    void SaveState(StateWriter& w) override {
        const uint64_t now = clock_->Cycles();
        w.Write<uint32_t>("cr", cr_);
        w.Write<uint32_t>("sr", sr_);
        w.Write<uint32_t>("lr", lr_);
        w.Write<uint32_t>("cmpr", cmpr_);
        w.Write<uint32_t>("count", Count(now));
        w.Write<uint64_t>("prescale_phase", counting_ ? counter_.PhaseAt(now) : phase_);
        w.Write<uint64_t>("prescale_phase_den",
                          counting_ ? counter_.PhaseDenominator() : phase_den_);
    }

    void RestoreState(StateReader& r) override {
        uint32_t cr = 0, sr = 0, lr = 0, cmpr = 0, count = 0;
        uint64_t phase = 0, den = 0;
        r.Read("cr", cr);
        r.Read("sr", sr);
        r.Read("lr", lr);
        r.Read("cmpr", cmpr);
        r.Read("count", count);
        r.Read("prescale_phase", phase);
        r.Read("prescale_phase_den", den);
        clock_->Disarm(event_);
        ocif_pending_    = false;
        counting_        = false;
        suspended_       = false;
        cr_              = cr;
        sr_              = sr;
        lr_              = lr;
        cmpr_            = cmpr;
        base_value_      = count;
        phase_           = phase;
        phase_den_       = den;
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
        return static_cast<FreescaleEpitBase*>(ctx)->FastRead(off, width);
    }
    static void FastWriteThunk(void* ctx, uint32_t off, uint32_t value, uint32_t width) {
        static_cast<FreescaleEpitBase*>(ctx)->FastWrite(off, value, width);
    }

    static uint32_t Prescaler(uint32_t cr) {
        return (cr >> kCrPrescalerShift) & kCrPrescalerMask;
    }
    static uint32_t Clksrc(uint32_t cr) { return (cr >> kCrClksrcShift) & 0x3u; }
    static uint32_t Om(uint32_t cr) { return (cr >> kCrOmShift) & 0x3u; }

    uint32_t FastRead(uint32_t off, uint32_t width) {
        if (width != 4u) HaltUnsupportedAccess("FastRead", kBase + off, 0);
        switch (off) {
            case kOffCr:   return cr_;
            case kOffSr:   return sr_;
            case kOffLr:   return lr_;
            case kOffCmpr: return cmpr_;
            case kOffCnt:  return Count(clock_->Cycles());
            default: break;
        }
        HaltUnsupportedAccess("FastRead", kBase + off, 0);
    }

    void FastWrite(uint32_t off, uint32_t value, uint32_t width) {
        if (width != 4u) HaltUnsupportedAccess("FastWrite", kBase + off, value);
        switch (off) {
            case kOffCr:   WriteCr(value); return;
            case kOffSr:   WriteSr(value); return;
            case kOffLr:   WriteLr(value); return;
            case kOffCmpr: WriteCmpr(value); return;
            default: break;
        }
        HaltUnsupportedAccess("FastWrite", kBase + off, value);
    }

    /* MCIMX31RM Figure 33-10 / MCIMX51RM Figure 29-9: in set-and-forget mode the
       counter holds 0 for one tick, then loads EPITLR. */
    uint32_t ValueAfter(uint64_t ticks) const {
        if ((cr_ & kCrRld) == 0u || ticks <= base_value_) {
            return base_value_ - static_cast<uint32_t>(ticks);
        }
        const uint64_t period = uint64_t{lr_} + 1u;
        return lr_ - static_cast<uint32_t>((ticks - base_value_ - 1u) % period);
    }

    uint64_t TicksAt(uint64_t now) const { return counter_.TicksSince(now) - base_tick_; }

    uint32_t Count(uint64_t now) const {
        return counting_ ? ValueAfter(TicksAt(now)) : base_value_;
    }

    bool NextCompareIndex(uint64_t ticks, uint64_t& e) const {
        if ((cr_ & kCrRld) == 0u) {
            const uint64_t d = static_cast<uint32_t>(base_value_ - cmpr_);
            e = ticks <= d ? d : d + (((ticks - d) + 0xFFFFFFFFull) >> 32 << 32);
            return true;
        }
        if (cmpr_ <= base_value_ && ticks <= uint64_t{base_value_ - cmpr_}) {
            e = base_value_ - cmpr_;
            return true;
        }
        if (cmpr_ > lr_) return false;
        const uint64_t period = uint64_t{lr_} + 1u;
        const uint64_t first  = uint64_t{base_value_} + 1u + (lr_ - cmpr_);
        e = ticks <= first ? first : first + (ticks - first + period - 1u) / period * period;
        return true;
    }

    /* MCIMX31RM Figure 33-10 / MCIMX51RM Figure 29-9: OCIF sets on the counter
       clock edge that moves the counter off the compare value. */
    void CaptureDue(uint64_t now) {
        if (clock_->IsDue(event_, now)) ocif_pending_ = true;
    }

    void Arm(uint64_t now) {
        uint64_t e = 0;
        if (ocif_pending_) {
            clock_->Arm(event_, now);
            return;
        }
        if (!counting_ || (sr_ & kSrOcif) != 0u || !NextCompareIndex(TicksAt(now), e)) {
            clock_->Disarm(event_);
            return;
        }
        clock_->Arm(event_, counter_.CycleOfTick(base_tick_ + e + 1u));
    }

    void OnCompare() {
        if (!counting_ && !ocif_pending_) {
            emu_.Get<Fatal>().Die("EPIT %08X: compare event fired while the counter is "
                                  "stopped", kBase);
        }
        ocif_pending_ = false;
        sr_ |= kSrOcif;
        RefreshIrq();
        Arm(clock_->Cycles());
    }

    void RefreshIrq() {
        if ((sr_ & kSrOcif) != 0u && (cr_ & kCrOcien) != 0u) AssertIrqLine();
        else                                                  DeassertIrqLine();
    }

    FreescaleTimerInput Input() const {
        switch (Clksrc(cr_)) {
            case 1u:  return FreescaleTimerInput::kIpg;
            case 2u:  return FreescaleTimerInput::kHighfreq;
            default:  return FreescaleTimerInput::kLowfreq;
        }
    }

    /* MCIMX31RM Table 33-6 / MCIMX51RM Table 29-5 CLKSRC 00: clock is off. */
    uint64_t EnabledInputHz() const {
        if (suspended_ || (cr_ & kCrEn) == 0u || Clksrc(cr_) == 0u) return 0u;
        return clocks_->InputHz(kUnit, Input());
    }

    void RequireScale(bool ok, uint64_t input_hz) const {
        if (!ok) {
            emu_.Get<Fatal>().Die("EPIT %08X: %llu Hz input / %u against the %llu Hz core "
                                  "overflows the 64-bit scale", kBase,
                                  static_cast<unsigned long long>(input_hz),
                                  Prescaler(cr_) + 1u,
                                  static_cast<unsigned long long>(clock_->CpuHz()));
        }
    }

    uint64_t RatioCycles() const {
        return clock_->CpuHz() * (uint64_t{Prescaler(cr_)} + 1u);
    }

    void Rebase(uint64_t now) {
        base_value_ = Count(now);
        base_tick_  = counter_.TicksSince(now);
    }

    /* MCIMX31RM Table 33-6 / MCIMX51RM Table 29-5 ENMOD: with EN=0 the main
       counter and the prescaler counter freeze at their current values. */
    void Freeze(uint64_t now) {
        base_value_      = Count(now);
        phase_           = counter_.PhaseAt(now);
        phase_den_       = counter_.PhaseDenominator();
        counting_        = false;
    }

    /* MCIMX31RM Table 33-6 ENMOD and Figure 33-9, MCIMX51RM Table 29-5 ENMOD: after a
       prescaler counter reset the next prescaled pulse comes one input clock later. */
    void ResetPrescaler() {
        phase_     = Prescaler(cr_);
        phase_den_ = uint64_t{Prescaler(cr_)} + 1u;
    }

    void Resume(uint64_t now, uint64_t input_hz) {
        RequireScale(counter_.SetRatio(RatioCycles(), input_hz), input_hz);
        RequireScale(counter_.AnchorAtPhase(now, 0u, phase_, phase_den_), input_hz);
        base_tick_     = 0u;
        ratio_cycles_  = RatioCycles();
        ratio_ticks_   = input_hz;
        counting_      = true;
    }

    void Retime() {
        const uint64_t now      = clock_->Cycles();
        const uint64_t input_hz = EnabledInputHz();
        CaptureDue(now);
        if (!counting_) {
            if (input_hz != 0u) Resume(now, input_hz);
        } else if (input_hz == 0u) {
            Freeze(now);
        } else if (input_hz != ratio_ticks_ || RatioCycles() != ratio_cycles_) {
            base_value_ = Count(now);
            RequireScale(counter_.Rescale(now, RatioCycles(), input_hz), input_hz);
            base_tick_    = counter_.TicksSince(now);
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
            case FreescaleLowPowerMode::kWait: enable = kCrWaiten; break;
            case FreescaleLowPowerMode::kDoze: enable = kCrDozen;  break;
            case FreescaleLowPowerMode::kStop:
            case FreescaleLowPowerMode::kStateRetention: enable = kCrStopen; break;
        }
        if ((cr_ & enable) != 0u && clocks_->InputRunsIn(kUnit, Input(), mode)) return;
        suspended_ = true;
        Retime();
    }

    void OnIdleExit() {
        if (!suspended_) return;
        suspended_ = false;
        Retime();
    }

    void WriteCr(uint32_t value) {
        LOG(SocTimer, "EPIT %08X: CR <- %08X (was %08X)\n", kBase, value, cr_);
        if ((value & kCrSwr) != 0u) {
            if (value != kCrSwr) {
                emu_.Get<Fatal>().Die("EPIT %08X: SWR write 0x%08X carries other bits; "
                                      "the value those bits take is not modeled", kBase,
                                      value);
            }
            ResetRegisters(cr_ & kCrSwrKeep);
            return;
        }
        value &= kCrWritable;
        if (Om(value) != 0u) {
            emu_.Get<Fatal>().Die("EPIT %08X: EPITCR 0x%08X drives the ipp_do_epito "
                                  "output pin, which is not modeled", kBase, value);
        }
        const uint32_t old    = cr_;
        const bool     was_en = (old & kCrEn) != 0u;
        const bool     now_en = (value & kCrEn) != 0u;
        if (was_en && now_en &&
            (Clksrc(old) != Clksrc(value) || Prescaler(old) != Prescaler(value))) {
            emu_.Get<Fatal>().Die("EPIT %08X: EPITCR 0x%08X changes CLKSRC or PRESCALER of "
                                  "the enabled timer (was 0x%08X); not modeled", kBase,
                                  value, old);
        }
        const uint64_t now = clock_->Cycles();
        CaptureDue(now);
        if (counting_) {
            if (now_en) Rebase(now);
            else        Freeze(now);
        }
        cr_ = value;
        /* MCIMX31RM §33.6.1.1 with Figure 33-9: "A change in the value of the PRESCALER
           field is immediately reflected on its output clock frequency." */
        if (Prescaler(old) != Prescaler(value)) ResetPrescaler();
        if (!was_en && now_en && (value & kCrEnmod) != 0u) {
            base_value_ = (value & kCrRld) != 0u ? lr_ : kCntReset;
            ResetPrescaler();
        }
        Retime();
        RefreshIrq();
    }

    void WriteSr(uint32_t value) {
        if ((value & kSrOcif) == 0u) return;
        ocif_pending_ = false;
        sr_ &= ~kSrOcif;
        clock_->Disarm(event_);
        RefreshIrq();
        Arm(clock_->Cycles());
    }

    void WriteLr(uint32_t value) {
        const uint64_t now = clock_->Cycles();
        CaptureDue(now);
        if (counting_) Rebase(now);
        lr_ = value;
        if ((cr_ & kCrIovw) != 0u) base_value_ = value;
        Arm(now);
    }

    void WriteCmpr(uint32_t value) {
        const uint64_t now = clock_->Cycles();
        CaptureDue(now);
        if (counting_) {
            const uint32_t cnt = Count(now);
            const int32_t  gap = static_cast<int32_t>(cnt - value);
            if (gap <= 0) {
                LOG(Caution, "[EPITPAST] EPIT %08X cmpr<-%08X cnt=%08X behind=%d ticks\n",
                    kBase, value, cnt, -gap);
            }
        }
        cmpr_ = value;
        Arm(now);
    }

    void ResetRegisters(uint32_t cr) {
        clock_->Disarm(event_);
        ocif_pending_    = false;
        counting_        = false;
        suspended_       = false;
        cr_              = cr;
        sr_              = 0u;
        lr_              = kLrReset;
        cmpr_            = 0u;
        base_value_      = kCntReset;
        ResetPrescaler();
        Retime();
        RefreshIrq();
    }

    void HardwareReset() { ResetRegisters(0u); }

    GuestCycleClock*        clock_  = nullptr;
    FreescaleTimerClocks*   clocks_ = nullptr;
    GuestCycleClock::Event* event_  = nullptr;
    CycleAnchoredCounter    counter_;

    uint32_t cr_   = 0u;
    uint32_t sr_   = 0u;
    uint32_t lr_   = kLrReset;
    uint32_t cmpr_ = 0u;

    bool     counting_        = false;
    bool     suspended_       = false;
    bool     ocif_pending_    = false;
    uint32_t base_value_      = kCntReset;
    uint64_t base_tick_       = 0u;
    uint64_t phase_           = 0u;
    uint64_t phase_den_       = 1u;
    uint64_t ratio_cycles_    = 0u;
    uint64_t ratio_ticks_     = 0u;
};

}

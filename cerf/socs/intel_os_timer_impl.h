#pragma once

#include "../peripherals/peripheral_base.h"

#include "cycle_anchored_counter.h"
#include "guest_cpu_reset.h"

#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "../jit/guest_cycle_clock.h"
#include "../jit/guest_engine.h"
#include "../peripherals/peripheral_dispatcher.h"
#include "../state/state_stream.h"

#include <cstdint>

#include "intel_os_timer_census.h"

#include "../core/rate_probe.h"

template <uint32_t kOscrHz>
class IntelOsTimerBase : public Peripheral {
public:
    using Peripheral::Peripheral;

    void OnReady() override {
        clock_      = &emu_.Get<GuestCycleClock>();
        engine_     = &emu_.Get<GuestEngine>();
        rate_probe_ = &emu_.Get<RateProbe>();
        SetUnits();
        for (int n = 0; n < 4; ++n) {
            event_[n] = clock_->Add([this, n] { OnMatch(n); });
        }
        counter_.Anchor(clock_->Cycles(), 0u);
        ArmAll();
        clock_->RegisterRateListener([this] { OnRateChange(); });
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            OnResetLine();
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioSize() const override { return 0x00001000u; }

    FastReadFn  FastReader() override { return &IntelOsTimerBase::FastReadThunk; }
    FastWriteFn FastWriter() override { return &IntelOsTimerBase::FastWriteThunk; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (!IsKnown(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
        return ReadReg(off);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        if (!IsKnown(off)) HaltUnsupportedAccess("WriteWord", addr, value);
        WriteReg(off, value);
    }

    void SaveState(StateWriter& w) override {
        const uint64_t now = clock_->Cycles();
        for (int n = 0; n < 4; ++n) w.Write<uint32_t>("osmr", osmr_[n]);
        w.Write<uint32_t>("ossr", ossr_);
        w.Write<uint32_t>("ower", ower_);
        w.Write<uint32_t>("oier", oier_);
        w.Write<uint32_t>("oscr", Oscr(now));
        w.Write<uint64_t>("oscr_phase", counter_.PhaseAt(now));
        w.Write<uint64_t>("oscr_phase_den", counter_.PhaseDenominator());
        for (int n = 0; n < 4; ++n) {
            w.Write<uint8_t>("match_due", clock_->IsDue(event_[n], now) ? 1u : 0u);
        }
        for (int n = 0; n < 4; ++n) w.Write<uint32_t>("last_match_oscr", last_match_oscr_[n]);
        for (int n = 0; n < 4; ++n) w.Write<uint8_t>("have_match", have_match_[n] ? 1u : 0u);
        w.Write<uint8_t>("pair_oscr_read", pair_oscr_read_ ? 1u : 0u);
        w.Write<uint32_t>("pair_oscr", pair_oscr_);
        w.Write<uint32_t>("period_cand", period_cand_);
        w.Write<uint8_t>("bank_pending", bank_pending_ ? 1u : 0u);
        w.Write<uint32_t>("bank_oscr", bank_oscr_);
        w.Write<uint8_t>("have_period", have_period_ ? 1u : 0u);
        w.Write<uint32_t>("period", period_);
        w.Write<uint8_t>("isr_write_pending", isr_write_pending_ ? 1u : 0u);
        w.Write<uint8_t>("bank_pair_since_match", bank_pair_since_match_ ? 1u : 0u);
        w.Write<uint8_t>("osmr0_written_since_ack", osmr0_written_since_ack_ ? 1u : 0u);
        w.Write<uint8_t>("last_write_rephased", last_write_rephased_ ? 1u : 0u);
        w.Write<uint8_t>("oscr_read_any", oscr_read_any_ ? 1u : 0u);
    }

    void RestoreState(StateReader& r) override {
        for (int n = 0; n < 4; ++n) r.Read("osmr", osmr_[n]);
        r.Read("ossr", ossr_);
        r.Read("ower", ower_);
        r.Read("oier", oier_);
        uint32_t oscr = 0;
        r.Read("oscr", oscr);
        uint64_t phase = 0, phase_den = 0;
        r.Read("oscr_phase", phase);
        r.Read("oscr_phase_den", phase_den);
        bool due[4] = {};
        for (int n = 0; n < 4; ++n) {
            uint8_t v = 0;
            r.Read("match_due", v);
            if (v > 1u) {
                r.Reject("IntelOsTimer: restored match_due flag %u is not 0 or 1", v);
            }
            due[n] = v != 0u;
        }
        for (int n = 0; n < 4; ++n) r.Read("last_match_oscr", last_match_oscr_[n]);
        for (int n = 0; n < 4; ++n) {
            uint8_t v = 0;
            r.Read("have_match", v);
            have_match_[n] = v != 0u;
        }
        uint8_t flag = 0;
        r.Read("pair_oscr_read", flag);
        pair_oscr_read_ = flag != 0u;
        r.Read("pair_oscr", pair_oscr_);
        r.Read("period_cand", period_cand_);
        r.Read("bank_pending", flag);
        bank_pending_ = flag != 0u;
        r.Read("bank_oscr", bank_oscr_);
        r.Read("have_period", flag);
        have_period_ = flag != 0u;
        r.Read("period", period_);
        r.Read("isr_write_pending", flag);
        isr_write_pending_ = flag != 0u;
        r.Read("bank_pair_since_match", flag);
        bank_pair_since_match_ = flag != 0u;
        r.Read("osmr0_written_since_ack", flag);
        osmr0_written_since_ack_ = flag != 0u;
        r.Read("last_write_rephased", flag);
        last_write_rephased_ = flag != 0u;
        r.Read("oscr_read_any", flag);
        oscr_read_any_ = flag != 0u;
        const uint64_t now = clock_->Cycles();
        if (!counter_.AnchorAtPhase(now, oscr, phase, phase_den)) {
            r.Reject("IntelOsTimer: restored OSCR phase %llu/%llu is not a fraction of "
                     "one tick this build can place",
                     static_cast<unsigned long long>(phase),
                     static_cast<unsigned long long>(phase_den));
        }
        for (int n = 0; n < 4; ++n) {
            if (due[n]) clock_->Arm(event_[n], now);
            else        ArmChannel(n);
        }
    }

    void PostRestore() override { PushMatchLevel(); }

protected:
    /* SA-1110 §9.4.2: the OSSR status bits are routed to the interrupt
       controller. §9.4.5: OIER gates only the SET of an OSSR bit - clearing an
       enable bit does not clear a set status bit, so OIER is not in the level. */
    virtual void SetMatchLevel(uint32_t level4) = 0;

    virtual void OnResetLine() {
        ower_ = 0;
        oier_ = 0;
        ForgetGuestSequence();
    }

    void ResetRegistersToZero() {
        ForgetCounterDomain();
        for (int n = 0; n < 4; ++n) osmr_[n] = 0u;
        ossr_ = 0u;
        oier_ = 0u;
        counter_.SetCountAt(clock_->Cycles(), 0u);
        ArmAll();
        PushMatchLevel();
    }

    uint32_t FastRead(uint32_t off, uint32_t width) {
        if (width != 4 || !IsKnown(off)) {
            HaltUnsupportedAccess("FastRead", MmioBase() + off, 0);
        }
        return ReadReg(off);
    }

private:
    static bool IsKnown(uint32_t off) {
        return off == 0x00 || off == 0x04 || off == 0x08 || off == 0x0C ||
               off == 0x10 || off == 0x14 || off == 0x18 || off == 0x1C;
    }

    static uint32_t FastReadThunk(void* ctx, uint32_t off, uint32_t width) {
        return static_cast<IntelOsTimerBase*>(ctx)->FastRead(off, width);
    }
    static void FastWriteThunk(void* ctx, uint32_t off, uint32_t value, uint32_t width) {
        static_cast<IntelOsTimerBase*>(ctx)->FastWrite(off, value, width);
    }

    void SetUnits() {
        RequireUnits(counter_.SetRatio(clock_->CpuHz(), kOscrHz));
    }

    void RequireUnits(bool ok) {
        if (!ok) {
            emu_.Get<Fatal>().Die(
                "IntelOsTimer: OSCR rate %u Hz against the %llu Hz core overflows "
                "the 64-bit scale", kOscrHz,
                static_cast<unsigned long long>(clock_->CpuHz()));
        }
    }

    void OnRateChange() {
        RequireUnits(counter_.Rescale(clock_->Cycles(), clock_->CpuHz(), kOscrHz));
        ArmAll();
    }

    /* SA-1110 §9.4.1: the OSCR increments on rising edges of the 3.6864-MHz
       clock. */
    uint32_t Oscr(uint64_t cycles) const {
        return counter_.CountAt(cycles);
    }

    /* SA-1110 §9.4.2: each OSMR is compared against the OSCR following every
       rising edge of the 3.6864-MHz clock. */
    void ArmChannel(int n) {
        clock_->Arm(event_[n], counter_.NextMatchCycle(osmr_[n], clock_->Cycles()));
    }

    void ArmAll() {
        for (int n = 0; n < 4; ++n) ArmChannel(n);
    }

    /* SA-1110 §9.4.4: the OSSR bit is set at the match and stays set until the
       guest writes a one, so a write with the bit clear is not the service of
       that match. §9.4.2: every OSMR is compared on each rising edge. */
    void AbsorbRephase(int n, uint32_t value) {
        if (n != 0 || !have_period_ || !have_match_[n] ||
            (ossr_ & (1u << n)) != 0u) {
            return;
        }
        if (!last_write_rephased_) {
            ++census_.absorb_step;
            return;
        }
        const uint32_t oscr  = Oscr(clock_->Cycles());
        const uint32_t phase = oscr - last_match_oscr_[n];
        const uint32_t ahead = value - oscr;
        if (bank_pair_since_match_) {
            bank_pair_since_match_ = false;
            last_match_oscr_[n]    = oscr;
            census_.OnAbsorbSkipped(phase);
            return;
        }
        if (phase == 0u || phase >= ahead) {
            last_match_oscr_[n] = oscr;
            return;
        }
        uint32_t crossed = 0u;
        for (int c = 0; c < 4; ++c) {
            const uint32_t d = osmr_[c] - oscr;
            if (c != n && d != 0u && d <= phase) crossed |= 1u << c;
        }
        census_.OnAbsorb(phase);
        counter_.Anchor(counter_.AnchorCycle(), counter_.AnchorCount() + phase);
        last_match_oscr_[n] = oscr + phase;
        for (int c = 0; c < 4; ++c) {
            if ((crossed & (1u << c)) != 0u) OnMatch(c);
        }
        ArmAll();
    }

    void ClearPairLatches() {
        pair_oscr_read_ = false;
        oscr_read_any_  = false;
    }

    void PushMatchLevel() { SetMatchLevel(ossr_ & 0xFu); }

    bool GuestIrqMasked() { return engine_->GuestIrqMasked(); }

    void ForgetCounterDomain() {
        for (int n = 0; n < 4; ++n) have_match_[n] = false;
        ForgetGuestSequence();
    }

    void ForgetGuestSequence() {
        ClearPairLatches();
        bank_pending_      = false;
        have_period_       = false;
        period_cand_       = 0u;
        isr_write_pending_ = false;
        bank_pair_since_match_ = false;
        osmr0_written_since_ack_ = false;
        last_write_rephased_ = false;
    }

    /* falcon_4220__4_10 nk.exe sub_800F5550 / symbol_mk500 nk.exe sub_801BD03C: OEMIdle
       banks (phase + accum) / P read through sub_800F5DE8 / sub_801BD5DC and returns
       without re-arming OSMR0 when the bank consumes the deadline. */
    void RearmOmittedExit() {
        const uint32_t target = bank_oscr_ + period_;
        const uint32_t oscr   = Oscr(clock_->Cycles());
        if (static_cast<int32_t>(target - oscr) <= 0) {
            emu_.Get<Fatal>().Die(
                "IntelOsTimer: omitted-exit re-arm target 0x%08X at or behind OSCR 0x%08X "
                "(bank 0x%08X period %u)",
                target, oscr, bank_oscr_, period_);
        }
        osmr_[0]      = target;
        bank_pending_ = false;
        ArmChannel(0);
        ++census_.rearm;
    }

    void LearnPeriod(uint32_t value) {
        if (have_period_) return;
        const uint32_t step = value - osmr_[0];
        if (step != 0u && step == period_cand_) {
            period_      = step;
            have_period_ = true;
        }
        period_cand_ = step;
    }

    void OnMatch(int n) {
        if (n == 0) census_.OnMatch0(bank_pending_);
        if (n == 0) census_.Report(clock_->NowNs(), period_);
        if (n == 0 && bank_pending_ && have_period_ && (oier_ & 0x1u) != 0u) {
            RearmOmittedExit();
            ++census_.rearm_match;
            return;
        }
        if (n == 0) bank_pending_ = false;
        if (n == 0) isr_write_pending_ = true;
        if (n == 0) bank_pair_since_match_ = false;
        last_match_oscr_[n] = osmr_[n];
        have_match_[n]      = true;
        const uint32_t bit = 1u << n;
        /* SA-1110 §9.4.5: the OIER enables decide whether a match will set a
           status bit in the OSSR - for every match register, with no WME term. */
        if ((oier_ & bit) != 0u) {
            ossr_ |= bit;
            PushMatchLevel();
            rate_probe_->Inc(RateProbe::Counter::OstFires);
        }
        ArmChannel(n);
        /* SA-1110 §9.4.3 OWER bit 0 (WME): 0 - OSMR3 matches cause an interrupt
           request; 1 - OSMR3 matches cause a reset of the SA-1110. §9.4.6 and
           PXA255 §4.4.1 enable that reset on OWER[0], with no OIER term. */
        if (n == 3 && (ower_ & 0x1u) != 0u) {
            emu_.Get<GuestCpuReset>().WatchdogReset();
        }
    }

    uint32_t ReadReg(uint32_t off) {
        switch (off) {
            case 0x00: case 0x04: case 0x08: case 0x0C: {
                const int n = static_cast<int>(off >> 2);
                if (n == 0) {
                    const bool masked = GuestIrqMasked();
                    const bool pair   = pair_oscr_read_ && (ossr_ & 0x1u) == 0u && masked;
                    if (oscr_read_any_ && (ossr_ & 0x1u) == 0u) {
                        bank_pair_since_match_ = true;
                    }
                    census_.OnOsmr0Read(pair, oscr_read_any_, (ossr_ & 0x1u) != 0u,
                                        masked);
                    if (pair && osmr0_written_since_ack_ && !last_write_rephased_) {
                        ++census_.pairs_post_grid_write;
                    } else if (pair) {
                        if (bank_pending_ && have_period_ && (oier_ & 0x1u) != 0u) {
                            RearmOmittedExit();
                        }
                        bank_pending_ = true;
                        bank_oscr_    = pair_oscr_;
                        ++census_.banks;
                    }
                }
                if (n != 0) census_.OnAuxOsmrRead(oscr_read_any_);
                ClearPairLatches();
                return osmr_[n];
            }
            case 0x10: {
                rate_probe_->Inc(RateProbe::Counter::OstReadOscr);
                const uint32_t oscr = Oscr(clock_->Cycles());
                pair_oscr_read_ = GuestIrqMasked();
                oscr_read_any_  = true;
                pair_oscr_      = oscr;
                return oscr;
            }
            case 0x14: ClearPairLatches(); return ossr_ & 0xFu;
            case 0x18: ClearPairLatches(); return ower_ & 0x1u;
            case 0x1C: ClearPairLatches(); return oier_ & 0xFu;
        }
        HaltUnsupportedAccess("ReadReg", MmioBase() + off, 0);
    }

    void WriteReg(uint32_t off, uint32_t value) {
        switch (off) {
            case 0x00: case 0x04: case 0x08: case 0x0C: {
                const int n = static_cast<int>(off >> 2);
                ClearPairLatches();
                const uint32_t step = value - osmr_[n];
                if (n == 0) {
                    if (isr_write_pending_) {
                        LearnPeriod(value);
                        isr_write_pending_ = false;
                    }
                    if (bank_pending_) ++census_.resolved_write;
                    bank_pending_            = false;
                    osmr0_written_since_ack_ = true;
                    last_write_rephased_ =
                        !(have_period_ && step != 0u && step % period_ == 0u);
                }
                osmr_[n] = value;
                AbsorbRephase(n, value);
                ArmChannel(n);
                return;
            }
            case 0x10:
                ForgetCounterDomain();
                counter_.SetCountAt(clock_->Cycles(), value);
                ArmAll();
                return;
            /* SA-1110 §9.4.4: an OSSR bit is cleared by writing a one to it;
               writing zeros has no effect. */
            case 0x14:
                ClearPairLatches();
                ossr_ &= ~(value & 0xFu);
                if ((value & 0x1u) != 0u) osmr0_written_since_ack_ = false;
                PushMatchLevel();
                return;
            /* SA-1110 §9.4.3: WME is a write-once bit that can only be changed
               by a hardware, software or sleep-mode reset. */
            case 0x18:
                ClearPairLatches();
                ower_ |= (value & 0x1u);
                return;
            case 0x1C:
                ClearPairLatches();
                oier_ = value & 0xFu;
                return;
        }
        HaltUnsupportedAccess("WriteReg", MmioBase() + off, value);
    }

    void FastWrite(uint32_t off, uint32_t value, uint32_t width) {
        if (width != 4 || !IsKnown(off)) {
            HaltUnsupportedAccess("FastWrite", MmioBase() + off, value);
        }
        WriteReg(off, value);
    }

    GuestCycleClock*        clock_      = nullptr;
    GuestEngine*            engine_     = nullptr;
    RateProbe*              rate_probe_ = nullptr;
    GuestCycleClock::Event* event_[4]   = {};

    CycleAnchoredCounter counter_;

    uint32_t last_match_oscr_[4] = {};
    bool     have_match_[4]      = {};

    bool     pair_oscr_read_      = false;
    uint32_t pair_oscr_           = 0;
    uint32_t period_cand_         = 0;
    bool     bank_pending_        = false;
    uint32_t bank_oscr_           = 0;
    bool     have_period_         = false;
    uint32_t period_              = 0;
    bool     isr_write_pending_   = false;
    bool     bank_pair_since_match_   = false;
    bool     osmr0_written_since_ack_ = false;
    bool     last_write_rephased_     = false;
    bool     oscr_read_any_           = false;

    IntelOsTimerCensus census_;

    uint32_t osmr_[4] = {};
    uint32_t ossr_    = 0;
    uint32_t ower_    = 0;
    uint32_t oier_    = 0;
};

#pragma once

#include "../peripherals/peripheral_base.h"

#include "cycle_anchored_counter.h"
#include "guest_cpu_reset.h"
#include "intel_os_timer_census.h"
#include "intel_os_timer_kernel_invariants.h"

#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "../jit/guest_cycle_clock.h"
#include "../jit/guest_engine.h"
#include "../peripherals/peripheral_dispatcher.h"
#include "../state/state_stream.h"

#include <cstdint>

#include "../core/rate_probe.h"

template <uint32_t kOscrHz>
class IntelOsTimerBase : public Peripheral {
public:
    using Peripheral::Peripheral;

    void OnReady() override {
        clock_      = &emu_.Get<GuestCycleClock>();
        engine_     = &emu_.Get<GuestEngine>();
        invariants_ = &emu_.Get<IntelOsTimerKernelInvariants>();
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
        w.Write<uint8_t>("pair_oscr_read", pair_oscr_read_ ? 1u : 0u);
        w.Write<uint32_t>("pair_oscr", pair_oscr_);
        w.Write<uint8_t>("oscr_read_any", oscr_read_any_ ? 1u : 0u);
        w.Write<uint8_t>("osmr0_read_last", osmr0_read_last_ ? 1u : 0u);
        w.Write<uint8_t>("bank_pair_since_match", bank_pair_since_match_ ? 1u : 0u);
        invariants_->Save(w);
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
        uint8_t flag = 0;
        r.Read("pair_oscr_read", flag);
        pair_oscr_read_ = flag != 0u;
        r.Read("pair_oscr", pair_oscr_);
        r.Read("oscr_read_any", flag);
        oscr_read_any_ = flag != 0u;
        r.Read("osmr0_read_last", flag);
        osmr0_read_last_ = flag != 0u;
        r.Read("bank_pair_since_match", flag);
        bank_pair_since_match_ = flag != 0u;
        invariants_->Restore(r);
        const uint64_t now = clock_->Cycles();
        if (!counter_.AnchorAtPhase(now, oscr, phase, phase_den)) {
            r.Reject("IntelOsTimer: restored OSCR phase %llu/%llu is not a fraction of "
                     "one tick this build can place",
                     static_cast<unsigned long long>(phase),
                     static_cast<unsigned long long>(phase_den));
        }
        ArmAll();
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
        ForgetGuestReads();
        invariants_->ForgetGuestSequence();
    }

    void ResetRegistersToZero() {
        ForgetGuestReads();
        invariants_->ForgetCounterDomain();
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

    void AdvanceCounter(int n, uint32_t oscr, uint32_t by) {
        uint32_t crossed = 0u;
        for (int c = 0; c < 4; ++c) {
            const uint32_t d = osmr_[c] - oscr;
            if (c != n && d != 0u && d <= by) crossed |= 1u << c;
        }
        counter_.Anchor(counter_.AnchorCycle(), counter_.AnchorCount() + by);
        for (int c = 0; c < 4; ++c) {
            if ((crossed & (1u << c)) != 0u) OnMatch(c);
        }
        ArmAll();
    }

    void ApplyRearm(const IntelOsTimerRearm& rearm) {
        const uint32_t oscr = Oscr(clock_->Cycles());
        if (static_cast<int32_t>(rearm.target - oscr) <= 0) {
            emu_.Get<Fatal>().Die(
                "IntelOsTimer: omitted-exit re-arm target 0x%08X at or behind OSCR 0x%08X "
                "(bank 0x%08X period %u)",
                rearm.target, oscr, rearm.bank, rearm.period);
        }
        osmr_[0] = rearm.target;
        ArmChannel(0);
    }

    void PushMatchLevel() { SetMatchLevel(ossr_ & 0xFu); }

    bool Status(int n) const { return (ossr_ & (1u << n)) != 0u; }

    bool GuestIrqMasked() const { return engine_->GuestIrqMasked(); }

    void ClearPairLatches() {
        pair_oscr_read_  = false;
        oscr_read_any_   = false;
        osmr0_read_last_ = false;
    }

    void ForgetGuestReads() {
        ClearPairLatches();
        bank_pair_since_match_ = false;
    }

    void ReadOsmr0AfterOscr() {
        const bool status0 = Status(0);
        const bool masked  = GuestIrqMasked();
        const bool pair    = pair_oscr_read_ && !status0 && masked;
        if (!status0) bank_pair_since_match_ = true;
        census_.OnOsmr0Read(pair, true, status0, masked);
        if (!pair) return;
        IntelOsTimerRearm rearm;
        if (invariants_->OnMaskedPair((oier_ & 0x1u) != 0u, pair_oscr_, census_, rearm)) {
            ApplyRearm(rearm);
        }
    }

    void OnMatch(int n) {
        IntelOsTimerRearm rearm;
        if (invariants_->OnMatch(n, osmr_[n], (oier_ & 0x1u) != 0u, census_, rearm)) {
            ApplyRearm(rearm);
            return;
        }
        if (n == 0) bank_pair_since_match_ = false;
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
                if (n != 0) {
                    census_.OnAuxOsmrRead(oscr_read_any_);
                } else if (oscr_read_any_) {
                    ReadOsmr0AfterOscr();
                }
                ClearPairLatches();
                if (n == 0) osmr0_read_last_ = true;
                return osmr_[n];
            }
            case 0x10: {
                rate_probe_->Inc(RateProbe::Counter::OstReadOscr);
                const uint32_t oscr = Oscr(clock_->Cycles());
                if (osmr0_read_last_ && !Status(0)) {
                    bank_pair_since_match_ = true;
                    ++census_.rev_pairs;
                }
                osmr0_read_last_ = false;
                pair_oscr_read_  = GuestIrqMasked();
                oscr_read_any_   = true;
                pair_oscr_       = oscr;
                return oscr;
            }
            case 0x14: ClearPairLatches(); return ossr_ & 0xFu;
            case 0x18: ClearPairLatches(); return ower_ & 0x1u;
            case 0x1C: ClearPairLatches(); return oier_ & 0xFu;
        }
        HaltUnsupportedAccess("ReadReg", MmioBase() + off, 0);
    }

    void WriteOsmr(int n, uint32_t value) {
        ClearPairLatches();
        if (n == 0) {
            WriteOsmr0(value);
        } else {
            osmr_[n] = value;
        }
        ArmChannel(n);
    }

    void WriteOsmr0(uint32_t value) {
        ++census_.osmr0_writes;
        const uint32_t old = osmr_[0];
        const IntelOsTimerOsmrWrite plan =
            invariants_->OnChannel0Write(value - old, Status(0), census_);
        osmr_[0] = value;
        if (plan.walk_away) {
            const uint32_t oscr  = Oscr(clock_->Cycles());
            const uint32_t ahead = old - oscr;
            if (invariants_->WalkAway(ahead, census_)) AdvanceCounter(0, oscr, ahead);
        }
        if (plan.absorb) {
            const uint32_t oscr = Oscr(clock_->Cycles());
            const uint32_t by =
                invariants_->Absorb(value, oscr, bank_pair_since_match_, census_);
            bank_pair_since_match_ = false;
            if (by != 0u) AdvanceCounter(0, oscr, by);
        }
    }

    void WriteReg(uint32_t off, uint32_t value) {
        switch (off) {
            case 0x00: case 0x04: case 0x08: case 0x0C:
                WriteOsmr(static_cast<int>(off >> 2), value);
                return;
            case 0x10:
                ForgetGuestReads();
                invariants_->ForgetCounterDomain();
                counter_.SetCountAt(clock_->Cycles(), value);
                ArmAll();
                return;
            /* SA-1110 §9.4.4: an OSSR bit is cleared by writing a one to it;
               writing zeros has no effect. */
            case 0x14:
                ClearPairLatches();
                if ((value & 0x1u) != 0u) {
                    ++census_.tick_acks;
                    invariants_->OnTickAck();
                }
                ossr_ &= ~(value & 0xFu);
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

    GuestCycleClock*              clock_      = nullptr;
    GuestEngine*                  engine_     = nullptr;
    IntelOsTimerKernelInvariants* invariants_ = nullptr;
    RateProbe*                    rate_probe_ = nullptr;
    GuestCycleClock::Event*       event_[4]   = {};

    CycleAnchoredCounter counter_;

    uint32_t osmr_[4] = {};
    uint32_t ossr_    = 0;
    uint32_t ower_    = 0;
    uint32_t oier_    = 0;

    bool     pair_oscr_read_        = false;
    bool     oscr_read_any_         = false;
    uint32_t pair_oscr_             = 0;
    bool     osmr0_read_last_       = false;
    bool     bank_pair_since_match_ = false;

    IntelOsTimerCensus census_;
};

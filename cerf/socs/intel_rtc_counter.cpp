#include "intel_rtc_counter.h"

#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "../core/log.h"
#include "../core/tick_scale.h"
#include "../host/guest_deep_sleep.h"
#include "../jit/guest_engine.h"
#include "../state/state_stream.h"

namespace {

/* SA-1110 Dev Man §9.3.5.2 and PXA255 Dev Man §4.3.3.2: the trim interval is
   hard-wired to 2^10-1 periods of the HZ clock; the integer counter compares
   against the C15..C0 divider count and resets when the two are equal. */
constexpr uint64_t kTrimIntervalSec = 1023u;
constexpr uint64_t kCounterSpan     = 0x10000u;
constexpr uint32_t kRttrDivMask     = 0x0000FFFFu;
constexpr uint32_t kRttrDelShift    = 16u;
constexpr uint32_t kRttrDelMask     = 0x000003FFu;
constexpr uint32_t kRtsrStatus      = IntelRtcCounter::kRtsrAl | IntelRtcCounter::kRtsrHz;
constexpr uint32_t kRtsrEnables     = IntelRtcCounter::kRtsrAle | IntelRtcCounter::kRtsrHze;

}

IntelRtcCounter::IntelRtcCounter(CerfEmulator& emu, Traits traits,
                                 std::function<void()> on_status)
    : emu_(emu), traits_(traits), on_status_(std::move(on_status)) {
    core_.traits = &traits_;
}

void IntelRtcCounter::Attach(uint64_t osc_num, uint64_t osc_den) {
    osc_.Attach(osc_num, osc_den);
    const OscillatorTicks::Reading now = osc_.Sample();
    total_seen_ = now.total;
    park_seen_  = now.park;
    GuestCycleClock& clk = emu_.Get<GuestCycleClock>();
    edge_ev_ = clk.Add([this] { Rearm(); });
    clk.RegisterRateListener([this] { OnRateChange(); });
    emu_.Get<GuestDeepSleep>().RegisterParkClock([this] { Rearm(); });
}

uint64_t IntelRtcCounter::Core::Divider() const {
    return static_cast<uint64_t>(rttr & kRttrDivMask) + 1u;
}

uint64_t IntelRtcCounter::Core::TrimDelete() const {
    return static_cast<uint64_t>((rttr >> kRttrDelShift) & kRttrDelMask);
}

uint64_t IntelRtcCounter::Core::TrimCycle() const {
    return kTrimIntervalSec * Divider() + TrimDelete();
}

uint64_t IntelRtcCounter::Core::Emitted(uint64_t ticks) const {
    const uint64_t e = ticks / Divider();
    return e < kTrimIntervalSec ? e : kTrimIntervalSec;
}

uint64_t IntelRtcCounter::Core::CounterValue() const {
    if (lead_ticks != 0u) return kCounterSpan - lead_ticks;
    if (cycle_ticks >= kTrimIntervalSec * Divider()) return 0u;
    return cycle_ticks % Divider();
}

/* PXA255 Dev Man §4.3.3: "When the clock divisor count (RTTR[15:0]) is set to
   0x0, the HZ clock feeding the RTC maintains a high level signal - essentially
   disabling the RTC." */
bool IntelRtcCounter::Core::Stopped() const {
    return traits->zero_divider_stops && (rttr & kRttrDivMask) == 0u;
}

void IntelRtcCounter::Core::SetRttr(uint32_t value) {
    const uint32_t old     = rttr;
    const uint64_t prev    = Divider();
    const uint64_t emitted = Emitted(cycle_ticks);
    const uint64_t deleted =
        emitted == kTrimIntervalSec ? cycle_ticks - kTrimIntervalSec * prev : 0u;
    const uint64_t count   = CounterValue();
    rttr       = value & traits->rttr_mask;
    lead_ticks = 0u;
    if ((rttr & kRttrDivMask) == 0u || (old & kRttrDivMask) == 0u) {
        cycle_ticks = 0u;
        return;
    }
    const uint64_t div = Divider();
    if (emitted == kTrimIntervalSec) {
        const uint64_t d = TrimDelete();
        cycle_ticks = (kTrimIntervalSec * div + (deleted < d ? deleted : d)) % TrimCycle();
        return;
    }
    if (count < div) {
        cycle_ticks = emitted * div + count;
        return;
    }
    cycle_ticks = emitted * div;
    lead_ticks  = kCounterSpan - count;
}

bool IntelRtcCounter::Core::Credit(uint64_t ticks, bool asleep) {
    if (Stopped()) return false;
    if (lead_ticks != 0u) {
        if (ticks < lead_ticks) {
            lead_ticks -= ticks;
            return false;
        }
        ticks     -= lead_ticks;
        lead_ticks = 0u;
    }

    const uint64_t cycle = TrimCycle();
    const uint64_t total = cycle_ticks + ticks;
    const uint64_t edges = (total / cycle) * kTrimIntervalSec +
                           Emitted(total % cycle) - Emitted(cycle_ticks);
    cycle_ticks = total % cycle;
    if (edges == 0u) return false;

    /* SA-1110 Dev Man §9.3.2: "Following each rising edge of the 1-Hz clock, this
       register is compared to the RCNR. If the two are equal and the enable bit is
       set, then the alarm bit in the RTC status register is set." */
    const uint32_t before = rcnr;
    rcnr = static_cast<uint32_t>(before + edges);
    hz_edges += edges;
    const bool hz_edge = !asleep || traits->hz_in_sleep;
    if (hz_edge && (!traits->hz_needs_hze || (rtsr & kRtsrHze) != 0u)) rtsr |= kRtsrHz;
    const uint64_t to_alarm = static_cast<uint32_t>(rtar - before);
    /* PXA27x Dev Man §21.4 Figure 21-2: on a counter == alarm match "the RTC
       controller signals the power manager, regardless of the state of the
       corresponding alarm-enable bit". */
    if (edges >= 0x100000000ull || (to_alarm != 0u && to_alarm <= edges)) {
        ++match_events;
        if ((rtsr & kRtsrAle) != 0u) {
            rtsr |= kRtsrAl;
            ++alarm_events;
        }
    }
    return true;
}

/* SA-1110 §9.3.3 and PXA255 §4.3.2.4: AL and HZ clear by writing ones, ALE and HZE
   are read/write. PXA255 Table 4-37 LCK: "1 - RTTR value is not allowed to be
   altered"; PXA27x Table 21-6 LCK: "1 = Value of RTTR cannot be overwritten". */
void IntelRtcCounter::Core::Land(Reg reg, uint32_t value) {
    switch (reg) {
        case kRegRcnr: rcnr = value; break;
        case kRegRtar: rtar = value; break;
        case kRegRtsr: rtsr = ((rtsr & ~value) & kRtsrStatus) | (value & kRtsrEnables); break;
        case kRegRttr:
            if ((rttr & traits->rttr_lock) == 0u) SetRttr(value);
            break;
        case kRegExt:
        case kRegCount:
            break;
    }
}

uint64_t IntelRtcCounter::Core::EdgesToMatch() const {
    const uint64_t to = static_cast<uint32_t>(rtar - rcnr);
    return to == 0u ? 0x100000000ull : to;
}

uint64_t IntelRtcCounter::Core::TicksToEdge(uint64_t edges) const {
    const uint64_t cycle = TrimCycle();
    const uint64_t div   = Divider();
    const uint64_t e0    = Emitted(cycle_ticks);
    const uint64_t left  = kTrimIntervalSec - e0;
    if (edges <= left) return lead_ticks + (e0 + edges) * div - cycle_ticks;
    const uint64_t m = edges - left;
    const uint64_t q = (m - 1u) / kTrimIntervalSec;
    return lead_ticks + (cycle - cycle_ticks) + q * cycle + (m - q * kTrimIntervalSec) * div;
}

uint64_t IntelRtcCounter::Core::TicksToInterrupt() const {
    const bool hz_rises = (rtsr & (kRtsrHze | kRtsrHz)) == kRtsrHze;
    const bool al_rises = (rtsr & (kRtsrAle | kRtsrAl)) == kRtsrAle;
    if (Stopped() || (!hz_rises && !al_rises)) return kNever;
    return TicksToEdge(hz_rises ? 1u : EdgesToMatch());
}

uint8_t IntelRtcCounter::SyncOf(Reg reg) const {
    switch (reg) {
        case kRegRcnr:  return traits_.rcnr_sync;
        case kRegRtar:  return traits_.rtar_sync;
        case kRegRtsr:  return traits_.rtsr_sync;
        case kRegRttr:  return traits_.rttr_sync;
        case kRegExt:   return traits_.ext_sync;
        case kRegCount: break;
    }
    emu_.Get<Fatal>().Die("%s: SyncOf reached register %u", traits_.name, reg);
}

uint64_t IntelRtcCounter::NextLanding() const {
    uint64_t next = kNever;
    for (uint8_t r = 0; r < kRegCount; ++r) {
        if (pend_n_[r] != 0u && pend_[r][0].land < next) next = pend_[r][0].land;
    }
    return next;
}

bool IntelRtcCounter::CreditSpan(uint64_t ticks, uint64_t& slept, bool& park_start) {
    const uint64_t s = ticks < slept ? ticks : slept;
    slept -= s;
    bool edges = false;
    if (s != 0u) {
        if (park_start) {
            park_from_ = core_.rcnr;
            park_start = false;
        }
        edges = core_.Credit(s, true);
    }
    if (ticks != s) edges = core_.Credit(ticks - s, false) || edges;
    return edges;
}

void IntelRtcCounter::LandDue(uint64_t land) {
    for (uint8_t r = 0; r < kRegCount; ++r) {
        if (pend_n_[r] == 0u || pend_[r][0].land != land) continue;
        const Pending p = pend_[r][0];
        pend_[r][0] = pend_[r][1];
        pend_[r][1] = Pending{};
        --pend_n_[r];
        if (r == kRegExt) ext_land_(p.a, p.b);
        else              core_.Land(static_cast<Reg>(r), p.a);
    }
}

void IntelRtcCounter::Advance() {
    const OscillatorTicks::Reading now = osc_.Sample();
    const uint64_t slept = now.park - park_seen_;
    uint64_t slept_left  = slept;
    bool     park_start  = slept != 0u && park_ticks_ == 0u;
    uint64_t pos         = total_seen_;
    bool     changed     = false;
    for (uint64_t land = NextLanding(); land <= now.total; land = NextLanding()) {
        changed = CreditSpan(land - pos, slept_left, park_start) || changed;
        pos = land;
        LandDue(land);
        changed = true;
    }
    changed = CreditSpan(now.total - pos, slept_left, park_start) || changed;
    total_seen_ = now.total;
    park_seen_  = now.park;
    park_ticks_ += slept;
    if (changed) on_status_();
    if (park_ticks_ == 0u || emu_.Get<GuestEngine>().DeepSleep()) return;
    const GuestCycleClock::Rate osc = osc_.OscRate();
    LOG(SocTimer, "[RTCSLEEP] %s park %llu ms: rcnr %u -> %u rtar %u rtsr=0x%X\n",
        traits_.name,
        static_cast<unsigned long long>(ScaleU64(park_ticks_, 1000u * osc.den, osc.num)),
        park_from_, core_.rcnr, core_.rtar, core_.rtsr & kRtsrMask);
    park_ticks_ = 0u;
}

void IntelRtcCounter::Rearm() {
    Advance();
    GuestCycleClock& clk    = emu_.Get<GuestCycleClock>();
    const bool       asleep = emu_.Get<GuestEngine>().DeepSleep();
    Core     v    = core_;
    uint64_t pos  = total_seen_;
    uint8_t  next[kRegCount] = {};
    for (;;) {
        const uint64_t t    = v.TicksToInterrupt();
        uint64_t       land = kNever;
        for (uint8_t r = 0; r < kRegCount; ++r) {
            if (next[r] < pend_n_[r] && pend_[r][next[r]].land < land) land = pend_[r][next[r]].land;
        }
        if (t != kNever && (land == kNever || pos + t <= land)) {
            osc_.ArmAt(edge_ev_, pos + t);
            return;
        }
        if (land == kNever) {
            clk.Disarm(edge_ev_);
            return;
        }
        v.Credit(land - pos, asleep);
        pos = land;
        for (uint8_t r = 0; r < kRegCount; ++r) {
            if (next[r] >= pend_n_[r] || pend_[r][next[r]].land != land) continue;
            if (r != kRegExt) v.Land(static_cast<Reg>(r), pend_[r][next[r]].a);
            ++next[r];
        }
    }
}

int64_t IntelRtcCounter::SleptNsAtEdge(uint64_t edges) {
    Advance();
    if (core_.Stopped() || edges == 0u) return GuestDeepSleep::kNoParkWake;
    return osc_.SleptNsAtTick(total_seen_ + core_.TicksToEdge(edges));
}

void IntelRtcCounter::RequireSettled(const char* when) {
    Advance();
    if (NextLanding() == kNever) return;
    emu_.Get<Fatal>().Die("%s: %s with an RTC register write still in its 32 kHz "
                          "synchronization window", traits_.name, when);
}

bool IntelRtcCounter::PendingExt(uint8_t i, uint32_t& a, uint32_t& b) const {
    if (i >= pend_n_[kRegExt]) return false;
    a = pend_[kRegExt][i].a;
    b = pend_[kRegExt][i].b;
    return true;
}

void IntelRtcCounter::OnRateChange() {
    Advance();
    osc_.Rescale();
    Rearm();
}

/* SA-1110 Dev Man §9.3.1: "After the processor writes to the RCNR, all other writes to
   this register location are ignored until the new value is actually loaded into the
   counter." */
void IntelRtcCounter::Schedule(Reg reg, uint32_t a, uint32_t b) {
    Advance();
    const uint8_t sync = SyncOf(reg);
    if (sync == 0u) {
        if (reg == kRegExt) ext_land_(a, b);
        else                core_.Land(reg, a);
        Rearm();
        on_status_();
        return;
    }
    Pending*       q    = pend_[reg];
    uint8_t&       n    = pend_n_[reg];
    const uint64_t land = total_seen_ + sync;
    if (reg == kRegRcnr && traits_.rcnr_busy_ignores && n != 0u) {
        LOG(SocTimer, "[RTC] %s RCNR <- 0x%08X ignored: 0x%08X lands at tick %llu (now %llu)\n",
            traits_.name, a, q[0].a, static_cast<unsigned long long>(q[0].land),
            static_cast<unsigned long long>(total_seen_));
        return;
    }
    if (n != 0u && q[n - 1u].land == land) {
        q[n - 1u].a = reg == kRegRtsr ? (((q[n - 1u].a | a) & kRtsrStatus) | (a & kRtsrEnables)) : a;
        q[n - 1u].b = b;
    } else {
        if (n == kPendMax) {
            emu_.Get<Fatal>().Die("%s: register %u written a third time inside its %u-tick "
                                  "synchronization window", traits_.name, reg, sync);
        }
        q[n++] = Pending{land, a, b};
    }
    Rearm();
}

void IntelRtcCounter::WriteRcnr(uint32_t v) { Schedule(kRegRcnr, v, 0u); }
void IntelRtcCounter::WriteRtar(uint32_t v) { Schedule(kRegRtar, v, 0u); }
void IntelRtcCounter::WriteRttr(uint32_t v) { Schedule(kRegRttr, v, 0u); }
void IntelRtcCounter::WriteRtsr(uint32_t v) { Schedule(kRegRtsr, v, 0u); }
void IntelRtcCounter::WriteExt(uint32_t a, uint32_t b) { Schedule(kRegExt, a, b); }

/* PXA255 Dev Man §4.3.2.1: "A write to the RTTC will increment the RTC Count
   Register (RCNR) by one." */
void IntelRtcCounter::IncrementRcnr() {
    Advance();
    if (pend_n_[kRegRcnr] != 0u) {
        emu_.Get<Fatal>().Die("%s: an RTTR write while an RCNR load is pending; whether the "
                              "increment lands before or after the load is not modelled",
                              traits_.name);
    }
    ++core_.rcnr;
    Rearm();
    on_status_();
}

void IntelRtcCounter::ClearAlarmStatus() {
    Advance();
    core_.rtsr &= ~kRtsrAl;
    on_status_();
}

void IntelRtcCounter::SetOscRate(uint64_t osc_num, uint64_t osc_den) {
    const GuestCycleClock::Rate osc = osc_.OscRate();
    if (osc_num == osc.num && osc_den == osc.den) return;
    Advance();
    osc_.SetOscRate(osc_num, osc_den);
    Rearm();
}

void IntelRtcCounter::CreditCoreStop(uint64_t ns) {
    Advance();
    osc_.CreditAwakeNs(ns);
    Rearm();
}

void IntelRtcCounter::DropPending(Reg reg) {
    pend_n_[reg]  = 0u;
    pend_[reg][0] = Pending{};
    pend_[reg][1] = Pending{};
}

void IntelRtcCounter::ResetCounter() {
    Advance();
    DropPending(kRegRcnr);
    DropPending(kRegRtar);
    DropPending(kRegRtsr);
    DropPending(kRegExt);
    core_.rcnr = 0u;
    core_.rtar = 0u;
    core_.rtsr = 0u;
    Rearm();
    on_status_();
}

void IntelRtcCounter::ResetRttr(uint32_t rttr) {
    Advance();
    DropPending(kRegRttr);
    core_.SetRttr(rttr);
    Rearm();
}

void IntelRtcCounter::Save(StateWriter& w) {
    Advance();
    w.Write("rtar", core_.rtar);  w.Write("rcnr", core_.rcnr);
    w.Write("rttr", core_.rttr);  w.Write("rtsr", core_.rtsr);
    w.Write("cycle_ticks", core_.cycle_ticks);  w.Write("lead_ticks", core_.lead_ticks);
    uint64_t in[kRegCount][kPendMax] = {};
    uint32_t a[kRegCount][kPendMax]  = {};
    uint32_t b[kRegCount][kPendMax]  = {};
    for (uint8_t r = 0; r < kRegCount; ++r) {
        for (uint8_t i = 0; i < pend_n_[r]; ++i) {
            in[r][i] = pend_[r][i].land - total_seen_;
            a[r][i]  = pend_[r][i].a;
            b[r][i]  = pend_[r][i].b;
        }
    }
    w.Write("pend_n", pend_n_);  w.Write("pend_in", in);
    w.Write("pend_a", a);        w.Write("pend_b", b);
    osc_.Save(w);
}

void IntelRtcCounter::Restore(StateReader& r) {
    r.Read("rtar", core_.rtar);  r.Read("rcnr", core_.rcnr);
    r.Read("rttr", core_.rttr);  r.Read("rtsr", core_.rtsr);
    r.Read("cycle_ticks", core_.cycle_ticks);  r.Read("lead_ticks", core_.lead_ticks);
    if ((core_.rttr & ~traits_.rttr_mask) != 0u || (core_.rtsr & ~kRtsrMask) != 0u ||
        core_.cycle_ticks >= core_.TrimCycle() || core_.lead_ticks >= kCounterSpan) {
        r.Reject("%s: RTC counter state out of range (rttr 0x%X rtsr 0x%X)",
                 traits_.name, core_.rttr, core_.rtsr);
    }
    uint8_t  n[kRegCount]            = {};
    uint64_t in[kRegCount][kPendMax] = {};
    uint32_t a[kRegCount][kPendMax]  = {};
    uint32_t b[kRegCount][kPendMax]  = {};
    r.Read("pend_n", n);  r.Read("pend_in", in);
    r.Read("pend_a", a);  r.Read("pend_b", b);
    for (uint8_t reg = 0; reg < kRegCount; ++reg) {
        const uint8_t sync  = SyncOf(static_cast<Reg>(reg));
        const uint8_t limit = reg == kRegRcnr && traits_.rcnr_busy_ignores ? 1u : kPendMax;
        bool bad = n[reg] > limit || (sync == 0u && n[reg] != 0u);
        for (uint8_t i = 0; i < n[reg] && !bad; ++i) {
            bad = in[reg][i] == 0u || in[reg][i] > sync || (i != 0u && in[reg][i] <= in[reg][0]) ||
                  (reg == kRegRtsr && (a[reg][i] & ~kRtsrMask) != 0u) ||
                  (reg == kRegRttr && (a[reg][i] & ~traits_.rttr_mask) != 0u);
        }
        if (bad) {
            r.Reject("%s: pending write state of register %u out of range (count %u)",
                     traits_.name, reg, n[reg]);
        }
    }
    osc_.Restore(r);
    const OscillatorTicks::Reading now = osc_.Sample();
    total_seen_ = now.total;
    park_seen_  = now.park;
    park_ticks_ = 0u;
    for (uint8_t reg = 0; reg < kRegCount; ++reg) {
        pend_n_[reg] = n[reg];
        for (uint8_t i = 0; i < kPendMax; ++i) {
            pend_[reg][i] = i < n[reg] ? Pending{total_seen_ + in[reg][i], a[reg][i], b[reg][i]}
                                       : Pending{};
        }
    }
}

#pragma once

#include "../jit/guest_cycle_clock.h"
#include "oscillator_ticks.h"

#include <cstdint>
#include <functional>

class CerfEmulator;
class StateReader;
class StateWriter;

class IntelRtcCounter {
public:
    struct Traits {
        const char* name;
        uint32_t    rttr_mask;
        uint32_t    rttr_lock;
        bool        zero_divider_stops;
        bool        hz_needs_hze;
        bool        hz_in_sleep;
        uint8_t     rcnr_sync;
        uint8_t     rtar_sync;
        uint8_t     rtsr_sync;
        uint8_t     rttr_sync;
        uint8_t     ext_sync;
        bool        rcnr_busy_ignores;
    };

    static constexpr uint32_t kRtsrAl   = 0x1u;
    static constexpr uint32_t kRtsrHz   = 0x2u;
    static constexpr uint32_t kRtsrAle  = 0x4u;
    static constexpr uint32_t kRtsrHze  = 0x8u;
    static constexpr uint32_t kRtsrMask = 0xFu;

    using ExtLand = std::function<void(uint32_t, uint32_t)>;

    IntelRtcCounter(CerfEmulator& emu, Traits traits, std::function<void()> on_status);

    void Attach(uint64_t osc_num, uint64_t osc_den);
    void SetExtLand(ExtLand fn) { ext_land_ = std::move(fn); }

    void Advance();
    void Rearm();

    uint32_t Rcnr() const { return core_.rcnr; }
    uint32_t Rtar() const { return core_.rtar; }
    uint32_t Rttr() const { return core_.rttr; }
    uint32_t Rtsr() const { return core_.rtsr & kRtsrMask; }
    uint64_t AlarmEvents() const { return core_.alarm_events; }
    uint64_t MatchEvents() const { return core_.match_events; }
    uint64_t HzEdges() const { return core_.hz_edges; }

    uint64_t EdgesToMatch() const { return core_.EdgesToMatch(); }
    int64_t  SleptNsAtEdge(uint64_t edges);
    void     RequireSettled(const char* when);
    bool     PendingExt(uint8_t i, uint32_t& a, uint32_t& b) const;

    void WriteRcnr(uint32_t v);
    void WriteRtar(uint32_t v);
    void WriteRttr(uint32_t v);
    void WriteRtsr(uint32_t v);
    void WriteExt(uint32_t a, uint32_t b);
    void IncrementRcnr();
    void ClearAlarmStatus();
    void SetOscRate(uint64_t osc_num, uint64_t osc_den);
    void CreditCoreStop(uint64_t ns);
    void ResetCounter();
    void ResetRttr(uint32_t rttr);

    void Save(StateWriter& w);
    void Restore(StateReader& r);

private:
    enum Reg : uint8_t { kRegRcnr, kRegRtar, kRegRtsr, kRegRttr, kRegExt, kRegCount };
    static constexpr uint64_t kNever   = ~0ull;
    static constexpr uint8_t  kPendMax = 2u;

    struct Core {
        const Traits* traits       = nullptr;
        uint32_t      rtar         = 0;
        uint32_t      rcnr         = 0;
        uint32_t      rttr         = 0;
        uint32_t      rtsr         = 0;
        uint64_t      cycle_ticks  = 0;
        uint64_t      lead_ticks   = 0;
        uint64_t      alarm_events = 0;
        uint64_t      match_events = 0;
        uint64_t      hz_edges     = 0;

        uint64_t Divider() const;
        uint64_t TrimDelete() const;
        uint64_t TrimCycle() const;
        uint64_t Emitted(uint64_t ticks) const;
        uint64_t CounterValue() const;
        bool     Stopped() const;
        uint64_t TicksToEdge(uint64_t edges) const;
        uint64_t EdgesToMatch() const;
        uint64_t TicksToInterrupt() const;
        void     SetRttr(uint32_t value);
        bool     Credit(uint64_t ticks, bool asleep);
        void     Land(Reg reg, uint32_t value);
    };

    struct Pending {
        uint64_t land;
        uint32_t a;
        uint32_t b;
    };

    uint8_t  SyncOf(Reg reg) const;
    void     Schedule(Reg reg, uint32_t a, uint32_t b);
    uint64_t NextLanding() const;
    bool     CreditSpan(uint64_t ticks, uint64_t& slept, bool& park_start);
    void     LandDue(uint64_t land);
    void     DropPending(Reg reg);
    void     OnRateChange();

    CerfEmulator&         emu_;
    Traits                traits_;
    std::function<void()> on_status_;
    ExtLand               ext_land_;
    OscillatorTicks       osc_{emu_, true};
    Core                  core_;

    uint64_t total_seen_ = 0;
    uint64_t park_seen_  = 0;
    uint64_t park_ticks_ = 0;
    uint32_t park_from_  = 0;

    Pending pend_[kRegCount][kPendMax] = {};
    uint8_t pend_n_[kRegCount]         = {};

    GuestCycleClock::Event* edge_ev_ = nullptr;
};

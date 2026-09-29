#pragma once

#include <cstdint>

class CerfEmulator;
class GuestCycleClock;
class StateReader;
class StateWriter;
class Vr41xxRtcxTicks;

class Vr41xxPiuScanTiming {
public:
    static constexpr uint16_t kIdle = 0, kData = 1, kCmd = 2, kAdPort = 3;

    explicit Vr41xxPiuScanTiming(CerfEmulator& emu) : emu_(emu) {}

    void Attach(GuestCycleClock* clock, Vr41xxRtcxTicks* rtcx);

    uint64_t ReadyCycle(uint16_t kind, uint16_t stable, uint64_t start_tick, uint64_t start_cycle);
    void     Begin(uint16_t kind, uint16_t stable, uint64_t start_tick, uint64_t start_cycle);
    uint16_t Take();
    void     Drop() { kind_ = kIdle; }

    uint16_t Kind() const { return kind_; }
    uint64_t ReadyAt() const { return ready_cycle_; }

    void Save(StateWriter& w, uint64_t now) const;
    void Restore(StateReader& r, uint64_t now);

private:
    CerfEmulator&    emu_;
    GuestCycleClock* clock_       = nullptr;
    Vr41xxRtcxTicks* rtcx_        = nullptr;
    uint16_t         kind_        = kIdle;
    uint64_t         ready_cycle_ = 0;
};

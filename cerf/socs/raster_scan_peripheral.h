#pragma once

#include "../jit/guest_cycle_clock.h"
#include "../peripherals/peripheral_base.h"
#include "raster_scan_clock.h"

#include <cstdint>
#include <mutex>

class RasterScanPeripheral : public Peripheral {
public:
    using Peripheral::Peripheral;

protected:
    struct ScanShape {
        GuestCycleClock::Rate  tick;
        RasterScanClock::Frame frame;
    };

    void     AttachScanClock();
    void     OnScanSourceClockChange();
    void     OnScanFunctionalClockChange(bool running);
    uint64_t ScanNow();

    bool     ScanLiveLocked() const { return state_ == State::Live; }
    bool     ScanActiveLocked() const { return state_ != State::Stopped; }
    uint64_t ScanTickInFrameLocked(uint64_t now) const;
    uint64_t ScanTicksLocked(uint64_t now) const { return scan_.PositionAt(now).ticks; }
    void     StartScanLocked(uint64_t now);
    void     StopScanLocked();
    bool     PauseScanLocked(uint64_t now);
    void     UnpauseScanLocked(uint64_t now);
    bool     GateScanLocked(bool running, uint64_t now);
    bool     CatchUpLocked(uint64_t now);
    void     RearmScanLocked();

    void SaveScanLocked(StateWriter& w);
    void RestoreScanLocked(StateReader& r);
    void ResumeScanLocked(uint64_t now);

    virtual ScanShape ScanShapeLocked() const = 0;
    virtual bool      EdgeRaisesInterruptLocked(uint32_t, bool) const { return true; }
    virtual bool      FrameEdgesInertLocked() const { return false; }
    virtual void FrameEdgeLocked(uint32_t edge_index) = 0;
    virtual void ScanEdgesRan()                       = 0;

    mutable std::mutex state_mtx_;

private:
    enum class State : uint8_t { Stopped = 0, Live = 1, Paused = 2 };

    static constexpr uint32_t kArmFrames = 2u;

    void ArmLocked();
    void OnScanEvent();
    void DieUnschedulable(const char* what, const ScanShape& s);

    GuestCycleClock*          clock_ = nullptr;
    GuestCycleClock::Event*   event_ = nullptr;
    RasterScanClock           scan_;
    RasterScanClock::Position held_at_;
    uint64_t edges_done_  = 0;
    State    state_       = State::Stopped;
    State    restored_    = State::Stopped;
};

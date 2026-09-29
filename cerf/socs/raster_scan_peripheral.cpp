#include "raster_scan_peripheral.h"

#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "../state/state_stream.h"

#include <algorithm>

void RasterScanPeripheral::AttachScanClock() {
    clock_ = &emu_.Get<GuestCycleClock>();
    event_ = clock_->Add([this] { OnScanEvent(); });
    clock_->RegisterRateListener([this] { OnScanSourceClockChange(); });
}

uint64_t RasterScanPeripheral::ScanNow() {
    return clock_->Cycles();
}

uint64_t RasterScanPeripheral::ScanTickInFrameLocked(uint64_t now) const {
    return scan_.TickInFrame(now);
}

void RasterScanPeripheral::StartScanLocked(uint64_t now) {
    const ScanShape s = ScanShapeLocked();
    if (!scan_.Start(now, clock_->ClockRate(), s.tick, s.frame)) DieUnschedulable("start", s);
    edges_done_ = 0u;
    state_      = State::Live;
    ArmLocked();
}

void RasterScanPeripheral::StopScanLocked() {
    state_ = State::Stopped;
    clock_->Disarm(event_);
}

bool RasterScanPeripheral::PauseScanLocked(uint64_t now) {
    const bool edged = CatchUpLocked(now);
    if (state_ == State::Live) {
        held_at_ = scan_.PositionAt(now);
        state_   = State::Paused;
        clock_->Disarm(event_);
    }
    return edged;
}

void RasterScanPeripheral::UnpauseScanLocked(uint64_t now) {
    if (state_ != State::Paused) return;
    const ScanShape s = ScanShapeLocked();
    if (!scan_.Resume(now, clock_->ClockRate(), s.tick, s.frame, held_at_)) {
        DieUnschedulable("resume from a pause", s);
    }
    state_ = State::Live;
    ArmLocked();
}

bool RasterScanPeripheral::GateScanLocked(bool running, uint64_t now) {
    if (state_ == State::Live && !running) return PauseScanLocked(now);
    if (state_ == State::Paused && running) UnpauseScanLocked(now);
    return false;
}

void RasterScanPeripheral::OnScanFunctionalClockChange(bool running) {
    bool edged;
    bool rescale;
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        rescale = running && state_ == State::Live;
        edged   = GateScanLocked(running, clock_->Cycles());
    }
    if (rescale) OnScanSourceClockChange();
    else if (edged) ScanEdgesRan();
}

void RasterScanPeripheral::DieUnschedulable(const char* what, const ScanShape& s) {
    const GuestCycleClock::Rate cpu = clock_->ClockRate();
    emu_.Get<Fatal>().Die("RasterScanPeripheral 0x%08X: scan %s: a %llu/%llu Hz tick against the "
                          "%llu/%llu Hz core, frame %llu ticks with %u edges, cannot be scheduled",
                          MmioBase(), what, static_cast<unsigned long long>(s.tick.num),
                          static_cast<unsigned long long>(s.tick.den),
                          static_cast<unsigned long long>(cpu.num),
                          static_cast<unsigned long long>(cpu.den),
                          static_cast<unsigned long long>(s.frame.ticks), s.frame.edges);
}

void RasterScanPeripheral::ArmLocked() {
    const uint32_t n = scan_.EdgesPerFrame();
    for (uint32_t k = 0; k < kArmFrames * n; ++k) {
        const uint64_t edge       = edges_done_ + k;
        const bool     this_frame = edge / n == edges_done_ / n;
        if (!EdgeRaisesInterruptLocked(static_cast<uint32_t>(edge % n), this_frame)) continue;
        uint64_t cycle;
        if (!scan_.EdgeCycle(edge, cycle)) {
            emu_.Get<Fatal>().Die("RasterScanPeripheral 0x%08X: frame edge %llu overflows the "
                                  "64-bit tick count", MmioBase(),
                                  static_cast<unsigned long long>(edge));
        }
        clock_->Arm(event_, cycle);
        return;
    }
    clock_->Disarm(event_);
}

void RasterScanPeripheral::RearmScanLocked() {
    if (state_ == State::Live) ArmLocked();
}

bool RasterScanPeripheral::CatchUpLocked(uint64_t now) {
    if (state_ == State::Live && FrameEdgesInertLocked()) {
        edges_done_ = std::max(edges_done_, scan_.EdgesThrough(now));
        return false;
    }
    bool ran = false;
    while (state_ == State::Live) {
        uint64_t cycle;
        if (!scan_.EdgeCycle(edges_done_, cycle)) {
            emu_.Get<Fatal>().Die("RasterScanPeripheral 0x%08X: frame edge %llu overflows the "
                                  "64-bit tick count", MmioBase(),
                                  static_cast<unsigned long long>(edges_done_));
        }
        if (now < cycle) break;
        const uint32_t index = static_cast<uint32_t>(edges_done_ % scan_.EdgesPerFrame());
        ++edges_done_;
        FrameEdgeLocked(index);
        ran = true;
    }
    if (ran && state_ == State::Live) ArmLocked();
    return ran;
}

void RasterScanPeripheral::OnScanEvent() {
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        CatchUpLocked(clock_->Cycles());
    }
    ScanEdgesRan();
}

void RasterScanPeripheral::OnScanSourceClockChange() {
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        if (state_ != State::Live) return;
        const uint64_t now = clock_->Cycles();
        CatchUpLocked(now);
        if (state_ == State::Live) {
            const ScanShape s = ScanShapeLocked();
            if (!scan_.Rescale(now, clock_->ClockRate(), s.tick)) DieUnschedulable("rescale", s);
            ArmLocked();
        }
    }
    ScanEdgesRan();
}

void RasterScanPeripheral::SaveScanLocked(StateWriter& w) {
    RasterScanClock::Position at;
    if (state_ == State::Live)   at = scan_.PositionAt(clock_->Cycles());
    if (state_ == State::Paused) at = held_at_;
    w.Write<uint8_t>("scan_state", static_cast<uint8_t>(state_));
    w.Write<uint64_t>("scan_ticks", at.ticks);
    w.Write<uint64_t>("scan_phase", at.phase);
    w.Write<uint64_t>("scan_phase_den", at.phase_den);
    w.Write<uint64_t>("scan_edges", edges_done_);
}

void RasterScanPeripheral::RestoreScanLocked(StateReader& r) {
    uint8_t                   state = 0;
    RasterScanClock::Position at;
    uint64_t                  edges = 0;
    r.Read("scan_state", state);
    r.Read("scan_ticks", at.ticks);
    r.Read("scan_phase", at.phase);
    r.Read("scan_phase_den", at.phase_den);
    r.Read("scan_edges", edges);
    StopScanLocked();
    restored_   = static_cast<State>(state);
    held_at_    = at;
    edges_done_ = edges;
}

void RasterScanPeripheral::ResumeScanLocked(uint64_t now) {
    const State restored = restored_;
    restored_ = State::Stopped;
    if (restored == State::Paused) {
        state_ = State::Paused;
        return;
    }
    if (restored != State::Live) return;
    const ScanShape s = ScanShapeLocked();
    if (!scan_.Resume(now, clock_->ClockRate(), s.tick, s.frame, held_at_)) {
        DieUnschedulable("resume from a restore", s);
    }
    state_ = State::Live;
    ArmLocked();
}

#include "freescale_usb_frame_index.h"

#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "../state/state_stream.h"

namespace {

constexpr uint64_t kMicroframesPerSecond = 8000u;

/* MCIMX51RM Table 60-43: FRINDEX[13:0]. Table 60-41 FRI: with the 1024-element list the
   index rolls over every time FRINDEX[13] toggles, with 512 every time FRINDEX[12] toggles. */
constexpr uint32_t kFrindexMask  = 0x3FFFu;
constexpr uint32_t kRolloverSpan = 0x2000u;

}

/* MCIMX51RM Table 60-40: FS[2:0] is USBCMD bits 15, 3 and 2. */
uint32_t FreescaleUsbFrameIndex::FrameListSizeCode(uint32_t usbcmd) {
    return (((usbcmd >> 15) & 1u) << 2) | ((usbcmd >> 2) & 3u);
}

void FreescaleUsbFrameIndex::SetFrameListSize(uint32_t core, uint32_t fs) {
    if (fs_[core] == fs) return;
    Latch(core, Now());
    fs_[core] = static_cast<uint8_t>(fs);
}

void FreescaleUsbFrameIndex::Attach() {
    clock_ = &emu_.Get<GuestCycleClock>();
    if (!uframes_.SetRatio(clock_->CpuHz(), kMicroframesPerSecond)) {
        emu_.Get<Fatal>().Die("FreescaleUsbFrameIndex: micro-frame ratio against %llu Hz overflows",
                              static_cast<unsigned long long>(clock_->CpuHz()));
    }
    uframes_.Anchor(clock_->Cycles(), 0u);
}

void FreescaleUsbFrameIndex::SetClocked(uint32_t core, bool on) {
    if (clocked_[core] == on) return;
    Latch(core, Now());
    clocked_[core] = on;
}

void FreescaleUsbFrameIndex::Rescale() {
    if (!uframes_.Rescale(clock_->Cycles(), clock_->CpuHz(), kMicroframesPerSecond)) {
        emu_.Get<Fatal>().Die("FreescaleUsbFrameIndex: micro-frame rescale to %llu Hz overflows",
                              static_cast<unsigned long long>(clock_->CpuHz()));
    }
}

uint32_t FreescaleUsbFrameIndex::Now() const {
    return uframes_.CountAt(clock_->Cycles());
}

/* MCIMX51RM Table 60-41: SRI sets on every micro-frame start, FRI only in the host
   controller when the frame list index rolls over. */
uint32_t FreescaleUsbFrameIndex::StatusAt(uint32_t core, uint32_t now) const {
    uint32_t status = latched_[core];
    if (!Counting(core)) return status;
    const uint64_t elapsed = static_cast<uint32_t>(now - mark_[core]);
    const uint32_t span    = kRolloverSpan >> fs_[core];
    if (elapsed != 0u) status |= kStsSri;
    if (host_[core] && (frindex_[core] & (span - 1u)) + elapsed >= span) {
        status |= kStsFri;
    }
    return status;
}

uint32_t FreescaleUsbFrameIndex::FrindexAt(uint32_t core, uint32_t now) const {
    if (!Counting(core)) return frindex_[core];
    return (frindex_[core] & ~kFrindexMask) |
           ((frindex_[core] + (now - mark_[core])) & kFrindexMask);
}

void FreescaleUsbFrameIndex::Latch(uint32_t core, uint32_t now) {
    if (Counting(core)) {
        latched_[core] = StatusAt(core, now);
        frindex_[core] = FrindexAt(core, now);
    }
    mark_[core] = now;
}

void FreescaleUsbFrameIndex::SetRunning(uint32_t core, bool running, bool host) {
    if (running_[core] == running) return;
    Latch(core, Now());
    running_[core] = running;
    host_[core]    = host;
}

uint32_t FreescaleUsbFrameIndex::Frindex(uint32_t core) {
    return FrindexAt(core, Now());
}

void FreescaleUsbFrameIndex::WriteFrindex(uint32_t core, uint32_t value) {
    const uint32_t now = Now();
    Latch(core, now);
    frindex_[core] = value;
}

/* MCIMX51RM Table 60-40 RST: the controller resets its timers, counters and state machines
   to their initial value. */
void FreescaleUsbFrameIndex::Reset(uint32_t core) {
    mark_[core]    = Now();
    frindex_[core] = 0u;
    latched_[core] = 0u;
}

void FreescaleUsbFrameIndex::ResetAll() {
    for (uint32_t c = 0; c < kCores; ++c) {
        running_[c] = false;
        host_[c]    = false;
        fs_[c]      = 0u;
        Reset(c);
    }
}

uint32_t FreescaleUsbFrameIndex::Status(uint32_t core) {
    return StatusAt(core, Now());
}

void FreescaleUsbFrameIndex::ClearStatus(uint32_t core, uint32_t bits) {
    Latch(core, Now());
    latched_[core] &= ~bits;
}

uint64_t FreescaleUsbFrameIndex::NextFrameCycle(uint32_t core) {
    const uint64_t now = clock_->Cycles();
    const uint32_t to_frame = 8u - (Frindex(core) & 7u);
    return uframes_.CycleOfTick(uframes_.TicksSince(now) + to_frame);
}

uint64_t FreescaleUsbFrameIndex::NextStatusCycle(uint32_t core, uint32_t bits) {
    if (!Counting(core)) return kNever;
    const uint64_t cycles  = clock_->Cycles();
    const uint64_t ticks   = uframes_.TicksSince(cycles);
    const uint32_t now     = uframes_.CountAt(cycles);
    const uint32_t status  = StatusAt(core, now);
    const uint32_t elapsed = now - mark_[core];
    uint64_t due = kNever;
    if ((bits & kStsSri) != 0u && (status & kStsSri) == 0u) due = ticks + 1u;
    if ((bits & kStsFri) != 0u && host_[core] && (status & kStsFri) == 0u) {
        const uint32_t span = kRolloverSpan >> fs_[core];
        const uint32_t left = span - (frindex_[core] & (span - 1u)) - elapsed;
        if (ticks + left < due) due = ticks + left;
    }
    return due == kNever ? kNever : uframes_.CycleOfTick(due);
}

void FreescaleUsbFrameIndex::Save(StateWriter& w) {
    const uint64_t cycles = clock_->Cycles();
    const uint32_t now    = uframes_.CountAt(cycles);
    std::array<uint8_t, kCores>  running{};
    std::array<uint8_t, kCores>  host{};
    std::array<uint32_t, kCores> frindex{};
    std::array<uint32_t, kCores> status{};
    for (uint32_t c = 0; c < kCores; ++c) {
        running[c] = running_[c] ? 1u : 0u;
        host[c]    = host_[c] ? 1u : 0u;
        frindex[c] = FrindexAt(c, now);
        status[c]  = StatusAt(c, now);
    }
    w.WriteBytes("uframe_running", running.data(), sizeof(running));
    w.WriteBytes("uframe_host", host.data(), sizeof(host));
    w.WriteBytes("uframe_fs", fs_.data(), sizeof(fs_));
    w.WriteBytes("frindex", frindex.data(), sizeof(frindex));
    w.WriteBytes("uframe_status", status.data(), sizeof(status));
    w.Write<uint32_t>("uframe_count", now);
    w.Write<uint64_t>("uframe_phase", uframes_.PhaseAt(cycles));
    w.Write<uint64_t>("uframe_phase_den", uframes_.PhaseDenominator());
}

void FreescaleUsbFrameIndex::Restore(StateReader& r) {
    std::array<uint8_t, kCores>  running{};
    std::array<uint8_t, kCores>  host{};
    std::array<uint32_t, kCores> frindex{};
    std::array<uint32_t, kCores> status{};
    r.ReadBytes("uframe_running", running.data(), sizeof(running));
    r.ReadBytes("uframe_host", host.data(), sizeof(host));
    r.ReadBytes("uframe_fs", fs_.data(), sizeof(fs_));
    r.ReadBytes("frindex", frindex.data(), sizeof(frindex));
    r.ReadBytes("uframe_status", status.data(), sizeof(status));
    uint32_t count = 0u;
    uint64_t phase = 0u, phase_den = 0u;
    r.Read("uframe_count", count);
    r.Read("uframe_phase", phase);
    r.Read("uframe_phase_den", phase_den);
    uframes_.AnchorAtPhase(clock_->Cycles(), count, phase, phase_den);
    const uint32_t now = Now();
    for (uint32_t c = 0; c < kCores; ++c) {
        running_[c] = running[c] != 0u;
        host_[c]    = host[c] != 0u;
        frindex_[c] = frindex[c];
        latched_[c] = status[c];
        mark_[c]    = now;
    }
}

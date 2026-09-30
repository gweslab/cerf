#include "sa1111_serial_transfer.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../state/state_stream.h"

Sa1111SerialTransfer::Sa1111SerialTransfer(CerfEmulator& emu, const char* owner,
                                           uint64_t tick_hz, const Keys& keys,
                                           std::function<void(uint64_t now)> settle)
    : emu_(emu), owner_(owner), tick_hz_(tick_hz), keys_(keys), settle_(std::move(settle)) {}

void Sa1111SerialTransfer::Attach() {
    clock_ = &emu_.Get<GuestCycleClock>();
    clock_->RegisterRateListener([this] { OnRateChange(); });
}

GuestCycleClock& Sa1111SerialTransfer::Clock() const {
    if (clock_ == nullptr) {
        emu_.Get<Fatal>().Die("%s: serial transfer used before Attach", owner_);
    }
    return *clock_;
}

void Sa1111SerialTransfer::RequireScale(bool fits) const {
    if (fits) return;
    emu_.Get<Fatal>().Die("%s: the %llu Hz transfer clock against the %llu Hz core overflows "
                          "the 64-bit scale", owner_, static_cast<unsigned long long>(tick_hz_),
                          static_cast<unsigned long long>(Clock().CpuHz()));
}

void Sa1111SerialTransfer::Start(uint64_t now, uint64_t ticks) {
    RequireScale(counter_.SetRatio(Clock().CpuHz(), tick_hz_));
    counter_.Anchor(now, 0u);
    ticks_  = ticks;
    active_ = true;
}

void Sa1111SerialTransfer::OnRateChange() {
    const uint64_t now = clock_->Cycles();
    if (settle_) settle_(now);
    if (!Busy(now)) return;
    RequireScale(counter_.Rescale(now, clock_->CpuHz(), tick_hz_));
}

void Sa1111SerialTransfer::Save(StateWriter& w, uint64_t now) const {
    const bool busy = Busy(now);
    w.Write<uint8_t>(keys_.busy, busy ? 1u : 0u);
    w.Write<uint64_t>(keys_.ticks, busy ? ticks_ : 0u);
    w.Write<uint64_t>(keys_.elapsed, busy ? Elapsed(now) : 0u);
    w.Write<uint64_t>(keys_.phase, busy ? counter_.PhaseAt(now) : 0u);
    w.Write<uint64_t>(keys_.phase_den, busy ? counter_.PhaseDenominator() : 1u);
}

void Sa1111SerialTransfer::Restore(StateReader& r, uint64_t now) {
    uint8_t  busy = 0u;
    uint64_t ticks = 0u, elapsed = 0u, phase = 0u, phase_den = 1u;
    r.Read(keys_.busy, busy);
    r.Read(keys_.ticks, ticks);
    r.Read(keys_.elapsed, elapsed);
    r.Read(keys_.phase, phase);
    r.Read(keys_.phase_den, phase_den);
    active_ = busy != 0u;
    ticks_  = ticks;
    if (!active_) return;
    RequireScale(counter_.SetRatio(Clock().CpuHz(), tick_hz_));
    counter_.AnchorAtPhase(now, static_cast<uint32_t>(elapsed), phase, phase_den);
}

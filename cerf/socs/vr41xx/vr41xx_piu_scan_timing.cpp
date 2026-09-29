#include "vr41xx_piu_scan_timing.h"

#include <algorithm>

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../state/state_stream.h"
#include "vr41xx_rtcx_ticks.h"

namespace {

constexpr uint64_t kAdConversionNs = 10000u;

}

void Vr41xxPiuScanTiming::Attach(GuestCycleClock* clock, Vr41xxRtcxTicks* rtcx) {
    clock_ = clock;
    rtcx_  = rtcx;
}

/* DataScan "S A S A S A S A", ADPScan "A A A A", S = STABLE x 30 us, A = "about 10 us"
   (VR4121 UM Figure 20-5, VR4102 UM Figure 19-5); STABLE is the DataScan and CmdScan
   stabilization time (VR4121 UM 20.3.4); CmdScan fetches "one port only" (20.2 (4)). */
uint64_t Vr41xxPiuScanTiming::ReadyCycle(uint16_t kind, uint16_t stable, uint64_t start_tick,
                                         uint64_t start_cycle) {
    const uint64_t pairs  = kind == kData ? 4u : kind == kCmd ? 1u : 0u;
    const uint64_t convs  = kind == kCmd ? 1u : 4u;
    const uint64_t settle = pairs * (stable & 0x003Fu);
    const uint64_t settled =
        settle == 0u ? start_cycle : std::max(start_cycle, rtcx_->CycleOf(start_tick + settle));
    return settled + clock_->NsToCycles(static_cast<int64_t>(convs * kAdConversionNs));
}

void Vr41xxPiuScanTiming::Begin(uint16_t kind, uint16_t stable, uint64_t start_tick,
                                uint64_t start_cycle) {
    if (kind_ != kIdle) {
        emu_.Get<Fatal>().Die("VR41xx PIU: scan %u started while scan %u is in flight; "
                              "PADDLOSTINTR is not modeled", kind, kind_);
    }
    kind_        = kind;
    ready_cycle_ = ReadyCycle(kind, stable, start_tick, start_cycle);
}

uint16_t Vr41xxPiuScanTiming::Take() {
    const uint16_t kind = kind_;
    kind_ = kIdle;
    return kind;
}

void Vr41xxPiuScanTiming::Save(StateWriter& w, uint64_t now) const {
    w.Write("scan_kind", kind_);
    w.Write("scan_ready_in", kind_ != kIdle && ready_cycle_ > now ? ready_cycle_ - now : uint64_t{0});
}

void Vr41xxPiuScanTiming::Restore(StateReader& r, uint64_t now) {
    uint64_t ready_in = 0;
    r.Read("scan_kind", kind_);
    r.Read("scan_ready_in", ready_in);
    ready_cycle_ = now + ready_in;
}

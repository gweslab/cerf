#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "pxa255_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <chrono>
#include <cstdint>
#include <mutex>

namespace {

/* PXA255 RTC, base 0x40900000 (§4.3). §4.3.1: RCNR is a free-running 1 Hz
   up-counter "unaffected by transitions into and out of Sleep" - it advances in
   real wall-clock time and keeps ticking while the JIT thread is parked in deep
   sleep, where guest-cycle time does not advance, so the resumed guest reads the
   true elapsed wall time. */
class Pxa255Rtc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Pxa255;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x40900000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    using Clock = std::chrono::steady_clock;
    static constexpr uint32_t kRttrMask = 0x03FFFFFFu;  /* bits 25:0 */

    /* RCNR = rcnr_base_ + whole real seconds elapsed since baseline_. A guest
       write rebases (base = value, baseline = now); reads recompute live. */
    uint32_t ReadRcnrLocked() const {
        const auto secs = std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now() - baseline_).count();
        return rcnr_base_ + static_cast<uint32_t>(secs);
    }

    mutable std::mutex  mtx_;
    uint32_t            rcnr_base_ = 0;        /* §4.3.1 RCNR resets to 0. */
    Clock::time_point   baseline_  = Clock::now();
    uint32_t            rtar_ = 0;
    uint32_t            rtsr_ = 0;
    uint32_t            rttr_ = 0x00007FFFu;   /* §4.3.3 nRESET default. */
};

uint32_t Pxa255Rtc::ReadWord(uint32_t addr) {
    std::lock_guard<std::mutex> g(mtx_);
    switch (addr - MmioBase()) {
        case 0x00: return ReadRcnrLocked();
        case 0x04: return rtar_;
        case 0x08: return rtsr_ & 0xFu;
        case 0x0C: return rttr_ & kRttrMask;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa255Rtc::WriteWord(uint32_t addr, uint32_t value) {
    std::lock_guard<std::mutex> g(mtx_);
    switch (addr - MmioBase()) {
        case 0x00: rcnr_base_ = value; baseline_ = Clock::now(); return;
        case 0x04: rtar_ = value; return;
        /* RTSR: HZ(bit1)/AL(bit0) are write-1-to-clear status; HZE(bit3)/
           ALE(bit2) are read/write enables (Table 4-40). */
        case 0x08: rtsr_ = (rtsr_ & 0x3u & ~value) | (value & 0xCu); return;
        /* §4.3.2: a write to RTTR increments RCNR by one. */
        case 0x0C: rttr_ = value & kRttrMask; ++rcnr_base_; return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Pxa255Rtc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> g(mtx_);
    w.Write("rcnr", ReadRcnrLocked());
    w.Write("rtar", rtar_); w.Write("rtsr", rtsr_); w.Write("rttr", rttr_);
}

void Pxa255Rtc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> g(mtx_);
    r.Read("rcnr", rcnr_base_);
    baseline_ = Clock::now();    /* never raw-serialize a time_point (hibernation.md) */
    r.Read("rtar", rtar_); r.Read("rtsr", rtsr_); r.Read("rttr", rttr_);
}

}  /* namespace */

REGISTER_SERVICE(Pxa255Rtc);

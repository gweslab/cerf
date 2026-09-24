#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "omap3530_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/virtual_clock.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "omap3530_clocks.h"

#include <cstdint>
#include <mutex>

namespace {

/* OMAP3530 TRM SPRUF98Y Table 16-92 (printed p. 2662): base 0x4832 0000,
   4K bytes. Table 16-93: REG_32KSYNCNT_REV 0x0000 R, REG_32KSYNCNT_SYSCONFIG
   0x0004 R/W, REG_32KSYNCNT_CR 0x0010 R. */
constexpr uint32_t kSynctimerBasePa = 0x48320000u;
constexpr uint32_t kSynctimerSize   = 0x00001000u;

constexpr uint32_t kOffRev       = 0x00;
constexpr uint32_t kOffSysconfig = 0x04;
constexpr uint32_t kOffCr        = 0x10;

/* OMAP3530 TRM SPRUF98Y Table 16-98 (printed p. 2663): REG_32KSYNCNT_CR
   COUNTER_VALUE [31:0], reset 0x00000003. §16.6.1 (printed p. 2660): counting
   starts from the reset value three 32-kHz clock periods after the power-up
   reset is released. */
constexpr uint32_t kCounterResetValue = 0x00000003u;

class Omap3530Synctimer : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Omap3530;
    }
    /* §16.6.1 (printed p. 2660): the counter is reset only while the external
       asynchronous power-up reset sys_nrespwron is active. §16.6.1.2 lists
       "Start and keep counting after power-on reset", so no CPU reset line
       rewinds it. */
    void OnReady() override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        SetAnchorLocked(kCounterResetValue, NowNs());
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kSynctimerBasePa; }
    uint32_t MmioSize() const override { return kSynctimerSize; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    static uint32_t NsToTicks(int64_t ns) {
        if (ns <= 0) return 0;
        return static_cast<uint32_t>(static_cast<uint64_t>(ns) *
                                     kOmap3530TkPerUnit / kOmap3530NsPerUnit);
    }

    int64_t NowNs() const { return emu_.Get<VirtualClock>().NowNs(); }

    /* §16.6.1 (printed p. 2660): a free-running 32-bit upward counter that
       wraps back to 0 after 0xFFFF FFFF. */
    uint32_t CounterAtLocked(int64_t now) const {
        return count_anchor_ + NsToTicks(now - anchor_ns_);
    }

    void SetAnchorLocked(uint32_t count, int64_t now) {
        count_anchor_ = count;
        anchor_ns_    = now;
    }

    mutable std::mutex state_mutex_;
    uint32_t           count_anchor_ = kCounterResetValue;
    int64_t            anchor_ns_    = 0;
};

uint32_t Omap3530Synctimer::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    std::lock_guard<std::mutex> lk(state_mutex_);
    switch (off) {
    /* Table 16-94 (printed p. 2662): CID_REV [7:0] holds the counter revision
       number, whose reset value the manual gives as TI internal data. */
    case kOffRev:       return 0u;
    case kOffCr:        return CounterAtLocked(NowNs());
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Omap3530Synctimer::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    std::lock_guard<std::mutex> lk(state_mutex_);
    switch (off) {
    /* Table 16-93 (printed p. 2662): REV and CR are type R. §16.6.1.2 (printed
       p. 2660): "no write operation is supported (no error/no action on
       write)". */
    case kOffRev:       return;
    case kOffCr:        return;
    /* Table 16-96 (printed p. 2663): REG_32KSYNCNT_SYSCONFIG "is used for IDLE
       modes only"; its one field IDLEMODE [4:3] is "Power management REQ/ACK
       control". */
    case kOffSysconfig: return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Omap3530Synctimer::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    w.Write<uint32_t>("counter", CounterAtLocked(NowNs()));
}

void Omap3530Synctimer::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    uint32_t counter = 0;
    r.Read("counter", counter);
    SetAnchorLocked(counter, NowNs());
}

}  /* namespace */

REGISTER_SERVICE(Omap3530Synctimer);

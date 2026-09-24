#include "../../peripherals/peripheral_base.h"

#include "../guest_cpu_reset.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../host/guest_deep_sleep.h"
#include "../../jit/guest_engine.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <atomic>

namespace {

/* SA-1110 Dev Man §9.6.1: RSRR +0x0 bit 0 SWR=1 triggers chip
   software reset. RCSR +0x4 is W1C on bits 3:0 = SMR|WDR|SWR|HWR;
   HWR cold-resets to 1, others to 0; bits 31:4 reserved. */

class Sa11xxResetController : public Peripheral,
                             public ResetCauseLatch,
                             public DeepSleepWaker {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestCpuReset>().SetCauseLatch(this);
        emu_.Get<GuestDeepSleep>().RegisterWaker(this);
    }

    /* §9.6.1.2 RCSR: bit0=HWR bit1=SWR bit2=WDR. §9.6: DRAM survives
       SWR/WDR, is lost on HWR - hence warm→SWR, cold→HWR. PPC2002
       startup (nk @0x411E0) needs RCSR&7 != 0; a causeless reset reads
       as sleep-exit and resumes from a stale save block (UND loop). */
    void LatchWarmReset() override {
        rcsr_.fetch_or(0x2u, std::memory_order_acq_rel);
    }
    void LatchColdReset() override {
        rcsr_.fetch_or(0x1u, std::memory_order_acq_rel);
    }
    void LatchWatchdogReset() override {
        rcsr_.fetch_or(0x4u, std::memory_order_acq_rel);
    }
    /* DeepSleepWaker: §9.6.1.2 RCSR bit3 SMR (sleep-mode reset) - the OAL boot
       path reads it and takes its sleep-resume branch. */
    void LatchSleepWakeCause() override {
        rcsr_.fetch_or(0x8u, std::memory_order_acq_rel);
    }
    void ClearSleepWakeCause() override {
        rcsr_.fetch_and(~0x8u, std::memory_order_acq_rel);
    }

    uint32_t MmioBase() const override { return 0x90030000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    /* Atomic: latched from host/timer threads while the JIT thread
       reads/W1C-clears it. */
    std::atomic<uint32_t> rcsr_{0x1u};  /* HWR cold-reset state per §9.6.1.2. */

    /* SA-1110 Dev Man App. D.1: TUCR (+0x08, reset 0) is a R/W control
       register - TSEL2:0 clock-out select, MIR, PMD; no hardware-set
       bits - so plain storage is faithful. The clock-out routing
       (TSEL=0b101 drives RCLK to the SA-1111) has no CERF side effect. */
    uint32_t tucr_ = 0;

    void ApplyRcsrW1c(uint32_t v) {
        rcsr_.fetch_and(~(v & 0xFu), std::memory_order_acq_rel);
    }

    void HandleRsrrWrite(uint32_t value) {
        /* §9.6.1.1: SWR=0 has no effect; SWR=1 invokes a full chip
           reset. The SA-1110 sets the SWR status bit in RCSR as the
           reset reason so the kernel can identify the source on the
           re-entered boot path. */
        if ((value & 0x1u) == 0) return;
        const uint32_t rcsr = rcsr_.fetch_or(0x2u, std::memory_order_acq_rel) | 0x2u;
        LOG(SocReset, "RSRR SWR=1: triggering guest reset (rcsr_=0x%08X)\n",
            rcsr);
        emu_.Get<GuestEngine>().SetResetPending(false);
    }
};

uint8_t Sa11xxResetController::ReadByte(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off == 0x0) return 0;                /* RSRR W-only, reads 0. */
    if (off >= 0x4 && off <= 0x7) {
        return static_cast<uint8_t>((rcsr_ >> (8 * (off - 0x4))) & 0xFFu);
    }
    if (off >= 0x8 && off <= 0xB) {
        return static_cast<uint8_t>((tucr_ >> (8 * (off - 0x8))) & 0xFFu);
    }
    HaltUnsupportedAccess("ReadByte", addr, 0);
}

uint32_t Sa11xxResetController::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off == 0x0) return 0;
    if (off == 0x4) return rcsr_;
    if (off == 0x8) return tucr_;
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Sa11xxResetController::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - MmioBase();
    if (off == 0x0) { HandleRsrrWrite(value); return; }
    if (off == 0x4) { ApplyRcsrW1c(value); return; }
    if (off >= 0x5 && off <= 0x7) return;    /* RCSR bytes 1..3 reserved. */
    if (off >= 0x8 && off <= 0xB) {
        const uint32_t shift = 8 * (off - 0x8);
        tucr_ = (tucr_ & ~(0xFFu << shift)) | (static_cast<uint32_t>(value) << shift);
        return;
    }
    HaltUnsupportedAccess("WriteByte", addr, value);
}

void Sa11xxResetController::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off == 0x0) { HandleRsrrWrite(value); return; }
    if (off == 0x4) { ApplyRcsrW1c(value); return; }
    if (off == 0x8) { tucr_ = value; return; }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Sa11xxResetController::SaveState(StateWriter& w) {
    w.Write("rcsr", rcsr_.load(std::memory_order_acquire));
    w.Write("tucr", tucr_);
}

void Sa11xxResetController::RestoreState(StateReader& r) {
    uint32_t rcsr = 0;
    r.Read("rcsr", rcsr);
    rcsr_.store(rcsr, std::memory_order_release);
    r.Read("tucr", tucr_);
}

}  /* namespace */

REGISTER_SERVICE(Sa11xxResetController);

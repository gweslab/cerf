#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../jit/arm_jit.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace {

/* SA-1110 Dev Man §9.6.1: RSRR +0x0 bit 0 SWR=1 triggers chip
   software reset. RCSR +0x4 is W1C on bits 3:0 = SMR|WDR|SWR|HWR;
   HWR cold-resets to 1, others to 0; bits 31:4 reserved. */

class Sa1110ResetController : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::SA1110;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x90030000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    uint32_t rcsr_ = 0x1u;  /* HWR cold-reset state per §9.6.1.2. */

    void ApplyRcsrW1c(uint32_t v) { rcsr_ &= ~(v & 0xFu); }

    void HandleRsrrWrite(uint32_t value) {
        /* §9.6.1.1: SWR=0 has no effect; SWR=1 invokes a full chip
           reset. The SA-1110 sets the SWR status bit in RCSR as the
           reset reason so the kernel can identify the source on the
           re-entered boot path. */
        if ((value & 0x1u) == 0) return;
        rcsr_ |= 0x2u;
        LOG(SocReset, "RSRR SWR=1: triggering guest reset (rcsr_=0x%08X)\n",
            rcsr_);
        emu_.Get<ArmJit>().SetResetPending();
    }
};

uint8_t Sa1110ResetController::ReadByte(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off == 0x0) return 0;                /* RSRR W-only, reads 0. */
    if (off >= 0x4 && off <= 0x7) {
        return static_cast<uint8_t>((rcsr_ >> (8 * (off - 0x4))) & 0xFFu);
    }
    HaltUnsupportedAccess("ReadByte", addr, 0);
}

uint32_t Sa1110ResetController::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off == 0x0) return 0;
    if (off == 0x4) return rcsr_;
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Sa1110ResetController::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - MmioBase();
    if (off == 0x0) { HandleRsrrWrite(value); return; }
    if (off == 0x4) { ApplyRcsrW1c(value); return; }
    if (off >= 0x5 && off <= 0x7) return;    /* RCSR bytes 1..3 reserved. */
    HaltUnsupportedAccess("WriteByte", addr, value);
}

void Sa1110ResetController::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off == 0x0) { HandleRsrrWrite(value); return; }
    if (off == 0x4) { ApplyRcsrW1c(value); return; }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

}  /* namespace */

REGISTER_SERVICE(Sa1110ResetController);

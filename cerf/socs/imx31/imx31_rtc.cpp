#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x53FD8000u;
constexpr uint32_t kSize = 0x00004000u;

/* MCIMX31RM Table 36-1 (PDF p1511): RTC has 10 R/W registers at
   offsets 0x00..0x24. Reset value of RTCCTL = 0x80 (EN=1, XTL=00,
   GEN=0, SWR=0); all other registers reset to 0. */
constexpr uint32_t kSlotCount     = 10u;
constexpr uint32_t kLastOff       = 0x24u;
constexpr uint32_t kRtcctlSlot    =  4u;
constexpr uint32_t kRtcisrSlot    =  5u;
constexpr uint32_t kRtcctlResetV  = 0x00000080u;

/* MCIMX31RM Table 36-8 (PDF p1518): RTCCTL bit layout — bit 7 EN,
   bits 6-5 XTL, bit 1 GEN, bit 0 SWR (self-clearing software reset).
   The reserved bits stay 0 on read. */
constexpr uint32_t kRtcctlMask    = 0x000000E3u;
constexpr uint32_t kRtcctlSwrBit  = 1u << 0;

/* MCIMX31RM Table 36-9 (PDF p1519): RTCISR — bits 15..0 are interrupt
   flags (SAM7..SAM0, 2HZ, HR, 1HZ, DAY, ALM, MIN, SW), all W1C; bit 6
   reserved (reads 0). */
constexpr uint32_t kRtcisrW1cMask = 0x0000FFBFu;

bool OffsetToSlot(uint32_t off, uint32_t* slot_out) {
    if (off > kLastOff || (off & 0x3u) != 0u) return false;
    *slot_out = off / 4u;
    return true;
}

class Imx31Rtc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override {
        for (uint32_t i = 0; i < kSlotCount; ++i) regs_[i] = 0u;
        regs_[kRtcctlSlot] = kRtcctlResetV;
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    uint32_t regs_[kSlotCount] = {};
};

uint32_t Imx31Rtc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - kBase;
    uint32_t slot;
    if (!OffsetToSlot(off, &slot)) HaltUnsupportedAccess("ReadWord", addr, 0);
    return regs_[slot];
}

void Imx31Rtc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - kBase;
    uint32_t slot;
    if (!OffsetToSlot(off, &slot)) HaltUnsupportedAccess("WriteWord", addr, value);
    if (slot == kRtcctlSlot) {
        if ((value & kRtcctlSwrBit) != 0) {
            const uint32_t preserved_en = regs_[kRtcctlSlot] & 0x80u;
            for (uint32_t i = 0; i < kSlotCount; ++i) regs_[i] = 0u;
            regs_[kRtcctlSlot] = preserved_en;
            return;
        }
        regs_[slot] = value & kRtcctlMask;
        return;
    }
    if (slot == kRtcisrSlot) {
        regs_[slot] &= ~(value & kRtcisrW1cMask);
        return;
    }
    regs_[slot] = value;
}

}  /* namespace */

REGISTER_SERVICE(Imx31Rtc);

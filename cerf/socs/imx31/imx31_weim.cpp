#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

constexpr uint32_t kWeimBase = 0xB8002000u;
constexpr uint32_t kWeimSize = 0x00001000u;

constexpr uint32_t kSlotCount = 19u;

/* CSCR0U/L/A defaults per BOOT_CFG; Zune 30 (Keel) boots from NOR so the
   documented defaults in Table 18-5 apply. All other slots reset 0. */
constexpr uint32_t kResetValues[kSlotCount] = {
    0x00000100u,   /* 0x00 CSCR0U */
    0x00000801u,   /* 0x04 CSCR0L */
    0x00008000u,   /* 0x08 CSCR0A */
    0x00000000u,   /* 0x10 CSCR1U */
    0x00000000u,   /* 0x14 CSCR1L */
    0x00000000u,   /* 0x18 CSCR1A */
    0x00000000u,   /* 0x20 CSCR2U */
    0x00000000u,   /* 0x24 CSCR2L */
    0x00000000u,   /* 0x28 CSCR2A */
    0x00000000u,   /* 0x30 CSCR3U */
    0x00000000u,   /* 0x34 CSCR3L */
    0x00000000u,   /* 0x38 CSCR3A */
    0x00000000u,   /* 0x40 CSCR4U */
    0x00000000u,   /* 0x44 CSCR4L */
    0x00000000u,   /* 0x48 CSCR4A */
    0x00000000u,   /* 0x50 CSCR5U */
    0x00000000u,   /* 0x54 CSCR5L */
    0x00000000u,   /* 0x58 CSCR5A */
    0x00000100u,   /* 0x60 WCR    — per Table 18-5; figure shows 0,
                                    table is authoritative */
};

class Imx31Weim : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override {
        for (uint32_t i = 0; i < kSlotCount; ++i) regs_[i] = kResetValues[i];
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kWeimBase; }
    uint32_t MmioSize() const override { return kWeimSize; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    uint32_t regs_[kSlotCount] = {};

    /* CSCR layout: 6 CS groups of 3 dwords each at +0x10 stride,
       then WCR at 0x60. Gap slots 0x0C/0x1C/0x2C/0x3C/0x4C/0x5C
       are NOT documented; halt-on-access. */
    static bool OffsetToSlot(uint32_t off, uint32_t* slot_out) {
        if ((off & 0x3u) != 0u) return false;
        if (off == 0x60u) { *slot_out = 18u; return true; }
        if (off >= 0x60u) return false;
        const uint32_t group = off / 0x10u;        /* 0..5 = CS0..CS5 */
        const uint32_t in_gp = off & 0x0Fu;        /* 0/4/8 = U/L/A; 0xC = gap */
        if (group >= 6u) return false;
        if (in_gp == 0x0u) { *slot_out = group * 3u + 0u; return true; }
        if (in_gp == 0x4u) { *slot_out = group * 3u + 1u; return true; }
        if (in_gp == 0x8u) { *slot_out = group * 3u + 2u; return true; }
        return false;  /* 0xC gap */
    }
};

uint32_t Imx31Weim::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint32_t slot;
    if (!OffsetToSlot(off, &slot)) HaltUnsupportedAccess("ReadWord", addr, 0);
    return regs_[slot];
}

void Imx31Weim::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    uint32_t slot;
    if (!OffsetToSlot(off, &slot)) HaltUnsupportedAccess("WriteWord", addr, value);
    regs_[slot] = value;
}

}  /* namespace */

REGISTER_SERVICE(Imx31Weim);

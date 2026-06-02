#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

constexpr uint32_t kCcmBase = 0x53F80000u;
constexpr uint32_t kCcmSize = 0x00004000u;

constexpr uint32_t kSlotCount = 26u;

/* Reset values verbatim from MCIMX31RM Table 3-1 (PDF p197..199).
   CCMR default depends on the external CLKSS pin signal; CERF picks
   the CLKSS-low encoding (0x074B_0B7B). */
constexpr uint32_t kResetValues[kSlotCount] = {
    0x074B0B7Bu,   /* 0x00 CCMR    */
    0xFF870B48u,   /* 0x04 PDR0    */
    0x49FCFE7Fu,   /* 0x08 PDR1    */
    0x007F0000u,   /* 0x0C RCSR    */
    0x04001800u,   /* 0x10 MPCTL   */
    0x04051C03u,   /* 0x14 UPCTL   */
    0x04043001u,   /* 0x18 SPCTL   */
    0x00000280u,   /* 0x1C COSR    */
    0xFFFFFFFFu,   /* 0x20 CGR0    */
    0xFFFFFFFFu,   /* 0x24 CGR1    */
    0xFFFFFFFFu,   /* 0x28 CGR2    */
    0xFFFFFFFFu,   /* 0x2C WIMR0   */
    0x0000000Fu,   /* 0x30 LDC     */
    0x00000000u,   /* 0x34 DCVR0   */
    0x00000000u,   /* 0x38 DCVR1   */
    0x00000000u,   /* 0x3C DCVR2   */
    0x00000000u,   /* 0x40 DCVR3   */
    0x00000000u,   /* 0x44 LTR0    */
    0x00004040u,   /* 0x48 LTR1    */
    0x00000000u,   /* 0x4C LTR2    */
    0x00000000u,   /* 0x50 LTR3    */
    0x00000000u,   /* 0x54 LTBR0   (R only) */
    0x00000000u,   /* 0x58 LTBR1   (R only) */
    0x80209828u,   /* 0x5C PMCR0   */
    0x00AA0000u,   /* 0x60 PMCR1   */
    0x00000285u,   /* 0x64 PDR2    */
};

constexpr uint32_t kRcsrSlot  =  3u;
constexpr uint32_t kLtbr0Slot = 21u;
constexpr uint32_t kLtbr1Slot = 22u;
constexpr uint32_t kPmcr0Slot = 23u;
constexpr uint32_t kPmcr0DptenBit = 1u << 0;
constexpr uint32_t kPmcr0DvfenBit = 1u << 4;

class Imx31Ccm : public Peripheral {
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

    uint32_t MmioBase() const override { return kCcmBase; }
    uint32_t MmioSize() const override { return kCcmSize; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint16_t ReadHalf (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    uint32_t regs_[kSlotCount] = {};

    static bool OffsetToSlot(uint32_t off, uint32_t* slot_out) {
        if (off > 0x64u || (off & 0x3u) != 0u) return false;
        *slot_out = off / 4u;
        return true;
    }
};

uint32_t Imx31Ccm::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint32_t slot;
    if (!OffsetToSlot(off, &slot)) HaltUnsupportedAccess("ReadWord", addr, 0);
    return regs_[slot];
}

void Imx31Ccm::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    uint32_t slot;
    if (!OffsetToSlot(off, &slot)) HaltUnsupportedAccess("WriteWord", addr, value);
    if (slot == kLtbr0Slot || slot == kLtbr1Slot) return;
    if (slot == kRcsrSlot) {
        constexpr uint32_t kRcsrRoMask = (0x1Fu << 23) | 0x7u;
        regs_[slot] = (regs_[slot] & kRcsrRoMask) | (value & ~kRcsrRoMask);
        return;
    }
    if (slot == kPmcr0Slot) {
        if ((value & kPmcr0DptenBit) != 0 || (value & kPmcr0DvfenBit) != 0) {
            LOG(SocClkpwr, "[CCM] PMCR0 write 0x%08X enables DPTC/DVFS state "
                        "machine; CERF does not simulate workload counters, "
                        "comparator crossings, or interrupt event generation\n",
                value);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        constexpr uint32_t kLbflBit = 1u << 20;
        const uint32_t preserved = regs_[slot] & kLbflBit & value;
        regs_[slot] = (value & ~kLbflBit) | preserved;
        return;
    }
    regs_[slot] = value;
}

uint8_t Imx31Ccm::ReadByte(uint32_t addr) {
    const uint32_t base  = addr & ~0x3u;
    const uint32_t shift = (addr & 0x3u) * 8u;
    return static_cast<uint8_t>((ReadWord(base) >> shift) & 0xFFu);
}

uint16_t Imx31Ccm::ReadHalf(uint32_t addr) {
    if ((addr & 0x1u) != 0) HaltUnsupportedAccess("ReadHalf-unaligned", addr, 0);
    const uint32_t base  = addr & ~0x3u;
    const uint32_t shift = (addr & 0x2u) * 8u;
    return static_cast<uint16_t>((ReadWord(base) >> shift) & 0xFFFFu);
}

void Imx31Ccm::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t base  = addr & ~0x3u;
    const uint32_t shift = (addr & 0x3u) * 8u;
    const uint32_t old   = ReadWord(base);
    const uint32_t merged = (old & ~(0xFFu << shift)) |
                            (static_cast<uint32_t>(value) << shift);
    WriteWord(base, merged);
}

void Imx31Ccm::WriteHalf(uint32_t addr, uint16_t value) {
    if ((addr & 0x1u) != 0) HaltUnsupportedAccess("WriteHalf-unaligned", addr, value);
    const uint32_t base  = addr & ~0x3u;
    const uint32_t shift = (addr & 0x2u) * 8u;
    const uint32_t old   = ReadWord(base);
    const uint32_t merged = (old & ~(0xFFFFu << shift)) |
                            (static_cast<uint32_t>(value) << shift);
    WriteWord(base, merged);
}

}  /* namespace */

REGISTER_SERVICE(Imx31Ccm);

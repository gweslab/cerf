#include "imx31_ccm.h"

#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>
#include "imx31_id.h"

namespace {

constexpr uint32_t kSlotCount = Imx31Ccm::kSlotCount;

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

constexpr uint32_t kCcmrSlot  = 0u;
constexpr uint32_t kPdr1Slot  = 2u;
constexpr uint32_t kUpctlSlot = 5u;
constexpr uint32_t kSpctlSlot = 6u;
constexpr uint32_t kCgr1Slot  = 9u;

/* The board crystal feeding pll_ref_clk (MCIMX31RM Figure 3-24). The manual states
   no frequency; 27 MHz is derived from the OAL's own PLL constants (nk.exe start():
   MPCTL=0x00082407, SPCTL=0x00021C01, UPCTL=0x007C1822), the only reference at which
   Eqn 3-1 yields integral 528.000 / 396.000 / 338.688 MHz. */
constexpr uint32_t kCkihHz = 27000000u;

}  /* namespace */

bool Imx31Ccm::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Imx31;
}

void Imx31Ccm::OnReady() {
    for (uint32_t i = 0; i < kSlotCount; ++i) regs_[i] = kResetValues[i];
    emu_.Get<PeripheralDispatcher>().Register(this);
}

/* Eqn 3-1: Fvco = Fref x 2 x (MFI + MFN/MFD) / PD. Field encodings per Table 3-8
   (MPCTL) / Table 3-9 (UPCTL): PD and MFD are stored biased by one, MFI saturates
   up to 5, MFN is a signed 10-bit two's-complement numerator. */
uint32_t Imx31Ccm::PllHz(uint32_t ctl) const {
    const uint32_t pd  = ((ctl >> 26) & 0xFu) + 1u;
    const uint32_t mfd = ((ctl >> 16) & 0x3FFu) + 1u;
    uint32_t mfi = (ctl >> 10) & 0xFu;
    if (mfi < 5u) mfi = 5u;
    int32_t mfn = static_cast<int32_t>(ctl & 0x3FFu);
    if (mfn & 0x200) mfn -= 0x400;

    const int64_t num = static_cast<int64_t>(2) * kCkihHz *
                        (static_cast<int64_t>(mfi) * mfd + mfn);
    return static_cast<uint32_t>(num / (static_cast<int64_t>(mfd) * pd));
}

uint32_t Imx31Ccm::SsiClockHz(uint32_t ssi) const {
    const uint32_t ccmr = regs_[kCcmrSlot];
    const uint32_t pdr1 = regs_[kPdr1Slot];

    /* Table 3-4: SSI1S = CCMR[19:18], SSI2S = CCMR[22:21].
       Table 3-6: SSI1_PRE_PODF = PDR1[8:6], SSI1_PODF = PDR1[5:0],
                  SSI2_PRE_PODF = PDR1[17:15], SSI2_PODF = PDR1[14:9].
       Both dividers are stored biased by one. */
    uint32_t sel, pre, post;
    if (ssi == 1u) {
        sel  = (ccmr >> 18) & 0x3u;
        pre  = ((pdr1 >> 6) & 0x7u) + 1u;
        post = ((pdr1 >> 0) & 0x3Fu) + 1u;
    } else {
        sel  = (ccmr >> 21) & 0x3u;
        pre  = ((pdr1 >> 15) & 0x7u) + 1u;
        post = ((pdr1 >> 9) & 0x3Fu) + 1u;
    }

    uint32_t src;
    switch (sel) {
        case 1: {
            /* usb_clk is the USB PLL through USB_PRDF = PDR1[31:30] and
               USB_PODF = PDR1[29:27], both stored biased by one (Table 3-6). */
            const uint32_t usb_pre  = ((pdr1 >> 30) & 0x3u) + 1u;
            const uint32_t usb_post = ((pdr1 >> 27) & 0x7u) + 1u;
            src = PllHz(regs_[kUpctlSlot]) / (usb_pre * usb_post);
            break;
        }
        case 2: src = PllHz(regs_[kSpctlSlot]); break;   /* serial_clk */
        default:
            /* mcu_clk taps mcu_main_clk after the MCU switch unit and its
               dividers, which this register file does not model. */
            LOG(SocClkpwr, "[CCM] SSI%u clock source select %u (mcu_clk/reserved) "
                "is not modelled\n", ssi, sel);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    return src / (pre * post);
}

void Imx31Ccm::RegisterGate1Listener(std::function<void()> fn) {
    gate1_listeners_.push_back(std::move(fn));
}

/* Figure 3-24: the hsp divider is fed from mcu_main_clk; Table 3-5 HSP_PODF
   [13:11], value + 1. */
uint64_t Imx31Ccm::HspClkHz() const {
    return McuMainClkHz() / (((regs_[kPdr0Slot] >> 11) & 0x7u) + 1u);
}

uint32_t Imx31Ccm::ClockGate1(uint32_t index) const {
    return (regs_[kCgr1Slot] >> (2u * index)) & 0x3u;
}

/* MCIMX31RM Table 3-12: 01 on in run mode only, 10 on in run and wait modes,
   11 on in all modes except when the PLL clock is off. */
bool Imx31Ccm::ClockGateRunsIn(uint32_t cg, FreescaleLowPowerMode mode) {
    switch (mode) {
        case FreescaleLowPowerMode::kRun:  return cg != 0u;
        case FreescaleLowPowerMode::kWait: return cg == 2u || cg == 3u;
        case FreescaleLowPowerMode::kDoze: return cg == 3u;
        default:                           return false;
    }
}

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
    if (slot == kCgr1Slot && old != value) {
        for (auto& fn : gate1_listeners_) fn();
    }
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

REGISTER_SERVICE(Imx31Ccm);

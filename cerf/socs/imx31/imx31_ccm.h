#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../state/state_stream.h"

#include <cstdint>

/* MCIMX31RM Table 3-1: AP Clock Controller at 0x53F8_0000. Named (not anonymous)
   so Imx31AudioPlayer can resolve the SSI serial clock its sample rate derives
   from (MCIMX31RM Figure 3-24, Table 3-4 SSIxS, Table 3-6 SSIx_PODF). */
class Imx31Ccm : public Peripheral {
public:
    using Peripheral::Peripheral;

    static constexpr uint32_t kSlotCount = 26u;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x53F80000u; }
    uint32_t MmioSize() const override { return 0x00004000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint16_t ReadHalf (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    /* JIT-thread-only register file (no worker thread). */
    void SaveState(StateWriter& w) override    { w.WriteBytes("regs", regs_, sizeof(regs_)); }
    void RestoreState(StateReader& r) override { r.ReadBytes("regs", regs_, sizeof(regs_)); }

    /* ccm_ssi_clk for SSI1 / SSI2 (MCIMX31RM Figure 3-24): the CCMR-selected PLL
       through the SSIx pre and post dividers. Returns 0 for an unselectable source. */
    uint32_t SsiClockHz(uint32_t ssi) const;

private:
    uint32_t PllHz(uint32_t pll_ctl_reg) const;

    uint32_t regs_[kSlotCount] = {};

    static bool OffsetToSlot(uint32_t off, uint32_t* slot_out) {
        if (off > 0x64u || (off & 0x3u) != 0u) return false;
        *slot_out = off / 4u;
        return true;
    }
};

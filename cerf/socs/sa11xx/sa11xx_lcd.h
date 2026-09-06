#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>

/* SA-1110 §11.7 LCD Controller. Register layout per §11.7.12:
   LCCR0 +0x00, LCSR +0x04 (W1C), DBAR1 +0x10, DCAR1 +0x14 (R-O),
   DBAR2 +0x18, DCAR2 +0x1C (R-O), LCCR1 +0x20, LCCR2 +0x24,
   LCCR3 +0x28. */

class Sa11xxLcd : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0xB0100000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    bool     IsEnabled() const { return (lccr0_ & 0x1u) != 0; }    /* LCCR0.LEN */
    bool     IsColor()   const { return (lccr0_ & 0x2u) == 0; }    /* LCCR0.CMS=0 */
    uint32_t GetFbPa()   const { return dbar1_; }
    uint32_t GetDbar2Pa() const { return dbar2_; }  /* dual-panel lower half */
    uint32_t GetGuestW() const { return (lccr1_ & 0x3FFu) + 16u; } /* §11.7.4.1: PPL = pixels - 16 */
    uint32_t GetGuestH() const {
        const uint32_t lpp = (lccr2_ & 0x3FFu) + 1u;   /* §11.7.5.1: LPP = lines - 1 */
        /* §11.7.3.3: SDS (LCCR0 bit 2) = dual-panel STN - the screen is two
           LPP-line panels (upper DBAR1 + lower DBAR2), so real lines = 2*LPP. */
        return (lccr0_ & 0x4u) ? lpp * 2u : lpp;
    }

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    uint32_t lccr0_ = 0;
    uint32_t lcsr_  = 0;
    uint32_t dbar1_ = 0;
    uint32_t dbar2_ = 0;
    uint32_t lccr1_ = 0;
    uint32_t lccr2_ = 0;
    uint32_t lccr3_ = 0;

    uint32_t ReadReg(uint32_t off) const;
    void     WriteReg(uint32_t off, uint32_t value);
    void     PublishScreenSizeOnEnableEdge(uint32_t old_lccr0,
                                           uint32_t new_lccr0);

    static bool IsKnown(uint32_t off) {
        return off == 0x00 || off == 0x04 ||
               off == 0x10 || off == 0x14 || off == 0x18 || off == 0x1C ||
               off == 0x20 || off == 0x24 || off == 0x28;
    }
};

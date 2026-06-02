#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>

/* PXA255 GPIO, 3 banks x 32 pins (§4.1.3, addresses Table 4-49, base
   0x40E00000). GPLR (§4.1.3.1) reports the CURRENT PIN LEVEL regardless of
   direction: the output latch for output pins (GPDR=1), the externally
   driven level for input pins (GPDR=0). Board wiring sets the input levels
   via SetInputLevel (e.g. an idle-high PCMCIA card-detect = no card). */
class Pxa255Gpio : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool     ShouldRegister() override;
    void     OnReady() override;
    uint32_t MmioBase() const override { return 0x40E00000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    /* Drive an external input pin's level (board wiring). Reflected by GPLR
       for that pin while it is configured as an input (GPDR bit = 0). */
    void SetInputLevel(uint32_t gpio, bool high);

private:
    uint32_t in_[3]   = {};   /* externally driven input levels (board wiring). */
    uint32_t out_[3]  = {};   /* output-data: GPSR sets, GPCR clears. */
    uint32_t gpdr_[3] = {};   /* pin direction (1 = output). */
    uint32_t grer_[3] = {};   /* rising-edge detect enable. */
    uint32_t gfer_[3] = {};   /* falling-edge detect enable. */
    uint32_t gafr_[6] = {};   /* alternate-function select (0L/0U..2L/2U). */
};

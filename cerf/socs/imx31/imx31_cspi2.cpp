#include "imx31_cspi_engine.h"

#include "../../core/cerf_emulator.h"
#include "../../peripherals/freescale_mc13783/mc13783.h"

#include <cstdint>

namespace {

/* MCIMX31RM Table 2-3 SPBA0 layout: CSPI2 at 0x5001_0000, 16 KB. */
constexpr uint32_t kBase = 0x50010000u;

class Imx31Cspi2 : public Imx31CspiEngine {
public:
    using Imx31CspiEngine::Imx31CspiEngine;

    uint32_t MmioBase() const override { return kBase; }

protected:
    uint32_t SpiExchange(uint32_t cs, uint32_t tx) override {
        if (cs != 0) {
            /* Zune Keel wires Atlas to SS0 only. */
            HaltUnsupportedAccess("CSPI2 XCH (no device on SS!=0)", kBase + 0x08u, tx);
        }
        return emu_.Get<Mc13783>().SpiExchange(tx);
    }
};

}  /* namespace */

REGISTER_SERVICE(Imx31Cspi2);

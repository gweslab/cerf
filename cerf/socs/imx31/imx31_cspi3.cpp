#include "imx31_cspi_engine.h"

#include <cstdint>

namespace {

/* MCIMX31RM Table 2-3 AIPS2 layout: CSPI3 at 0x53F8_4000, 16 KB. */
constexpr uint32_t kBase = 0x53F84000u;

class Imx31Cspi3 : public Imx31CspiEngine {
public:
    using Imx31CspiEngine::Imx31CspiEngine;

    uint32_t MmioBase() const override { return kBase; }

protected:
    uint32_t SpiExchange(uint32_t /*cs*/, uint32_t /*tx*/) override {
        /* CSPI3 SS1 is the LCD panel's write-only config bus: ddraw_ipu_sdc.dll
           writes panel registers and never reads RXDATA back (IDA sub_3191758/
           _31917EC/_3191820/_3191860). The panel absorbs the word, the transfer
           completes (engine sets TC), and the unread RXDATA is immaterial. */
        return 0;
    }
};

}  /* namespace */

REGISTER_SERVICE(Imx31Cspi3);

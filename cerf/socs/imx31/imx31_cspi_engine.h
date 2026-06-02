#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

/* Shared i.MX31 CSPI register engine (MCIMX31RM Ch 24). The register behaviour
   is identical across CSPI1/2/3; concrete ports supply their MMIO base and the
   per-port SPI exchange (which slave a transfer talks to). */
class Imx31CspiEngine : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioSize() const override { return 0x00004000u; }  /* SPBA 16 KB slot */

    uint32_t ReadWord(uint32_t addr) override;
    void WriteWord(uint32_t addr, uint32_t value) override;

protected:
    /* Exchange one word on chip-select cs, returning the slave's response.
       Called only on a CONREG XCH with EN set. */
    virtual uint32_t SpiExchange(uint32_t cs, uint32_t tx) = 0;

private:
    uint32_t conreg_      = 0;
    uint32_t intreg_      = 0;
    uint32_t dmareg_      = 0;
    uint32_t statreg_     = 0x00000003u;  /* §24.3.3.6: EN=0 -> STATREG reads TH|TE */
    uint32_t periodreg_   = 0;
    uint32_t testreg_     = 0;
    uint32_t last_txdata_ = 0;
    uint32_t last_rxdata_ = 0;
};

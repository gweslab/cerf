#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "imx31_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

/* Shared i.MX31 CSPI register engine (MCIMX31RM Ch 24). The register behaviour
   is identical across CSPI1/2/3; concrete ports supply their MMIO base and the
   per-port SPI exchange (which slave a transfer talks to). */
class Imx31CspiEngine : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx31;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioSize() const override { return 0x00004000u; }  /* SPBA 16 KB slot */

    uint32_t ReadWord(uint32_t addr) override;
    void WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override {
        w.Write("conreg", conreg_);    w.Write("intreg", intreg_);      w.Write("dmareg", dmareg_);
        w.Write("statreg", statreg_);   w.Write("periodreg", periodreg_);   w.Write("testreg", testreg_);
        w.Write("last_txdata", last_txdata_); w.Write("last_rxdata", last_rxdata_);
    }
    void RestoreState(StateReader& r) override {
        r.Read("conreg", conreg_);    r.Read("intreg", intreg_);      r.Read("dmareg", dmareg_);
        r.Read("statreg", statreg_);   r.Read("periodreg", periodreg_);   r.Read("testreg", testreg_);
        r.Read("last_txdata", last_txdata_); r.Read("last_rxdata", last_rxdata_);
    }

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

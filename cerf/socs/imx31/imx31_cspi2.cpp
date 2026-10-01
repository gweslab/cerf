#include "imx31_cspi_engine.h"

#include "../../core/cerf_emulator.h"
#include "../../peripherals/freescale_mc13783/mc13783.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

/* MCIMX31RM Table 2-3 SPBA0 layout: CSPI2 at 0x5001_0000, 16 KB. */
constexpr uint32_t kBase = 0x50010000u;

class Imx31Cspi2 : public Imx31CspiEngine {
public:
    using Imx31CspiEngine::Imx31CspiEngine;

    uint32_t MmioBase() const override { return kBase; }

    /* Forward the Atlas PMIC (a Service, off the Peripheral walk) through the
       CS that drives it. TryGet keeps Save/Restore symmetric on any future
       iMX31 board without an Atlas. */
    void SaveState(StateWriter& w) override {
        Imx31CspiEngine::SaveState(w);
        if (auto* pmic = emu_.TryGet<Mc13783>()) pmic->SaveState(w);
    }
    void RestoreState(StateReader& r) override {
        Imx31CspiEngine::RestoreState(r);
        if (auto* pmic = emu_.TryGet<Mc13783>()) pmic->RestoreState(r);
    }
    void PostRestore() override {
        Imx31CspiEngine::PostRestore();
        if (auto* pmic = emu_.TryGet<Mc13783>()) pmic->PostRestore();
    }

protected:
    uint32_t SpiExchange(uint32_t cs, uint32_t tx) override {
        if (cs != 0) {
            /* Zune Keel wires Atlas to SS0 only. */
            HaltUnsupportedAccess("CSPI2 XCH (no device on SS!=0)", kBase + 0x08u, tx);
        }
        return emu_.Get<Mc13783>().SpiExchange(tx);
    }

    FreescaleModule ClockModule() const override { return FreescaleModule::kCspi2; }
};

}  /* namespace */

REGISTER_SERVICE(Imx31Cspi2);

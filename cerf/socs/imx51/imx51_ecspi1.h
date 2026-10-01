#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>
#include <deque>

class FreescaleModuleClocks;
class SpiSlave;
class StateWriter;
class StateReader;

/* i.MX51 eCSPI1, base 0x70010000 + TZIC IRQ 36 (ipdacp.dll sub_C0D83F58/F80);
   register offsets + STATREG reset 0x3 = MCIMX51RM Table 26-3. 32-bit registers. */
class Imx51Ecspi1 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override;
    uint32_t MmioSize() const override;

    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    /* Board wiring: the SPI slave on this bus attaches itself here in OnReady. */
    void AttachSlave(SpiSlave* slave) { slave_ = slave; }

private:
    void DoExchange();        /* run a CONREG.XCH-triggered burst against the slave */
    void RecomputeStatus();   /* refresh STATREG FIFO-state bits from the FIFOs */
    void RaiseIrqIfPending(); /* assert/deassert TZIC src 36 per STATREG & INTREG */

    uint32_t conreg_    = 0;
    uint32_t configreg_ = 0;
    uint32_t intreg_    = 0;
    uint32_t dmareg_    = 0;
    uint32_t statreg_   = 0x00000003u;  /* reset: TE | TDR (FIFOs empty), Table 26-3 */
    uint32_t periodreg_ = 0;
    uint32_t testreg_   = 0;

    std::deque<uint32_t> tx_fifo_;
    std::deque<uint32_t> rx_fifo_;

    SpiSlave*              slave_         = nullptr;
    FreescaleModuleClocks* module_clocks_ = nullptr;
};

#pragma once

#include "../../peripherals/uart16550/uart16550.h"

#include "../../core/cerf_emulator.h"
#include "../../state/state_stream.h"
#include "../irq_controller.h"

#include <cstdint>

/* Intel PXA27x Developer's Manual 280000-001 Table 28-8 (pages 28-25, 28-26):
   STRBR 0x4070_0000, STIER 0x4070_0004, STIIR 0x4070_0008, STLCR 0x4070_000C,
   STMCR 0x4070_0010, STLSR 0x4070_0014, STMSR 0x4070_0018, STSPR 0x4070_001C,
   STISR 0x4070_0020. */
class Pxa2xxUart16550 : public Uart16550 {
public:
    Pxa2xxUart16550(CerfEmulator& emu, Config cfg) : Uart16550(emu, cfg) {}

    void SaveState(StateWriter& w) override {
        Uart16550::SaveState(w);
        w.Write(isr_);
    }
    void RestoreState(StateReader& r) override {
        Uart16550::RestoreState(r);
        r.Read(isr_);
    }

protected:
    uint32_t RegStride() const override { return 4u; }

    void SetInterruptLine(bool pending) override {
        auto& intc = emu_.Get<IrqController>();
        if (pending) intc.AssertIrq  (static_cast<int>(IntcBit()));
        else         intc.DeAssertIrq(static_cast<int>(IntcBit()));
    }

    uint32_t ReadExtReg(uint32_t idx) override {
        if (idx == 8u) return isr_;
        return Uart16550::ReadExtReg(idx);
    }
    void WriteExtReg(uint32_t idx, uint32_t value) override {
        if (idx == 8u) { isr_ = value; return; }
        Uart16550::WriteExtReg(idx, value);
    }

    virtual uint32_t IntcBit() const = 0;

private:
    uint32_t isr_ = 0;
};

#include "pxa2xx_intc.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

namespace {

class Pxa2xxIntcMmio : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd) return false;
        return bd->GetSoc() == SocFamily::PXA25x || bd->GetSoc() == SocFamily::PXA27x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    /* Intel PXA27x Developer's Manual 280000-001 Table 25-16: interrupt
       controller registers at 0x40D0_0000. */
    uint32_t MmioBase() const override { return 0x40D00000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint8_t ReadByte(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        auto& intc = Concrete();
        if (!intc.IsKnown(off & ~0x3u)) HaltUnsupportedAccess("ReadByte", addr, 0);
        return intc.ReadByteAt(off);
    }
    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        auto& intc = Concrete();
        if (!intc.IsKnown(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
        return intc.ReadReg(off);
    }
    void WriteByte(uint32_t addr, uint8_t value) override {
        const uint32_t off = addr - MmioBase();
        auto& intc = Concrete();
        if (!intc.IsKnown(off & ~0x3u)) HaltUnsupportedAccess("WriteByte", addr, value);
        intc.WriteByteAt(off, value);
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        auto& intc = Concrete();
        if (!intc.IsKnown(off)) HaltUnsupportedAccess("WriteWord", addr, value);
        intc.WriteReg(off, value);
    }

    void SaveState(StateWriter& w) override    { Concrete().SaveState(w); }
    void RestoreState(StateReader& r) override { Concrete().RestoreState(r); }
    void PostRestore() override                { Concrete().PostRestore(); }

private:
    Pxa2xxIntc& Concrete() {
        return static_cast<Pxa2xxIntc&>(emu_.Get<IrqController>());
    }
};

}

REGISTER_SERVICE(Pxa2xxIntcMmio);

#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Figure 6-11 (page 6-71):
   "0x1000_0000" "Static nCS<4> (64 MB)" in both map options. */
class SymbolMk500NCs4OpenBus : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::SymbolMk500;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x10000000u; }
    uint32_t MmioSize() const override { return 0x04000000u; }

    /* SMSC9211.dll (ImageBase 0x10000000) RVA 0x2C18 "LDR r3,[r1,#0x64]" /
       0x2C1C "CMP r3,r2" against the RVA 0x2D38 literal 0x87654321 / 0x2C20
       "BNE 0x2D2C" / 0x2D2C "MOV r0,#0" / 0x2D34 "BX lr". */
    uint8_t  ReadByte(uint32_t addr) override { Trace("r8",  addr); return 0xFFu; }
    uint16_t ReadHalf(uint32_t addr) override { Trace("r16", addr); return 0xFFFFu; }
    uint32_t ReadWord(uint32_t addr) override { Trace("r32", addr); return 0xFFFFFFFFu; }

    void WriteByte(uint32_t addr, uint8_t)  override { Trace("w8",  addr); }
    void WriteHalf(uint32_t addr, uint16_t) override { Trace("w16", addr); }
    void WriteWord(uint32_t addr, uint32_t) override { Trace("w32", addr); }

private:
    void Trace(const char* op, uint32_t addr) {
        if (++accesses_ <= 16u) {
            LOG(Periph, "[MK500 nCS4] %s 0x%08X (floating bus)\n", op, addr);
        }
    }

    uint32_t accesses_ = 0;
};

}  /* namespace */

REGISTER_SERVICE(SymbolMk500NCs4OpenBus);

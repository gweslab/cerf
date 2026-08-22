#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Figure 6-11 (page 6-71):
   "0x0800_0000 Static nCS<2> (64 MB)". Table 6-44 (page 6-85):
   "0x4800_0064 SA1110"; Table 6-31 (page 6-73) bit 8 SXENX reset 0 =
   "Use six 64 Mbyte chip selects (nCS<5:0>)". */
class SymbolMk500NCs2OpenBus : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::SymbolMk500;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x08000000u; }
    uint32_t MmioSize() const override { return 0x04000000u; }

    /* doc.dll 0x023C4E80 "LDRB r3,[r5]" chip-ID dispatch: 0x023C4F48
       "CMP r3,#0x7F" / 0x023C4F4C "BLT 0x023C4E0C" routes 0xFF to 0x023C4E0C
       "MOV r0,#0x120" / "ORR r0,r0,#3"; 0x023C4E8C "BEQ 0x023C4F28" routes
       0x00 to the chip-found path. */
    uint8_t  ReadByte(uint32_t addr) override { Trace("r8",  addr); return 0xFFu; }
    uint16_t ReadHalf(uint32_t addr) override { Trace("r16", addr); return 0xFFFFu; }
    uint32_t ReadWord(uint32_t addr) override { Trace("r32", addr); return 0xFFFFFFFFu; }

    void WriteByte(uint32_t addr, uint8_t)  override { Trace("w8",  addr); }
    void WriteHalf(uint32_t addr, uint16_t) override { Trace("w16", addr); }
    void WriteWord(uint32_t addr, uint32_t) override { Trace("w32", addr); }

private:
    void Trace(const char* op, uint32_t addr) {
        if (++accesses_ <= 16u) {
            LOG(Periph, "[MK500 nCS2] %s 0x%08X (floating bus)\n", op, addr);
        }
    }

    uint32_t accesses_ = 0;
};

}  /* namespace */

REGISTER_SERVICE(SymbolMk500NCs2OpenBus);

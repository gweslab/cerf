#include "../../peripherals/peripheral_base.h"

#include "casio_cassiopeia_e55_pccard.h"

#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../board_context.h"

#include <cstdint>

namespace {

/* casio_cassiopeia_e55 pcmcia.dll sub_14C1604 @0x14C1604 fills the descriptor's second
   region with 0xB400C000-0xB400C7FF on both straps; NetBSD sys/arch/hpcmips/conf/VR41XX
   gives the Cassiopeia E series isaportoffset 0xc000 with wdc0 at port 0x170, so a window
   offset is the card's I/O address. */
constexpr uint32_t kIoBase = 0x1400C000u;
constexpr uint32_t kIoSize = 0x800u;

class CasioCassiopeiaE55PcCardIo : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::CasioCassiopeiaE55;
    }

    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kIoBase; }
    uint32_t MmioSize() const override { return kIoSize; }

    uint8_t ReadByte(uint32_t addr) override {
        return emu_.Get<CasioCassiopeiaE55PcCard>().ReadIo8(addr - kIoBase);
    }
    void WriteByte(uint32_t addr, uint8_t value) override {
        emu_.Get<CasioCassiopeiaE55PcCard>().WriteIo8(addr - kIoBase, value);
    }
    uint16_t ReadHalf(uint32_t addr) override {
        return emu_.Get<CasioCassiopeiaE55PcCard>().ReadIo16(addr - kIoBase);
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        emu_.Get<CasioCassiopeiaE55PcCard>().WriteIo16(addr - kIoBase, value);
    }
};

}  /* namespace */

REGISTER_SERVICE(CasioCassiopeiaE55PcCardIo);

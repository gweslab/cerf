#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace {

/* H3600_EGPIO_PHYS = SA1100_CS5_PHYS (0x48000000) + 0x01000000 =
   0x49000000 per Linux arch/arm/mach-sa1100/include/mach/h3xxx.h. */

class Ipaq3650Egpio : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::Ipaq3650;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x49000000u; }
    uint32_t MmioSize() const override { return 0x00000004u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    uint32_t Latched() const { return latched_; }

private:
    uint32_t latched_ = 0;
};

uint8_t Ipaq3650Egpio::ReadByte(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    return static_cast<uint8_t>((latched_ >> (8 * off)) & 0xFFu);
}

uint32_t Ipaq3650Egpio::ReadWord(uint32_t addr) {
    if (addr != MmioBase()) HaltUnsupportedAccess("ReadWord", addr, 0);
    return latched_;
}

void Ipaq3650Egpio::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off    = addr - MmioBase();
    const uint32_t shift  = 8 * off;
    const uint32_t mask   = 0xFFu << shift;
    latched_ = (latched_ & ~mask) | (static_cast<uint32_t>(value) << shift);
}

void Ipaq3650Egpio::WriteWord(uint32_t addr, uint32_t value) {
    if (addr != MmioBase()) HaltUnsupportedAccess("WriteWord", addr, value);
    latched_ = value;
}

}  /* namespace */

REGISTER_SERVICE(Ipaq3650Egpio);

#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace {

/* SA-1110 §6.2.3.1 Zero Bank — memory-controller-decoded read-zero
   region at PA 0xE0000000+ for D-cache writeback flushing
   ("writeBackDC" loop reads 8 KB here to evict cache lines). */

class Sa1110ZeroBank : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::SA1110;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0xE0000000u; }
    uint32_t MmioSize() const override { return 0x01000000u; }

    uint8_t  ReadByte (uint32_t)              override { return 0; }
    uint16_t ReadHalf (uint32_t)              override { return 0; }
    uint32_t ReadWord (uint32_t)              override { return 0; }
    void     WriteByte(uint32_t, uint8_t)     override {}
    void     WriteHalf(uint32_t, uint16_t)    override {}
    void     WriteWord(uint32_t, uint32_t)    override {}
};

}  /* namespace */

REGISTER_SERVICE(Sa1110ZeroBank);

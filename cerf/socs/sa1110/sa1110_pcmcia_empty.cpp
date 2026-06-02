#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace {

/* SA-1110 §6.2: PCMCIA 0/1 memory + attribute + IO spaces span
   PA 0x20000000-0x3FFFFFFF. PCMCIA convention: bus floats high
   (all-1s read) when no card is inserted. */

class Sa1110PcmciaEmpty : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::SA1110;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x20000000u; }
    uint32_t MmioSize() const override { return 0x20000000u; }   /* 512 MB */

    uint8_t  ReadByte (uint32_t)              override { return 0xFFu; }
    uint16_t ReadHalf (uint32_t)              override { return 0xFFFFu; }
    uint32_t ReadWord (uint32_t)              override { return 0xFFFFFFFFu; }
    void     WriteByte(uint32_t, uint8_t)     override {}
    void     WriteHalf(uint32_t, uint16_t)    override {}
    void     WriteWord(uint32_t, uint32_t)    override {}
};

}  /* namespace */

REGISTER_SERVICE(Sa1110PcmciaEmpty);

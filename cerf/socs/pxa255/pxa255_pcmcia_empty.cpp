#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace {

/* PXA255 PCMCIA/CF Slot 0 (0x20000000) + Slot 1 (0x30000000), 256 MB each,
   spanning PA 0x20000000-0x3FFFFFFF (manual 278693 §2.12 Fig 2-3). With no
   card inserted the bus floats high, so every access reads all-1s. */
class Pxa255PcmciaEmpty : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x20000000u; }
    uint32_t MmioSize() const override { return 0x20000000u; }   /* 512 MB */

    uint8_t  ReadByte (uint32_t)           override { return 0xFFu; }
    uint16_t ReadHalf (uint32_t)           override { return 0xFFFFu; }
    uint32_t ReadWord (uint32_t)           override { return 0xFFFFFFFFu; }
    void     WriteByte(uint32_t, uint8_t)  override {}
    void     WriteHalf(uint32_t, uint16_t) override {}
    void     WriteWord(uint32_t, uint32_t) override {}
};

}  /* namespace */

REGISTER_SERVICE(Pxa255PcmciaEmpty);

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "pxa255_id.h"

#include <cstdint>

namespace {

/* Intel PXA255 Developer's Manual Table 11-8 (page 11-16): ICSR0 at 0x4080_0014, ICSR1 at
   0x4080_0018; Table 11-6 (page 11-13) ICSR0 reset 0x0000_0000; Table 11-7 (page 11-15) ICSR1
   reset 0x0000_0008. */
constexpr uint32_t kIcsr0 = 0x14u, kIcsr1 = 0x18u;
constexpr uint32_t kIcsr0Reset = 0x00000000u, kIcsr1Reset = 0x00000008u;

class Pxa255Ficp : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Pxa255;
    }

    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return 0x40800000u; }
    uint32_t MmioSize() const override { return 0x00000020u; }

    uint32_t ReadWord(uint32_t addr) override {
        switch (addr - MmioBase()) {
        case kIcsr0: return kIcsr0Reset;
        case kIcsr1: return kIcsr1Reset;
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }
};

}  // namespace

REGISTER_SERVICE(Pxa255Ficp);

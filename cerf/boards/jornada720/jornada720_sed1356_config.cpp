#include "../../peripherals/epson_sed1356/sed1356_config.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "jornada_720_id.h"

namespace {

/* Jornada 720: EPSON SED1356 / S1D13506 at host-bus PA 0x48000000 (SA-1110
   static CS), 512 KB external display buffer, REG[000h] = product 0x4 /
   revision 1 (0x11). */
class Jornada720Sed1356Config : public Sed1356Config {
public:
    using Sed1356Config::Sed1356Config;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Jornada720;
    }

    uint32_t HostWindowBase()        const override { return 0x48000000u; }
    uint32_t DisplayBufferBytes()    const override { return 0x80000u; }
    uint8_t  ProductRevCode()        const override { return 0x11u; }
    bool     RegMemSelectLockedAtReset() const override { return true; }

    /* jornada720 ddi.dll mode tables from 0x00FFF0B0: the 90 Hz set (0x0100001C),
       672 x 243 Ts, LCD PCLK = BUSCLK / 2. */
    uint64_t BusClockHz() const override { return 29393280u; }
    void     RegisterBusClockListener(std::function<void()>) override {}
};

}  /* namespace */

REGISTER_SERVICE_AS(Jornada720Sed1356Config, Sed1356Config);

#include "../../peripherals/epson_sed1356/sed1356_config.h"

#include "../../core/cerf_emulator.h"
#include "../../socs/pxa255/pxa255_memory_controller.h"
#include "../board_context.h"
#include "nec_mobilepro_900_id.h"

namespace {

/* NEC P530: EPSON S1D13806 at PA 0x0C000000 (PXA255 static CS), 1.25 MB
   embedded buffer. Base/size/640x240x16 decoded from the in-ROM driver
   S1D13806.dll (ddi.dll sub_1C12038); product id 0x7 per Linux s1d13xxxfb.h. */
class NecMobilePro900Sed1356Config : public Sed1356Config {
public:
    using Sed1356Config::Sed1356Config;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NecMobilepro900;
    }

    uint32_t HostWindowBase()        const override { return 0x0C000000u; }
    uint32_t DisplayBufferBytes()    const override { return 0x140000u; }
    uint8_t  ProductRevCode()        const override { return 0x1Cu; }
    bool     RegMemSelectLockedAtReset() const override { return false; }

    /* S1D13806 X28B-G-014-01 §3.2 p.12: BUSCLK "is driven by one of the Cotulla clock signals
       SDCLK1 or SDCLK2"; nec_mobilepro_900_ce4_2 XIP.BIN nk.exe sub_9023DAF8 / sub_9023DE40:
       MDREFR K2RUN cleared before sleep and set after it. */
    uint64_t BusClockHz() const override {
        return emu_.Get<Pxa255MemoryController>().Sdclk2Hz();
    }

    void RegisterBusClockListener(std::function<void()> fn) override {
        emu_.Get<Pxa255MemoryController>().RegisterSdclk2Listener(std::move(fn));
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(NecMobilePro900Sed1356Config, Sed1356Config);

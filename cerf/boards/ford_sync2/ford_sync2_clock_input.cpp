#include "../../socs/imx51/imx51_clock_input.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "ford_sync_2_id.h"

namespace {

/* IMX51CEC Table 3 XTAL/EXTAL: "Freescale BSP (Board Support Package) software
   requires 24 MHz on EXTAL." */
class FordSync2ClockInput : public Imx51ClockInput {
public:
    using Imx51ClockInput::Imx51ClockInput;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::FordSync2;
    }

    uint64_t OscHz() const override { return 24000000u; }

    /* MC13892 datasheet: CLK32KMCU is "intended as the CKIL input to the system
       processor", Table 22 "32.768 kHz". */
    uint64_t CkilHz() const override { return 32768u; }
};

}

REGISTER_SERVICE_AS(FordSync2ClockInput, Imx51ClockInput);

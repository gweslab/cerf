#include "../../socs/sa11xx/sa11xx_pre_kernel_ppcr.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "simpad_sl4_id.h"

namespace {

class SimpadSl4PreKernelPpcr : public Sa11xxPreKernelPpcr {
public:
    using Sa11xxPreKernelPpcr::Sa11xxPreKernelPpcr;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SimpadSl4;
    }

    /* SA-1110 Developer's Manual §8.2 Table 8-1: CCF 01010 selects
       206.4 MHz on the 3.6864-MHz crystal. */
    uint32_t PpcrValue() const override { return 0x0000000Au; }
};

}

REGISTER_SERVICE_AS(SimpadSl4PreKernelPpcr, Sa11xxPreKernelPpcr);

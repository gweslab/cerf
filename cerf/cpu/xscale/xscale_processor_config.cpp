#include "xscale_processor_config_base.h"

#include "../../boards/board_context.h"
#include "../../socs/pxa255/pxa255_id.h"
#include "../../core/cerf_emulator.h"

namespace {

class XscaleProcessorConfig final : public XscaleProcessorConfigBase {
public:
    using XscaleProcessorConfigBase::XscaleProcessorConfigBase;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Pxa255;
    }

    /* PXA255 manual Table 2-3. */
    uint32_t Midr() const override { return 0x69052D06u; }

    /* XScale Core Dev Manual Table 7-5; PXA255 manual section 1.1. */
    uint32_t Ctr() const override { return 0x0B1AA1AAu; }

    /* PXA255 manual Table 3-20: CCCR reset 0x121, L = 27, M = 1; Table 3-1
       row "27 1" run frequency 99.5 MHz = 27 x 3.6864 MHz. */
    uint32_t CpuClockHz() const override { return 99532800u; }

    bool AccessesSpsrInSystemMode() const override { return true; }
};

}

REGISTER_SERVICE_AS(XscaleProcessorConfig, ArmProcessorConfig);

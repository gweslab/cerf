#include "xscale_processor_config_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"

namespace {

class XscaleProcessorConfig final : public XscaleProcessorConfigBase {
public:
    using XscaleProcessorConfigBase::XscaleProcessorConfigBase;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }

    /* PXA255 manual Table 2-3. */
    uint32_t Midr() const override { return 0x69052D06u; }

    /* XScale Core Dev Manual Table 7-5; PXA255 manual section 1.1. */
    uint32_t Ctr() const override { return 0x0B1AA1AAu; }

    /* PXA255 manual Table 3-20. */
    uint32_t CpuClockHz() const override { return 398131200u; }
    uint32_t CpuToOscrDivider() const override { return 108u; }
    uint32_t CpuToHighfreqClockDivider() const override { return 108u; }
    uint32_t CpuToLowfreqClockDivider() const override { return 12150u; }
};

}

REGISTER_SERVICE_AS(XscaleProcessorConfig, ArmProcessorConfig);

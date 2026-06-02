#include "omap3530_sdma_base.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"

namespace {

class Omap3530CamDma : public Omap3530SdmaBase {
public:
    using Omap3530SdmaBase::Omap3530SdmaBase;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::OMAP3530;
    }

    uint32_t MmioBase() const override { return 0x48052800u; }
    uint32_t MmioSize() const override { return 0x00000800u; }

protected:
    uint32_t ChannelCount() const override { return 4u; }
    /* Camera DMA L0 → MPU IRQ_CAM0 (24). L1..L3 do NOT contiguous-map
       to 25/26/27 — those are DSS/Mailbox/McBSP5, unrelated. */
    int IrqForLine(int j) const override { return (j == 0) ? 24 : -1; }
};

}  /* namespace */

REGISTER_SERVICE(Omap3530CamDma);

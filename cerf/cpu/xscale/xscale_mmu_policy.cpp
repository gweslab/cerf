#include "../mmu_policy.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"

namespace {

class XscaleMmuPolicy : public MmuPolicy {
public:
    using MmuPolicy::MmuPolicy;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }

    /* XScale Core Dev Manual Table 7-8: TTBR base is bits[31:14],
       bits[13:0] reserved/write-as-zero (16-KB L1-table alignment). */
    uint32_t TtbrL1BaseMask() const override { return 0xFFFFC000u; }
};

}  /* namespace */

REGISTER_SERVICE_AS(XscaleMmuPolicy, MmuPolicy);

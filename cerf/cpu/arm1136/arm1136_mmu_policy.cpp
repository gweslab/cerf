#include "../mmu_policy.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"

namespace {

class Arm1136MmuPolicy : public MmuPolicy {
public:
    using MmuPolicy::MmuPolicy;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::ZuneKeel;
    }

    /* ARM1136 TRM §3.3.9 Figure 3-29 (p.3-73): TTBR0[31 : 14-N] is the
       first-level table base; N comes from TTBCR. CE 5.0 uses the
       legacy ARMv5 short descriptor path with TTBCR.N=0, so the L1
       base mask is bits [31:14] = 0xFFFFC000 (16 KB-aligned L1). */
    uint32_t TtbrL1BaseMask() const override { return 0xFFFFC000u; }
};

}  /* namespace */

REGISTER_SERVICE_AS(Arm1136MmuPolicy, MmuPolicy);

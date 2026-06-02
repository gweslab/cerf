#include "../mmu_policy.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"

namespace {

class Arm920tMmuPolicy : public MmuPolicy {
public:
    using MmuPolicy::MmuPolicy;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::Smdk2410DevEmu;
    }

    uint32_t TtbrL1BaseMask() const override { return 0xFFFFF000u; }
};

}  /* namespace */

REGISTER_SERVICE_AS(Arm920tMmuPolicy, MmuPolicy);

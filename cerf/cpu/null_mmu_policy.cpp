#include "mmu_policy.h"

#include "../boards/board_detector.h"
#include "../core/cerf_emulator.h"

namespace {

class NullMmuPolicy : public MmuPolicy {
public:
    using MmuPolicy::MmuPolicy;

    bool ShouldRegister() override {
        return emu_.Get<BoardDetector>().GetBoard() == Board::Unknown;
    }

    uint32_t TtbrL1BaseMask() const override { return 0; }
};

}  /* namespace */

REGISTER_SERVICE_AS(NullMmuPolicy, MmuPolicy);

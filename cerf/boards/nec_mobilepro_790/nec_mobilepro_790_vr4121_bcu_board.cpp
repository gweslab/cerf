#include "../../socs/vr4121/vr4121_bcu_board.h"

#include "../../core/cerf_emulator.h"
#include "../../socs/vr4121/vr4121_bcu_regs.h"
#include "../board_context.h"
#include "nec_mobilepro_790_id.h"

#include <cstdint>

namespace {

constexpr uint32_t kBank0ChipBytes = 0x02000000u;
constexpr uint16_t kBootRamSize    = 0x3334u;

class NecMobilePro790Vr4121BcuBoard : public Vr4121BcuBoard {
public:
    using Vr4121BcuBoard::Vr4121BcuBoard;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NecMobilepro790;
    }

    bool Sdram() const override { return true; }

    std::optional<Vr4121DramWiring> DramWiring() const override {
        return Vr4121DramWiring{ true, { kBank0ChipBytes, 0u, 0u, 0u } };
    }

    std::vector<Vr4121BcuBootWrite> KernelEntryWrites() const override {
        return {
            { vr4121_bcu::kOffCnt1, vr4121_bcu::kCnt1Dram64 | vr4121_bcu::kCnt1Rd64d },
            { vr4121_bcu::kOffRamSize, kBootRamSize },
        };
    }
};

}

REGISTER_SERVICE_AS(NecMobilePro790Vr4121BcuBoard, Vr4121BcuBoard);

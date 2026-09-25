#include "../../socs/vr4121/vr4121_bcu_board.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "casio_toricomail_id.h"

#include <cstdint>

namespace {

class CasioToricomailVr4121BcuBoard : public Vr4121BcuBoard {
public:
    using Vr4121BcuBoard::Vr4121BcuBoard;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::CasioToricomail;
    }

    bool Sdram() const override { return true; }

    std::optional<Vr4121DramWiring> DramWiring() const override { return std::nullopt; }

    /* casio_toricomail_ce212 nk.exe (XIP[1] boot image) 0xBFC08568..0xBFC08620, the last
       store to each register; identical in casio_messagecam_ce212 / casio_pocketpostpet_ce212. */
    std::vector<Vr4121BcuBootWrite> KernelEntryWrites() const override {
        return {
            { 0x00u, 0xE414u },
            { 0x02u, 0x0001u },
            { 0x04u, 0x3322u },
            { 0x06u, 0x2222u },
            { 0x0Au, 0x1703u },
            { 0x0Eu, 0x019Bu },
            { 0x16u, 0x0007u },
            { 0x1Au, 0x0020u },
            { 0x1Eu, 0x0342u },
        };
    }
};

}

REGISTER_SERVICE_AS(CasioToricomailVr4121BcuBoard, Vr4121BcuBoard);

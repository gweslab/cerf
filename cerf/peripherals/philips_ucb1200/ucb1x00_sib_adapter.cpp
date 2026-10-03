#include "../../socs/pr31x00/pr31x00_sib_codec.h"

#include "ucb1x00_codec.h"

#include "../../boards/board_context.h"
#include "../../boards/philips_nino_300/philips_nino_300_id.h"
#include "../../boards/philips_velo_1/philips_velo_1_id.h"
#include "../../boards/sharp_mobilon_hc4100/sharp_mobilon_hc4100_id.h"
#include "../../core/cerf_emulator.h"

#include <cstdint>

namespace {

class Ucb1x00SibAdapter : public Pr31x00SibCodec {
public:
    using Pr31x00SibCodec::Pr31x00SibCodec;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd) return false;
        const std::string_view board = bd->GetBoardId();
        return board == BoardId::PhilipsNino300 || board == BoardId::PhilipsVelo1 ||
               board == BoardId::SharpMobilonHc4100;
    }

    uint16_t ReadReg(uint8_t reg) override {
        return emu_.Get<Ucb1x00Codec>().ReadReg(reg);
    }
    void WriteReg(uint8_t reg, uint16_t value) override {
        emu_.Get<Ucb1x00Codec>().WriteReg(reg, value);
    }
    bool IrqAsserted() override { return emu_.Get<Ucb1x00Codec>().IrqAsserted(); }
    void SaveState(StateWriter& w) override    { emu_.Get<Ucb1x00Codec>().SaveState(w); }
    void RestoreState(StateReader& r) override { emu_.Get<Ucb1x00Codec>().RestoreState(r); }
};

}  /* namespace */

REGISTER_SERVICE_AS(Ucb1x00SibAdapter, Pr31x00SibCodec);

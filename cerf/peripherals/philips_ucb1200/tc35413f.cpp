#include "ucb1x00_codec.h"

#include "../../boards/board_context.h"
#include "../../boards/sharp_mobilon_hc4100/sharp_mobilon_hc4100_id.h"
#include "../../core/cerf_emulator.h"

#include <cstdint>

namespace {

/* NetBSD hpcmips ucb1200reg.h TC35413F_ID 0x9712 (TOSHIBA); ucb1200.c ucb_id[]
   drives the TC35413F with the UCB1200 register map. */
constexpr uint16_t kIdTc35413f = 0x9712u;

class Tc35413f : public Ucb1x00Codec {
public:
    using Ucb1x00Codec::Ucb1x00Codec;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SharpMobilonHc4100;
    }

protected:
    uint16_t DeviceId() const override { return kIdTc35413f; }

    std::array<uint16_t, 16> PowerOnRegs() const override { return {}; }
};

}

REGISTER_SERVICE_AS(Tc35413f, Ucb1x00Codec);

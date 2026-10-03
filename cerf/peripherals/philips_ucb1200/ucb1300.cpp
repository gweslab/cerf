#include "ucb1x00_codec.h"

#include "../../boards/board_context.h"
#include "../../boards/simpad_sl4/simpad_sl4_id.h"
#include "../../core/cerf_emulator.h"

#include <cstdint>

namespace {

/* Linux ucb1x00.h UCB_ID_1300 0x1005. NetBSD hpcmips ucb1200reg.h UCB1300_ID records
   0x100a for the same part. */
constexpr uint16_t kIdUcb1300 = 0x1005u;

/* UCB1300 datasheet p.50: TEL_DIV resets to 16, AUD_DIV to 9. */
constexpr uint16_t kResetTelDiv = 16u;
constexpr uint16_t kResetAudDiv = 9u;

class Ucb1300 : public Ucb1x00Codec {
public:
    using Ucb1x00Codec::Ucb1x00Codec;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SimpadSl4;
    }

protected:
    uint16_t DeviceId() const override { return kIdUcb1300; }

    std::array<uint16_t, 16> PowerOnRegs() const override {
        std::array<uint16_t, 16> r{};
        r[5] = kResetTelDiv;
        r[7] = kResetAudDiv;
        return r;
    }
};

}

REGISTER_SERVICE_AS(Ucb1300, Ucb1x00Codec);

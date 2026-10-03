#include "ucb1x00_codec.h"

#include "../../boards/board_context.h"
#include "../../boards/philips_velo_1/philips_velo_1_id.h"
#include "../../core/cerf_emulator.h"

#include <cstdint>

namespace {

/* NetBSD hpcmips ucb1200reg.h UCB1100_ID 0x1003 (version 3, device 0, supplier 1).
   PR31500.PDF p.2 names the UCB1100 as the PR31500's analog companion. */
constexpr uint16_t kIdUcb1100 = 0x1003u;

constexpr uint16_t kResetTelDiv = 16u;
constexpr uint16_t kResetAudDiv = 6u;

class Ucb1100 : public Ucb1x00Codec {
public:
    using Ucb1x00Codec::Ucb1x00Codec;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::PhilipsVelo1;
    }

protected:
    uint16_t DeviceId() const override { return kIdUcb1100; }

    std::array<uint16_t, 16> PowerOnRegs() const override {
        std::array<uint16_t, 16> r{};
        r[5] = kResetTelDiv;
        r[7] = kResetAudDiv;
        return r;
    }
};

}

REGISTER_SERVICE_AS(Ucb1100, Ucb1x00Codec);

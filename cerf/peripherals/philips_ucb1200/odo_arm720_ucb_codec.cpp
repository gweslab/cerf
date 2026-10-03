#include "ucb1x00_codec.h"

#include "../../boards/board_context.h"
#include "../../boards/odo_arm720/odo_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"

#include <cstdint>

namespace {

constexpr uint16_t kAdcCrPollBits = 0x0C00u;

constexpr uint8_t  kRegAdcCr       = 10u;
constexpr uint8_t  kRegMode        = 13u;
constexpr uint16_t kAdcCrStubBits  = 0x3F00u;
constexpr uint16_t kModeStubBits   = 0x0280u;

class OdoArm720UcbCodec : public Ucb1x00Codec {
public:
    using Ucb1x00Codec::Ucb1x00Codec;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Odo;
    }

protected:
    uint16_t DeviceId() const override {
        emu_.Get<Fatal>().Die("odo ucb: ID register read; the codec part on this "
                              "board is not identified");
    }

    std::array<uint16_t, 16> PowerOnRegs() const override { return {}; }

    uint16_t AdcCrReadBack(uint16_t written) const override {
        return static_cast<uint16_t>(written | kAdcCrPollBits);
    }

    uint16_t StubWriteBits(uint8_t reg) const override {
        if (reg == kRegAdcCr) return kAdcCrStubBits;
        if (reg == kRegMode)  return kModeStubBits;
        return 0u;
    }
};

}

REGISTER_SERVICE_AS(OdoArm720UcbCodec, Ucb1x00Codec);

#include "../../socs/sa11xx/sa11xx_ssp_clock_input.h"

#include "../../boards/board_context.h"
#include "smartbook_g138_id.h"
#include "../../core/cerf_emulator.h"

#include <cstdint>

namespace {

/* smartbook_g138_ce4_1 wavedev.dll sub_23C1BBC: SSCR1 ECS, SSCR0 16-bit TI frames with SCR 0,
   GAFR bit 19; smartbook_g138_ce4_2 wavedev.dll dword_1B88090: the hardware rate, 44100. */
constexpr uint64_t kFrameHz      = 44100u;
constexpr uint64_t kWordsPerFrame = 2u;
constexpr uint64_t kBitsPerWord  = 16u;
constexpr uint64_t kScrDivider   = 2u;

class SmartbookG138SspClock : public Sa11xxSspClockInput {
public:
    using Sa11xxSspClockInput::Sa11xxSspClockInput;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SmartbookG138;
    }

    bool Frequency(GuestCycleClock::Rate& hz) const override {
        hz = GuestCycleClock::Rate{kFrameHz * kWordsPerFrame * kBitsPerWord * kScrDivider, 1u};
        return true;
    }
};

}

REGISTER_SERVICE_AS(SmartbookG138SspClock, Sa11xxSspClockInput);

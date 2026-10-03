#include "../../socs/sa11xx/sa11xx_dma_audio_player.h"

#include "../../boards/board_context.h"
#include "smartbook_g138_id.h"
#include "../../core/cerf_emulator.h"

#include <cstdint>

namespace {

/* G138 wavedev (sub_1B81E34) points the playback DMA at the SA-1110 SSP (SSDR
   0x8007006C): TX DDAR 0x81C01BE8 matched by mask 0xFFFFFFF0 == 0x81C01BE0 (the
   RX DDAR 0x81C01BF9 falls outside the match). */
constexpr uint32_t kSspAudioTxDdarMask  = 0xFFFFFFF0u;
constexpr uint32_t kSspAudioTxDdarValue = 0x81C01BE0u;

class SmartBookG138AudioPlayer : public Sa11xxDmaAudioPlayer {
public:
    using Sa11xxDmaAudioPlayer::Sa11xxDmaAudioPlayer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SmartbookG138;
    }

protected:
    Sa11xxAudioConfig AudioConfig() const override {
        return { kSspAudioTxDdarMask, kSspAudioTxDdarValue,
                 /*channels=*/2, /*bits=*/16, /*max_page=*/0x2000u,
                 /*allow_resampler=*/true, "SmartBookAudio" };
    }
};

}  /* namespace */

REGISTER_SERVICE(SmartBookG138AudioPlayer);

#include "../../socs/sa11xx/sa11xx_dma_audio_player.h"

#include "../../boards/board_context.h"
#include "jornada_820_id.h"
#include "../../core/cerf_emulator.h"

#include <cstdint>

namespace {

/* SA-1100 MCP audio transmit DMA: DA[31:8]=0x818002 (MCDR0 port 0x80060008),
   the runtime DDAR wavedev programs is 0x818002A8 (DW=1 halfword, RW=0 write).
   The dev-man Table 11-6 text export misaligns the DS column. Mono 16-bit PCM
   (subframe 0, 12-bit codec data left-justified in a 16-bit FIFO entry). */
constexpr uint32_t kMcpAudioTxDdarMask  = 0xFFFFFFF0u;
constexpr uint32_t kMcpAudioTxDdarValue = 0x818002A0u;

class Jornada820AudioPlayer : public Sa11xxDmaAudioPlayer {
public:
    using Sa11xxDmaAudioPlayer::Sa11xxDmaAudioPlayer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Jornada820;
    }

protected:
    Sa11xxAudioConfig AudioConfig() const override {
        return { kMcpAudioTxDdarMask, kMcpAudioTxDdarValue,
                 /*channels=*/1, /*bits=*/16, /*max_page=*/0x2000u,
                 /*allow_resampler=*/false, "J820Audio" };
    }
};

}  /* namespace */

REGISTER_SERVICE(Jornada820AudioPlayer);

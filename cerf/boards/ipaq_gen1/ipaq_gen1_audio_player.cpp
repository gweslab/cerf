#include "../../socs/sa11xx/sa11xx_dma_audio_player.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "ipaq_gen1_egpio.h"

#include <cstdint>

namespace {

/* iPAQ H3600 SSP audio transmit DMA: DA[31:8]=0x81C01B (SSP data port), wavedev
   TX DDAR = 0x81C01BE8, RW (bit 0) = 0 = transmit (sub_F51924). Mask keeps bit 0
   so this does NOT also match the receive/microphone channel 0x81C01BF9 (RW=1).
   Fixed 22050 Hz stereo (no MCP rate divisor). */
constexpr uint32_t kDdarSspTxMask  = 0xFFFFFF01u;
constexpr uint32_t kDdarSspTxValue = 0x81C01B00u;

class IpaqGen1AudioPlayer : public Sa11xxDmaAudioPlayer {
public:
    using Sa11xxDmaAudioPlayer::Sa11xxDmaAudioPlayer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::IpaqGen1;
    }

protected:
    Sa11xxAudioConfig AudioConfig() const override {
        return { kDdarSspTxMask, kDdarSspTxValue,
                 /*channels=*/2, /*bits=*/16, /*max_page=*/16384u,
                 /*allow_resampler=*/false, "IpaqGen1Audio" };
    }
    uint32_t SampleRateHz() override { return 22050u; }

    /* Bit 10 (0x400) AUD_ON "Enables power to audio output amp", O(H): NetBSD
       sys/arch/hpcarm/dev/ipaq_gpioreg.h. */
    bool OutputMuted() const override {
        return (emu_.Get<IpaqGen1Egpio>().Latched() &
                IpaqGen1Egpio::kAudioOutputEnable) == 0;
    }
};

}  /* namespace */

REGISTER_SERVICE(IpaqGen1AudioPlayer);

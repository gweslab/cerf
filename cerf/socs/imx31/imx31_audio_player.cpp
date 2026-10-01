#define NOMINMAX

#include "../freescale_sdma_audio_player.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "imx31_id.h"
#include "imx31_sdma.h"
#include "imx31_ssi2.h"

namespace {

class Imx31AudioPlayer : public FreescaleSdmaAudioPlayer {
public:
    using FreescaleSdmaAudioPlayer::FreescaleSdmaAudioPlayer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx31;
    }

protected:
    FreescaleSdmaChannelHost& Sdma() override { return emu_.Get<Imx31Sdma>(); }

    /* MCIMX31RM Table 2-5 (SDMA Events Summary): SSI2 transmit 2 = 23,
       SSI2 transmit 1 = 25. */
    bool TxEventSsi(int event, uint32_t& ssi) const override {
        if (event != 23 && event != 25) return false;
        ssi = 2u;
        return true;
    }

    /* zune_keel wavedev_wm8978.dll render loops sub_30E5B64 / sub_30E5C88 / sub_30E5F10
       write the DMA buffer as interleaved 16-bit stereo frames. */
    FreescaleAudioFormat StreamFormat(uint32_t ssi) override {
        auto& ssi2 = emu_.Get<Imx31Ssi2>();
        if (ssi2.TxWordsPerFrame() != 2u || ssi2.TxWordLengthBits() != 16u) {
            emu_.Get<Fatal>().Die("iMX31-Audio: SSI%u transmits %u words x %u bits per frame; "
                                  "only 2 x 16 is modelled", ssi, ssi2.TxWordsPerFrame(),
                                  ssi2.TxWordLengthBits());
        }
        const uint32_t rate = ssi2.TxFrameRateHz(ssi2.SsiClockHz());
        return FreescaleAudioFormat{rate, 2u, 16u};
    }

    FreescaleSsiTransmitter& Transmitter(uint32_t) override {
        return emu_.Get<Imx31Ssi2>().Transmitter();
    }

    void RegisterTxSources(std::function<void()> on_write) override {
        emu_.Get<Imx31Ssi2>().RegisterTxControlListener(std::move(on_write));
    }

    const char* LogTag() const override { return "iMX31-Audio"; }
};

}

REGISTER_SERVICE(Imx31AudioPlayer);

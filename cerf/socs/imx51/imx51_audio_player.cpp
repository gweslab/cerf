#define NOMINMAX

#include "../freescale_sdma_audio_player.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "imx51_id.h"
#include "imx51_sdma.h"
#include "imx51_ssi1.h"
#include "imx51_ssi2.h"
#include "imx51_ssi3.h"
#include "imx51_ssi_slave_format.h"

namespace {

class Imx51AudioPlayer : public FreescaleSdmaAudioPlayer {
public:
    using FreescaleSdmaAudioPlayer::FreescaleSdmaAudioPlayer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }

protected:
    FreescaleSdmaChannelHost& Sdma() override { return emu_.Get<Imx51Sdma>(); }

    /* MCIMX51RM Table 3-3 (SDMA Event Mapping): SSI1 TX=29/27, SSI2 TX=25/23,
       SSI3 TX=47/37. */
    bool TxEventSsi(int event, uint32_t& ssi) const override {
        switch (event) {
            case 29: case 27: ssi = 1u; return true;
            case 25: case 23: ssi = 2u; return true;
            case 47: case 37: ssi = 3u; return true;
        }
        return false;
    }

    FreescaleAudioFormat StreamFormat(uint32_t ssi) override {
        switch (ssi) {
            case 1u: return SlaveFormat(emu_.Get<Imx51Ssi1>(), ssi);
            case 2u: return SlaveFormat(emu_.Get<Imx51Ssi2>(), ssi);
            case 3u: return SlaveFormat(emu_.Get<Imx51Ssi3>(), ssi);
        }
        emu_.Get<Fatal>().Die("iMX51-Audio: SSI%u is not an i.MX51 SSI", ssi);
    }

    FreescaleSsiTransmitter& Transmitter(uint32_t ssi) override {
        switch (ssi) {
            case 1u: return emu_.Get<Imx51Ssi1>().Transmitter();
            case 2u: return emu_.Get<Imx51Ssi2>().Transmitter();
            case 3u: return emu_.Get<Imx51Ssi3>().Transmitter();
        }
        emu_.Get<Fatal>().Die("iMX51-Audio: SSI%u is not an i.MX51 SSI", ssi);
    }

    void RegisterTxSources(std::function<void()> on_write) override {
        emu_.Get<Imx51Ssi1>().RegisterTxControlListener(on_write);
        emu_.Get<Imx51Ssi2>().RegisterTxControlListener(on_write);
        emu_.Get<Imx51Ssi3>().RegisterTxControlListener(std::move(on_write));
    }

    const char* LogTag() const override { return "iMX51-Audio"; }

private:
    template <class Ssi>
    FreescaleAudioFormat SlaveFormat(const Ssi& ssi, uint32_t n) {
        if (!ssi.TxClockExternal()) {
            emu_.Get<Fatal>().Die("iMX51-Audio: SSI%u generates its transmit clock or frame sync "
                                  "on chip (STCR 0x%08X, SACNT 0x%08X); that rate is not modeled",
                                  n, ssi.Stcr(), ssi.Sacnt());
        }
        return emu_.Get<Imx51SsiSlaveFormat>().Format(n);
    }
};

}

REGISTER_SERVICE(Imx51AudioPlayer);

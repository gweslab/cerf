#include "../../socs/imx51/imx51_ssi_slave_format.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../board_context.h"
#include "ford_sync_2_id.h"

namespace {

class FordSync2SsiSlaveFormat : public Imx51SsiSlaveFormat {
public:
    using Imx51SsiSlaveFormat::Imx51SsiSlaveFormat;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::FordSync2;
    }

    /* sync_2 wavedev2_cs42448.dll BSPAudioInit sub_C0CB65B0: ports 0-1 take sub_C0CB0FA8 ->
       sub_C0CB0E2C(obj, 2, 48000, 16), port 2 sub_C0CBAC38 -> sub_C0CB0E2C(obj, 1, 8000, 16);
       sub_C0CB4478 stores the port in [+0x17C], MapRegisters sub_C0CB56E8 maps it to SSI n+1. */
    FreescaleAudioFormat Format(uint32_t ssi) const override {
        switch (ssi) {
            case 1u: case 2u: return FreescaleAudioFormat{48000u, 2u, 16u};
            case 3u:          return FreescaleAudioFormat{8000u, 1u, 16u};
        }
        emu_.Get<Fatal>().Die("FordSync2SsiSlaveFormat: SSI%u has no stream format on this board",
                              ssi);
    }

    /* sync_2 wavedev2_cs42448.dll sub_C0CB21C8 (vtable off_C0C8DB6C of sub_C0CB0FA8's codec)
       writes CS42448 reg 3 = 4 (master single-speed), reg 4 = 0x49 (I2S); CS42448 DS648F5
       Table 5: I2S SCLK/LRCK (Master Mode) 64x. */
    uint32_t FrameSyncBitClocks(uint32_t ssi) const override {
        if (ssi == 1u || ssi == 2u) return 64u / 2u;
        emu_.Get<Fatal>().Die("FordSync2SsiSlaveFormat: SSI%u has no external bit clock on this "
                              "board", ssi);
    }
};

}

REGISTER_SERVICE_AS(FordSync2SsiSlaveFormat, Imx51SsiSlaveFormat);

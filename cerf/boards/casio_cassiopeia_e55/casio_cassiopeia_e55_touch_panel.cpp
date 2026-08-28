#include "../../socs/vr41xx/vr41xx_piu_panel.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../board_context.h"

#include <cstdint>
#include <optional>

namespace {

/* casio_cassiopeia_e55 touch.dll sub_14D05DC issues one command scan, PIUCMDREG = 0xCC0, whose
   ADCMD(3:0) is 0; none of the eight functions holding an xref to the mapped base reads
   PIUAB0REG. */
constexpr uint16_t kAdcmdCommandScan = 0;

class CasioCassiopeiaE55TouchPanel : public Vr41xxPiuPanel {
public:
    using Vr41xxPiuPanel::Vr41xxPiuPanel;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::CasioCassiopeiaE55;
    }

    std::optional<uint16_t> ConvertCommandPort(uint16_t adcmd,
                                               uint16_t /*pos_x*/,
                                               uint16_t /*pos_y*/) override {
        if (adcmd != kAdcmdCommandScan) {
            emu_.Get<Fatal>().Die("CasioCassiopeiaE55TouchPanel: PIUCMDREG ADCMD=0x%X selects "
                                  "an A/D port this board's panel does not drive", adcmd);
        }
        return std::nullopt;
    }

    /* casio_cassiopeia_e55 touch.dll sub_14D05DC writes PIUCNTREG 14, 0x100, 0x200 and 4; none
       carries D5 PADSCANTYPE, which VR4111 UM 20.3.1 p426 defines as "0: Prohibit". */
    std::optional<uint16_t> PressureSample() override { return std::nullopt; }

    /* casio_cassiopeia_e55 touch.dll writes neither PIUASCNREG nor PIUAMSKREG. */
    std::optional<uint16_t> AdPortScanSample(uint16_t port) override {
        emu_.Get<Fatal>().Die("CasioCassiopeiaE55TouchPanel: ADPortScan A/D port 0x%X this "
                              "board does not drive", port);
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(CasioCassiopeiaE55TouchPanel, Vr41xxPiuPanel);

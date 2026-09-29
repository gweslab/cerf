#include "sed1356_power_sequence.h"

#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../../core/cerf_emulator.h"

namespace {

class S1d13506PowerSequence : public Sed1356PowerSequence {
public:
    using Sed1356PowerSequence::Sed1356PowerSequence;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetBoardId() == BoardId::Jornada720;
    }

    /* SED1356 X25B-A-001-12 Table 7-20 p.78: t1 and t3 give maxima only. */
    uint32_t LcdPowerOnLines(uint8_t) const override { return 0u; }

    /* Table 7-20 p.78: t4 "LCD Enable Bit low to FPLINE, FPSHIFT, FPDATA, DRDY active and LCD
       Power Save Status bit high", Max note 1 (130 T_FPFRAME dual, 65 single); t2 "FPFRAME
       inactive to LCD Power Save Status bit high", Max 5 T_FPFRAME. */
    PanelDown LcdDisableToPanelDown(uint32_t panel_divisor, uint8_t) const override {
        return PanelDown{Delay{}, Delay{65u * panel_divisor, 0u}};
    }

    /* Table 7-21 p.80: t5 status high min 128, max 129 T_FPFRAME; t3 FPLINE, FPSHIFT, FPDATA,
       DRDY inactive max 129 T_FPFRAME + T_FPLINE. */
    PanelDown PowerSaveToPanelDown() const override {
        return PanelDown{Delay{128u, 0u}, Delay{129u, 1u}};
    }

    bool LcdDisabledReadsPanelDown() const override { return false; }

    /* Figure 7-21 p.79 note; REG[021h] bits 7-6 Table 8-12 p.132: 00 CBR refresh. */
    bool MemoryControllerPowersDown(uint8_t refresh_reg) const override {
        return (refresh_reg & 0xC0u) != 0u;
    }
};

}

REGISTER_SERVICE_AS(S1d13506PowerSequence, Sed1356PowerSequence);

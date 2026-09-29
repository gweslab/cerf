#include "sed1356_power_sequence.h"

#include "../../boards/board_context.h"
#include "../../boards/nec_mobilepro_900/nec_mobilepro_900_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"

namespace {

class S1d13806PowerSequence : public Sed1356PowerSequence {
public:
    using Sed1356PowerSequence::Sed1356PowerSequence;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetBoardId() == BoardId::NecMobilepro900;
    }

    /* S1D13806 X28B-A-001-13 Table 6-15 p.62 t2: LCD Enable high to panel active,
       min 1 T_FPLINE. */
    uint32_t LcdPowerOnLines(uint8_t power_save_reg) const override {
        RequireBit4Set(power_save_reg, "power-on");
        return 1u;
    }

    /* Table 6-15 p.62 t1: LCD Enable Bit low to FPFRAME, FPLINE, FPSHIFT, FPDATA, DRDY
       inactive, max 1 T_FPLINE. */
    PanelDown LcdDisableToPanelDown(uint32_t, uint8_t power_save_reg) const override {
        RequireBit4Set(power_save_reg, "power-off");
        return PanelDown{Delay{}, Delay{0u, 1u}};
    }

    /* Table 6-16 p.63 t1: power save to LCD Power Save Status rising, min 1, max 2 T_FPLINE;
       REG[1F1h] p.145 bit 1: "When this bit = 1, the panel is powered down." */
    PanelDown PowerSaveToPanelDown() const override {
        return PanelDown{Delay{0u, 1u}, Delay{0u, 2u}};
    }

    /* REG[1F1h] p.145 note: "When the LCD panel is not enabled (REG[1FCh] bit 0 = 0), this
       bit returns a 1." */
    bool LcdDisabledReadsPanelDown() const override { return true; }

    /* §19.1 p.199: in power save mode "Memory is in self-refresh mode". */
    bool MemoryControllerPowersDown(uint8_t) const override { return true; }

private:
    /* Table 6-15 p.62 note: "The above timing assumes REG[1F0h] bit 4 is set to 1." */
    void RequireBit4Set(uint8_t power_save_reg, const char* edge) const {
        if ((power_save_reg & 0x10u) == 0u) {
            emu_.Get<Fatal>().Die("S1d13806: LCD %s with REG[1F0h] bit 4 clear (0x%02X) is not "
                                  "modelled", edge, power_save_reg);
        }
    }
};

}

REGISTER_SERVICE_AS(S1d13806PowerSequence, Sed1356PowerSequence);

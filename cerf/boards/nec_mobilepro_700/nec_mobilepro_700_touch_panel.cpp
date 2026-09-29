#include "../../socs/vr41xx/vr41xx_piu_panel.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../board_context.h"
#include "nec_mobilepro_700_battery.h"
#include "nec_mobilepro_700_id.h"

#include <cstdint>
#include <iterator>
#include <optional>

namespace {

/* PIUCMDREG ADCMD(3:0): 0100 ADIN0, 0101 ADIN1, 0110 ADIN2 (VR4102 UM 19.3.5 (2/2)). */
enum : uint16_t { kAdcmdAdin0 = 4, kAdcmdAdin1 = 5, kAdcmdAdin2 = 6 };

/* nec_mobilepro_700_ce2 touch.dll sub_15A0E24: battery word = 379 * ADINx / ADIN2, read by
   battdrv.dll BatteryDriverGetStatus 0x1560644 through TouchPanelBatteryGetInfo 0x15A08C8. */
constexpr uint16_t kAdin2Reference = 379u;

struct MainPackStep {
    uint16_t threshold;
    int      percent;
};

/* battdrv.dll main-pack table 0x15604A8 (threshold, percent). */
constexpr MainPackStep kMainPack[] = {
    {859u, 100}, {818u, 90}, {795u, 80}, {774u, 70}, {747u, 60},
    {727u, 50},  {709u, 40}, {691u, 30}, {665u, 20}, {0u, 10},
};

/* battdrv.dll backup table 0x1560540 first row (859 -> 100). */
constexpr uint16_t kBackupCellHealthy = 859u;

/* touch.dll sub_15A0BB0 treats a contact as valid at Z >= 0x340. */
constexpr uint16_t kPressureContact = 0x03FFu;

class NecMobilePro700TouchPanel : public Vr41xxPiuPanel {
public:
    using Vr41xxPiuPanel::Vr41xxPiuPanel;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NecMobilepro700;
    }

    std::optional<uint16_t> ConvertCommandPort(uint16_t adcmd, uint16_t, uint16_t) override {
        switch (adcmd) {
            case kAdcmdAdin0: return MainPackWord();
            case kAdcmdAdin1: return kBackupCellHealthy;
            case kAdcmdAdin2: return kAdin2Reference;
            default:
                LOG(Caution, "NecMobilePro700TouchPanel: PIUCMDREG ADCMD=0x%X selects an "
                        "A/D port this board's panel does not drive\n", adcmd);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }

    std::optional<uint16_t> PressureSample() override { return kPressureContact; }

    std::optional<uint16_t> AdPortScanSample(uint16_t port) override {
        LOG(Caution, "NecMobilePro700TouchPanel: ADPortScan A/D port 0x%X is not modeled on "
                "this board\n", port);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

private:
    uint16_t MainPackWord() const {
        const int fill = emu_.Get<NecMobilePro700Battery>().FillPercent();
        for (const MainPackStep& step : kMainPack) {
            if (fill >= step.percent) return step.threshold;
        }
        return kMainPack[std::size(kMainPack) - 1u].threshold;
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(NecMobilePro700TouchPanel, Vr41xxPiuPanel);

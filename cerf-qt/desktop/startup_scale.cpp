#include "startup_scale.h"

#include "../dpi_scale.h"
#include "../frontend_config.h"

#include <cerfcore/boards/board_context.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>

namespace cerffrontend {

REGISTER_SERVICE(StartupScale);

int StartupScale::Factor(int primary_display_dpi) const {
    const int configured = emu_.Get<FrontendConfig>().DefaultScale();
    if (configured != FrontendConfig::kDynamicScale) {
        LOG(Lcd, "StartupScale: configured %dx\n", configured);
        return configured;
    }
    if (emu_.Get<cerfcore::BoardContext>().HasHighDpi()) {
        LOG(Lcd, "StartupScale: dynamic, high-DPI board -> %dx\n", FrontendConfig::kOriginalScale);
        return FrontendConfig::kOriginalScale;
    }
    int factor = IntegerFactorForDpi(primary_display_dpi);
    if (factor > kDynamicMaxFactor) factor = kDynamicMaxFactor;
    LOG(Lcd, "StartupScale: dynamic, primary display %d dpi -> %dx\n", primary_display_dpi,
        factor);
    return factor;
}

}

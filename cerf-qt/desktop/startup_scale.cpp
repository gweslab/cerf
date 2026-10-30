#include "startup_scale.h"

#include "../dpi_scale.h"
#include "../frontend_config.h"

#include <cerfcore/boards/board_context.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>

#include <algorithm>

namespace cerffrontend {

REGISTER_SERVICE(StartupScale);

int StartupScale::Factor(int primary_display_dpi) const {
    const int configured = emu_.Get<FrontendConfig>().DefaultScale();
    if (configured != FrontendConfig::kDynamicScale) {
        LOG(Lcd, "StartupScale: configured %dx\n", configured);
        return configured;
    }
    const int host   = std::min(IntegerFactorForDpi(primary_display_dpi), kDynamicMaxFactor);
    const int board  = emu_.Get<cerfcore::BoardContext>().DynamicScaleFactor();
    const int factor = std::max(FrontendConfig::kOriginalScale, host + board);
    LOG(Lcd, "StartupScale: dynamic, primary display %d dpi -> %dx, board %+d -> %dx\n", primary_display_dpi, host,
        board, factor);
    return factor;
}

}

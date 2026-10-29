#include <cerfcore/host/device_selection.h>
#include "frontend_config.h"
#include <cerfcore/host/user_alert.h>

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/fatal.h>
#include <cerfcore/core/product_name.h>

#include <string>

namespace cerffrontend {

namespace {

class ConfiguredDeviceSelection : public cerfcore::DeviceSelection {
public:
    using cerfcore::DeviceSelection::DeviceSelection;

    std::string SelectedDevice() override {
        const char* cli = emu_.Config().device_override;
        if (cli && cli[0]) return cli;

        auto&             config = emu_.Get<FrontendConfig>();
        const std::string device = config.Device();
        if (!device.empty()) return device;

#if !CERF_DEV_MODE
        emu_.Get<cerfcore::UserAlert>().Show(
            cerfcore::AlertLevel::kError, cerfcore::AlertPlacement::kStandalone,
            "No device - " CERF_PRODUCT_NAME,
            "No device is selected. CERF will exit.\n\nStart a device from " CERF_PRODUCT_NAME
            ", or pass --device=NAME.");
#endif
        emu_.Get<cerfcore::Fatal>().UserError("device is blank: set \"device\" in %s or pass --device=NAME",
                                              config.Path().c_str());
    }
};

}

REGISTER_SERVICE_AS(ConfiguredDeviceSelection, cerfcore::DeviceSelection);

}

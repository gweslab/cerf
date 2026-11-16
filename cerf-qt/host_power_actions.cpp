#include "host_power_actions.h"

#include "host_power.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/fatal.h>
#include <cerfcore/core/log.h>
#include <cerfcore/core/product_name.h>
#include <cerfcore/host/user_alert.h>
#include <cerfcore/platform/host_error.h>

#include <cstdint>
#include <string>
#include <utility>

namespace cerffrontend {

REGISTER_SERVICE(HostPowerActions);

void HostPowerActions::RequireSuspend() {
    if (host_power::Suspend() == nullptr) emu_.Get<cerfcore::Fatal>().Die("host suspend is not implemented on this host");
}

void HostPowerActions::Suspend(std::function<void()> after) {
    uint32_t code = 0;
    if (host_power::Suspend()(code)) {
        after();
        return;
    }
    const std::string reason = cerfcore::host_platform::ErrorText(code);
    LOG(Caution, "HostPowerActions: the host did not suspend: %s\n", reason.c_str());
    emu_.Get<cerfcore::UserAlert>().Post(cerfcore::AlertLevel::kError, "Host suspend - " CERF_PRODUCT_NAME,
                                         "The state is saved, but this computer did not go to sleep.\n\n" + reason,
                                         std::move(after));
}

void HostPowerActions::PowerOff() { emu_.Get<cerfcore::Fatal>().Die("host power-off is not implemented"); }

void HostPowerActions::Restart() { emu_.Get<cerfcore::Fatal>().Die("host restart is not implemented"); }

}

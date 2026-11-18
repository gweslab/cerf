#include "frontend_config.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/service.h>
#include <cerfcore/state/crash_state_saver.h>

namespace cerffrontend {

namespace {

class CrashStateSetting : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override {
        emu_.Get<cerfcore::CrashStateSaver>().SetEnabled(emu_.Get<FrontendConfig>().SaveStateOnCrash());
    }
};

}

REGISTER_SERVICE(CrashStateSetting);

}

#include "device_status_files.h"
#include "frontend_window.h"
#include "periodic_device_file.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/config_json.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/log.h>
#include <cerfcore/core/service.h>
#include <cerfcore/platform/host_error.h>
#include <cerfcore/platform/host_process.h>

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <string>

namespace cerffrontend {

namespace {

constexpr auto kHeartbeatInterval = std::chrono::seconds(2);

int64_t NowUnix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

class RunningStatusReporter : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override {
        const std::string name = emu_.Get<cerfcore::DeviceConfig>().device_name;
        if (name.empty()) return;
        window_ = &emu_.Get<FrontendWindow>();
        worker_.Start(cerfcore::GetDeviceDir(name) + kRunningStatusFileName, kHeartbeatInterval,
                      [this] { WriteStatus(); });
    }

    void OnShutdown() override { worker_.Stop(true); }

private:
    void WriteStatus() {
        nlohmann::ordered_json j;
        j[kRunningStatusPidKey]       = cerfcore::host_platform::CurrentProcessId();
        j[kRunningStatusWindowKey]    = window_->NativeHandle();
        j[kRunningStatusHeartbeatKey] = NowUnix();
        uint32_t error = 0;
        if (cerfcore::CfgWriteJsonFile(worker_.Path(), j, error)) {
            write_failed_ = false;
            return;
        }
        if (!write_failed_)
            LOG(Caution, "RunningStatusReporter: %s not written: %s\n", worker_.Path().c_str(),
                cerfcore::host_platform::ErrorText(error).c_str());
        write_failed_ = true;
    }

    FrontendWindow*    window_       = nullptr;
    bool               write_failed_ = false;
    PeriodicDeviceFile worker_{"RunningStatusReporter"};
};

}

REGISTER_SERVICE(RunningStatusReporter);

}

#include "bar_widgets.h"
#include "host_key_binding.h"
#include "input_capture.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/service.h>

#include <memory>
#include <string>
#include <vector>

namespace cerffrontend {

namespace {

class CaptureLockWidget final : public BarWidget {
public:
    explicit CaptureLockWidget(cerfcore::CerfEmulator& emu) : emu_(emu) {}

    std::string Name() const override { return "Input Capture"; }
    BarGroup    Group() const override { return BarGroup::InputCapture; }

    std::string Tooltip() const override {
        const std::string key = emu_.Get<HostKeyBinding>().Label();
        return emu_.Get<InputCapture>().IsCaptured()
                   ? "Input captured - " + key + " (or click) to release"
                   : "Input free - " + key + " (or click) to capture (Alt+Tab etc. -> guest)";
    }

    bool PrimaryClick() override {
        emu_.Get<InputCapture>().Toggle();
        return true;
    }

    std::vector<MenuItem> Menu() override {
        const std::string key = emu_.Get<HostKeyBinding>().Label();
        return {MenuItem::Action(emu_.Get<InputCapture>().IsCaptured() ? "Release input capture\t" + key
                                                                       : "Capture input\t" + key,
                                 [this] { emu_.Get<InputCapture>().Toggle(); })};
    }

    BarIcon Icon() const override { return ResourceIcon{emu_.Get<InputCapture>().IsCaptured() ? "lock_on" : "lock_off"}; }

private:
    cerfcore::CerfEmulator& emu_;
};

class CaptureLockWidgetSource : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override { emu_.Get<BarWidgets>().Add(std::make_unique<CaptureLockWidget>(emu_)); }
};

}

REGISTER_SERVICE(CaptureLockWidgetSource);

}

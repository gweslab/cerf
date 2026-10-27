#include "host_key_binding.h"
#include "input_capture.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/service.h>
#include <cerfcore/host/host_widget.h>
#include <cerfcore/host/host_widget_registry.h>

#include <string>
#include <vector>

namespace cerffrontend {

namespace {

class CaptureLockWidget : public cerfcore::Service, public cerfcore::HostWidget {
public:
    using cerfcore::Service::Service;

    void OnReady() override { emu_.Get<cerfcore::HostWidgetRegistry>().Register(this); }

    std::string           WidgetName() const override { return "Input Capture"; }
    cerfcore::WidgetGroup Group() const override { return cerfcore::WidgetGroup::InputCapture; }

    std::string Tooltip() const override {
        const std::string key = emu_.Get<HostKeyBinding>().Label();
        return emu_.Get<InputCapture>().IsCaptured()
                   ? "Input captured - " + key + " (or click) to release"
                   : "Input free - " + key + " (or click) to capture (Alt+Tab etc. -> guest)";
    }

    bool TryPrimaryAction() override {
        emu_.Get<InputCapture>().Toggle();
        return true;
    }

    std::vector<cerfcore::WidgetControl> Controls() override {
        const std::string     key = emu_.Get<HostKeyBinding>().Label();
        cerfcore::ActionControl it;
        it.id    = "toggle_capture";
        it.label = emu_.Get<InputCapture>().IsCaptured() ? "Release input capture\t" + key
                                                         : "Capture input\t" + key;
        it.press = [this] { emu_.Get<InputCapture>().Toggle(); };
        return {cerfcore::WidgetControl{std::move(it)}};
    }

    cerfcore::WidgetIcon Icon() const override {
        return cerfcore::ResourceIcon{emu_.Get<InputCapture>().IsCaptured() ? "lock_on" : "lock_off"};
    }

    bool PollDirty() override {
        const bool cap = emu_.Get<InputCapture>().IsCaptured();
        if (cap == last_drawn_cap_) return false;
        last_drawn_cap_ = cap;
        return true;
    }

private:
    bool last_drawn_cap_ = false;
};

}

REGISTER_SERVICE(CaptureLockWidget);

}

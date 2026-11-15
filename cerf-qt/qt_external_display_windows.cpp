#include "emulator_window_host.h"
#include "external_display_container.h"
#include "frontend_window.h"
#include "qt_ui_thread.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/service.h>
#include <cerfcore/host/external_displays.h>

#include <functional>
#include <map>
#include <memory>
#include <utility>

namespace cerffrontend {

namespace {

class QtExternalDisplayWindows : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override {
        auto& displays = emu_.Get<cerfcore::ExternalDisplays>();
        displays.Subscribe([this](const cerfcore::ExternalDisplayEvent& event) { RunOnUi([this, event] { Apply(event); }); });
        for (const cerfcore::ExternalDisplayInfo& info : displays.Displays())
            RunOnUi([this, info] { Apply({cerfcore::ExternalDisplayEventKind::kAttached, info}); });
    }

private:
    void RunOnUi(std::function<void()> job) {
        if (OnUiThread()) {
            job();
            return;
        }
        emu_.Get<FrontendWindow>().RunOnUiThread(std::move(job));
    }

    void Apply(const cerfcore::ExternalDisplayEvent& event) {
        const cerfcore::ExternalDisplayInfo& info = event.display;
        switch (event.kind) {
            case cerfcore::ExternalDisplayEventKind::kAttached:
                if (windows_.count(info.id) == 0)
                    windows_[info.id] =
                        emu_.Get<EmulatorWindowHost>().OpenExternalDisplay(info.id, info.name, info.width, info.height);
                return;
            case cerfcore::ExternalDisplayEventKind::kResized: {
                const auto it = windows_.find(info.id);
                if (it != windows_.end() && it->second) it->second->SetSurfaceSize(info.width, info.height);
                return;
            }
            case cerfcore::ExternalDisplayEventKind::kDetached:
                windows_.erase(info.id);
                return;
        }
    }

    std::map<int, std::unique_ptr<ExternalDisplayContainer>> windows_;
};

}

REGISTER_SERVICE(QtExternalDisplayWindows);

}

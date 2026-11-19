#include "automation_server.h"

#include "../automation_option.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/service.h>
#include <cerfcore/host/emulation_pause.h>
#include <cerfcore/host/guest_debug_lines.h>
#include <cerfcore/host/guest_deep_sleep.h>
#include <cerfcore/host/guest_power_notifier.h>

#include <string>
#include <string_view>

namespace cerffrontend {

namespace {

class AutomationGuestEvents : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool ShouldRegister() override { return AutomationRequested(emu_.Argc(), emu_.Argv()); }

    void OnReady() override {
        auto& server = emu_.Get<AutomationServer>();
        suspend_topic_ = server.AddTopic("guest.suspend", "The guest suspended itself or woke up.",
                                         [this] { return SuspendState(); });
        pause_topic_   = server.AddTopic("pause", "The emulator paused or resumed.", [this] { return PauseState(); });
        reboot_topic_   = server.AddTopic("guest.reboot", "A reset of the guest was requested.");
        released_topic_ = server.AddTopic("guest.reset_released", "A reset of the guest ended.");
        debug_topic_ = server.AddTopic("guest.debug", "A line of the debug output of the guest operating system.");

        emu_.Get<cerfcore::GuestDeepSleep>().RegisterSuspendListener([this, &server](bool suspended) {
            server.Publish(suspend_topic_, [suspended] { return AutomationJson{{"suspended", suspended}}; });
        });
        emu_.Get<cerfcore::EmulationPause>().RegisterChangeListener(
            [this, &server] { server.Publish(pause_topic_, [this] { return PauseState(); }); });
        auto& power = emu_.Get<cerfcore::GuestPowerNotifier>();
        power.RegisterRebootListener(
            [this, &server] { server.Publish(reboot_topic_, [] { return AutomationJson::object(); }); });
        power.RegisterResetReleasedListener(
            [this, &server] { server.Publish(released_topic_, [] { return AutomationJson::object(); }); });
        emu_.Get<cerfcore::GuestDebugLines>().Subscribe(
            [this, &server](std::string_view line, std::string_view source) {
                if (!server.Watched(debug_topic_)) return;
                server.Publish(debug_topic_, [text = std::string(line), from = std::string(source)] {
                    return AutomationJson{{"line", text}, {"source", from}};
                });
            });
    }

private:
    AutomationJson SuspendState() {
        return AutomationJson{{"suspended", emu_.Get<cerfcore::GuestDeepSleep>().Suspended()}};
    }

    AutomationJson PauseState() {
        auto& pause = emu_.Get<cerfcore::EmulationPause>();
        return AutomationJson{{"paused", pause.IsPaused()}, {"user_paused", pause.IsUserPaused()}};
    }

    size_t suspend_topic_  = 0;
    size_t pause_topic_    = 0;
    size_t reboot_topic_   = 0;
    size_t released_topic_ = 0;
    size_t debug_topic_    = 0;
};

}

REGISTER_SERVICE(AutomationGuestEvents);

}

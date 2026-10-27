#include "canvas_tabs.h"

#include "boot_screen.h"
#include "canvas_input.h"
#include "frontend_window.h"
#include "hw_screen_renderer.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/emulation_pause.h>
#include <cerfcore/host/guest_deep_sleep.h>
#include <cerfcore/host/guest_power_notifier.h>

namespace cerffrontend {

REGISTER_SERVICE(CanvasTabs);

void CanvasTabs::OnReady() {
    tab_ = emu_.Get<cerfcore::DeviceConfig>().start_tab;
    emu_.Get<cerfcore::GuestPowerNotifier>().RegisterRebootListener([this] {
        emu_.Get<FrontendWindow>().RunOnUiThread([this] {
            emu_.Get<FrontendWindow>().SetTab(emu_.Get<cerfcore::DeviceConfig>().start_tab, false);
            RearmAutoSwitch();
        });
    });
}

bool CanvasTabs::Set(Tab tab, bool user_initiated) {
    if (user_initiated) user_picked_view_ = true;
    if (tab_ == tab) return false;
    if (tab_ == Tab::Framebuffer) emu_.Get<CanvasInput>().ReleasePenIfDown();
    tab_ = tab;
    return true;
}

void CanvasTabs::RearmAutoSwitch() {
    latched_once_     = false;
    user_picked_view_ = false;
}

bool CanvasTabs::OnPresentTick(bool has_frame) {
    if (!has_frame || latched_once_) return false;
    latched_once_ = true;
    emu_.Get<BootScreen>().OnFramebufferLatched();
    if (user_picked_view_) return false;
    tab_ = Tab::Framebuffer;
    return true;
}

bool CanvasTabs::RenderAlt(uint32_t* bits, int width, int height, int dpi) {
    if (tab_ == Tab::Framebuffer) return false;
    if (tab_ == Tab::Boot) {
        emu_.Get<BootScreen>().RenderInto(bits, static_cast<uint32_t>(width),
                                          static_cast<uint32_t>(height), dpi);
        return true;
    }
    emu_.Get<HwScreenRenderer>().RenderInto(bits, static_cast<uint32_t>(width),
                                            static_cast<uint32_t>(height), dpi);
    return true;
}

bool CanvasTabs::ShouldDesaturate() {
    return tab_ == Tab::Framebuffer && (emu_.Get<cerfcore::EmulationPause>().IsPaused() ||
                                        emu_.Get<cerfcore::GuestDeepSleep>().Asleep());
}

}

#include <cerffrontend/guest_auto_resize.h>

#include <cerffrontend/frontend_window.h>
#include <cerffrontend/guest_additions_ui_policy.h>

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/user_config_writer.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_resize.h>

namespace cerffrontend {

REGISTER_SERVICE_AS(GuestAutoResize, cerfcore::GuestResizePolicy);

bool GuestAutoResize::ShouldRegister() {
    return emu_.Get<cerfcore::DeviceConfig>().guest_additions;
}

void GuestAutoResize::OnReady() {
    if (!Available()) enabled_.store(false, std::memory_order_release);
}

bool GuestAutoResize::Available() const {
    return emu_.Get<GuestAdditionsUiPolicy>().LiveResizeAvailable();
}

void GuestAutoResize::SetEnabled(bool on) {
    if (!Available()) return;
    enabled_.store(on, std::memory_order_release);
}

void GuestAutoResize::OnUserResizeEnd(uint32_t canvas_w, uint32_t canvas_h) {
    if (!Enabled()) return;
    const auto& window = emu_.Get<FrontendWindow>();
    uint32_t    w      = canvas_w;
    uint32_t    h      = canvas_h;
    if (window.Mode() == ViewportMode::Integer) {
        const uint32_t factor = static_cast<uint32_t>(window.IntegerFactor());
        w /= factor;
        h /= factor;
    }
    if (w == 0 || h == 0) return;
    if (w == last_w_ && h == last_h_) return;
    last_w_ = w;
    last_h_ = h;
    emu_.Get<cerfcore::CerfVirtResize>().RequestResize(w, h);
    emu_.Get<cerfcore::UserConfigWriter>().WriteConfigurableScreenSize(w, h);
}

}

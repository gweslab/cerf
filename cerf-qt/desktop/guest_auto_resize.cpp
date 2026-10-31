#include "../guest_additions_ui_policy.h"
#include "qt_main_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/log.h>
#include <cerfcore/core/user_config_writer.h>
#include <cerfcore/host/guest_resize_policy.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_framebuffer.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_resize.h>

#include <atomic>
#include <cstdint>

namespace cerffrontend {

namespace {

class GuestAutoResize : public cerfcore::GuestResizePolicy {
public:
    using cerfcore::GuestResizePolicy::GuestResizePolicy;

    bool ShouldRegister() override { return emu_.Get<cerfcore::DeviceConfig>().guest_additions; }

    void OnReady() override {
        if (!Available()) enabled_.store(false, std::memory_order_release);
    }

    bool Available() const override { return emu_.Get<GuestAdditionsUiPolicy>().LiveResizeAvailable(); }

    bool Enabled() const override { return enabled_.load(std::memory_order_acquire); }

    void SetEnabled(bool on) override {
        if (!Available()) return;
        enabled_.store(on, std::memory_order_release);
    }

    void OnUserResizeEnd(uint32_t canvas_w, uint32_t canvas_h) override {
        if (!Enabled()) return;
        const auto& window = emu_.Get<QtMainWindow>();
        uint32_t    w      = 0;
        uint32_t    h      = 0;
        window.SurfaceForCanvas(canvas_w, canvas_h, w, h);
        if (w == 0 || h == 0) return;
        const uint32_t surface_w = window.GuestSurfaceWidth();
        const uint32_t surface_h = window.GuestSurfaceHeight();
        LOG(Lcd, "GuestAutoResize: canvas %ux%u -> surface %ux%u, current %ux%u\n", canvas_w, canvas_h, w, h,
            surface_w, surface_h);
        const bool     pending   = last_w_ != 0 && (last_w_ != surface_w || last_h_ != surface_h);
        if (pending ? (w == last_w_ && h == last_h_) : (w == surface_w && h == surface_h)) return;
        if (!emu_.Get<cerfcore::CerfVirtFramebuffer>().FitsPrimary(w, h, "live resize")) return;
        last_w_ = w;
        last_h_ = h;
        emu_.Get<cerfcore::CerfVirtResize>().RequestResize(w, h);
        emu_.Get<cerfcore::UserConfigWriter>().WriteConfigurableScreenSize(w, h);
    }

private:
    std::atomic<bool> enabled_{true};
    uint32_t          last_w_ = 0;
    uint32_t          last_h_ = 0;
};

}

REGISTER_SERVICE_AS(GuestAutoResize, cerfcore::GuestResizePolicy);

}

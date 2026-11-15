#include "../guest_resize_policy.h"
#include "../qt_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/host/guest_live_resize.h>

#include <atomic>
#include <cstdint>

namespace cerffrontend {

namespace {

class GuestAutoResize : public GuestResizePolicy {
public:
    using GuestResizePolicy::GuestResizePolicy;

    bool ShouldRegister() override { return emu_.Get<cerfcore::DeviceConfig>().guest_additions; }

    void OnReady() override {
        if (!Available()) enabled_.store(false, std::memory_order_release);
    }

    bool Available() const override { return emu_.Get<cerfcore::GuestLiveResize>().Supported(); }

    bool Enabled() const override { return enabled_.load(std::memory_order_acquire); }

    void SetEnabled(bool on) override {
        if (!Available()) return;
        enabled_.store(on, std::memory_order_release);
    }

    void OnUserResizeEnd(uint32_t canvas_w, uint32_t canvas_h) override {
        if (!Enabled()) return;
        uint32_t w = 0;
        uint32_t h = 0;
        emu_.Get<QtEmulatorWindow>().SurfaceForCanvas(canvas_w, canvas_h, w, h);
        emu_.Get<cerfcore::GuestLiveResize>().Request(w, h);
    }

private:
    std::atomic<bool> enabled_{true};
};

}

REGISTER_SERVICE_AS(GuestAutoResize, GuestResizePolicy);

}

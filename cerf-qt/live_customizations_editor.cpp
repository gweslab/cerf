#include "frontend_window.h"
#include "guest_additions_ui_policy.h"
#include "manager_windows.h"

#include <cerfcore/boot/guest_cold_boot.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/device_config_refresh.h>
#include <cerfcore/host/customizations_editor.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_customizations_reset.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_framebuffer.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_resize.h>
#include <cerfcore/socs/guest_cpu_reset.h>

#include <cstdint>
#include <optional>

namespace cerffrontend {

namespace {

class LiveCustomizationsEditor : public cerfcore::CustomizationsEditor {
public:
    using cerfcore::CustomizationsEditor::CustomizationsEditor;

    bool ShouldRegister() override { return emu_.Get<cerfcore::DeviceConfig>().guest_additions; }

    bool Open(bool force_reboot) override {
        std::optional<int> ce_major;
        uint16_t           major = 0, minor = 0;
        if (emu_.Get<GuestAdditionsUiPolicy>().CeVersion(major, minor)) ce_major = major;

        auto&          cfg    = emu_.Get<cerfcore::DeviceConfig>();
        const uint32_t prev_w = cfg.board_configurable_screen_width;
        const uint32_t prev_h = cfg.board_configurable_screen_height;

        GuestReset reset = GuestReset::kNone;
        if (!emu_.Get<ManagerWindows>().EditLiveCustomizations(force_reboot, ce_major, reset)) return false;

        emu_.Get<cerfcore::DeviceConfigRefresh>().Refresh();
        emu_.Get<cerfcore::CerfVirtCustomizationsReset>().Invalidate();
        Apply(reset, prev_w, prev_h);
        return true;
    }

private:
    void Apply(GuestReset reset, uint32_t prev_w, uint32_t prev_h) {
        auto&          cfg = emu_.Get<cerfcore::DeviceConfig>();
        const uint32_t w   = cfg.board_configurable_screen_width;
        const uint32_t h   = cfg.board_configurable_screen_height;

        auto&      win  = emu_.Get<FrontendWindow>();
        const bool fits = emu_.Get<cerfcore::CerfVirtFramebuffer>().FitsPrimary(w, h, "live customization");
        switch (reset) {
            case GuestReset::kSoft:
                if (fits) {
                    win.SetGuestResolution(w, h);
                    win.FitToResolution(w, h);
                }
                emu_.Get<cerfcore::GuestCpuReset>().WarmReset();
                return;
            case GuestReset::kHard:
                if (fits) {
                    win.SetGuestResolution(w, h);
                    win.FitToResolution(w, h);
                }
                emu_.Get<cerfcore::GuestColdBoot>().RequestHardReset();
                return;
            case GuestReset::kNone:
                if (fits && (w != prev_w || h != prev_h)) {
                    win.FitToResolution(w, h);
                    emu_.Get<cerfcore::CerfVirtResize>().RequestResize(w, h);
                }
                return;
        }
    }
};

}

REGISTER_SERVICE_AS(LiveCustomizationsEditor, cerfcore::CustomizationsEditor);

}

#define NOMINMAX
#include "customizations_transaction.h"

#include "../boards/board_context.h"
#include "../boot/guest_cold_boot.h"
#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/device_config_refresh.h"
#include "../peripherals/cerf_virt/cerf_virt_customizations_reset.h"
#include "../peripherals/cerf_virt/cerf_virt_framebuffer.h"
#include "../peripherals/cerf_virt/cerf_virt_resize.h"
#include "../socs/guest_cpu_reset.h"
#include "guest_additions_ui_policy.h"
#include "host_window.h"
#include "launcher_transaction.h"

REGISTER_SERVICE(CustomizationsTransaction);

bool CustomizationsTransaction::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

bool CustomizationsTransaction::Open(HWND owner, bool force_reboot) {
    const bool soft_default =
        force_reboot || emu_.Get<GuestAdditionsUiPolicy>().DefaultResetIsSoft();

    nlohmann::json query;
    query["force_reboot"]  = force_reboot;
    query["default_reset"] = soft_default ? "soft" : "none";

    nlohmann::json response;
    if (!emu_.Get<LauncherTransaction>().Run(owner, "customizations", query,
                                             response))
        return false;

    emu_.Get<DeviceConfigRefresh>().Refresh();

    if (!response.is_object() || !response.contains("reboot")) return false;

    emu_.Get<CerfVirtCustomizationsReset>().Invalidate();

    std::string reboot;
    if (response["reboot"].is_string())
        reboot = response["reboot"].get<std::string>();
    Apply(std::move(reboot));
    return true;
}

void CustomizationsTransaction::Apply(std::string reboot) {
    auto& cfg = emu_.Get<DeviceConfig>();
    const uint32_t w = cfg.board_configurable_screen_width;
    const uint32_t h = cfg.board_configurable_screen_height;

    const uint32_t bpp =
        emu_.Get<BoardContext>().ResolveGuestAdditionsColorDepth();
    if (bpp != emu_.Get<CerfVirtFramebuffer>().Bpp() && reboot.empty())
        reboot = "soft";

    auto& win = emu_.Get<HostWindow>();
    if (reboot == "soft") {
        win.SetGuestResolution(w, h);
        win.FitToResolution(w, h);
        emu_.Get<GuestCpuReset>().WarmReset();
    } else if (reboot == "hard") {
        win.SetGuestResolution(w, h);
        win.FitToResolution(w, h);
        emu_.Get<GuestColdBoot>().RequestHardReset();
    } else {
        win.FitToResolution(w, h);
        emu_.Get<CerfVirtResize>().RequestResize(w, h);
    }
}

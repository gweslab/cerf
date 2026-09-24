#define NOMINMAX
#include <windows.h>

#include "host_auto_resize.h"

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/log.h"
#include "../core/user_config_writer.h"
#include "../peripherals/cerf_virt/cerf_virt_resize.h"
#include "guest_additions_ui_policy.h"
#include "host_icon_cache.h"
#include "host_widget_registry.h"
#include "host_window.h"
#include "live_customizations_transaction.h"
#include "task_manager_window.h"

#include <string>
#include <vector>

REGISTER_SERVICE(HostAutoResize);

bool HostAutoResize::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

void HostAutoResize::OnReady() {
    if (!emu_.Get<GuestAdditionsUiPolicy>().LiveResizeAvailable())
        enabled_.store(false, std::memory_order_release);
    emu_.Get<HostWidgetRegistry>().Register(this);
}

HostAutoResize::~HostAutoResize() = default;

void HostAutoResize::Toggle() {
    if (!emu_.Get<GuestAdditionsUiPolicy>().LiveResizeAvailable()) return;
    enabled_.store(!enabled_.load(std::memory_order_acquire),
                   std::memory_order_release);
}

void HostAutoResize::OnUserResizeEnd(uint32_t canvas_w, uint32_t canvas_h) {
    if (!Enabled() || canvas_w == 0 || canvas_h == 0) return;
    if (canvas_w == last_w_ && canvas_h == last_h_) return;
    last_w_ = canvas_w;
    last_h_ = canvas_h;
    emu_.Get<CerfVirtResize>().RequestResize(canvas_w, canvas_h);
    emu_.Get<UserConfigWriter>().WriteConfigurableScreenSize(canvas_w,
                                                             canvas_h);
}

std::wstring HostAutoResize::Tooltip() const {
    if (!emu_.Get<GuestAdditionsUiPolicy>().LiveResizeAvailable())
        return L"Guest Additions - right-click for tools";
    return Enabled()
        ? L"Guest Additions - auto-resize ON (click to disable, right-click for tools)"
        : L"Guest Additions - auto-resize OFF (click to enable, right-click for tools)";
}

void HostAutoResize::OnPrimaryAction() { Toggle(); }

std::vector<WidgetMenuItem> HostAutoResize::BuildMenu() {
    std::vector<WidgetMenuItem> items;

    WidgetMenuItem header;
    header.label   = L"CERF Guest Additions";
    header.enabled = false;
    items.push_back(std::move(header));

    items.push_back(WidgetMenuItem{});   /* separator */

    WidgetMenuItem taskmgr;
    taskmgr.label    = L"Task manager…";
    taskmgr.on_click = [this] { emu_.Get<TaskManagerWindow>().Show(); };
    items.push_back(std::move(taskmgr));

    WidgetMenuItem chres;
    chres.label    = L"Resolution / Customizations…";
    chres.on_click = [this] {
        emu_.Get<LiveCustomizationsTransaction>().Open(
            emu_.Get<HostWindow>().Hwnd(), false);
    };
    items.push_back(std::move(chres));

    if (emu_.Get<GuestAdditionsUiPolicy>().LiveResizeAvailable()) {
        WidgetMenuItem resize;
        resize.label    = L"Resize guest to window";
        resize.checked  = Enabled();
        resize.on_click = [this] { Toggle(); };
        items.push_back(std::move(resize));
    }

    return items;
}

void HostAutoResize::DrawIcon(HDC dc, const RECT& box) const {
    emu_.Get<HostIconCache>().DrawCentered(
        dc, box, Enabled() ? L"ICON_GA" : L"ICON_GA_DISABLED");
}

bool HostAutoResize::PollDirty() {
    const bool on = Enabled();
    if (on == last_drawn_on_) return false;
    last_drawn_on_ = on;
    return true;
}

#define NOMINMAX
#include <windows.h>

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/folder_share_config.h"
#include "../core/service.h"
#include "host_gdiplus.h"
#include "host_widget.h"
#include "host_widget_registry.h"
#include "host_window.h"
#include "live_customizations_transaction.h"

#include <string>
#include <vector>

namespace {

constexpr COLORREF kFolderClr   = RGB(232, 196, 92);
constexpr COLORREF kDisabledClr = RGB(224, 224, 224);

class FolderShareWidget : public Service, public HostWidget {
public:
    using Service::Service;

    bool ShouldRegister() override {
        return emu_.Get<DeviceConfig>().guest_additions;
    }

    void OnReady() override { emu_.Get<HostWidgetRegistry>().Register(this); }

    std::wstring WidgetName() const override { return L"Shared folder"; }
    WidgetGroup  Group() const override { return WidgetGroup::Storage; }
    std::wstring Tooltip() const override {
        auto& cfg = emu_.Get<FolderShareConfig>();
        if (!cfg.Enabled())
            return L"Shared folder: off - click to configure";
        return L"Shared folder: " + cfg.HostRoot();
    }
    void OnPrimaryAction() override { Configure(); }
    std::vector<WidgetMenuItem> BuildMenu() override {
        std::vector<WidgetMenuItem> items;
        WidgetMenuItem configure;
        configure.label    = L"Configure shared folder…";
        configure.on_click = [this] { Configure(); };
        items.push_back(std::move(configure));
        return items;
    }
    void DrawIcon(HDC dc, const RECT& box) const override {
        const COLORREF clr = emu_.Get<FolderShareConfig>().Enabled()
                                 ? kFolderClr : kDisabledClr;
        const int cx = (box.left + box.right) / 2;
        const int cy = (box.top + box.bottom) / 2;
        const POINT folder[6] = {
            { cx - 8, cy + 6 }, { cx - 8, cy - 6 }, { cx - 2, cy - 6 },
            { cx,     cy - 3 }, { cx + 8, cy - 3 }, { cx + 8, cy + 6 },
        };
        emu_.Get<HostGdiPlus>().FillPolygonAA(dc, folder, 6, clr, clr);
    }
    bool PollDirty() override {
        const bool on = emu_.Get<FolderShareConfig>().Enabled();
        if (on == drawn_enabled_) return false;
        drawn_enabled_ = on;
        return true;
    }

private:
    void Configure() {
        emu_.Get<LiveCustomizationsTransaction>().Open(
            emu_.Get<HostWindow>().Hwnd(), false);
    }

    bool drawn_enabled_ = false;
};

}

REGISTER_SERVICE(FolderShareWidget);

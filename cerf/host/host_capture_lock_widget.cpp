#define NOMINMAX
#include <windows.h>
#include "ui_language.h"

#include "../core/cerf_emulator.h"
#include "../core/service.h"
#include "host_icon_cache.h"
#include "host_input_capture.h"
#include "host_key_binding.h"
#include "host_widget.h"
#include "host_widget_registry.h"

#include <string>
#include <vector>

namespace {

class HostCaptureLockWidget : public Service, public HostWidget {
public:
    using Service::Service;

    void OnReady() override {
        emu_.Get<HostWidgetRegistry>().Register(this);
    }

    std::wstring WidgetName() const override { return L"Input capture"; }
    std::wstring MenuLabel() const override { return emu_.Get<UiLanguage>().Text("input.capture.input_capture"); }
    WidgetGroup  Group() const override { return WidgetGroup::InputCapture; }
    std::wstring Tooltip() const override {
        const std::wstring key = emu_.Get<HostKeyBinding>().Label();
        return emu_.Get<HostInputCapture>().IsCaptured()
            ? emu_.Get<UiLanguage>().Text("input.capture.input_captured") + key + emu_.Get<UiLanguage>().Text("input.capture.or_click_to_release")
            : emu_.Get<UiLanguage>().Text("input.capture.input_free") + key +
                  emu_.Get<UiLanguage>().Text("input.capture.or_click_to_capture_alt_tab_etc_guest");
    }
    bool TryPrimaryAction() override {
        emu_.Get<HostInputCapture>().Toggle();
        return true;
    }
    std::vector<WidgetMenuItem> BuildMenu() override {
        const std::wstring key = emu_.Get<HostKeyBinding>().Label();
        WidgetMenuItem it;
        it.label    = emu_.Get<HostInputCapture>().IsCaptured()
                          ? emu_.Get<UiLanguage>().Text("input.capture.release_input_capture") + key
                          : emu_.Get<UiLanguage>().Text("input.capture.capture_input") + key;
        it.on_click = [this] { emu_.Get<HostInputCapture>().Toggle(); };
        return { std::move(it) };
    }
    void DrawIcon(HDC dc, const RECT& box) const override {
        const bool cap = emu_.Get<HostInputCapture>().IsCaptured();
        emu_.Get<HostIconCache>().DrawCentered(
            dc, box, cap ? L"ICON_LOCK_ON" : L"ICON_LOCK_OFF");
    }
    bool PollDirty() override {
        const bool cap = emu_.Get<HostInputCapture>().IsCaptured();
        if (cap == last_drawn_cap_) return false;
        last_drawn_cap_ = cap;
        return true;
    }

private:
    bool last_drawn_cap_ = false;
};

}  /* namespace */

REGISTER_SERVICE(HostCaptureLockWidget);

#include "keyboard_widget.h"

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../state/state_stream.h"
#include "host_icon_cache.h"
#include "host_widget_registry.h"
#include "keyboard_hotkey_menu.h"
#include "keyboard_input.h"
#include "keyboard_map.h"
#include "keyboard_mapping_dialog.h"
#include "keyboard_router.h"

REGISTER_SERVICE(KeyboardWidget);

bool KeyboardWidget::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions ||
           emu_.TryGet<KeyboardMap>() != nullptr;
}

void KeyboardWidget::OnReady() {
    emu_.Get<HostWidgetRegistry>().Register(this);
}

std::wstring KeyboardWidget::Tooltip() const {
    auto& router = emu_.Get<KeyboardRouter>();
    KeyboardInput* active = router.Active();
    std::wstring tip = active ? active->SourceName() : L"Keyboard";
    /* The click hint is only true when BuildMenu yields something: a source
       radio (>1 source) or the mapping section (a KeyboardMap exists). */
    const bool has_menu = router.Sources().size() > 1 ||
                          emu_.TryGet<KeyboardMap>() != nullptr;
    if (has_menu) tip += L" - click to configure input / see key mappings";
    return tip;
}

void KeyboardWidget::DrawIcon(HDC dc, const RECT& box) const {
    const wchar_t* icon = L"ICON_KEYBOARD";
    if (auto* a = emu_.Get<KeyboardRouter>().Active()) icon = a->IconResourceName();
    emu_.Get<HostIconCache>().DrawCentered(dc, box, icon);
}

bool KeyboardWidget::PollDirty() {
    const KeyboardInput* a = emu_.Get<KeyboardRouter>().Active();
    if (a == drawn_source_) return false;
    drawn_source_ = a;
    return true;
}

std::vector<WidgetMenuItem> KeyboardWidget::BuildMenu() {
    std::vector<WidgetMenuItem> items;

    auto& router  = emu_.Get<KeyboardRouter>();
    auto  sources = router.Sources();
    if (sources.size() > 1) {
        KeyboardInput* active = router.Active();
        for (auto* s : sources) {
            WidgetMenuItem mi;
            mi.label    = s->SourceName();
            mi.checked  = (s == active);
            mi.on_click = [this, s] { emu_.Get<KeyboardRouter>().SetActive(s); };
            items.push_back(std::move(mi));
        }
    }

    if (emu_.TryGet<KeyboardMap>()) {
        if (!items.empty()) items.push_back(WidgetMenuItem{});   /* separator */

        WidgetMenuItem see;
        see.label    = L"See keyboard mapping";
        see.on_click = [this] { emu_.Get<KeyboardMappingDialog>().Show(); };
        items.push_back(std::move(see));

        if (auto* hk = emu_.TryGet<KeyboardHotkeyMenu>()) {
            for (auto& sec : hk->HotkeySections()) {
                if (sec.empty()) continue;
                items.push_back(WidgetMenuItem{});   /* separator */
                for (auto& it : sec) items.push_back(std::move(it));
            }
        }
    }
    return items;
}

void KeyboardWidget::SaveWidgetState(StateWriter& w) const {
    KeyboardInput* a = emu_.Get<KeyboardRouter>().Active();
    const std::wstring name = a ? a->SourceName() : std::wstring();
    w.Write<uint32_t>("name_count", static_cast<uint32_t>(name.size()));
    w.WriteBytes("name", name.data(), name.size() * sizeof(wchar_t));
    w.Write<uint8_t>("user_picked", emu_.Get<KeyboardRouter>().UserPicked() ? 1u : 0u);
}

void KeyboardWidget::RestoreWidgetState(StateReader& r) {
    uint32_t n = 0;
    r.Read("name_count", n);
    if (n > 1024u) r.Reject("keyboard source name of %u characters", n);
    std::wstring name(n, L'\0');
    r.ReadBytes("name", name.data(), n * sizeof(wchar_t));
    if (!name.empty()) emu_.Get<KeyboardRouter>().RestoreActiveByName(name);
    uint8_t picked = 0;
    r.Read("user_picked", picked);
    emu_.Get<KeyboardRouter>().RestoreUserPicked(picked != 0);
}

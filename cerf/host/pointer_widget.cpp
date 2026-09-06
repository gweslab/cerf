#include "pointer_widget.h"

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../state/state_stream.h"
#include "host_icon_cache.h"
#include "host_widget_registry.h"
#include "pointer_input.h"
#include "pointer_router.h"
#include "pointer_source.h"
#include "pointer_stylus_simulation.h"
#include "stylus_alt_tap.h"

REGISTER_SERVICE(PointerWidget);

bool PointerWidget::ShouldRegister() {
    if (emu_.Get<DeviceConfig>().guest_additions) return true;
    if (emu_.Get<PointerRouter>().Sources().size() > 1) return true;
    return emu_.Get<StylusAltTap>().Supported();
}

void PointerWidget::OnReady() {
    emu_.Get<HostWidgetRegistry>().Register(this);
}

bool PointerWidget::AltTapItemVisible() const {
    PointerSource* active = emu_.Get<PointerRouter>().Active();
    return active && active->Kind() == PointerKind::Stylus &&
           emu_.Get<StylusAltTap>().Armable();
}

bool PointerWidget::StylusSimItemVisible() const {
    auto* ga = emu_.TryGet<PointerInput>();
    return ga && emu_.Get<PointerRouter>().Active() ==
                     static_cast<PointerSource*>(ga);
}

std::wstring PointerWidget::Tooltip() const {
    auto& router = emu_.Get<PointerRouter>();
    PointerSource* active = router.Active();
    std::wstring tip = active ? active->SourceName() : L"Pointing device";
    if (router.Sources().size() > 1)      tip += L" - click to switch input device";
    else if (PrimaryActionOpensMenu())    tip += L" - click to configure";
    return tip;
}

void PointerWidget::OnPrimaryAction() {
    emu_.Get<PointerRouter>().CycleNext();
}

bool PointerWidget::PrimaryActionOpensMenu() const {
    return emu_.Get<PointerRouter>().Sources().size() < 2 &&
           (AltTapItemVisible() || StylusSimItemVisible());
}

std::vector<WidgetMenuItem> PointerWidget::BuildMenu() {
    std::vector<WidgetMenuItem> items;
    auto& router  = emu_.Get<PointerRouter>();
    auto  sources = router.Sources();
    PointerSource* active = router.Active();
    if (sources.size() > 1) {
        for (auto* s : sources) {
            WidgetMenuItem mi;
            mi.label    = s->SourceName();
            mi.checked  = (s == active);
            mi.on_click = [this, s] { emu_.Get<PointerRouter>().SetActive(s); };
            items.push_back(std::move(mi));
        }
    }

    std::vector<WidgetMenuItem> options;
    if (AltTapItemVisible()) {
        WidgetMenuItem mi;
        mi.label    = L"Do Alt+Tap when you Right Click";
        mi.checked  = emu_.Get<StylusAltTap>().Enabled();
        mi.on_click = [this] {
            auto& t = emu_.Get<StylusAltTap>();
            t.SetEnabled(!t.Enabled());
        };
        options.push_back(std::move(mi));
    }
    if (StylusSimItemVisible()) {
        WidgetMenuItem mi;
        mi.label    = L"Send movement only when mouse is clicked (stylus simulation)";
        mi.checked  = emu_.Get<PointerStylusSimulation>().Enabled();
        mi.on_click = [this] {
            auto& s = emu_.Get<PointerStylusSimulation>();
            s.SetEnabled(!s.Enabled());
        };
        options.push_back(std::move(mi));
    }

    if (!options.empty() && !items.empty()) items.push_back(WidgetMenuItem{});
    for (auto& o : options) items.push_back(std::move(o));
    return items;
}

void PointerWidget::DrawIcon(HDC dc, const RECT& box) const {
    const wchar_t* icon = L"ICON_INPUT_GA_POINTER";
    if (auto* a = emu_.Get<PointerRouter>().Active()) icon = a->IconResourceName();
    emu_.Get<HostIconCache>().DrawCentered(dc, box, icon);
}

bool PointerWidget::PollDirty() {
    const PointerSource* a = emu_.Get<PointerRouter>().Active();
    if (a == drawn_source_) return false;
    drawn_source_ = a;
    return true;
}

void PointerWidget::SaveWidgetState(StateWriter& w) const {
    PointerSource* a = emu_.Get<PointerRouter>().Active();
    const std::wstring name = a ? a->SourceName() : std::wstring();
    w.Write<uint32_t>(static_cast<uint32_t>(name.size()));
    w.WriteBytes(name.data(), name.size() * sizeof(wchar_t));
    w.Write<uint8_t>(emu_.Get<PointerRouter>().UserPicked() ? 1u : 0u);
    w.Write<uint8_t>(emu_.Get<StylusAltTap>().Enabled() ? 1u : 0u);
    w.Write<uint8_t>(emu_.Get<PointerStylusSimulation>().Enabled() ? 1u : 0u);
    emu_.Get<StylusAltTap>().SaveState(w);
}

void PointerWidget::RestoreWidgetState(StateReader& r) {
    uint32_t n = 0;
    r.Read(n);
    if (n > 1024u) return;   /* corrupt; outer section frame realigns */
    std::wstring name(n, L'\0');
    r.ReadBytes(name.data(), n * sizeof(wchar_t));
    if (!name.empty()) emu_.Get<PointerRouter>().RestoreActiveByName(name);
    uint8_t picked = 0;
    r.Read(picked);
    emu_.Get<PointerRouter>().RestoreUserPicked(picked != 0);
    uint8_t alt_tap = 1;
    r.Read(alt_tap);
    auto& tap = emu_.Get<StylusAltTap>();
    tap.SetEnabled(alt_tap != 0);
    uint8_t stylus_sim = 0;
    r.Read(stylus_sim);
    emu_.Get<PointerStylusSimulation>().SetEnabled(stylus_sim != 0);
    tap.RestoreState(r);
}

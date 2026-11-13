#include "viewport_menu.h"

#include "../host_key_binding.h"
#include "../integer_scales.h"

#include <cerfcore/core/cerf_emulator.h>

#include <string>
#include <utility>

namespace cerffrontend {

REGISTER_SERVICE(ViewportMenu);

void ViewportMenu::Append(std::vector<MenuItem>& items, ViewportMenuTarget& target,
                          std::function<void()> open_shaders) {
    ViewportMenuTarget* t            = &target;
    const ViewportMode  mode         = target.Mode();
    const int           n            = target.IntegerFactor();
    int                 integer_pick = kIntegerScales[0];
    for (const int scale : kIntegerScales)
        if (n >= scale) integer_pick = scale;

    auto mode_item = [&](const char* label, ViewportMode m) {
        return MenuItem::Radio(label, mode == m, [t, m] {
            t->SetViewportMode(m);
            t->AfterModeChange(false);
        });
    };
    auto integer_item = [&](int factor) {
        return MenuItem::Radio("x" + std::to_string(factor),
                               mode == ViewportMode::Integer && integer_pick == factor, [t, factor] {
                                   t->SetIntegerScale(factor);
                                   t->AfterModeChange(true);
                               });
    };

    items.push_back(mode_item("Original view (x1)", ViewportMode::Original));
    std::vector<MenuItem> scales;
    for (const int scale : kIntegerScales) scales.push_back(integer_item(scale));
    items.push_back(MenuItem::Submenu("Integer scale", std::move(scales)));
    items.push_back(mode_item("Scale to window size", ViewportMode::Aspect));
    items.push_back(mode_item("Stretch", ViewportMode::Stretch));
    items.push_back(MenuItem{});
    if (open_shaders) items.push_back(MenuItem::Action("RetroArch Shaders…", std::move(open_shaders)));
    items.push_back(MenuItem::Check("Full screen\t" + emu_.Get<HostKeyBinding>().LabelWith("F"), target.IsFullscreen(),
                                    [t] { t->ToggleFullscreen(); }));
    items.push_back(MenuItem{});
    items.push_back(MenuItem::Action("Save screenshot", [t] { t->SaveScreenshot(); }));
    items.push_back(MenuItem::Action("Copy screenshot", [t] { t->CopyScreenshot(); }));
}

}

#include "viewport_menu.h"

#include "../host_key_binding.h"
#include "../integer_scales.h"

#include <cerfcore/core/cerf_emulator.h>

#include <string>

namespace cerffrontend {

REGISTER_SERVICE(ViewportMenu);

void ViewportMenu::Append(std::vector<MenuItem>& items, ViewportMenuTarget& target) {
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
        return MenuItem::Radio("Integer scale " + std::to_string(factor) + "x",
                               mode == ViewportMode::Integer && integer_pick == factor, [t, factor] {
                                   t->SetIntegerScale(factor);
                                   t->AfterModeChange(true);
                               });
    };

    items.push_back(mode_item("Original view", ViewportMode::Original));
    items.push_back(mode_item("Resize + match aspect ratio", ViewportMode::Aspect));
    items.push_back(mode_item("Stretch", ViewportMode::Stretch));
    for (const int scale : kIntegerScales) items.push_back(integer_item(scale));
    items.push_back(MenuItem::Check("Apply aliasing", target.Antialias(), [t] { t->SetAntialias(!t->Antialias()); }));
    items.push_back(MenuItem{});
    items.push_back(MenuItem::Check("Full screen\t" + emu_.Get<HostKeyBinding>().LabelWith("F"), target.IsFullscreen(),
                                    [t] { t->ToggleFullscreen(); }));
    items.push_back(MenuItem{});
    items.push_back(MenuItem::Action("Save screenshot", [t] { t->SaveScreenshot(); }));
    items.push_back(MenuItem::Action("Copy screenshot", [t] { t->CopyScreenshot(); }));
}

}

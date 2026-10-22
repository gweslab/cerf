#include <cerffrontend/viewport_menu.h>

#include <cerffrontend/host_key_binding.h>
#include <cerffrontend/integer_scales.h>

#include <cerfcore/core/cerf_emulator.h>

#include <string>
#include <utility>

namespace cerffrontend {

REGISTER_SERVICE(ViewportMenu);

namespace {

MenuItem Check(std::string label, bool checked, bool radio, std::function<void()> on_click) {
    MenuItem item;
    item.label    = std::move(label);
    item.checked  = checked;
    item.radio    = radio;
    item.on_click = std::move(on_click);
    return item;
}

}

void ViewportMenu::Append(std::vector<MenuItem>& items, ViewportMenuTarget& target) {
    ViewportMenuTarget* t            = &target;
    const ViewportMode  mode         = target.Mode();
    const int           n            = target.IntegerFactor();
    int                 integer_pick = kIntegerScales[0];
    for (const int scale : kIntegerScales)
        if (n >= scale) integer_pick = scale;

    auto mode_item = [&](const char* label, ViewportMode m) {
        return Check(label, mode == m, true, [t, m] {
            t->SetViewportMode(m);
            t->AfterModeChange(false);
        });
    };
    auto integer_item = [&](int factor) {
        return Check("Integer scale " + std::to_string(factor) + "x",
                     mode == ViewportMode::Integer && integer_pick == factor, true,
                     [t, factor] {
                         t->SetIntegerScale(factor);
                         t->AfterModeChange(true);
                     });
    };

    items.push_back(mode_item("Original view", ViewportMode::Original));
    items.push_back(mode_item("Resize + match aspect ratio", ViewportMode::Aspect));
    items.push_back(mode_item("Stretch", ViewportMode::Stretch));
    for (const int scale : kIntegerScales) items.push_back(integer_item(scale));
    items.push_back(Check("Apply aliasing", target.Antialias(), false,
                          [t] { t->SetAntialias(!t->Antialias()); }));
    items.push_back(MenuItem{});
    items.push_back(Check("Full screen\t" + emu_.Get<HostKeyBinding>().LabelWith("F"),
                          target.IsFullscreen(), false, [t] { t->ToggleFullscreen(); }));
    items.push_back(MenuItem{});
    MenuItem save;
    save.label    = "Save screenshot";
    save.on_click = [t] { t->SaveScreenshot(); };
    items.push_back(std::move(save));
    MenuItem copy;
    copy.label    = "Copy screenshot";
    copy.on_click = [t] { t->CopyScreenshot(); };
    items.push_back(std::move(copy));
}

}

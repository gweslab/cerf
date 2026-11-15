#include "bar_widgets_menu.h"

#include "bar_widgets.h"

#include <cerfcore/core/cerf_emulator.h>

#include <utility>

namespace cerffrontend {

REGISTER_SERVICE(BarWidgetsMenu);

std::vector<MenuItem> BarWidgetsMenu::Build() {
    std::vector<MenuItem> out;
    const auto            ordered = emu_.Get<BarWidgets>().Ordered();
    for (auto it = ordered.rbegin(); it != ordered.rend(); ++it) {
        BarWidget*            w     = *it;
        std::vector<MenuItem> items = w->Menu();
        if (items.empty())
            out.push_back(MenuItem::Info(w->Name()));
        else if (items.size() == 1 && items[0].submenu.empty())
            out.push_back(std::move(items[0]));
        else
            out.push_back(MenuItem::Submenu(w->Name(), std::move(items)));
    }
    return out;
}

}

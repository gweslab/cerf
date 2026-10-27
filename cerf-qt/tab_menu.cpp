#include "tab_menu.h"

#include <cerfcore/core/cerf_emulator.h>

namespace cerffrontend {

REGISTER_SERVICE(TabMenu);

MenuItem TabMenu::Item(FrontendWindow::Tab tab) {
    const char* label = tab == FrontendWindow::Tab::Hw ? "Hardware Screen" : "Framebuffer";
    return MenuItem::Radio(label, emu_.Get<FrontendWindow>().CurrentTab() == tab,
                           [this, tab] { emu_.Get<FrontendWindow>().SetTab(tab, true); });
}

}

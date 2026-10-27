#include "host_menu_model.h"

#include "frontend_dialogs.h"
#include "../frontend_window.h"
#include "../host_key_binding.h"
#include "../input_capture.h"
#include "../link_opener.h"
#include "../product_links.h"
#include "../screenshots.h"
#include "../tab_menu.h"
#include "../widget_menu_builder.h"
#include "qt_main_window.h"
#include "qt_manager_window_opener.h"

#include <cerfcore/boards/board_context.h>
#include <cerfcore/boot/guest_cold_boot.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/product_name.h>
#include <cerfcore/host/emulation_pause.h>
#include <cerfcore/socs/guest_cpu_reset.h>
#include <cerfcore/state/hibernation.h>

#include <functional>
#include <string>
#include <utility>

namespace cerffrontend {

REGISTER_SERVICE(HostMenuModel);

const char* HostMenuModel::Title(int index) const {
    switch (index) {
        case 0: return "Actions";
        case 1: return "View";
        case 2: return "Help";
    }
    return "";
}

std::vector<MenuItem> HostMenuModel::Build(int index) {
    switch (index) {
        case 0: return Actions();
        case 1: return View();
        case 2: return Help();
    }
    return {};
}

void HostMenuModel::PickStateFile(bool save) {
    auto&             hibernation = emu_.Get<cerfcore::Hibernation>();
    const std::string path =
        emu_.Get<FrontendDialogs>().ChooseStateFile(save, hibernation.DefaultStatePath());
    if (path.empty()) return;
    if (save) hibernation.SaveAsync(path);
    else      hibernation.RestoreAsync(path, false);
}

void HostMenuModel::ConfirmHardReset() {
    if (emu_.Get<FrontendDialogs>().ConfirmWarning(
            "Hard reset - " CERF_PRODUCT_NAME,
            "Hard reset clears all guest RAM.\nUnsaved guest data and the object store are "
            "lost.\n\nContinue?"))
        emu_.Get<cerfcore::GuestColdBoot>().RequestHardReset();
}

std::vector<MenuItem> HostMenuModel::Actions() {
    auto&       key   = emu_.Get<HostKeyBinding>();
    auto&       pause = emu_.Get<cerfcore::EmulationPause>();
    std::vector<MenuItem> items;
    items.push_back(MenuItem::Action("Save state…", [this] { PickStateFile(true); }));
    items.push_back(MenuItem::Action("Load state…", [this] { PickStateFile(false); }));
    items.push_back(MenuItem{});

    MenuItem toggle = MenuItem::Action((pause.IsUserPaused() ? "Resume\t" : "Pause\t") + key.LabelWith("P"),
                                       [this] { emu_.Get<cerfcore::EmulationPause>().Toggle(); });
    toggle.enabled = pause.UserCanToggle();
    items.push_back(std::move(toggle));
    items.push_back(MenuItem::Action("Send Ctrl+Alt+Del\t" + key.LabelWith("Del"),
                                     [this] { emu_.Get<InputCapture>().SendCtrlAltDel(); }));
    items.push_back(MenuItem{});
    items.push_back(MenuItem::Action("Soft reset", [this] { emu_.Get<cerfcore::GuestCpuReset>().WarmReset(); }));
    items.push_back(MenuItem::Action("Hard reset…", [this] { ConfirmHardReset(); }));
    items.push_back(MenuItem{});
    items.push_back(MenuItem::Action("Settings…",
                                     [this] { emu_.Get<QtManagerWindowOpener>().OpenSettings(); }));
    items.push_back(MenuItem{});
    for (MenuItem& widget : emu_.Get<WidgetMenuBuilder>().BuildAllWidgets())
        items.push_back(std::move(widget));
    return items;
}

ViewportMode HostMenuModel::MainViewport::Mode() const { return emu_.Get<QtMainWindow>().Mode(); }

int HostMenuModel::MainViewport::IntegerFactor() const {
    return emu_.Get<QtMainWindow>().IntegerFactor();
}

bool HostMenuModel::MainViewport::Antialias() const {
    return emu_.Get<QtMainWindow>().Antialias();
}

void HostMenuModel::MainViewport::SetViewportMode(ViewportMode m) {
    emu_.Get<QtMainWindow>().SetViewportMode(m);
}

void HostMenuModel::MainViewport::SetIntegerScale(int factor) {
    emu_.Get<QtMainWindow>().SetIntegerScale(factor);
}

void HostMenuModel::MainViewport::SetAntialias(bool on) {
    emu_.Get<QtMainWindow>().SetAntialias(on);
}

bool HostMenuModel::MainViewport::IsFullscreen() const {
    return emu_.Get<QtMainWindow>().IsFullscreen();
}

void HostMenuModel::MainViewport::ToggleFullscreen() {
    emu_.Get<QtMainWindow>().ToggleFullscreen();
}

void HostMenuModel::MainViewport::SaveScreenshot() { emu_.Get<Screenshots>().Save(); }

void HostMenuModel::MainViewport::CopyScreenshot() { emu_.Get<Screenshots>().Copy(); }

void HostMenuModel::MainViewport::AfterModeChange(bool) {
    emu_.Get<QtMainWindow>().RefitIfFollowingGuest();
}

std::vector<MenuItem> HostMenuModel::View() {
    auto& win  = emu_.Get<QtMainWindow>();
    auto& tabs = emu_.Get<TabMenu>();

    std::vector<MenuItem> items;
    items.push_back(tabs.Item(FrontendWindow::Tab::Hw));
    items.push_back(tabs.Item(FrontendWindow::Tab::Framebuffer));
    items.push_back(MenuItem{});
    emu_.Get<ViewportMenu>().Append(items, main_viewport_);
    items.push_back(MenuItem{});
    items.push_back(MenuItem::Check("Match guest size", win.FollowGuest(),
                                    [this] { emu_.Get<QtMainWindow>().MatchGuestSize(); }));
    return items;
}

std::vector<MenuItem> HostMenuModel::Help() {
    std::vector<MenuItem> items;
    items.push_back(MenuItem::Action("Articles (opens in browser)",
                                     [this] { emu_.Get<LinkOpener>().Open(kArticlesUrl.text); }));
    items.push_back(MenuItem{});
    items.push_back(
        MenuItem::Action("About",
                         [this] { emu_.Get<QtManagerWindowOpener>().OpenAbout(EmulatedDeviceLine()); }));
    return items;
}

std::string HostMenuModel::EmulatedDeviceLine() const {
    auto& board = emu_.Get<cerfcore::BoardContext>();
    if (board.GetBoardId().empty()) return std::string();
    return std::string("Emulating:  ") + board.BoardName() + "  ·  " + board.SocName();
}

}

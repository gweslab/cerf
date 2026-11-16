#include "host_menu_model.h"

#include "frontend_dialogs.h"
#include "../enterprise_menu.h"
#include "../frontend_window.h"
#include "../host_key_binding.h"
#include "../hud_selection.h"
#include "../link_opener.h"
#include "../live_property_sheet.h"
#include "../product_links.h"
#include "../cerfman/property_fields.h"
#include "../cerfman/settings_pages.h"
#include "../screenshots.h"
#include "../tab_menu.h"
#include "../view_rotation.h"
#include "../bar_widgets_menu.h"
#include "../yes_no_prompt.h"
#include "../qt_emulator_window.h"
#include "../native_menu_bar.h"
#include "desktop_guest_follow.h"
#include "qt_manager_window_opener.h"

#include <cerfcore/boards/board_context.h>
#include <cerfcore/boot/guest_cold_boot.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/product_name.h>
#include <cerfcore/host/auto_calibration.h>
#include <cerfcore/host/emulation_pause.h>
#include <cerfcore/host/keyboard_router.h>
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
    if (emu_.Get<YesNoPrompt>().Ask("Hard reset - " CERF_PRODUCT_NAME,
                                    "Hard reset clears all guest RAM.\nUnsaved guest data and the object store are "
                                    "lost.\n\nContinue?",
                                    YesNoLevel::kWarning, YesNoEnter::kNo) == PromptAnswer::kYes)
        emu_.Get<cerfcore::GuestColdBoot>().RequestHardResetFromHost();
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
                                     [this] { emu_.Get<cerfcore::KeyboardRouter>().SendCtrlAltDel(); }));
    if (emu_.Get<cerfcore::AutoCalibration>().CanPress())
        items.push_back(MenuItem::Action("Calibrate screen", [this] {
            emu_.Get<cerfcore::AutoCalibration>().Request(cerfcore::CalibrationTrigger::kMenu);
        }));
    items.push_back(MenuItem{});
    items.push_back(
        MenuItem::Action("Soft reset", [this] { emu_.Get<cerfcore::GuestCpuReset>().WarmResetFromHost(); }));
    items.push_back(MenuItem::Action("Hard reset…", [this] { ConfirmHardReset(); }));
    items.push_back(MenuItem{});
    MenuItem settings = MenuItem::Action("Settings…", [this] {
        emu_.Get<QtManagerWindowOpener>().OpenSettings(settings_page::kHome, EmulatedDeviceLine());
    });
    settings.role     = MenuRole::kSettings;
    items.push_back(std::move(settings));
    for (MenuItem& item : emu_.Get<EnterpriseMenu>().Items()) items.push_back(std::move(item));
    items.push_back(MenuItem{});
    for (MenuItem& widget : emu_.Get<BarWidgetsMenu>().Build())
        items.push_back(std::move(widget));
    return items;
}

ViewportMode HostMenuModel::MainViewport::Mode() const { return emu_.Get<QtEmulatorWindow>().Mode(); }

int HostMenuModel::MainViewport::IntegerFactor() const {
    return emu_.Get<QtEmulatorWindow>().IntegerFactor();
}

void HostMenuModel::MainViewport::SetViewportMode(ViewportMode m) {
    emu_.Get<QtEmulatorWindow>().SetViewportMode(m);
}

void HostMenuModel::MainViewport::SetIntegerScale(int factor) {
    emu_.Get<QtEmulatorWindow>().SetIntegerScale(factor);
}

bool HostMenuModel::MainViewport::IsFullscreen() const {
    return emu_.Get<QtEmulatorWindow>().IsFullscreen();
}

void HostMenuModel::MainViewport::ToggleFullscreen() {
    emu_.Get<QtEmulatorWindow>().ToggleFullscreen();
}

void HostMenuModel::MainViewport::SaveScreenshot() { emu_.Get<Screenshots>().Save(nullptr); }

void HostMenuModel::MainViewport::CopyScreenshot() { emu_.Get<Screenshots>().Copy(); }

void HostMenuModel::MainViewport::AfterModeChange(bool) {
    emu_.Get<QtEmulatorWindow>().RefitIfFollowingGuest();
}

std::vector<MenuItem> HostMenuModel::View() {
    auto& tabs = emu_.Get<TabMenu>();

    std::vector<MenuItem> items;
    items.push_back(tabs.Item(FrontendWindow::Tab::Hw));
    items.push_back(tabs.Item(FrontendWindow::Tab::Framebuffer));
    items.push_back(MenuItem{});
    emu_.Get<ViewportMenu>().Append(items, main_viewport_,
                                    [this] { emu_.Get<LivePropertySheet>().Open(sheet_page::kShaders, false); });
    items.push_back(MenuItem{});
    if (NativeMenuBar::Active()) {
        const auto& hud  = emu_.Get<HudSelection>();
        MenuItem    show = MenuItem::Check("Show HUD", hud.Shown(), [this] { emu_.Get<HudSelection>().Toggle(); });
        show.enabled     = hud.CanShow();
        items.push_back(std::move(show));
    }
    items.push_back(emu_.Get<ViewRotation>().MenuRow());
    items.push_back(MenuItem{});
    items.push_back(MenuItem::Check("Match guest size", emu_.Get<DesktopGuestFollow>().FollowsGuest(),
                                    [this] { emu_.Get<QtEmulatorWindow>().MatchGuestSize(); }));
    return items;
}

std::vector<MenuItem> HostMenuModel::Help() {
    std::vector<MenuItem> items;
    items.push_back(
        MenuItem::Action("Tutorial", [this] { emu_.Get<QtManagerWindowOpener>().OpenTutorial(); }));
    items.push_back(MenuItem::Action("Articles (opens in browser)",
                                     [this] { emu_.Get<LinkOpener>().Open(kArticlesUrl.text); }));
    items.push_back(MenuItem{});
    MenuItem about = MenuItem::Action("About", [this] {
        emu_.Get<QtManagerWindowOpener>().OpenSettings(settings_page::kAbout, EmulatedDeviceLine());
    });
    about.role = MenuRole::kAbout;
    items.push_back(std::move(about));
    return items;
}

std::string HostMenuModel::EmulatedDeviceLine() const {
    auto& board = emu_.Get<cerfcore::BoardContext>();
    if (board.GetBoardId().empty()) return std::string();
    return std::string("Emulating:  ") + board.BoardName() + "  ·  " + board.SocName();
}

}

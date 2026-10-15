#define NOMINMAX

#include "host_menu.h"
#include "ui_language.h"

#include "../boot/guest_cold_boot.h"
#include "../core/cerf_emulator.h"
#include "../socs/guest_cpu_reset.h"
#include "about_transaction.h"
#include "host_canvas.h"
#include "host_input_capture.h"
#include "host_key_binding.h"
#include "host_link_opener.h"
#include "host_screenshot.h"
#include "host_widget_registry.h"
#include "settings_transaction.h"
#include "host_window.h"
#include "emulation_pause.h"
#include "../state/hibernation.h"

#include <commdlg.h>

REGISTER_SERVICE(HostMenu);

namespace {

enum MenuId : int {
    kIdCtrlAltDel  = 201,
    kIdSoftReset   = 202,
    kIdHardReset   = 203,
    kIdSaveState   = 204,
    kIdLoadState   = 205,
    kIdPause       = 206,
    kIdSettings    = 207,
    kIdViewBoot    = 100,
    kIdViewHw      = 101,
    kIdViewFb      = 102,
    kIdVpOriginal  = 110,
    kIdVpAspect    = 111,
    kIdVpStretch   = 112,
    kIdVpInteger2  = 113,
    kIdVpInteger3  = 114,
    kIdVpInteger5  = 115,
    kIdAliasing    = 116,
    kIdFullscreen  = 117,
    kIdSaveShot    = 120,
    kIdCopyShot    = 121,
    kIdMatchGuest  = 122,
    kIdAbout       = 130,
    kIdArticles    = 131,
};

constexpr const wchar_t* kArticlesUrl = L"https://cerf.cx/articles/";

}  /* namespace */

HMENU HostMenu::Build() {
    HMENU bar = CreateMenu();

    HMENU actions = CreatePopupMenu();
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)actions, emu_.Get<UiLanguage>().Text("menu.actions"));

    HMENU view = CreatePopupMenu();
    AppendMenuW(view, MF_STRING, kIdViewBoot, emu_.Get<UiLanguage>().Text("menu.boot_screen"));
    AppendMenuW(view, MF_STRING, kIdViewHw,   emu_.Get<UiLanguage>().Text("menu.hardware_screen"));
    AppendMenuW(view, MF_STRING, kIdViewFb,     emu_.Get<UiLanguage>().Text("menu.framebuffer"));
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(view, MF_STRING, kIdVpOriginal, emu_.Get<UiLanguage>().Text("menu.original_view"));
    AppendMenuW(view, MF_STRING, kIdVpAspect,   emu_.Get<UiLanguage>().Text("menu.resize_match_aspect_ratio"));
    AppendMenuW(view, MF_STRING, kIdVpStretch,  emu_.Get<UiLanguage>().Text("menu.stretch"));
    AppendMenuW(view, MF_STRING, kIdVpInteger2, emu_.Get<UiLanguage>().Text("menu.integer_scale_2x"));
    AppendMenuW(view, MF_STRING, kIdVpInteger3, emu_.Get<UiLanguage>().Text("menu.integer_scale_3x"));
    AppendMenuW(view, MF_STRING, kIdVpInteger5, emu_.Get<UiLanguage>().Text("menu.integer_scale_5x"));
    AppendMenuW(view, MF_STRING, kIdAliasing,   emu_.Get<UiLanguage>().Text("menu.apply_aliasing"));
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(view, MF_STRING, kIdFullscreen,
                (emu_.Get<UiLanguage>().Text("menu.full_screen") +
                 emu_.Get<HostKeyBinding>().LabelWith(L"F")).c_str());
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(view, MF_STRING, kIdSaveShot,   emu_.Get<UiLanguage>().Text("menu.save_screenshot"));
    AppendMenuW(view, MF_STRING, kIdCopyShot,   emu_.Get<UiLanguage>().Text("menu.copy_screenshot"));
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(view, MF_STRING, kIdMatchGuest, emu_.Get<UiLanguage>().Text("menu.match_guest_size"));
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)view, emu_.Get<UiLanguage>().Text("menu.view"));

    HMENU help = CreatePopupMenu();
    AppendMenuW(help, MF_STRING, kIdArticles, emu_.Get<UiLanguage>().Text("menu.articles_opens_in_browser"));
    AppendMenuW(help, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(help, MF_STRING, kIdAbout, emu_.Get<UiLanguage>().Text("common.about"));
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)help, emu_.Get<UiLanguage>().Text("common.help"));

    bar_ = bar;
    return bar;
}

void HostMenu::Sync() {
    if (!bar_) return;

    HMENU view = GetSubMenu(bar_, 1);
    if (!view) return;
    auto& canvas = emu_.Get<HostCanvas>();
    int view_id = kIdViewBoot;
    switch (canvas.CurrentTab()) {
        case HostCanvas::Tab::Boot:             view_id = kIdViewBoot; break;
        case HostCanvas::Tab::Hw:             view_id = kIdViewHw;   break;
        case HostCanvas::Tab::Framebuffer:      view_id = kIdViewFb;     break;
    }
    CheckMenuRadioItem(view, kIdViewBoot, kIdViewFb, view_id, MF_BYCOMMAND);
    int vp_id = kIdVpOriginal;
    switch (canvas.Mode()) {
        case HostCanvas::ViewportMode::Original: vp_id = kIdVpOriginal; break;
        case HostCanvas::ViewportMode::Aspect:   vp_id = kIdVpAspect;   break;
        case HostCanvas::ViewportMode::Stretch:  vp_id = kIdVpStretch;  break;
        case HostCanvas::ViewportMode::Integer:
            if (canvas.IntegerFactor() >= 5)      vp_id = kIdVpInteger5;
            else if (canvas.IntegerFactor() >= 3) vp_id = kIdVpInteger3;
            else                                  vp_id = kIdVpInteger2;
            break;
    }
    CheckMenuRadioItem(view, kIdVpOriginal, kIdVpInteger5, vp_id, MF_BYCOMMAND);
    CheckMenuItem(view, kIdAliasing,
                  MF_BYCOMMAND | (canvas.Antialias() ? MF_CHECKED : MF_UNCHECKED));
    CheckMenuItem(view, kIdFullscreen,
                  MF_BYCOMMAND | (emu_.Get<HostWindow>().IsFullscreen()
                                      ? MF_CHECKED : MF_UNCHECKED));
    CheckMenuItem(view, kIdMatchGuest,
                  MF_BYCOMMAND | (emu_.Get<HostWindow>().FollowGuest()
                                      ? MF_CHECKED : MF_UNCHECKED));
}

void HostMenu::OnInitMenuPopup(HMENU popup) {
    Sync();
    HMENU actions = bar_ ? GetSubMenu(bar_, 0) : nullptr;
    if (popup == actions && actions) {
        while (GetMenuItemCount(actions) > 0)
            DeleteMenu(actions, 0, MF_BYPOSITION);
        AppendMenuW(actions, MF_STRING, kIdSaveState, emu_.Get<UiLanguage>().Text("menu.save_state"));
        AppendMenuW(actions, MF_STRING, kIdLoadState, emu_.Get<UiLanguage>().Text("menu.load_state"));
        AppendMenuW(actions, MF_SEPARATOR, 0, nullptr);
        auto& host_key = emu_.Get<HostKeyBinding>();
        auto& pause = emu_.Get<EmulationPause>();
        AppendMenuW(actions, MF_STRING | (pause.UserCanToggle() ? 0u : MF_GRAYED), kIdPause,
                    ((pause.IsUserPaused()
                          ? std::wstring(emu_.Get<UiLanguage>().Text("menu.resume")) : std::wstring(emu_.Get<UiLanguage>().Text("menu.pause"))) +
                     host_key.LabelWith(L"P")).c_str());
        AppendMenuW(actions, MF_STRING, kIdCtrlAltDel,
                    (emu_.Get<UiLanguage>().Text("menu.send_ctrl_alt_del") +
                     host_key.LabelWith(L"Del")).c_str());
        AppendMenuW(actions, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(actions, MF_STRING, kIdSoftReset, emu_.Get<UiLanguage>().Text("menu.soft_reset"));
        AppendMenuW(actions, MF_STRING, kIdHardReset, emu_.Get<UiLanguage>().Text("menu.hard_reset"));
        AppendMenuW(actions, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(actions, MF_STRING, kIdSettings, emu_.Get<UiLanguage>().Text("menu.settings"));
        AppendMenuW(actions, MF_SEPARATOR, 0, nullptr);
        emu_.Get<HostWidgetRegistry>().AppendAllToMenu(actions);
    }
}

void HostMenu::HandleCommand(int id) {
    auto& canvas = emu_.Get<HostCanvas>();

    auto pick_state_path = [this](bool save) -> std::wstring {
        wchar_t path[MAX_PATH];
        lstrcpynW(path, emu_.Get<Hibernation>().DefaultStatePath().c_str(), MAX_PATH);
        OPENFILENAMEW ofn{};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner   = emu_.Get<HostWindow>().Hwnd();
        ofn.lpstrFilter = L"State image (*.img)\0*.img\0All files (*.*)\0*.*\0";
        ofn.lpstrFile   = path;
        ofn.nMaxFile    = MAX_PATH;
        ofn.lpstrDefExt = L"img";
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR |
                    (save ? OFN_OVERWRITEPROMPT : OFN_FILEMUSTEXIST);
        const BOOL ok = save ? GetSaveFileNameW(&ofn) : GetOpenFileNameW(&ofn);
        return ok ? std::wstring(path) : std::wstring();
    };

    switch (id) {
        case kIdSaveState: {
            const std::wstring p = pick_state_path(true);
            if (!p.empty()) emu_.Get<Hibernation>().SaveAsync(p);
            break;
        }
        case kIdLoadState: {
            const std::wstring p = pick_state_path(false);
            if (!p.empty()) emu_.Get<Hibernation>().RestoreAsync(p, false);
            break;
        }
        case kIdPause:      emu_.Get<EmulationPause>().Toggle(); break;
        case kIdSettings:
            emu_.Get<SettingsTransaction>().Open(emu_.Get<HostWindow>().Hwnd());
            break;
        case kIdCtrlAltDel: emu_.Get<HostInputCapture>().SendCtrlAltDel(); break;
        case kIdSoftReset:  emu_.Get<GuestCpuReset>().WarmReset(); break;
        case kIdHardReset:
            if (MessageBoxW(emu_.Get<HostWindow>().Hwnd(),
                    emu_.Get<UiLanguage>().Text("menu.hard_reset_clears_all_guest_ram_unsaved_guest_data"),
                    emu_.Get<UiLanguage>().Text("menu.hard_reset_ce_runtime_foundation"),
                    MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES) {
                emu_.Get<GuestColdBoot>().RequestHardReset();
            }
            break;
        case kIdViewBoot:   canvas.SetTab(HostCanvas::Tab::Boot, true);        break;
        case kIdViewHw:   canvas.SetTab(HostCanvas::Tab::Hw, true);        break;
        case kIdViewFb:     canvas.SetTab(HostCanvas::Tab::Framebuffer, true); break;
        case kIdVpOriginal: canvas.SetViewportMode(HostCanvas::ViewportMode::Original);
                            emu_.Get<HostWindow>().RefitIfFollowingGuest(); break;
        case kIdVpAspect:   canvas.SetViewportMode(HostCanvas::ViewportMode::Aspect);
                            emu_.Get<HostWindow>().RefitIfFollowingGuest(); break;
        case kIdVpStretch:  canvas.SetViewportMode(HostCanvas::ViewportMode::Stretch);
                            emu_.Get<HostWindow>().RefitIfFollowingGuest(); break;
        case kIdVpInteger2: canvas.SetIntegerScale(2);
                            emu_.Get<HostWindow>().RefitIfFollowingGuest(); break;
        case kIdVpInteger3: canvas.SetIntegerScale(3);
                            emu_.Get<HostWindow>().RefitIfFollowingGuest(); break;
        case kIdVpInteger5: canvas.SetIntegerScale(5);
                            emu_.Get<HostWindow>().RefitIfFollowingGuest(); break;
        case kIdAliasing:   canvas.SetAntialias(!canvas.Antialias()); break;
        case kIdFullscreen: emu_.Get<HostWindow>().ToggleFullscreen(); break;
        case kIdSaveShot:   emu_.Get<HostScreenshot>().Save(); break;
        case kIdCopyShot:   emu_.Get<HostScreenshot>().Copy(); break;
        case kIdMatchGuest: emu_.Get<HostWindow>().MatchGuestSize(); break;
        case kIdAbout:
            emu_.Get<AboutTransaction>().Open(emu_.Get<HostWindow>().Hwnd());
            break;
        case kIdArticles:
            emu_.Get<HostLinkOpener>().Open(nullptr, kArticlesUrl);
            break;
    }
}

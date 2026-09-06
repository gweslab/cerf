#define NOMINMAX

#include "host_menu.h"

#include "../boot/guest_cold_boot.h"
#include "../core/cerf_emulator.h"
#include "../socs/guest_cpu_reset.h"
#include "about_dialog.h"
#include "host_canvas.h"
#include "host_input_capture.h"
#include "host_key_binding.h"
#include "host_link_opener.h"
#include "host_screenshot.h"
#include "host_widget_registry.h"
#include "settings_transaction.h"
#include "host_window.h"
#include "memory_visualizer.h"
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
    kIdViewMemViz  = 103,
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
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)actions, L"Actions");

    HMENU view = CreatePopupMenu();
    AppendMenuW(view, MF_STRING, kIdViewBoot, L"Boot Screen");
    AppendMenuW(view, MF_STRING, kIdViewHw,   L"Hardware Screen");
    AppendMenuW(view, MF_STRING, kIdViewFb,     L"Framebuffer");
    if (emu_.TryGet<MemoryVisualizer>())
        AppendMenuW(view, MF_STRING, kIdViewMemViz, L"Memory Visualizer (dev)");
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(view, MF_STRING, kIdVpOriginal, L"Original view");
    AppendMenuW(view, MF_STRING, kIdVpAspect,   L"Resize + match aspect ratio");
    AppendMenuW(view, MF_STRING, kIdVpStretch,  L"Stretch");
    AppendMenuW(view, MF_STRING, kIdVpInteger2, L"Integer scale 2x");
    AppendMenuW(view, MF_STRING, kIdVpInteger3, L"Integer scale 3x");
    AppendMenuW(view, MF_STRING, kIdVpInteger5, L"Integer scale 5x");
    AppendMenuW(view, MF_STRING, kIdAliasing,   L"Apply aliasing");
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(view, MF_STRING, kIdFullscreen,
                (L"Full screen\t" +
                 emu_.Get<HostKeyBinding>().LabelWith(L"F")).c_str());
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(view, MF_STRING, kIdSaveShot,   L"Save screenshot");
    AppendMenuW(view, MF_STRING, kIdCopyShot,   L"Copy screenshot");
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(view, MF_STRING, kIdMatchGuest, L"Match guest size");
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)view, L"View");

    HMENU help = CreatePopupMenu();
    AppendMenuW(help, MF_STRING, kIdArticles, L"Articles (opens in browser)");
    AppendMenuW(help, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(help, MF_STRING, kIdAbout, L"About");
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)help, L"Help");

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
        case HostCanvas::Tab::MemoryVisualizer: view_id = kIdViewMemViz; break;
    }
    CheckMenuRadioItem(view, kIdViewBoot, kIdViewMemViz, view_id, MF_BYCOMMAND);
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
        AppendMenuW(actions, MF_STRING, kIdSaveState, L"Save state...");
        AppendMenuW(actions, MF_STRING, kIdLoadState, L"Load state...");
        AppendMenuW(actions, MF_SEPARATOR, 0, nullptr);
        auto& host_key = emu_.Get<HostKeyBinding>();
        AppendMenuW(actions, MF_STRING, kIdPause,
                    ((emu_.Get<EmulationPause>().IsPaused()
                          ? std::wstring(L"Resume\t") : std::wstring(L"Pause\t")) +
                     host_key.LabelWith(L"P")).c_str());
        AppendMenuW(actions, MF_STRING, kIdCtrlAltDel,
                    (L"Send Ctrl+Alt+Del\t" +
                     host_key.LabelWith(L"Del")).c_str());
        AppendMenuW(actions, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(actions, MF_STRING, kIdSoftReset, L"Soft reset");
        AppendMenuW(actions, MF_STRING, kIdHardReset, L"Hard reset...");
        AppendMenuW(actions, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(actions, MF_STRING, kIdSettings, L"Settings...");
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
                    L"Hard reset clears all guest RAM.\n"
                    L"Unsaved guest data and the object store are lost.\n\n"
                    L"Continue?",
                    L"Hard reset - CE Runtime Foundation",
                    MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES) {
                emu_.Get<GuestColdBoot>().RequestHardReset();
            }
            break;
        case kIdViewBoot:   canvas.SetTab(HostCanvas::Tab::Boot, true);        break;
        case kIdViewHw:   canvas.SetTab(HostCanvas::Tab::Hw, true);        break;
        case kIdViewFb:     canvas.SetTab(HostCanvas::Tab::Framebuffer, true); break;
        case kIdViewMemViz: canvas.SetTab(HostCanvas::Tab::MemoryVisualizer, true); break;
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
        case kIdAbout:      emu_.Get<AboutDialog>().Show(); break;
        case kIdArticles:
            emu_.Get<HostLinkOpener>().Open(nullptr, kArticlesUrl);
            break;
    }
}

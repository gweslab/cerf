#include "hud_selection.h"

#include "frontend_window.h"
#include "hud_controls.h"
#include "hud_layout.h"

#include <cerfcore/boards/board_context.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/device_config_keys.h>
#include <cerfcore/core/device_config_refresh.h>
#include <cerfcore/core/hud_database.h>
#include <cerfcore/core/log.h>
#include <cerfcore/core/user_config_writer.h>

namespace cerffrontend {

REGISTER_SERVICE(HudSelection);

namespace {

using cerfcore::config_key::kHudNone;

}

void HudSelection::OnReady() {
    emu_.Get<cerfcore::DeviceConfigRefresh>().RegisterListener([this] { Apply(); });
    const std::string& setting = emu_.Get<cerfcore::DeviceConfig>().hud;
    if (setting != kHudNone) restore_setting_ = setting;
    active_ = Resolve(setting);
    LOG(Lcd, "HudSelection: setting '%s' -> %s\n", setting.c_str(), active_ ? active_->id.c_str() : "none");
}

const cerfcore::DbHud* HudSelection::Resolve(const std::string& setting) const {
    if (setting == kHudNone) return nullptr;
    auto& huds = emu_.Get<cerfcore::HudDatabase>();
    if (const cerfcore::DbHud* named = huds.Find(setting)) return named;
    auto& board = emu_.Get<cerfcore::BoardContext>();
    return huds.AutoFor(board.GetBoardId(), board.GetBoardFamilyId());
}

bool HudSelection::CanShow() const { return Shown() || Resolve(restore_setting_) != nullptr; }

void HudSelection::SetShown(bool shown) {
    emu_.Get<cerfcore::UserConfigWriter>().WriteHud(shown ? restore_setting_ : std::string(kHudNone));
    Apply();
}

void HudSelection::Toggle() { SetShown(!Shown()); }

ContentFrame HudSelection::Frame() const { return ContentFrame{active_}; }

HudInsets HudSelection::InsideInsets(double area_w, double area_h, int quarter, double fb_w, double fb_h) const {
    if (active_ == nullptr) return {};
    const bool     turned = (quarter & 1) != 0;
    const HudFrame frame  = HudInside(*active_, turned ? area_h : area_w, turned ? area_w : area_h,
                                      active_->ScreenFor(fb_w, fb_h));
    return HudCanvasInsets(HudInsideInsets(frame), quarter);
}

void HudSelection::Apply() {
    const std::string& setting = emu_.Get<cerfcore::DeviceConfig>().hud;
    if (setting != kHudNone) restore_setting_ = setting;
    const cerfcore::DbHud* next = Resolve(setting);
    if (next == active_) return;
    active_ = next;
    LOG(Lcd, "HudSelection: setting '%s' -> %s\n", setting.c_str(), active_ ? active_->id.c_str() : "none");
    emu_.Get<HudControls>().CancelAll();
    emu_.Get<FrontendWindow>().OnPresentationChanged();
}

}

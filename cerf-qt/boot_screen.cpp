#include "boot_screen.h"

#include <cerfcore/boards/board_context.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/guest_power_notifier.h>

namespace cerffrontend {

REGISTER_SERVICE(BootScreen);

void BootScreen::OnReady() {
    short_name_ = emu_.Get<cerfcore::BoardContext>().ShortBoardName();
    emu_.Get<cerfcore::GuestPowerNotifier>().RegisterRebootListener([this] { Restart(); });
}

std::string BootScreen::Label() const {
    if (Latched()) return "LCD is rendering.";
    if (RestartSerial() != 0) {
        const char* over = restart_label_.load(std::memory_order_acquire);
        return over ? over : "Rebooting...";
    }
    return "Booting " + short_name_ + "...";
}

void BootScreen::Restart() {
    latched_.store(false, std::memory_order_release);
    restart_serial_.fetch_add(1, std::memory_order_acq_rel);
}

void BootScreen::SetRestartLabel(const char* static_text) { restart_label_.store(static_text, std::memory_order_release); }

void BootScreen::OnFramebufferLatched() {
    restart_label_.store(nullptr, std::memory_order_release);
    latched_.store(true, std::memory_order_release);
}

void BootScreen::SetHwLineHit(QRectF hit, QPointF scale) {
    hit_   = hit;
    scale_ = scale;
}

bool BootScreen::HitTestHwLine(int x, int y) const { return hit_.contains(QPointF(x / scale_.x(), y / scale_.y())); }

}

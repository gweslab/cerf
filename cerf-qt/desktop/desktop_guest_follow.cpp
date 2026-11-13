#include "desktop_guest_follow.h"

#include "../guest_surface.h"
#include "../qt_device_pixels.h"
#include "../qt_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/guest_resize_policy.h>

#include <QQuickWindow>

#include <algorithm>

REGISTER_SERVICE(DesktopGuestFollow);

namespace {

constexpr int kResizeDebounceMs = 200;

}

void DesktopGuestFollow::OnReady() {
    resize_debounce_.setSingleShot(true);
    resize_debounce_.setInterval(kResizeDebounceMs);
    resize_debounce_.callOnTimeout(gate_.Bind([this] { FireLiveResize(); }));
}

bool DesktopGuestFollow::LiveResizeOn() const {
    const auto* policy = emu_.TryGet<cerfcore::GuestResizePolicy>();
    return policy != nullptr && policy->Enabled();
}

void DesktopGuestFollow::ArmLiveResize() {
    if (!LiveResizeOn()) return;
    if (emu_.Get<QtEmulatorWindow>().Window()->windowStates().testFlag(Qt::WindowMinimized)) return;
    resize_debounce_.start();
}

void DesktopGuestFollow::FireLiveResize() {
    const GuestSurface& surface = *emu_.Get<QtEmulatorWindow>().Surface();
    const QPointF       scale   = surface.PixelScale();
    if (auto* policy = emu_.TryGet<cerfcore::GuestResizePolicy>())
        policy->OnUserResizeEnd(static_cast<uint32_t>(DeviceExtent(surface.width(), scale.x())),
                                static_cast<uint32_t>(DeviceExtent(surface.height(), scale.y())));
}

void DesktopGuestFollow::OnStateChange(Qt::WindowStates before, Qt::WindowStates now) {
    if (now.testFlag(Qt::WindowMaximized)) follow_guest_ = false;
    const auto requested = std::find(pending_states_.begin(), pending_states_.end(), now);
    if (requested != pending_states_.end()) {
        pending_states_.erase(pending_states_.begin(), requested + 1);
        return;
    }
    if (requests_ > 0) return;
    pending_states_.clear();
    if ((before ^ now).testAnyFlags(Qt::WindowMaximized | Qt::WindowFullScreen)) OnUserResized();
}

void DesktopGuestFollow::ExpectResize(const QSize& before, const QSize& after) {
    if (after != before) pending_.push_back(after);
}

void DesktopGuestFollow::ExpectStates(Qt::WindowStates states) { pending_states_.push_back(states); }

void DesktopGuestFollow::OnResized(const QSize& size) {
    const auto requested = std::find(pending_.begin(), pending_.end(), size);
    if (requested != pending_.end()) {
        pending_.erase(pending_.begin(), requested + 1);
        return;
    }
    if (!placed_ || requests_ > 0) return;
    pending_.clear();
    const Qt::WindowStates states = emu_.Get<QtEmulatorWindow>().Window()->windowStates();
    if (!states.testAnyFlags(Qt::WindowMaximized | Qt::WindowFullScreen)) OnUserResized();
}

void DesktopGuestFollow::OnUserResized() {
    follow_guest_ = false;
    ArmLiveResize();
}

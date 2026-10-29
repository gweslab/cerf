#include "qt_pointer_lock.h"

#include "pointer-constraints-unstable-v1-client-protocol.h"
#include "relative-pointer-unstable-v1-client-protocol.h"
#include "wayland_registry_scan.h"

#include <cerfcore/core/log.h>

#include <QGuiApplication>
#include <QLibraryInfo>
#include <QVersionNumber>
#include <QWidget>
#include <QWindow>
#include <QtGui/qguiapplication_platform.h>

#include <wayland-client.h>

#include <cstring>

namespace {

class WaylandPointerLock final : public QtPointerLock {
public:
    explicit WaylandPointerLock(QtRelativeMotionSink& sink) : sink_(sink) {}
    ~WaylandPointerLock() override;

    bool Lock(QWidget& widget) override;
    void Unlock() override;
    bool CanWarp() override;

private:
    bool Bind(wl_display* display);

    static void OnGlobal(void* data, wl_registry* registry, uint32_t name, const char* interface, uint32_t version);
    static void OnRelativeMotion(void* data, zwp_relative_pointer_v1* relative, uint32_t utime_hi, uint32_t utime_lo,
                                 wl_fixed_t dx, wl_fixed_t dy, wl_fixed_t dx_unaccel, wl_fixed_t dy_unaccel);
    static void OnLocked(void* data, zwp_locked_pointer_v1* locked);
    static void OnUnlocked(void* data, zwp_locked_pointer_v1* locked);

    static const zwp_relative_pointer_v1_listener kRelativeListener;
    static const zwp_locked_pointer_v1_listener   kLockedListener;

    QtRelativeMotionSink&            sink_;
    bool                             bound_            = false;
    wl_display*                      display_          = nullptr;
    zwp_relative_pointer_manager_v1* relative_manager_ = nullptr;
    zwp_pointer_constraints_v1*      constraints_      = nullptr;
    zwp_relative_pointer_v1*         relative_         = nullptr;
    zwp_locked_pointer_v1*           locked_           = nullptr;
    bool                             active_           = false;
    bool                             warp_             = false;
};

const zwp_relative_pointer_v1_listener WaylandPointerLock::kRelativeListener = {&WaylandPointerLock::OnRelativeMotion};
const zwp_locked_pointer_v1_listener   WaylandPointerLock::kLockedListener   = {&WaylandPointerLock::OnLocked,
                                                                                &WaylandPointerLock::OnUnlocked};

WaylandPointerLock::~WaylandPointerLock() {
    if (locked_ != nullptr) Unlock();
    if (relative_manager_ != nullptr) zwp_relative_pointer_manager_v1_destroy(relative_manager_);
    if (constraints_ != nullptr) zwp_pointer_constraints_v1_destroy(constraints_);
}

void WaylandPointerLock::OnGlobal(void* data, wl_registry* registry, uint32_t name, const char* interface, uint32_t) {
    auto* self = static_cast<WaylandPointerLock*>(data);
    if (std::strcmp(interface, zwp_relative_pointer_manager_v1_interface.name) == 0) {
        self->relative_manager_ = static_cast<zwp_relative_pointer_manager_v1*>(
            wl_registry_bind(registry, name, &zwp_relative_pointer_manager_v1_interface, 1));
    } else if (std::strcmp(interface, zwp_pointer_constraints_v1_interface.name) == 0) {
        self->constraints_ = static_cast<zwp_pointer_constraints_v1*>(
            wl_registry_bind(registry, name, &zwp_pointer_constraints_v1_interface, 1));
    } else if (std::strcmp(interface, "wp_pointer_warp_v1") == 0) {
        self->warp_ = true;
    }
}

void WaylandPointerLock::OnRelativeMotion(void* data, zwp_relative_pointer_v1*, uint32_t, uint32_t, wl_fixed_t dx,
                                          wl_fixed_t dy, wl_fixed_t, wl_fixed_t) {
    auto* self = static_cast<WaylandPointerLock*>(data);
    if (self->active_) self->sink_.OnRelativeMotion(wl_fixed_to_double(dx), wl_fixed_to_double(dy));
}

void WaylandPointerLock::OnLocked(void* data, zwp_locked_pointer_v1*) { static_cast<WaylandPointerLock*>(data)->active_ = true; }

void WaylandPointerLock::OnUnlocked(void* data, zwp_locked_pointer_v1*) {
    static_cast<WaylandPointerLock*>(data)->active_ = false;
}

bool WaylandPointerLock::Bind(wl_display* display) {
    if (!bound_) {
        bound_   = true;
        display_ = display;
        WaylandRegistryScan scan(display, &OnGlobal, this);
        const bool          read = scan.Roundtrip();
        if (relative_manager_ != nullptr) wl_proxy_set_queue(reinterpret_cast<wl_proxy*>(relative_manager_), nullptr);
        if (constraints_ != nullptr) wl_proxy_set_queue(reinterpret_cast<wl_proxy*>(constraints_), nullptr);
        if (!read) LOG(Caution, "PointerLock: the Wayland roundtrip failed\n");
        else if (relative_manager_ == nullptr || constraints_ == nullptr)
            LOG(Cerf, "PointerLock: the Wayland compositor offers no relative pointer lock\n");
    }
    return relative_manager_ != nullptr && constraints_ != nullptr;
}

bool WaylandPointerLock::Lock(QWidget& widget) {
    const auto* wayland = qGuiApp->nativeInterface<QNativeInterface::QWaylandApplication>();
    if (wayland == nullptr) return false;
    wl_pointer* pointer = wayland->pointer();
    if (pointer == nullptr || !Bind(wayland->display())) return false;
    auto* surface = reinterpret_cast<wl_surface*>(widget.window()->windowHandle()->winId());
    relative_     = zwp_relative_pointer_manager_v1_get_relative_pointer(relative_manager_, pointer);
    zwp_relative_pointer_v1_add_listener(relative_, &kRelativeListener, this);
    locked_ = zwp_pointer_constraints_v1_lock_pointer(constraints_, surface, pointer, nullptr,
                                                      ZWP_POINTER_CONSTRAINTS_V1_LIFETIME_PERSISTENT);
    zwp_locked_pointer_v1_add_listener(locked_, &kLockedListener, this);
    wl_display_flush(display_);
    return true;
}

bool WaylandPointerLock::CanWarp() {
    const auto* wayland = qGuiApp->nativeInterface<QNativeInterface::QWaylandApplication>();
    if (wayland == nullptr) return true;
    Bind(wayland->display());
    return warp_ && QLibraryInfo::version() >= QVersionNumber(6, 10);
}

void WaylandPointerLock::Unlock() {
    zwp_locked_pointer_v1_destroy(locked_);
    zwp_relative_pointer_v1_destroy(relative_);
    locked_   = nullptr;
    relative_ = nullptr;
    active_   = false;
    wl_display_flush(display_);
}

}

std::unique_ptr<QtPointerLock> MakeQtPointerLock(QtRelativeMotionSink& sink) {
    return std::make_unique<WaylandPointerLock>(sink);
}

#include "surface_touch_host.h"

#include "balloon_hint.h"
#include "guest_surface.h"
#include "host_haptics.h"
#include "qt_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/host/pointer_source.h>

#include <QMetaObject>
#include <QQuickWindow>

namespace {

constexpr uint32_t kLockedHintMs = 1500;

QString LockedText(ViewMode mode) {
    switch (mode) {
        case ViewMode::FitScreen:   return QStringLiteral("Locked to fit the screen");
        case ViewMode::FitSafeZone: return QStringLiteral("Locked to fit the safe zone");
        default:                    return QStringLiteral("Locked to original scale");
    }
}

}

bool SurfaceTouchHost::DirectPen() const {
    return !surface_.CursorMode() && surface_.ActiveKind() != cerfcore::PointerKind::Relative;
}

bool SurfaceTouchHost::DoubleTapHelper() const {
    bool helper = false;
    surface_.Gate().Run(
        [&helper](cerfcore::CerfEmulator& emu) { helper = emu.Get<cerfcore::DeviceConfig>().double_tap_helper; });
    return helper;
}

qreal SurfaceTouchHost::Dpr() const { return surface_.Dpr(); }

void SurfaceTouchHost::PenDown(QPointF at) {
    surface_.SendCanvasMouse(cerffrontend::CanvasMouse::Kind::kDown, cerffrontend::MouseButton::kLeft, at * Dpr(),
                             cerffrontend::kHeldLeft);
}

void SurfaceTouchHost::PenMove(QPointF at) {
    surface_.SendCanvasMouse(cerffrontend::CanvasMouse::Kind::kMove, cerffrontend::MouseButton::kNone, at * Dpr(),
                             cerffrontend::kHeldLeft);
}

void SurfaceTouchHost::PenUp(QPointF at) {
    surface_.SendCanvasMouse(cerffrontend::CanvasMouse::Kind::kUp, cerffrontend::MouseButton::kLeft, at * Dpr(), 0);
}

void SurfaceTouchHost::PenCancel() {
    surface_.Gate().Run([](cerfcore::CerfEmulator& emu) { emu.Get<cerffrontend::CanvasInput>().OnPointerLost(); });
}

void SurfaceTouchHost::PenRightDown(QPointF at) {
    const QPointF scene = surface_.mapToScene(at);
    QMetaObject::invokeMethod(surface_.window(), "showTapBubble", Q_ARG(QVariant, scene.x()),
                              Q_ARG(QVariant, scene.y()));
    right_down_at_ = at * Dpr();
    surface_.SendCanvasMouse(cerffrontend::CanvasMouse::Kind::kDown, cerffrontend::MouseButton::kRight, right_down_at_,
                             cerffrontend::kHeldRight);
}

void SurfaceTouchHost::PenRightUp() {
    surface_.SendCanvasMouse(cerffrontend::CanvasMouse::Kind::kUp, cerffrontend::MouseButton::kRight, right_down_at_, 0);
}

void SurfaceTouchHost::PointerMoveBy(QPointF delta) {
    if (surface_.Pointer().MoveBy(delta * Dpr())) surface_.update();
}

void SurfaceTouchHost::PointerButton(GestureButton button, bool down) { surface_.Pointer().Button(button, down); }

void SurfaceTouchHost::PinchBegin(QPointF centroid, double distance) {
    surface_.PlacementState().BeginPinch(centroid * Dpr(), distance * Dpr());
}

void SurfaceTouchHost::PinchUpdate(QPointF centroid, double distance) {
    ViewPlacement& placement = surface_.PlacementState();
    const ViewMode before    = placement.Mode();
    placement.UpdatePinch(centroid * Dpr(), distance * Dpr());
    if (placement.Mode() != before && placement.Mode() != ViewMode::FreeForm) PerformThresholdHaptic(*surface_.window());
    surface_.ApplyPlacement();
}

void SurfaceTouchHost::PinchEnd() {
    const ViewPlacement& placement = surface_.PlacementState();
    if (!placement.PinchLocked()) return;
    surface_.Gate().Run([&placement](cerfcore::CerfEmulator& emu) {
        emu.Get<QtEmulatorWindow>().ShowHint(LockedText(placement.Mode()), kLockedHintMs,
                                             cerffrontend::BalloonHint::kCanvasBottomGap);
    });
}

void SurfaceTouchHost::ThreeFingerTap() { emit surface_.threeFingerTapped(); }

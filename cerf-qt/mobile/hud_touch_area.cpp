#include "hud_touch_area.h"

#include "android_haptics.h"

#include "../canvas_tabs.h"
#include "../hud_controls.h"
#include "../notification_overlay.h"
#include "../qt_device_pixels.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QMouseEvent>
#include <QQuickWindow>
#include <QTouchEvent>

HudTouchArea::HudTouchArea(QQuickItem* parent) : QQuickItem(parent) {
    setAcceptTouchEvents(true);
    setAcceptedMouseButtons(Qt::LeftButton | Qt::RightButton);
}

void HudTouchArea::Attach(cerfcore::CerfEmulator& emu) { gate_.Attach(emu); }

void HudTouchArea::Detach() {
    ReleaseAll();
    gate_ = cerfcore::InstanceGate();
}

QPoint HudTouchArea::DevicePoint(QPointF at) const {
    return ::DevicePoint(at, window() ? window()->devicePixelRatio() : 1.0);
}

bool HudTouchArea::contains(const QPointF& point) const {
    bool       hit = false;
    const QPoint at = DevicePoint(point);
    gate_.Run([&hit, at](cerfcore::CerfEmulator& emu) {
        uint32_t card = 0;
        hit = emu.Get<cerffrontend::CanvasTabs>().Current() == cerfcore::CanvasTab::Framebuffer &&
              emu.Get<cerffrontend::HudControls>().InBand(at.x(), at.y()) &&
              !emu.Get<cerffrontend::NotificationOverlay>().HitTest(at.x(), at.y(), card);
    });
    return hit;
}

void HudTouchArea::touchEvent(QTouchEvent* event) {
    gate_.Run([this, event](cerfcore::CerfEmulator& emu) {
        auto& hud = emu.Get<cerffrontend::HudControls>();
        for (const QEventPoint& point : event->points()) {
            const QPoint at = DevicePoint(point.position());
            switch (point.state()) {
                case QEventPoint::Pressed:
                    if (pointers_.count(point.id()) != 0 || !hud.Press(point.id(), at.x(), at.y())) break;
                    pointers_.insert(point.id());
                    PerformKeyPressHaptic(*window());
                    break;
                case QEventPoint::Released:
                    if (pointers_.erase(point.id()) == 0) break;
                    hud.Release(point.id(), true);
                    PerformKeyReleaseHaptic(*window());
                    break;
                default:
                    if (pointers_.count(point.id()) != 0) hud.Move(point.id(), at.x(), at.y());
                    break;
            }
        }
    });
    event->accept();
}

void HudTouchArea::touchUngrabEvent() { ReleaseAll(); }

void HudTouchArea::mousePressEvent(QMouseEvent* event) {
    const QPoint at = DevicePoint(event->position());
    gate_.Run([this, event, at](cerfcore::CerfEmulator& emu) {
        auto& hud = emu.Get<cerffrontend::HudControls>();
        if (event->button() == Qt::RightButton) {
            hud.ToggleLatch(at.x(), at.y());
            return;
        }
        mouse_pressed_ = hud.Press(cerffrontend::HudControls::kMousePointer, at.x(), at.y());
    });
    event->accept();
}

void HudTouchArea::mouseMoveEvent(QMouseEvent* event) {
    const QPoint at = DevicePoint(event->position());
    if (mouse_pressed_)
        gate_.Run([at](cerfcore::CerfEmulator& emu) {
            emu.Get<cerffrontend::HudControls>().Move(cerffrontend::HudControls::kMousePointer, at.x(), at.y());
        });
    event->accept();
}

void HudTouchArea::mouseReleaseEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton && mouse_pressed_) {
        mouse_pressed_ = false;
        gate_.Run([](cerfcore::CerfEmulator& emu) {
            emu.Get<cerffrontend::HudControls>().Release(cerffrontend::HudControls::kMousePointer, true);
        });
    }
    event->accept();
}

void HudTouchArea::mouseUngrabEvent() {
    if (!mouse_pressed_) return;
    mouse_pressed_ = false;
    gate_.Run([](cerfcore::CerfEmulator& emu) {
        emu.Get<cerffrontend::HudControls>().Release(cerffrontend::HudControls::kMousePointer, false);
    });
}

void HudTouchArea::ReleaseAll() {
    const std::set<int> pointers = std::move(pointers_);
    pointers_.clear();
    gate_.Run([&pointers](cerfcore::CerfEmulator& emu) {
        for (int id : pointers) emu.Get<cerffrontend::HudControls>().Release(id, false);
    });
    if (mouse_pressed_) {
        mouse_pressed_ = false;
        gate_.Run([](cerfcore::CerfEmulator& emu) {
            emu.Get<cerffrontend::HudControls>().Release(cerffrontend::HudControls::kMousePointer, false);
        });
    }
}

#include "status_bar_item.h"

#include "qt_menu_presenter.h"
#include "qt_device_pixels.h"
#include "qt_painter.h"
#include "qt_rgb_color.h"
#include "status_bar.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/host_widget.h>

#include <QHoverEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QQuickWindow>
#include <QWheelEvent>

#include <vector>

namespace {

constexpr int kScrollPerNotch = 2 * cerffrontend::StatusBar::kIconBoxW;

QRectF BoxRect(const cerffrontend::Rect& box) { return QRectF(box.left, box.top, box.Width(), box.Height()); }

}

StatusBarItem::StatusBarItem(QQuickItem* parent) : DevicePixelItem(parent) {
    SetOpaquePainting(true);
    setAcceptedMouseButtons(Qt::LeftButton | Qt::RightButton);
    setAcceptHoverEvents(true);
    setImplicitHeight(cerffrontend::StatusBar::kHeight);
    tick_.setInterval(static_cast<int>(cerffrontend::StatusBar::kTickMs));
    QObject::connect(&tick_, &QTimer::timeout, this, [this] { Tick(); });
    QObject::connect(this, &StatusBarItem::colorsChanged, this, [this] { update(); });
}

void StatusBarItem::Attach(cerfcore::CerfEmulator& emu) {
    gate_.Attach(emu);
    emu.Get<cerffrontend::StatusBar>().Relayout(static_cast<int>(width()), static_cast<int>(height()));
    tick_.start();
    update();
}

void StatusBarItem::Detach() {
    tick_.stop();
    gate_ = cerfcore::InstanceGate();
}

void StatusBarItem::Paint(QPainter* painter) {
    const int w = static_cast<int>(width());
    const int h = static_cast<int>(height());
    if (w <= 0 || h <= 0) return;
    gate_.Run([this, painter, w, h](cerfcore::CerfEmulator& emu) {
        FitDeviceImage(image_, w, h, window()->devicePixelRatio(), QImage::Format_RGB32);
        {
            QPainter  ip(&image_);
            QtPainter qp(emu, ip);
            emu.Get<cerffrontend::StatusBar>().Paint(
                qp, cerffrontend::Rect{0, 0, w, h},
                cerffrontend::StatusBar::Colors{FromQColor(background_), FromQColor(separator_), FromQColor(hover_)});
        }
        painter->drawImage(QPointF(0, 0), image_);
    });
}

void StatusBarItem::geometryChange(const QRectF& new_geometry, const QRectF& old_geometry) {
    DevicePixelItem::geometryChange(new_geometry, old_geometry);
    gate_.Run([this](cerfcore::CerfEmulator& emu) {
        if (emu.Get<cerffrontend::StatusBar>().Relayout(static_cast<int>(width()), static_cast<int>(height()))) update();
    });
}

void StatusBarItem::Tick() {
    gate_.Run([this](cerfcore::CerfEmulator& emu) {
        auto&                                     bar = emu.Get<cerffrontend::StatusBar>();
        const cerffrontend::StatusBar::TickResult r =
            bar.Tick(static_cast<int>(width()), static_cast<int>(height()));
        if (r.layout_changed) HideTip();
        for (size_t idx : r.tooltips_changed)
            if (static_cast<int>(idx) == tip_entry_) ShowTip(emu, tip_entry_);
        if (r.repaint) update();
    });
}

int StatusBarItem::EntryAt(cerfcore::CerfEmulator& emu, QPointF at) const {
    const auto& entries = emu.Get<cerffrontend::StatusBar>().Entries();
    for (size_t i = 0; i < entries.size(); ++i)
        if (entries[i].box.Contains(static_cast<int>(at.x()), static_cast<int>(at.y()))) return static_cast<int>(i);
    return -1;
}

void StatusBarItem::ShowTip(cerfcore::CerfEmulator& emu, int entry) {
    auto& bar  = emu.Get<cerffrontend::StatusBar>();
    tip_entry_ = entry;
    tip_       = QString::fromStdString(bar.TooltipAt(static_cast<size_t>(entry)));
    tip_rect_  = BoxRect(bar.Entries()[static_cast<size_t>(entry)].box);
    emit tipChanged();
}

void StatusBarItem::HideTip() {
    if (tip_entry_ < 0 && tip_.isEmpty()) return;
    tip_entry_ = -1;
    tip_.clear();
    emit tipChanged();
}

void StatusBarItem::hoverMoveEvent(QHoverEvent* event) {
    const QPointF at = event->position();
    gate_.Run([this, at](cerfcore::CerfEmulator& emu) {
        if (emu.Get<cerffrontend::StatusBar>().SetHover(static_cast<int>(at.x()))) update();
        const int entry = EntryAt(emu, at);
        if (entry < 0) HideTip();
        else if (entry != tip_entry_) ShowTip(emu, entry);
    });
}

void StatusBarItem::hoverLeaveEvent(QHoverEvent*) {
    gate_.Run([this](cerfcore::CerfEmulator& emu) {
        if (emu.Get<cerffrontend::StatusBar>().ClearHover()) update();
        HideTip();
    });
}

void StatusBarItem::SecondaryAction(cerfcore::CerfEmulator& emu, cerfcore::HostWidget* widget, QPointF at) {
    std::vector<cerffrontend::MenuItem> items;
    if (!emu.Get<cerffrontend::StatusBar>().ContextMenu(widget, items)) return;
    emu.Get<QtMenuPresenter>().Show(items, mapToScene(at));
}

void StatusBarItem::mousePressEvent(QMouseEvent* event) {
    event->accept();
    if (event->button() != Qt::LeftButton) return;
    const QPointF at = event->position();
    gate_.Run([this, at](cerfcore::CerfEmulator& emu) {
        auto& bar = emu.Get<cerffrontend::StatusBar>();
        HideTip();
        if (cerfcore::HostWidget* w = bar.WidgetAt(static_cast<int>(at.x())); w && !bar.PrimaryClick(w))
            SecondaryAction(emu, w, at);
    });
}

void StatusBarItem::mouseReleaseEvent(QMouseEvent* event) {
    if (event->button() != Qt::RightButton) return;
    const QPointF at = event->position();
    gate_.Run([this, at](cerfcore::CerfEmulator& emu) {
        HideTip();
        if (cerfcore::HostWidget* w = emu.Get<cerffrontend::StatusBar>().WidgetAt(static_cast<int>(at.x())))
            SecondaryAction(emu, w, at);
    });
}

void StatusBarItem::wheelEvent(QWheelEvent* event) {
    const QPoint pixels = event->pixelDelta();
    const QPoint angle  = event->angleDelta();
    const int    delta  = !pixels.isNull() ? (pixels.x() != 0 ? pixels.x() : pixels.y())
                                           : (angle.x() != 0 ? angle.x() : angle.y()) * kScrollPerNotch
                                                 / QWheelEvent::DefaultDeltasPerStep;
    gate_.Run([this, delta](cerfcore::CerfEmulator& emu) {
        if (emu.Get<cerffrontend::StatusBar>().Scroll(delta)) {
            HideTip();
            update();
        }
    });
}

bool StatusBarItem::WidgetSceneRect(const cerfcore::HostWidget* widget, QRectF& out) {
    bool found = false;
    gate_.Run([&](cerfcore::CerfEmulator& emu) {
        cerffrontend::Rect box;
        found = emu.Get<cerffrontend::StatusBar>().WidgetBox(widget, box);
        if (found) out = mapRectToScene(BoxRect(box));
    });
    return found;
}

bool StatusBarItem::CaptureWidgetSceneRect(QRectF& out) {
    bool found = false;
    gate_.Run([&](cerfcore::CerfEmulator& emu) {
        cerffrontend::Rect box;
        found = emu.Get<cerffrontend::StatusBar>().CaptureWidgetBox(box);
        if (found) out = mapRectToScene(BoxRect(box));
    });
    return found;
}

#include "qt_status_bar.h"

#include "../qt_device_pixels.h"
#include "../qt_painter.h"
#include "qt_menu_builder.h"
#include "qt_theme.h"

#include "../status_bar.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/host_widget.h>

#include <QEvent>
#include <QHelpEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QToolTip>
#include <QWheelEvent>

namespace {

constexpr int kScrollPerNotch = 2 * cerffrontend::StatusBar::kIconBoxW;

QRect BoxRect(const cerffrontend::Rect& box) {
    return QRect(box.left, box.top, box.Width(), box.Height());
}

}

QtStatusBar::QtStatusBar(cerfcore::CerfEmulator& emu, QWidget* parent)
    : QWidget(parent), gate_(emu) {
    setFixedHeight(cerffrontend::StatusBar::kHeight);
    setFocusPolicy(Qt::NoFocus);
    setAttribute(Qt::WA_OpaquePaintEvent);
    setAttribute(Qt::WA_AlwaysShowToolTips);
    setMouseTracking(true);
    QObject::connect(&tick_, &QTimer::timeout, this, [this] { Tick(); });
    tick_.start(static_cast<int>(cerffrontend::StatusBar::kTickMs));
}

void QtStatusBar::paintEvent(QPaintEvent*) {
    if (width() <= 0 || height() <= 0) return;
    gate_.Run([this](cerfcore::CerfEmulator& emu) {
        FitDeviceImage(image_, width(), height(), devicePixelRatioF(), QImage::Format_RGB32);
        {
            QPainter  ip(&image_);
            QtPainter painter(emu, ip);
            emu.Get<cerffrontend::StatusBar>().Paint(painter, cerffrontend::Rect{0, 0, width(), height()},
                                                     emu.Get<QtTheme>().IsDark());
        }
        QPainter p(this);
        p.drawImage(QPointF(0, 0), image_);
    });
}

void QtStatusBar::resizeEvent(QResizeEvent*) {
    gate_.Run([this](cerfcore::CerfEmulator& emu) {
        if (emu.Get<cerffrontend::StatusBar>().Relayout(width(), height())) update();
    });
}

void QtStatusBar::changeEvent(QEvent* event) {
    if (event->type() == QEvent::DevicePixelRatioChange) update();
    QWidget::changeEvent(event);
}

void QtStatusBar::Tick() {
    gate_.Run([this](cerfcore::CerfEmulator& emu) {
        auto&                                     bar = emu.Get<cerffrontend::StatusBar>();
        const cerffrontend::StatusBar::TickResult r   = bar.Tick(width(), height());
        if (tip_entry_ >= 0 && QToolTip::isVisible()) {
            for (size_t idx : r.tooltips_changed) {
                if (static_cast<int>(idx) != tip_entry_) continue;
                QToolTip::showText(QCursor::pos(), QString::fromStdString(bar.TooltipAt(idx)), this,
                                   BoxRect(bar.Entries()[idx].box));
            }
        }
        if (r.layout_changed) tip_entry_ = -1;
        if (r.repaint) update();
    });
}

int QtStatusBar::EntryAt(cerfcore::CerfEmulator& emu, const QPoint& pos) const {
    const auto& entries = emu.Get<cerffrontend::StatusBar>().Entries();
    for (size_t i = 0; i < entries.size(); ++i)
        if (entries[i].box.Contains(pos.x(), pos.y())) return static_cast<int>(i);
    return -1;
}

bool QtStatusBar::event(QEvent* event) {
    if (event->type() != QEvent::ToolTip) return QWidget::event(event);
    gate_.Run([this, event](cerfcore::CerfEmulator& emu) {
        auto*     help  = static_cast<QHelpEvent*>(event);
        const int entry = EntryAt(emu, help->pos());
        tip_entry_      = entry;
        if (entry < 0) {
            QToolTip::hideText();
            event->ignore();
            return;
        }
        auto& bar = emu.Get<cerffrontend::StatusBar>();
        QToolTip::showText(help->globalPos(), QString::fromStdString(bar.TooltipAt(entry)), this,
                           BoxRect(bar.Entries()[static_cast<size_t>(entry)].box));
    });
    return true;
}

void QtStatusBar::SecondaryAction(cerfcore::CerfEmulator& emu, cerfcore::HostWidget* w, const QPoint& pos) {
    std::vector<cerffrontend::MenuItem> items;
    if (!emu.Get<cerffrontend::StatusBar>().ContextMenu(w, items)) return;
    emu.Get<QtMenuBuilder>().RunContextMenu(items, mapToGlobal(pos));
}

void QtStatusBar::mousePressEvent(QMouseEvent* event) {
    if (event->button() != Qt::LeftButton) return;
    gate_.Run([this, event](cerfcore::CerfEmulator& emu) {
        const QPoint pos = event->position().toPoint();
        auto&        bar = emu.Get<cerffrontend::StatusBar>();
        if (cerfcore::HostWidget* w = bar.WidgetAt(pos.x()); w && !bar.PrimaryClick(w)) SecondaryAction(emu, w, pos);
    });
}

void QtStatusBar::mouseMoveEvent(QMouseEvent* event) {
    gate_.Run([this, event](cerfcore::CerfEmulator& emu) {
        if (emu.Get<cerffrontend::StatusBar>().SetHover(event->position().toPoint().x())) update();
    });
}

void QtStatusBar::leaveEvent(QEvent*) {
    gate_.Run([this](cerfcore::CerfEmulator& emu) {
        if (emu.Get<cerffrontend::StatusBar>().ClearHover()) update();
    });
}

void QtStatusBar::wheelEvent(QWheelEvent* event) {
    const QPoint pixels = event->pixelDelta();
    const QPoint angle  = event->angleDelta();
    const int    delta  = !pixels.isNull() ? (pixels.x() != 0 ? pixels.x() : pixels.y())
                                           : (angle.x() != 0 ? angle.x() : angle.y()) * kScrollPerNotch
                                                 / QWheelEvent::DefaultDeltasPerStep;
    gate_.Run([this, delta](cerfcore::CerfEmulator& emu) {
        if (emu.Get<cerffrontend::StatusBar>().Scroll(delta)) {
            tip_entry_ = -1;
            update();
        }
    });
}

void QtStatusBar::mouseReleaseEvent(QMouseEvent* event) {
    if (event->button() != Qt::RightButton) return;
    gate_.Run([this, event](cerfcore::CerfEmulator& emu) {
        const QPoint pos = event->position().toPoint();
        if (cerfcore::HostWidget* w = emu.Get<cerffrontend::StatusBar>().WidgetAt(pos.x()))
            SecondaryAction(emu, w, pos);
    });
}

bool QtStatusBar::WidgetScreenRect(cerfcore::CerfEmulator& emu, const cerfcore::HostWidget* w, QRect& out) const {
    cerffrontend::Rect box;
    if (!emu.Get<cerffrontend::StatusBar>().WidgetBox(w, box)) return false;
    const QRect local = BoxRect(box);
    out = QRect(mapToGlobal(local.topLeft()), local.size());
    return true;
}

bool QtStatusBar::CaptureWidgetScreenRect(cerfcore::CerfEmulator& emu, QRect& out) const {
    cerffrontend::Rect box;
    if (!emu.Get<cerffrontend::StatusBar>().CaptureWidgetBox(box)) return false;
    const QRect local = BoxRect(box);
    out = QRect(mapToGlobal(local.topLeft()), local.size());
    return true;
}

#include "qt_status_bar.h"

#include "qt_device_pixels.h"
#include "qt_menu_builder.h"
#include "qt_painter.h"
#include "qt_theme.h"

#include <cerffrontend/status_bar.h>

#include <cerfcore/host/host_widget.h>

#include <QEvent>
#include <QHelpEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QToolTip>

namespace {

QRect BoxRect(const cerffrontend::Rect& box) {
    return QRect(box.left, box.top, box.Width(), box.Height());
}

}

QtStatusBar::QtStatusBar(cerfcore::CerfEmulator& emu, QWidget* parent)
    : QWidget(parent), emu_(emu) {
    setFixedHeight(cerffrontend::StatusBar::kHeight);
    setFocusPolicy(Qt::NoFocus);
    setAttribute(Qt::WA_OpaquePaintEvent);
    setAttribute(Qt::WA_AlwaysShowToolTips);
    QObject::connect(&tick_, &QTimer::timeout, this, [this] { Tick(); });
    tick_.start(static_cast<int>(cerffrontend::StatusBar::kTickMs));
}

void QtStatusBar::paintEvent(QPaintEvent*) {
    if (width() <= 0 || height() <= 0) return;
    const qreal dpr = devicePixelRatioF();
    const int   dw  = DeviceExtent(width(), dpr);
    const int   dh  = DeviceExtent(height(), dpr);
    if (image_.width() != dw || image_.height() != dh) image_ = QImage(dw, dh, QImage::Format_RGB32);
    image_.setDevicePixelRatio(dpr);
    {
        QPainter  ip(&image_);
        QtPainter painter(emu_, ip);
        emu_.Get<cerffrontend::StatusBar>().Paint(painter, cerffrontend::Rect{0, 0, width(), height()},
                                                  emu_.Get<QtTheme>().IsDark());
    }
    QPainter p(this);
    p.drawImage(QPointF(0, 0), image_);
}

void QtStatusBar::resizeEvent(QResizeEvent*) {
    if (emu_.Get<cerffrontend::StatusBar>().Relayout(width(), height())) update();
}

void QtStatusBar::changeEvent(QEvent* event) {
    if (event->type() == QEvent::DevicePixelRatioChange) update();
    QWidget::changeEvent(event);
}

void QtStatusBar::Tick() {
    auto&                                     bar = emu_.Get<cerffrontend::StatusBar>();
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
}

int QtStatusBar::EntryAt(const QPoint& pos) const {
    const auto& entries = emu_.Get<cerffrontend::StatusBar>().Entries();
    for (size_t i = 0; i < entries.size(); ++i)
        if (entries[i].box.Contains(pos.x(), pos.y())) return static_cast<int>(i);
    return -1;
}

bool QtStatusBar::event(QEvent* event) {
    if (event->type() != QEvent::ToolTip) return QWidget::event(event);
    auto*     help  = static_cast<QHelpEvent*>(event);
    const int entry = EntryAt(help->pos());
    tip_entry_      = entry;
    if (entry < 0) {
        QToolTip::hideText();
        event->ignore();
        return true;
    }
    auto& bar = emu_.Get<cerffrontend::StatusBar>();
    QToolTip::showText(help->globalPos(), QString::fromStdString(bar.TooltipAt(entry)), this,
                       BoxRect(bar.Entries()[static_cast<size_t>(entry)].box));
    return true;
}

void QtStatusBar::SecondaryAction(cerfcore::HostWidget* w, const QPoint& pos) {
    std::vector<cerffrontend::MenuItem> items;
    if (!emu_.Get<cerffrontend::StatusBar>().ContextMenu(w, items)) return;
    emu_.Get<QtMenuBuilder>().RunContextMenu(items, mapToGlobal(pos));
}

void QtStatusBar::mousePressEvent(QMouseEvent* event) {
    if (event->button() != Qt::LeftButton) return;
    const QPoint pos = event->position().toPoint();
    auto&        bar = emu_.Get<cerffrontend::StatusBar>();
    if (cerfcore::HostWidget* w = bar.WidgetAt(pos.x()); w && !bar.PrimaryClick(w)) SecondaryAction(w, pos);
}

void QtStatusBar::mouseReleaseEvent(QMouseEvent* event) {
    if (event->button() != Qt::RightButton) return;
    const QPoint pos = event->position().toPoint();
    if (cerfcore::HostWidget* w = emu_.Get<cerffrontend::StatusBar>().WidgetAt(pos.x()))
        SecondaryAction(w, pos);
}

bool QtStatusBar::WidgetScreenRect(const cerfcore::HostWidget* w, QRect& out) const {
    cerffrontend::Rect box;
    if (!emu_.Get<cerffrontend::StatusBar>().WidgetBox(w, box)) return false;
    const QRect local = BoxRect(box);
    out = QRect(mapToGlobal(local.topLeft()), local.size());
    return true;
}

bool QtStatusBar::CaptureWidgetScreenRect(QRect& out) const {
    cerffrontend::Rect box;
    if (!emu_.Get<cerffrontend::StatusBar>().CaptureWidgetBox(box)) return false;
    const QRect local = BoxRect(box);
    out = QRect(mapToGlobal(local.topLeft()), local.size());
    return true;
}

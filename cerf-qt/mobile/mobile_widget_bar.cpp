#include "mobile_widget_bar.h"

#include "../qt_device_pixels.h"
#include "../qt_painter.h"
#include "mobile_emulator_window.h"
#include "mobile_menu_presenter.h"

#include "../button_row.h"
#include "../status_bar.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/host_widget.h>
#include <cerfcore/host/pointer_widget.h>

#include <QPainter>
#include <QQuickWindow>

#include <vector>

namespace {

constexpr qreal              kScale      = 2.0;
constexpr uint32_t           kHintHoldMs = 3000;
constexpr int                kHintGap    = 96;
constexpr cerffrontend::Rgb  kBackdrop{32, 32, 32};

}

MobileWidgetBar::MobileWidgetBar(QQuickItem* parent) : QQuickPaintedItem(parent) {
    setOpaquePainting(false);
    tick_.setInterval(static_cast<int>(cerffrontend::StatusBar::kTickMs));
    QObject::connect(&tick_, &QTimer::timeout, this, [this] { Tick(); });
}

void MobileWidgetBar::Attach(cerfcore::CerfEmulator& emu) {
    gate_.Attach(emu);
    const cerfcore::HostWidget* pointer = emu.TryGet<cerfcore::PointerWidget>();
    auto&                       bar     = emu.Get<cerffrontend::StatusBar>();
    bar.SetFilter([pointer](const cerfcore::HostWidget* w) {
        return w != pointer && w->Group() != cerfcore::WidgetGroup::InputCapture;
    });
    bar.SetRowShown(false);
    emu.Get<cerffrontend::ButtonRow>().SetPcKeysShown(true);
    tick_.start();
    Tick();
}

void MobileWidgetBar::Detach() {
    tick_.stop();
    gate_ = cerfcore::InstanceGate();
}

int MobileWidgetBar::UnitWidth(cerfcore::CerfEmulator& emu) const {
    const size_t count = emu.Get<cerffrontend::StatusBar>().ShownWidgets().size();
    return static_cast<int>(count) * cerffrontend::StatusBar::kIconBoxW;
}

void MobileWidgetBar::Tick() {
    gate_.Run([this](cerfcore::CerfEmulator& emu) {
        const int units = UnitWidth(emu);
        setImplicitWidth(units * kScale);
        setImplicitHeight(cerffrontend::StatusBar::kHeight * kScale);
        if (emu.Get<cerffrontend::StatusBar>().Tick(units, cerffrontend::StatusBar::kHeight).repaint) update();
    });
}

void MobileWidgetBar::paint(QPainter* painter) {
    gate_.Run([this, painter](cerfcore::CerfEmulator& emu) {
        const int   units = UnitWidth(emu);
        const int   high  = cerffrontend::StatusBar::kHeight;
        const qreal dpr   = window()->devicePixelRatio();
        FitDeviceImage(image_, units, high, dpr * kScale, QImage::Format_ARGB32_Premultiplied);
        image_.fill(Qt::transparent);
        {
            QPainter  ip(&image_);
            QtPainter qp(emu, ip);
            emu.Get<cerffrontend::StatusBar>().PaintWidgets(qp, kBackdrop);
        }
        painter->drawImage(QRectF(0, 0, units * kScale, high * kScale), image_);
    });
}

void MobileWidgetBar::Activate(qreal x, qreal y, bool menu) {
    QMetaObject::invokeMethod(
        this, [this, x, y, menu] { gate_.Run([&](cerfcore::CerfEmulator& emu) { RunWidget(emu, x, y, menu); }); },
        Qt::QueuedConnection);
}

void MobileWidgetBar::RunWidget(cerfcore::CerfEmulator& emu, qreal x, qreal y, bool menu) {
    auto&                 bar    = emu.Get<cerffrontend::StatusBar>();
    cerfcore::HostWidget* widget = bar.WidgetAt(static_cast<int>(x / kScale));
    if (!widget) return;
    if (!menu && bar.PrimaryClick(widget)) return;
    std::vector<cerffrontend::MenuItem> items;
    if (!bar.ContextMenu(widget, items)) return;
    if (menu || items.empty())
        emu.Get<MobileEmulatorWindow>().ShowHint(QString::fromStdString(widget->Tooltip()), kHintHoldMs, kHintGap);
    if (!items.empty()) emu.Get<MobileMenuPresenter>().Show(items, mapToScene(QPointF(x, y)));
}

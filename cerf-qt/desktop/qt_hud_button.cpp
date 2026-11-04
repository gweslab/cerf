#include "qt_hud_button.h"

#include "../tinted_symbol_icon.h"

#include <QEvent>
#include <QIcon>
#include <QPixmap>

#include <cmath>

namespace {

constexpr int kHudIconPx = 20;

}

QtHudButton::QtHudButton(QWidget* parent) : QToolButton(parent) {
    setAutoRaise(true);
    setCheckable(true);
    setIconSize(QSize(kHudIconPx, kHudIconPx));
    setToolTip(QStringLiteral("Show HUD"));
    setAccessibleName(QStringLiteral("Show HUD"));
    Tint();
}

void QtHudButton::changeEvent(QEvent* event) {
    QToolButton::changeEvent(event);
    if (event->type() == QEvent::PaletteChange) Tint();
}

void QtHudButton::Tint() {
    const qreal dpr  = devicePixelRatioF();
    const int   side = static_cast<int>(std::lround(kHudIconPx * dpr));
    QPixmap icon = QPixmap::fromImage(
        TintedSymbolIcon(QStringLiteral("gamepad"), QSize(side, side), palette().color(QPalette::WindowText)));
    icon.setDevicePixelRatio(dpr);
    setIcon(QIcon(icon));
}

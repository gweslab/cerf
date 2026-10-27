#include "qt_compact_menu_bar_style.h"

#include <QStyleOptionMenuItem>

namespace {

constexpr int kTitleWidthTrim  = 10;
constexpr int kTitleHeightTrim = 8;

}

QSize QtCompactMenuBarStyle::sizeFromContents(ContentsType type, const QStyleOption* option, const QSize& size,
                                              const QWidget* widget) const {
    QSize result = QProxyStyle::sizeFromContents(type, option, size, widget);
    if (type == CT_MenuBarItem && !result.isEmpty()) result -= QSize(kTitleWidthTrim, kTitleHeightTrim);
    return result;
}

void QtCompactMenuBarStyle::drawControl(ControlElement element, const QStyleOption* option, QPainter* painter,
                                        const QWidget* widget) const {
    if (element == CE_MenuBarItem) {
        if (const auto* title = qstyleoption_cast<const QStyleOptionMenuItem*>(option)) {
            QStyleOptionMenuItem wide = *title;
            wide.rect.adjust(-kTitleWidthTrim / 2, 0, kTitleWidthTrim / 2, 0);
            QProxyStyle::drawControl(element, &wide, painter, widget);
            return;
        }
    }
    QProxyStyle::drawControl(element, option, painter, widget);
}

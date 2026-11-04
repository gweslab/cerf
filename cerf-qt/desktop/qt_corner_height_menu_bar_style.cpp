#include "qt_corner_height_menu_bar_style.h"

#include <QMenuBar>

#include <algorithm>

QSize QtCornerHeightMenuBarStyle::sizeFromContents(ContentsType type, const QStyleOption* option, const QSize& size,
                                                   const QWidget* widget) const {
    QSize result = QProxyStyle::sizeFromContents(type, option, size, widget);
    const auto* bar = qobject_cast<const QMenuBar*>(widget);
    if (type != CT_MenuBarItem || result.isEmpty() || bar == nullptr) return result;
    for (const Qt::Corner corner : {Qt::TopLeftCorner, Qt::TopRightCorner})
        if (const QWidget* side = bar->cornerWidget(corner); side != nullptr && !side->isHidden())
            result.setHeight(std::max(result.height(), side->sizeHint().height()));
    return result;
}

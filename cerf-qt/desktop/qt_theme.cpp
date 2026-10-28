#include "qt_theme.h"

#include "qt_compact_menu_bar_style.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>

#include <QApplication>
#include <QPalette>
#include <QStyle>
#include <QStyleFactory>

REGISTER_SERVICE(QtTheme);

namespace {

constexpr char kFluentStyle[] = "windows11";
constexpr char kFusionStyle[] = "Fusion";

}

void QtTheme::ApplyStyle() {
    const QString native = QApplication::style()->name();
    if (native == QLatin1String(kFluentStyle))
        QApplication::setStyle(new QtCompactMenuBarStyle(QStyleFactory::create(QLatin1String(kFluentStyle))));
    else
        QApplication::setStyle(QLatin1String(kFusionStyle));
    QPalette       palette  = QApplication::palette();
    const QPalette standard = QApplication::style()->standardPalette();
    int            unset    = 0;
    for (int g = 0; g < QPalette::NColorGroups; ++g) {
        for (int r = 0; r < QPalette::NColorRoles; ++r) {
            const auto group = static_cast<QPalette::ColorGroup>(g);
            const auto role  = static_cast<QPalette::ColorRole>(r);
            if (role == QPalette::NoRole || palette.color(group, role).isValid()) continue;
            palette.setColor(group, role, standard.color(group, role));
            ++unset;
        }
    }
    if (unset != 0) QApplication::setPalette(palette);
    QApplication::style()->polish(palette);
    dark_ = palette.color(QPalette::Window).lightness() < palette.color(QPalette::WindowText).lightness();
    LOG(Cerf, "QtTheme: platform style %s, %s palette, %d colors from the style palette\n", qUtf8Printable(native),
        dark_ ? "dark" : "light", unset);
}

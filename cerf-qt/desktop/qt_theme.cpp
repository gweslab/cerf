#include "qt_theme.h"

#include "qt_compact_menu_bar_style.h"
#include "qt_corner_height_menu_bar_style.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>

#include <QApplication>
#include <QGuiApplication>
#include <QPalette>
#include <QStyle>
#include <QStyleFactory>
#include <QStyleHints>

REGISTER_SERVICE(QtTheme);

namespace {

constexpr char kFluentStyle[] = "windows11";
constexpr char kFusionStyle[] = "Fusion";

bool IsDarkPalette(const QPalette& palette) {
    return palette.color(QPalette::Window).lightness() < palette.color(QPalette::WindowText).lightness();
}

}

void QtTheme::ApplyStyle() {
    const QString native = QApplication::style()->name();
    if (native == QLatin1String(kFluentStyle))
        QApplication::setStyle(new QtCompactMenuBarStyle(QStyleFactory::create(QLatin1String(kFluentStyle))));
    else
        QApplication::setStyle(new QtCornerHeightMenuBarStyle(QStyleFactory::create(QLatin1String(kFusionStyle))));
    LOG(Cerf, "QtTheme: platform style %s\n", qUtf8Printable(native));
    ApplyPalette();
    QObject::connect(QGuiApplication::styleHints(), &QStyleHints::colorSchemeChanged, &scheme_receiver_,
                     gate_.Bind([this] { ApplyPalette(); }));
}

void QtTheme::ApplyPalette() {
    QPalette              palette  = QApplication::palette();
    const QPalette        standard = QApplication::style()->standardPalette();
    const Qt::ColorScheme scheme   = QGuiApplication::styleHints()->colorScheme();
    const bool replace = scheme != Qt::ColorScheme::Unknown && IsDarkPalette(palette) != (scheme == Qt::ColorScheme::Dark);
    int        unset   = 0;
    if (replace) {
        palette = standard;
    } else {
        for (int g = 0; g < QPalette::NColorGroups; ++g) {
            for (int r = 0; r < QPalette::NColorRoles; ++r) {
                const auto group = static_cast<QPalette::ColorGroup>(g);
                const auto role  = static_cast<QPalette::ColorRole>(r);
                if (role == QPalette::NoRole || palette.color(group, role).isValid()) continue;
                palette.setColor(group, role, standard.color(group, role));
                ++unset;
            }
        }
    }
    if (replace || unset != 0) QApplication::setPalette(palette);
    QApplication::style()->polish(palette);
    dark_ = IsDarkPalette(palette);
    if (replace)
        LOG(Cerf, "QtTheme: color scheme %d, %s palette from the style, the platform palette had the other scheme\n",
            static_cast<int>(scheme), dark_ ? "dark" : "light");
    else
        LOG(Cerf, "QtTheme: color scheme %d, %s palette, %d colors from the style palette\n", static_cast<int>(scheme),
            dark_ ? "dark" : "light", unset);
}

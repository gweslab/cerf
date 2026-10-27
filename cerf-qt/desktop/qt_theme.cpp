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
    QPalette palette = QApplication::palette();
    QApplication::style()->polish(palette);
    dark_ = palette.color(QPalette::Window).lightness() < palette.color(QPalette::WindowText).lightness();
    LOG(Cerf, "QtTheme: platform style %s, %s palette\n", qUtf8Printable(native), dark_ ? "dark" : "light");
}

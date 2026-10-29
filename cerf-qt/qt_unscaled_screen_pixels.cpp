#include "qt_unscaled_screen_pixels.h"

#include "qt_device_pixels.h"
#include "qt_screen_pixels.h"

#include <cerfcore/core/log.h>

#include <QGuiApplication>
#include <QScreen>

namespace {

QSize Unscaled(const QScreen& screen, const QSize& logical) {
    const QString platform = QGuiApplication::platformName();
    if (platform != QLatin1String("cocoa") && platform != QLatin1String("offscreen") &&
        platform != QLatin1String("minimal")) {
        LOG(Caution, "UnscaledScreenPixels: screen '%s' of QPA platform '%s' has no pixel size\n",
            qUtf8Printable(screen.name()), qUtf8Printable(platform));
        return kNoScreenPixels;
    }
    const qreal ratio = screen.devicePixelRatio();
    return QSize(DeviceExtent(logical.width(), ratio), DeviceExtent(logical.height(), ratio));
}

}

QSize UnscaledScreenPixels(const QScreen& screen) { return Unscaled(screen, screen.size()); }

QSize UnscaledWorkAreaPixels(const QScreen& screen) { return Unscaled(screen, screen.availableGeometry().size()); }

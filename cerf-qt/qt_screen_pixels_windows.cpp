#include "qt_screen_pixels.h"

#include "qt_unscaled_screen_pixels.h"

#include <cerfcore/core/log.h>

#include <QScreen>
#include <QtGui/qscreen_platform.h>

#define NOMINMAX
#include <windows.h>

namespace {

QSize MonitorRectSize(const QScreen& screen, RECT MONITORINFO::*rect, QSize (*unscaled)(const QScreen&)) {
    const auto* native = screen.nativeInterface<QNativeInterface::QWindowsScreen>();
    if (native == nullptr) return unscaled(screen);
    MONITORINFO info{};
    info.cbSize = sizeof(info);
    if (!GetMonitorInfoW(native->handle(), &info)) {
        LOG(Caution, "ScreenPixels: GetMonitorInfoW failed for screen '%s' (error %lu)\n",
            qUtf8Printable(screen.name()), GetLastError());
        return kNoScreenPixels;
    }
    const RECT& r = info.*rect;
    return QSize(r.right - r.left, r.bottom - r.top);
}

}

QSize ScreenPixels(const QScreen& screen) {
    return MonitorRectSize(screen, &MONITORINFO::rcMonitor, UnscaledScreenPixels);
}

QSize ScreenWorkAreaPixels(const QScreen& screen) {
    return MonitorRectSize(screen, &MONITORINFO::rcWork, UnscaledWorkAreaPixels);
}

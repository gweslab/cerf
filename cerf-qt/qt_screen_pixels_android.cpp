#include "qt_screen_pixels.h"

#include <cerfcore/core/log.h>

#include <QJniObject>
#include <QScreen>
#include <QtCore/qcoreapplication_platform.h>
#include <QtGui/qscreen_platform.h>

namespace {

QJniObject DisplayOf(const QScreen& screen) {
    const int        id      = screen.nativeInterface<QNativeInterface::QAndroidScreen>()->displayId();
    const QJniObject context = QNativeInterface::QAndroidApplication::context();
    const QJniObject manager = context.callObjectMethod("getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;",
                                                        QJniObject::fromString(QStringLiteral("display")).object());
    const QJniObject display = manager.callObjectMethod("getDisplay", "(I)Landroid/view/Display;", jint(id));
    if (!display.isValid())
        LOG(Caution, "ScreenPixels: no Android display %d for screen '%s'\n", id, qUtf8Printable(screen.name()));
    return display;
}

QSize RealSize(const QJniObject& display) {
    QJniObject size("android/graphics/Point");
    display.callMethod<void>("getRealSize", "(Landroid/graphics/Point;)V", size.object());
    return QSize(size.getField<jint>("x"), size.getField<jint>("y"));
}

}

QSize ScreenPixels(const QScreen& screen) {
    const QJniObject display = DisplayOf(screen);
    return display.isValid() ? RealSize(display) : kNoScreenPixels;
}

QSize ScreenSafeZonePixels(const QScreen& screen) {
    const QJniObject display = DisplayOf(screen);
    if (!display.isValid()) return kNoScreenPixels;
    QSize            size    = RealSize(display);
    const QJniObject cutout  = display.callObjectMethod("getCutout", "()Landroid/view/DisplayCutout;");
    if (cutout.isValid()) {
        size.rwidth() -= cutout.callMethod<jint>("getSafeInsetLeft") + cutout.callMethod<jint>("getSafeInsetRight");
        size.rheight() -= cutout.callMethod<jint>("getSafeInsetTop") + cutout.callMethod<jint>("getSafeInsetBottom");
    }
    return size;
}

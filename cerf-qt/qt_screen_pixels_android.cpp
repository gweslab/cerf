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

QMargins CutoutOf(const QJniObject& display) {
    const QJniObject cutout = display.callObjectMethod("getCutout", "()Landroid/view/DisplayCutout;");
    if (!cutout.isValid()) return {};
    return QMargins(cutout.callMethod<jint>("getSafeInsetLeft"), cutout.callMethod<jint>("getSafeInsetTop"),
                    cutout.callMethod<jint>("getSafeInsetRight"), cutout.callMethod<jint>("getSafeInsetBottom"));
}

}

QSize ScreenPixels(const QScreen& screen) {
    const QJniObject display = DisplayOf(screen);
    return display.isValid() ? RealSize(display) : kNoScreenPixels;
}

QSize ScreenSafeZonePixels(const QScreen& screen) {
    const QJniObject display = DisplayOf(screen);
    if (!display.isValid()) return kNoScreenPixels;
    const QSize    size   = RealSize(display);
    const QMargins cutout = CutoutOf(display);
    return QSize(size.width() - cutout.left() - cutout.right(), size.height() - cutout.top() - cutout.bottom());
}

QMarginsF ScreenCutoutMargins(const QScreen& screen) {
    const QJniObject display = DisplayOf(screen);
    if (!display.isValid()) return {};
    const QMargins cutout     = CutoutOf(display);
    const qreal    to_logical = qreal(1) / screen.devicePixelRatio();
    return QMarginsF(qRound(cutout.left() * to_logical), qRound(cutout.top() * to_logical),
                     qRound(cutout.right() * to_logical), qRound(cutout.bottom() * to_logical));
}

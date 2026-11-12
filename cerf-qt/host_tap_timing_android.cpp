#include "host_tap_timing.h"

#include <QJniObject>
#include <QtCore/qcoreapplication_platform.h>

#include <jni.h>

namespace {

constexpr char kViewConfigurationClass[] = "android/view/ViewConfiguration";

}

int TapTimeoutMs() { return QJniObject::callStaticMethod<jint>(kViewConfigurationClass, "getTapTimeout"); }

int DoubleTapMinTimeMs() { return 40; }

int DoubleTapTimeoutMs() { return QJniObject::callStaticMethod<jint>(kViewConfigurationClass, "getDoubleTapTimeout"); }

qreal DoubleTapSlopPx(qreal) {
    const QJniObject context       = QNativeInterface::QAndroidApplication::context();
    const QJniObject configuration = QJniObject::callStaticObjectMethod(
        kViewConfigurationClass, "get", "(Landroid/content/Context;)Landroid/view/ViewConfiguration;", context.object());
    return configuration.callMethod<jint>("getScaledDoubleTapSlop");
}

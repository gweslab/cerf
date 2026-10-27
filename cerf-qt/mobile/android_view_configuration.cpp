#include "android_view_configuration.h"

#include <QJniObject>
#include <QtCore/qcoreapplication_platform.h>

#include <jni.h>

namespace {

constexpr char kViewConfigurationClass[] = "android/view/ViewConfiguration";

}

int AndroidTapTimeoutMs() { return QJniObject::callStaticMethod<jint>(kViewConfigurationClass, "getTapTimeout"); }

int AndroidDoubleTapMinTimeMs() { return 40; }

int AndroidDoubleTapTimeoutMs() {
    return QJniObject::callStaticMethod<jint>(kViewConfigurationClass, "getDoubleTapTimeout");
}

int AndroidDoubleTapSlopPx() {
    const QJniObject context       = QNativeInterface::QAndroidApplication::context();
    const QJniObject configuration = QJniObject::callStaticObjectMethod(
        kViewConfigurationClass, "get", "(Landroid/content/Context;)Landroid/view/ViewConfiguration;", context.object());
    return configuration.callMethod<jint>("getScaledDoubleTapSlop");
}

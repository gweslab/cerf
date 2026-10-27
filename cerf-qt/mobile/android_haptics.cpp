#include "android_haptics.h"

#include <QJniObject>
#include <QWindow>
#include <QtCore/qcoreapplication_platform.h>

#include <jni.h>

namespace {

constexpr jint kLongPress                   = 0;
constexpr jint kClockTick                   = 4;
constexpr jint kGestureThresholdActivate    = 23;
constexpr int  kGestureThresholdActivateSdk = 34;

void Perform(QWindow& window, jint feedback) {
    const QJniObject view(reinterpret_cast<jobject>(window.winId()));
    QNativeInterface::QAndroidApplication::runOnAndroidMainThread(
        [view, feedback] { view.callMethod<jboolean>("performHapticFeedback", feedback); });
}

}

void PerformThresholdHaptic(QWindow& window) {
    Perform(window, QNativeInterface::QAndroidApplication::sdkVersion() >= kGestureThresholdActivateSdk
                        ? kGestureThresholdActivate
                        : kClockTick);
}

void PerformLongPressHaptic(QWindow& window) { Perform(window, kLongPress); }

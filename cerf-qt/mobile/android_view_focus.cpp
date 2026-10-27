#include "android_view_focus.h"

#include <QGuiApplication>
#include <QJniObject>
#include <QWindow>
#include <QtCore/qcoreapplication_platform.h>

#include <jni.h>

void FollowFocusWindowWithViewFocus(QGuiApplication& app) {
    QObject::connect(&app, &QGuiApplication::focusWindowChanged, &app, [](QWindow* window) {
        if (!window) return;
        const QJniObject view(reinterpret_cast<jobject>(window->winId()));
        QNativeInterface::QAndroidApplication::runOnAndroidMainThread(
            [view] { view.callMethod<jboolean>("requestFocus"); });
    });
}

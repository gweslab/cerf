#include "android_system_bars.h"

#include <QGuiApplication>
#include <QJSEngine>
#include <QJniEnvironment>
#include <QJniObject>
#include <QMetaObject>
#include <QStyleHints>
#include <QWindow>
#include <QtCore/qcoreapplication_platform.h>

#include <iterator>
#include <mutex>

struct SystemBarsLink {
    std::mutex         mutex;
    AndroidSystemBars* bars = nullptr;
};

namespace {

constexpr char kWatchClass[] = "cx/cerf/SystemBarsWatch";

void JNICALL SystemBarsShown(JNIEnv*, jclass, jlong handle) {
    SystemBarsLink&                   link = *reinterpret_cast<SystemBarsLink*>(handle);
    const std::lock_guard<std::mutex> lock(link.mutex);
    if (link.bars != nullptr)
        QMetaObject::invokeMethod(link.bars, &AndroidSystemBars::shown, Qt::QueuedConnection);
}

}

AndroidSystemBars::~AndroidSystemBars() {
    const std::lock_guard<std::mutex> lock(link_->mutex);
    link_->bars = nullptr;
}

void AndroidSystemBars::Install(QGuiApplication& app) {
    auto* bars        = new AndroidSystemBars(&app);
    bars->link_       = new SystemBarsLink;
    bars->link_->bars = bars;
    QJniEnvironment     env;
    const JNINativeMethod methods[] = {
        {"nativeShown", "(J)V", reinterpret_cast<void*>(SystemBarsShown)},
    };
    env.registerNativeMethods(env.findClass(kWatchClass), methods, std::size(methods));

    const QJniObject activity = QNativeInterface::QAndroidApplication::context();
    const jlong      handle   = reinterpret_cast<jlong>(bars->link_);
    QNativeInterface::QAndroidApplication::runOnAndroidMainThread([activity, handle] {
        QJniObject::callStaticMethod<void>(kWatchClass, "install", "(Landroid/app/Activity;J)V", activity.object(),
                                           handle);
    });
    QObject::connect(&app, &QGuiApplication::focusWindowChanged, bars, [bars] { bars->FollowFocusWindow(); });
    QObject::connect(app.styleHints(), &QStyleHints::colorSchemeChanged, bars, [bars] { bars->FollowFocusWindow(); });
}

void AndroidSystemBars::FollowFocusWindow() {
    QWindow* focus = QGuiApplication::focusWindow();
    if (focus != nullptr)
        QObject::connect(focus, &QWindow::visibilityChanged, this, &AndroidSystemBars::FollowFocusWindow,
                         Qt::UniqueConnection);
    const jboolean light = (focus != nullptr && focus->visibility() == QWindow::FullScreen) ||
                           QGuiApplication::styleHints()->colorScheme() == Qt::ColorScheme::Dark;
    const QJniObject activity = QNativeInterface::QAndroidApplication::context();
    QNativeInterface::QAndroidApplication::runOnAndroidMainThread([activity, light] {
        QJniObject::callStaticMethod<void>(kWatchClass, "useLightIcons", "(Landroid/app/Activity;Z)V",
                                           activity.object(), light);
    });
}

AndroidSystemBars* AndroidSystemBars::create(QQmlEngine*, QJSEngine*) {
    auto* bars = qApp->findChild<AndroidSystemBars*>(QString(), Qt::FindDirectChildrenOnly);
    QJSEngine::setObjectOwnership(bars, QJSEngine::CppOwnership);
    return bars;
}

void AndroidSystemBars::Hide() {
    const QJniObject activity = QNativeInterface::QAndroidApplication::context();
    QNativeInterface::QAndroidApplication::runOnAndroidMainThread([activity] {
        QJniObject::callStaticMethod<void>(kWatchClass, "hide", "(Landroid/app/Activity;)V", activity.object());
    });
}

#include "android_input_pacing.h"

#include "press_pacing.h"

#include <QJniEnvironment>
#include <QJniObject>
#include <QtCore/qcoreapplication_platform.h>

#include <iterator>

namespace {

constexpr char kPacerClass[] = "cx/cerf/InputEventPacer";

PressPacing& PacingOf(jlong handle) { return *reinterpret_cast<PressPacing*>(handle); }

jlong JNICALL PacingCreate(JNIEnv*, jclass) { return reinterpret_cast<jlong>(new PressPacing); }

void JNICALL PacingDestroy(JNIEnv*, jclass, jlong handle) { delete &PacingOf(handle); }

void JNICALL PacingPush(JNIEnv*, jclass, jlong handle, jint code, jboolean down, jboolean up, jboolean paced) {
    const KeyEdge edge = down ? KeyEdge::kDown : up ? KeyEdge::kUp : KeyEdge::kNone;
    PacingOf(handle).Push(code, edge, paced);
}

jboolean JNICALL PacingPopReady(JNIEnv*, jclass, jlong handle, jlong now_ms) { return PacingOf(handle).PopReady(now_ms); }

jlong JNICALL PacingHeadDue(JNIEnv*, jclass, jlong handle) { return PacingOf(handle).HeadDue(); }

}

void PaceInputEvents() {
    QJniEnvironment env;
    const JNINativeMethod methods[] = {
        {"nativeCreate", "()J", reinterpret_cast<void*>(PacingCreate)},
        {"nativeDestroy", "(J)V", reinterpret_cast<void*>(PacingDestroy)},
        {"nativePush", "(JIZZZ)V", reinterpret_cast<void*>(PacingPush)},
        {"nativePopReady", "(JJ)Z", reinterpret_cast<void*>(PacingPopReady)},
        {"nativeHeadDue", "(J)J", reinterpret_cast<void*>(PacingHeadDue)},
    };
    env.registerNativeMethods(env.findClass(kPacerClass), methods, std::size(methods));

    const QJniObject activity = QNativeInterface::QAndroidApplication::context();
    QNativeInterface::QAndroidApplication::runOnAndroidMainThread([activity] {
        QJniObject::callStaticMethod<void>(kPacerClass, "install", "(Landroid/app/Activity;)V", activity.object());
    });
}

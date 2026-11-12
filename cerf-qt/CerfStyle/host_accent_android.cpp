#include "host_accent.h"

#include <QGuiApplication>
#include <QJniObject>
#include <QtCore/qcoreapplication_platform.h>

namespace {

constexpr int kDynamicColorSdk = 31;

QColor SystemColor(const char* name) {
    const jint       id      = QJniObject::getStaticField<jint>("android/R$color", name);
    const QJniObject context = QNativeInterface::QAndroidApplication::context();
    return QColor::fromRgba(static_cast<QRgb>(context.callMethod<jint>("getColor", "(I)I", id)));
}

class SystemColorAccent : public HostAccent {
public:
    explicit SystemColorAccent(QObject* parent) : HostAccent(parent) {
        connect(qGuiApp, &QGuiApplication::applicationStateChanged, this, &SystemColorAccent::Reload);
        Reload();
    }

protected:
    void Reload() override {
        if (QNativeInterface::QAndroidApplication::sdkVersion() < kDynamicColorSdk) {
            Publish(QColor(), QColor());
            return;
        }
        Publish(SystemColor("system_accent1_600"), SystemColor("system_accent1_200"));
    }
};

}

HostAccent* NewHostAccent(QObject* parent) { return new SystemColorAccent(parent); }

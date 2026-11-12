#include "host_accent.h"

#include <QDBusArgument>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDBusVariant>
#include <QStringList>

namespace {

constexpr char kService[]   = "org.freedesktop.portal.Desktop";
constexpr char kPath[]      = "/org/freedesktop/portal/desktop";
constexpr char kInterface[] = "org.freedesktop.portal.Settings";
constexpr char kNamespace[] = "org.freedesktop.appearance";
constexpr char kKey[]       = "accent-color";

bool InUnitRange(double value) { return value >= 0.0 && value <= 1.0; }

QColor ParsePortalColor(const QDBusMessage& reply) {
    if (reply.type() != QDBusMessage::ReplyMessage || reply.arguments().isEmpty()) return QColor();
    const QDBusArgument rgb = reply.arguments().constFirst().value<QDBusVariant>().variant().value<QDBusArgument>();
    double              r   = -1.0;
    double              g   = -1.0;
    double              b   = -1.0;
    rgb.beginStructure();
    rgb >> r >> g >> b;
    rgb.endStructure();
    if (!InUnitRange(r) || !InUnitRange(g) || !InUnitRange(b)) return QColor();
    return QColor::fromRgbF(static_cast<float>(r), static_cast<float>(g), static_cast<float>(b));
}

class PortalAccent : public HostAccent {
public:
    explicit PortalAccent(QObject* parent) : HostAccent(parent) {
        QDBusConnection::sessionBus().connect(QString::fromLatin1(kService), QString::fromLatin1(kPath),
                                              QString::fromLatin1(kInterface), QStringLiteral("SettingChanged"),
                                              QStringList{QString::fromLatin1(kNamespace), QString::fromLatin1(kKey)},
                                              QString(), this, SLOT(Reload()));
        Reload();
    }

protected:
    void Reload() override {
        QDBusMessage call = QDBusMessage::createMethodCall(QString::fromLatin1(kService), QString::fromLatin1(kPath),
                                                           QString::fromLatin1(kInterface), QStringLiteral("ReadOne"));
        call << QString::fromLatin1(kNamespace) << QString::fromLatin1(kKey);
        auto* watcher = new QDBusPendingCallWatcher(QDBusConnection::sessionBus().asyncCall(call), this);
        connect(watcher, &QDBusPendingCallWatcher::finished, this, [this](QDBusPendingCallWatcher* finished) {
            const QColor color = ParsePortalColor(finished->reply());
            finished->deleteLater();
            Publish(color, color);
        });
    }
};

}

HostAccent* NewHostAccent(QObject* parent) { return new PortalAccent(parent); }

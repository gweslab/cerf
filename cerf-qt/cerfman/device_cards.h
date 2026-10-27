#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QSize>
#include <QString>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

#include <map>

class DeviceCards : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(QString runningState READ RunningState CONSTANT)
    Q_PROPERTY(QString savedState READ SavedState CONSTANT)
    Q_PROPERTY(QString offState READ OffState CONSTANT)

public:
    explicit DeviceCards(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static DeviceCards* create(QQmlEngine* qml, QJSEngine*) { return ManagerQmlEngine::Singleton<DeviceCards>(qml); }

    QString RunningState() const;
    QString SavedState() const;
    QString OffState() const;

    Q_INVOKABLE QVariantMap Rows(const QString& query) const;
    Q_INVOKABLE QVariantMap Details(const QString& name) const;
    Q_INVOKABLE QString     UpdateRomsLabel(int count) const;

private:
    QSize BadgeSize(const QString& arch) const;

    mutable std::map<QString, QSize> badge_sizes_;
};

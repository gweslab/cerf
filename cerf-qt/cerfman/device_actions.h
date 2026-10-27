#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

class DeviceActions : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(QString warmBoot READ WarmBoot CONSTANT)
    Q_PROPERTY(QString coldBoot READ ColdBoot CONSTANT)
    Q_PROPERTY(bool verboseLogs READ VerboseLogs WRITE SetVerboseLogs NOTIFY verboseLogsChanged)

public:
    explicit DeviceActions(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static DeviceActions* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<DeviceActions>(qml);
    }

    QString WarmBoot() const;
    QString ColdBoot() const;

    bool VerboseLogs() const;
    void SetVerboseLogs(bool verbose);

    Q_INVOKABLE QVariantMap Launch(const QString& name, const QString& boot, bool confirmed);
    Q_INVOKABLE bool        Running(const QString& name) const;
    Q_INVOKABLE bool        HasSavedState(const QString& name) const;
    Q_INVOKABLE QVariantMap DiscardSavedState(const QString& name);
    Q_INVOKABLE QVariantMap Remove(const QString& name);
    Q_INVOKABLE QString     Directory(const QString& name) const;
    Q_INVOKABLE QString     DisplayName(const QString& name) const;
    Q_INVOKABLE QString     RelativePath(const QString& name) const;
    Q_INVOKABLE QString     Rename(const QString& name, const QString& display_name);

signals:
    void verboseLogsChanged();

private:
    QVariantMap RunningError(const QString& name) const;
};

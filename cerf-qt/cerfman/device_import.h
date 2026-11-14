#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QUrl>
#include <QtQml/qqmlregistration.h>

class DeviceImport : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit DeviceImport(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static DeviceImport* create(QQmlEngine* qml, QJSEngine*) { return ManagerQmlEngine::Singleton<DeviceImport>(qml); }

    Q_INVOKABLE void Start(const QUrl& archive);

signals:
    void imported(const QString& name, const QString& missing_repository);

private:
    QString MissingRepository(const QString& name) const;
};

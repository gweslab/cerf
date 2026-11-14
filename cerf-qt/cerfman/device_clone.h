#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

class DeviceClone : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit DeviceClone(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static DeviceClone* create(QQmlEngine* qml, QJSEngine*) { return ManagerQmlEngine::Singleton<DeviceClone>(qml); }

    Q_INVOKABLE QVariantMap Start(const QString& name, bool personal, bool link, bool rom, bool storage,
                                  bool saved_state);

signals:
    void cloned(const QString& name);
};

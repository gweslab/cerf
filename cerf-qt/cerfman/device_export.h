#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QUrl>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

class DeviceExport : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit DeviceExport(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static DeviceExport* create(QQmlEngine* qml, QJSEngine*) { return ManagerQmlEngine::Singleton<DeviceExport>(qml); }

    Q_INVOKABLE QUrl        SuggestedTarget(const QString& name) const;
    Q_INVOKABLE void        Discard(const QString& destination) const;
    Q_INVOKABLE QVariantMap Start(const QString& name, const QString& destination, bool personal, bool link, bool rom,
                                  bool storage, bool saved_state);
};

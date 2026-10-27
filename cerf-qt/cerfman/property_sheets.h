#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>
#include "../manager_windows.h"

#include <QObject>
#include <QString>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

#include <optional>

class PropertySheets : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit PropertySheets(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static PropertySheets* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<PropertySheets>(qml);
    }

    Q_INVOKABLE QObject* CreateForDevice(const QString& name, bool running, const QString& initial_page);

    bool EditLive(const QVariantMap& window, const QString& device_dir, bool force_reboot,
                  std::optional<int> ce_major, cerffrontend::GuestReset& reset);
};

#pragma once

#include "device_file_copy.h"
#include "json_file.h"
#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

#include <optional>

struct ReplicaOptions {
    ReplicaOptions(bool keep_personal, bool keep_link, bool copy_rom, bool copy_storage, bool copy_saved_state)
        : personal(keep_personal),
          link(keep_link),
          rom_files(copy_rom),
          storage_files(copy_storage),
          saved_state(copy_saved_state) {}

    bool                   personal;
    bool                   link;
    bool                   rom_files;
    bool                   storage_files;
    bool                   saved_state;
    std::optional<QString> share_base;
    std::optional<QString> display_name;
};

struct DeviceReplicaPlan {
    Json           base;
    Json           user;
    DeviceFileCopy files;
};

class DeviceReplica : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit DeviceReplica(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static DeviceReplica* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<DeviceReplica>(qml);
    }

    Q_INVOKABLE QVariantMap Choices(const QString& name) const;

    DeviceReplicaPlan Plan(const QString& device_dir, const ReplicaOptions& options) const;
    static bool       WriteConfigs(const DeviceReplicaPlan& plan, const QString& dir, QString& error);
};

#pragma once

#include "json_file.h"
#include "manager_qml_engine.h"

#include <cerfcore/core/device_file_types.h>
#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QVariantList>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

#include <optional>
#include <string>
#include <vector>

class DeviceDirectory;

struct FormFile {
    QString id;
    QString name;
    bool    storage = false;
    QString value;
    QString default_value;
};

struct DeviceFileRef {
    enum class Layer { kBase, kUser, kDefault };

    Layer                        layer;
    cerfcore::DeviceFileSection  section;
    std::string                  key;
    std::optional<size_t>        index;
    QString                      value;
    QString                      resolved;
    bool                         present = false;
};

class DeviceFormRules : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit DeviceFormRules(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static DeviceFormRules* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<DeviceFormRules>(qml);
    }

    Q_INVOKABLE QVariantList FileTypes(const QString& board_id) const;
    Q_INVOKABLE QVariantMap  WithDefaults(const QString& board_id, const QVariantMap& files) const;
    Q_INVOKABLE QString      Problem(const QString& board_id, const QVariantMap& files,
                                     const QString& base_dir) const;

    std::vector<QString>       StorageFiles(const QString& device_dir) const;
    std::vector<DeviceFileRef> FileRefs(const DeviceDirectory& device, const Json& base, const Json& user) const;
    std::vector<FormFile>      FormFiles(const QString& board_id, const QVariantMap& files) const;

    static QString MissingFileProblem(const QString& name, const QString& path);
    static QString BlockKey(cerfcore::DeviceFileSection section);

private:
    QString FileProblem(const cerfcore::DeviceFileType& type, const QVariantMap& files,
                        const QString& base_dir) const;
    bool    IsRequired(const cerfcore::DeviceFileType& type, const QVariantMap& files,
                       const QString& base_dir) const;
};

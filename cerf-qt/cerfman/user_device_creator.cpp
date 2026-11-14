#include "user_device_creator.h"

#include "board_config_catalog.h"
#include "bundle_name.h"
#include "device_directory.h"
#include "device_file_copy.h"
#include "device_file_value.h"
#include "device_form_rules.h"
#include "filesystem_path.h"
#include "json_file.h"
#include "local_manifest_store.h"
#include "manager_operations.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/device_config_keys.h>

#include <QDir>

#include <vector>

REGISTER_SERVICE(UserDeviceCreator);

namespace {

namespace cfg = cerfcore::config_key;

struct RomFile {
    QString id;
    QString name;
    QString path;
};

QString ExistingDeviceProblem(const QString& name) {
    if (!EntryExists(PathOf(LocalManifestStore::DevicePath(name)))) return QString();
    return QStringLiteral("%1 already exists.\n\nPick a different name.")
        .arg(QDir::toNativeSeparators(LocalManifestStore::RelativeDevicePath(name)));
}

}

QString UserDeviceCreator::NameProblem(const QString& name) const {
    if (!IsSafeBundleName(name))
        return QStringLiteral("'%1' cannot be used as a device directory name.\n\n%2").arg(name, BundleNameRule());
    return ExistingDeviceProblem(name);
}

QString UserDeviceCreator::SuggestedName(const QString& board_name) const { return SafeBundleNameFrom(board_name); }

void UserDeviceCreator::Start(const QString& name, const QString& board_id, const QVariantMap& files,
                              const QVariantMap& board_config, bool copy) {
    Json       board  = {{cfg::kId, board_id.toStdString()}};
    const Json config = emu_.Get<BoardConfigCatalog>().Diff(board_id, board_config, {});
    if (!config.empty()) board[cfg::kConfig] = config;

    std::vector<RomFile> roms;
    std::vector<QString> storage_names;
    Json                 storage = Json::object();
    for (const FormFile& file : emu_.Get<DeviceFormRules>().FormFiles(board_id, files)) {
        if (file.storage) {
            if (file.value != file.default_value) storage[file.id.toStdString()] = file.value.toStdString();
            if (!cerfcore::IsAbsoluteHostPath(file.value.toStdString())) storage_names.push_back(file.value);
        } else if (!file.value.isEmpty()) {
            roms.push_back({file.id, file.name, ResolveDeviceFileValue(file.value, QDir::currentPath())});
        }
    }

    auto job = [name, board, roms, storage_names, storage, copy](const OperationProgress& progress, QString& error) {
        error = ExistingDeviceProblem(name);
        if (!error.isEmpty()) return OperationResult::kFailed;
        for (const RomFile& rom : roms) {
            error = DeviceFormRules::MissingFileProblem(rom.name, rom.path);
            if (!error.isEmpty()) return OperationResult::kFailed;
        }
        const QString target = LocalManifestStore::DevicePath(name);
        if (!MakeDirectory(target, error)) return OperationResult::kFailed;
        DeviceFileCopy files;
        for (const QString& storage_name : storage_names) files.Reserve(storage_name);
        Json rom_block = Json::object();
        for (const RomFile& rom : roms)
            rom_block[rom.id.toStdString()] =
                (copy ? files.Add(rom.path) : QDir::toNativeSeparators(rom.path)).toStdString();
        OperationResult result = files.Run(target, progress, error);
        if (result == OperationResult::kDone) {
            Json config = {{cfg::kMeta, {{cfg::kName, name.toStdString()}}},
                           {cfg::kRom, rom_block},
                           {cfg::kBoard, board}};
            if (!storage.empty()) config[cfg::kStorage] = storage;
            if (!WriteJsonFile(QDir(target).filePath(DeviceDirectory::UserConfigName()), config, error))
                result = OperationResult::kFailed;
        }
        QString cleanup;
        if (result != OperationResult::kDone && !RemoveEntry(PathOf(target), cleanup)) error += QLatin1Char('\n') + cleanup;
        return result;
    };
    emu_.Get<ManagerOperations>().Run(QStringLiteral("Creating %1…").arg(name), std::move(job),
                                      QStringLiteral("Created %1").arg(name), [this, name](OperationResult result) {
                                          if (result == OperationResult::kDone) emit created(name);
                                      });
}

#include "device_form_rules.h"

#include "device_directory.h"
#include "device_file_value.h"
#include "../qt_file_filters.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/device_config_keys.h>
#include <cerfcore/core/host_file_bytes.h>
#include <cerfcore/platform/host_file.h>

#include <QDir>
#include <QFileInfo>
#include <QStringList>

REGISTER_SERVICE(DeviceFormRules);

namespace {

using cerfcore::DeviceFileSection;
using cerfcore::DeviceFileType;

bool IsStorage(const DeviceFileType& type) { return type.section == DeviceFileSection::kStorage; }

QString BlockOf(const DeviceFileType& type) {
    return QString::fromLatin1(IsStorage(type) ? cerfcore::config_key::kStorage : cerfcore::config_key::kRom);
}

QString EffectiveValue(const DeviceFileType& type, const QString& value) {
    return IsStorage(type) ? DeviceDirectory::StorageFile(value, QString::fromStdString(type.id)) : value;
}

QString DefaultValue(const DeviceFileType& type) { return EffectiveValue(type, QString()); }

QString Value(const QVariantMap& files, const QString& block, const QString& id) {
    return files.value(block).toMap().value(id).toString();
}

bool IsAbsolute(const QString& path) { return cerfcore::IsAbsoluteHostPath(path.toStdString()); }

QString Shown(const QString& path) { return QDir::toNativeSeparators(path); }

QString MissingFolderText(const QString& name, const QString& folder) {
    return QStringLiteral("The folder for the %1 does not exist:\n%2").arg(name, Shown(folder));
}

}

QVariantList DeviceFormRules::FileTypes(const QString& board_id) const {
    QVariantList out;
    for (const DeviceFileType& type :
         emu_.Get<cerfcore::DeviceFileTypes>().ForBoard(board_id.toStdString())) {
        QStringList patterns;
        for (const std::string& format : type.formats)
            patterns.append(QStringLiteral("*.") + QString::fromStdString(format));
        QStringList filters;
        if (!patterns.isEmpty()) filters.append(NameFilter(QString::fromStdString(type.name), patterns));
        filters.append(AllFilesNameFilter());
        out.append(QVariantMap{
            {QStringLiteral("block"), BlockOf(type)},
            {QStringLiteral("id"), QString::fromStdString(type.id)},
            {QStringLiteral("name"), QString::fromStdString(type.name)},
            {QStringLiteral("note"), QString::fromStdString(type.note)},
            {QStringLiteral("storage"), IsStorage(type)},
            {QStringLiteral("nameFilters"), filters},
            {QStringLiteral("defaultSuffix"),
             type.formats.empty() ? QString() : QString::fromStdString(type.formats.front())}});
    }
    return out;
}

QVariantMap DeviceFormRules::WithDefaults(const QString& board_id, const QVariantMap& files) const {
    QVariantMap out = files;
    for (const DeviceFileType& type :
         emu_.Get<cerfcore::DeviceFileTypes>().ForBoard(board_id.toStdString())) {
        const QString block  = BlockOf(type);
        const QString id     = QString::fromStdString(type.id);
        QVariantMap   values = out.value(block).toMap();
        if (!values.contains(id)) values.insert(id, DefaultValue(type));
        out.insert(block, values);
    }
    return out;
}

bool DeviceFormRules::IsRequired(const DeviceFileType& type, const QVariantMap& files,
                                 const QString& base_dir) const {
    if (IsStorage(type) || type.optional) return false;
    for (const std::string& storage_id : type.optional_for_storage_ids) {
        const QString id    = QString::fromStdString(storage_id);
        const QString value = DeviceDirectory::StorageFile(
            Value(files, QString::fromLatin1(cerfcore::config_key::kStorage), id), id);
        const QString path = ResolveDeviceFileValue(value, base_dir);
        if (IsAbsolute(path) && cerfcore::HostFileNonEmpty(path.toStdString())) return false;
    }
    return true;
}

QString DeviceFormRules::FileProblem(const DeviceFileType& type, const QVariantMap& files,
                                     const QString& base_dir) const {
    const QString value = Value(files, BlockOf(type), QString::fromStdString(type.id));
    const QString name  = QString::fromStdString(type.name);
    if (value.isEmpty())
        return IsRequired(type, files, base_dir) ? QStringLiteral("Pick the %1.").arg(name) : QString();
    const QString path = ResolveDeviceFileValue(value, base_dir);
    if (!IsStorage(type) || IsDocumentFileValue(path)) return MissingFileProblem(name, path);
    const QFileInfo info(path);
    if (!IsAbsolute(path)) {
        const QString folder = QFileInfo(value).path();
        if (folder != QLatin1String("."))
            return MissingFolderText(name, folder);
        return QString();
    }
    if (info.isDir()) return QStringLiteral("%1 must be a file, not a folder:\n%2").arg(name, Shown(path));
    if (!QFileInfo(info.path()).isDir())
        return MissingFolderText(name, info.path());
    return QString();
}

QString DeviceFormRules::MissingFileProblem(const QString& name, const QString& path) {
    if (cerfcore::host_platform::HostFileExists(path.toStdString())) return QString();
    return QStringLiteral("%1 not found:\n%2").arg(name, Shown(path));
}

QString DeviceFormRules::Problem(const QString& board_id, const QVariantMap& files,
                                 const QString& base_dir) const {
    if (board_id.isEmpty()) return QStringLiteral("Pick a board.");
    for (const DeviceFileType& type :
         emu_.Get<cerfcore::DeviceFileTypes>().ForBoard(board_id.toStdString())) {
        const QString reason = FileProblem(type, files, base_dir);
        if (!reason.isEmpty()) return reason;
    }
    return QString();
}

std::vector<FormFile> DeviceFormRules::FormFiles(const QString& board_id, const QVariantMap& files) const {
    std::vector<FormFile> out;
    for (const DeviceFileType& type :
         emu_.Get<cerfcore::DeviceFileTypes>().ForBoard(board_id.toStdString())) {
        const QString id    = QString::fromStdString(type.id);
        const QString value = Value(files, BlockOf(type), id);
        out.push_back({id, QString::fromStdString(type.name), IsStorage(type), EffectiveValue(type, value),
                       DefaultValue(type)});
    }
    return out;
}

std::vector<QString> DeviceFormRules::StorageFiles(const QString& device_dir) const {
    const DeviceDirectory device(device_dir);
    FileValues            values = device.ReadFiles().storage;
    for (const DeviceFileType& type :
         emu_.Get<cerfcore::DeviceFileTypes>().ForBoard(device.BoardId().toStdString())) {
        const QString id = QString::fromStdString(type.id);
        if (IsStorage(type)) values.insert(id, EffectiveValue(type, values.value(id)));
    }
    std::vector<QString> out;
    for (const QString& value : values) out.push_back(device.ResolveFile(value));
    return out;
}

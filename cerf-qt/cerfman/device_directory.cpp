#include "device_directory.h"

#include "device_file_value.h"
#include "emulation_speed.h"
#include "property_fields.h"

#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/config_json.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/device_config_keys.h>

#include <QDir>
#include <QFileInfo>

namespace {

namespace cfg = cerfcore::config_key;
namespace pf  = persist_field;

constexpr char kRepositoryUrlKey[]    = "repository_url";
constexpr char kNameOnRepositoryKey[] = "name_on_repository";

Json& SubObject(Json& object, const char* key, Json& scratch) {
    auto it = object.find(key);
    scratch = it != object.end() && it->is_object() ? *it : Json::object();
    return scratch;
}

void StoreSub(Json& object, const char* key, const Json& sub) {
    if (sub.empty()) object.erase(key);
    else             object[key] = sub;
}

void PutOverride(Json& object, const char* block, const QString& key, const QString& value,
                 const QString& base) {
    Json  scratch;
    Json& sub = SubObject(object, block, scratch);
    if (!value.isEmpty() && value != base) sub[key.toStdString()] = value.toStdString();
    else                                   sub.erase(key.toStdString());
    StoreSub(object, block, sub);
}

bool IsPositiveInt(const Json& v) { return v.is_number_integer() && v.get<long long>() > 0; }

Json ExtractPersistFields(const Json& object) {
    Json out = Json::object();
    if (auto net = object.find(cfg::kNetwork); net != object.end() && net->is_object()) {
        if (auto e = net->find(cfg::kEnabled); e != net->end() && e->is_boolean())
            out[pf::kNetworkEnabled] = *e;
    }
    if (auto ga = object.find(cfg::kGuestAdditions); ga != object.end() && ga->is_object()) {
        if (auto v = ga->find(cfg::kEnabled); v != ga->end() && v->is_boolean()) out[pf::kGuestAdditions] = *v;
        if (auto v = ga->find(cfg::kColorScheme);
            v != ga->end() && v->is_string() && !v->get<std::string>().empty())
            out[pf::kColorScheme] = *v;
        if (auto v = ga->find(cfg::kFontSize); v != ga->end() && v->is_number_integer())
            out[pf::kFontSize] = *v;
        if (auto v = ga->find(cfg::kClearType); v != ga->end() && v->is_boolean())
            out[pf::kClearType] = *v;
        if (auto v = ga->find(cfg::kAllowUntrustedApps); v != ga->end() && v->is_boolean())
            out[pf::kAllowUntrustedApps] = *v;
        if (auto v = ga->find(cfg::kShareFolder);
            v != ga->end() && v->is_string() && !v->get<std::string>().empty())
            out[pf::kShareFolder] = *v;
        if (auto v = ga->find(cfg::kShareFolderMountPoint);
            v != ga->end() && v->is_string() && !v->get<std::string>().empty())
            out[pf::kMountPoint] = *v;
    }
    if (auto v = object.find(cfg::kFullScreen); v != object.end() && v->is_boolean())
        out[pf::kFullScreen] = *v;
    if (auto v = object.find(cfg::kDoubleTapHelper); v != object.end() && v->is_boolean())
        out[cfg::kDoubleTapHelper] = *v;
    if (auto v = object.find(cfg::kHud); v != object.end() && v->is_string() && !v->get<std::string>().empty())
        out[pf::kHud] = *v;
    for (const char* name : kMultiplierKeys) {
        if (auto v = object.find(name); v != object.end() && v->is_number()) out[name] = *v;
    }
    if (auto v = object.find(cfg::kCpuConfig); v != object.end() && v->is_object())
        out[pf::kCpuConfig] = *v;
    if (auto board = object.find(cfg::kBoard); board != object.end() && board->is_object()) {
        for (const ScreenFieldKey& screen : kScreenFieldKeys)
            if (auto v = board->find(screen.config_key); v != board->end() && IsPositiveInt(*v))
                out[screen.field] = *v;
    }
    return out;
}

}

QString DeviceDirectory::BaseConfigName() { return QString::fromLatin1(cerfcore::kDeviceConfigFileName); }

QString DeviceDirectory::UserConfigName() { return QString::fromLatin1(cerfcore::kUserConfigFileName); }

QString DeviceDirectory::StorageDefaultFile(const QString& storage_id) {
    return QString::fromStdString(cerfcore::DefaultStorageFileName(storage_id.toStdString()));
}

QString DeviceDirectory::StorageFile(const QString& value, const QString& storage_id) {
    return value.isEmpty() ? StorageDefaultFile(storage_id) : value;
}

QString DeviceDirectory::Name() const { return QFileInfo(path_).fileName(); }

QString DeviceDirectory::FilePath(const QString& name) const {
    return QDir(path_).filePath(name);
}

QString DeviceDirectory::ResolveFile(const QString& value) const { return ResolveDeviceFileValue(value, path_); }

Json DeviceDirectory::LoadBase() const { return LoadJsonObject(FilePath(BaseConfigName())); }

Json DeviceDirectory::LoadUser() const { return LoadJsonObject(FilePath(UserConfigName())); }

ParsedCerfJson DeviceDirectory::ReadMeta() const {
    const Json     base   = LoadBase();
    ParsedCerfJson merged = ParseCerfJson(FillMissingKeys(LoadUser(), base));
    ParsedCerfJson own    = ParseCerfJson(base);
    merged.width          = own.width;
    merged.height         = own.height;
    return merged;
}

std::optional<RepositoryLink> DeviceDirectory::ReadLink() const {
    const Json user = LoadUser();
    const auto it   = user.find(kManagerBlockKey);
    if (it == user.end() || !it->is_object()) return std::nullopt;
    const std::optional<QString> url  = JsonNonEmptyText(*it, kRepositoryUrlKey);
    const std::optional<QString> name = JsonNonEmptyText(*it, kNameOnRepositoryKey);
    if (!url || !name) return std::nullopt;
    return RepositoryLink{*url, *name};
}

FileValues DeviceDirectory::ReadBlock(const char* block, bool with_user) const {
    FileValues values;
    const Json layers[] = {LoadBase(), with_user ? LoadUser() : Json::object()};
    for (const Json& layer : layers) {
        const auto sub = layer.find(block);
        if (sub == layer.end() || !sub->is_object()) continue;
        for (const auto& [key, value] : sub->items())
            if (value.is_string() && !value.get<std::string>().empty())
                values.insert(QString::fromStdString(key), JsonString(value));
    }
    return values;
}

QString DeviceDirectory::RomPrimary() const {
    return ReadBlock(cfg::kRom, true).value(QString::fromLatin1(cfg::kPrimary));
}

QString DeviceDirectory::BoardId() const {
    return ReadBlock(cfg::kBoard, true).value(QString::fromLatin1(cfg::kId));
}

DeviceFiles DeviceDirectory::ReadFiles() const {
    return DeviceFiles{ReadBlock(cfg::kRom, true), ReadBlock(cfg::kStorage, true)};
}

std::pair<Json, Json> DeviceDirectory::ReadPersistFields() const {
    return {ExtractPersistFields(LoadBase()), ExtractPersistFields(LoadUser())};
}

bool DeviceDirectory::UpdateUser(const std::function<void(Json&)>& mutate, QString& error) const {
    std::string message;
    if (cerfcore::CfgUpdateJsonFile(FilePath(UserConfigName()).toStdString(), mutate,
                                    cerfcore::CfgEmptyObject::kRemoveFile, message))
        return true;
    error = QString::fromStdString(message);
    return false;
}

bool DeviceDirectory::WriteLink(const RepositoryLink& link, QString& error) const {
    return UpdateUser(
        [&](Json& object) {
            object[kManagerBlockKey] = Json{{kRepositoryUrlKey, link.repository_url.toStdString()},
                                            {kNameOnRepositoryKey, link.name_on_repository.toStdString()}};
        },
        error);
}

bool DeviceDirectory::WriteUserName(const QString& name, QString& error) const {
    return UpdateUser(
        [&](Json& object) {
            Json  scratch;
            Json& meta = SubObject(object, cfg::kMeta, scratch);
            if (!name.isEmpty()) meta[cfg::kName] = name.toStdString();
            else                 meta.erase(cfg::kName);
            StoreSub(object, cfg::kMeta, meta);
        },
        error);
}

bool DeviceDirectory::WriteBoardFileOverrides(const QString& board_id, const FileValues& rom,
                                              const FileValues& storage, QString& error) const {
    const QString    id_key       = QString::fromLatin1(cfg::kId);
    const QString    base_board   = ReadBlock(cfg::kBoard, false).value(id_key);
    const FileValues base_rom     = ReadBlock(cfg::kRom, false);
    const FileValues base_storage = ReadBlock(cfg::kStorage, false);
    return UpdateUser(
        [&](Json& object) {
            PutOverride(object, cfg::kBoard, id_key, board_id, base_board);
            for (auto it = rom.constBegin(); it != rom.constEnd(); ++it)
                PutOverride(object, cfg::kRom, it.key(), it.value(), base_rom.value(it.key()));
            for (auto it = storage.constBegin(); it != storage.constEnd(); ++it)
                PutOverride(object, cfg::kStorage, it.key(), it.value(),
                            StorageFile(base_storage.value(it.key()), it.key()));
        },
        error);
}

bool DeviceDirectory::WritePersistOverrides(const Json& fields, QString& error) const {
    return UpdateUser(
        [&](Json& object) {
            Json  net_scratch;
            Json& net = SubObject(object, cfg::kNetwork, net_scratch);
            if (fields.contains(pf::kNetworkEnabled)) net[cfg::kEnabled] = fields[pf::kNetworkEnabled];
            else                                      net.erase(cfg::kEnabled);
            StoreSub(object, cfg::kNetwork, net);

            Json  ga_scratch;
            Json& ga = SubObject(object, cfg::kGuestAdditions, ga_scratch);
            for (const char* name : {cfg::kEnabled, cfg::kColorScheme, cfg::kFontSize, cfg::kClearType,
                                     cfg::kAllowUntrustedApps, cfg::kShareFolder, cfg::kShareFolderMountPoint})
                ga.erase(name);
            if (fields.contains(pf::kGuestAdditions)) ga[cfg::kEnabled] = fields[pf::kGuestAdditions];
            if (auto cs = fields.find(pf::kColorScheme); cs != fields.end() && !cs->get<std::string>().empty())
                ga[cfg::kColorScheme] = *cs;
            if (fields.contains(pf::kFontSize)) ga[cfg::kFontSize] = fields[pf::kFontSize];
            if (fields.contains(pf::kClearType)) ga[cfg::kClearType] = fields[pf::kClearType];
            if (auto v = fields.find(pf::kAllowUntrustedApps); v != fields.end() && v->get<bool>())
                ga[cfg::kAllowUntrustedApps] = true;
            if (auto v = fields.find(pf::kShareFolder); v != fields.end() && !v->get<std::string>().empty())
                ga[cfg::kShareFolder] = *v;
            if (auto v = fields.find(pf::kMountPoint); v != fields.end() && !v->get<std::string>().empty())
                ga[cfg::kShareFolderMountPoint] = *v;
            StoreSub(object, cfg::kGuestAdditions, ga);

            if (fields.contains(pf::kFullScreen)) object[cfg::kFullScreen] = fields[pf::kFullScreen];
            else                                  object.erase(cfg::kFullScreen);
            if (fields.contains(cfg::kDoubleTapHelper)) object[cfg::kDoubleTapHelper] = fields[cfg::kDoubleTapHelper];
            else                                        object.erase(cfg::kDoubleTapHelper);
            if (fields.contains(pf::kHud)) object[cfg::kHud] = fields[pf::kHud];
            else                           object.erase(cfg::kHud);
            for (const char* name : kMultiplierKeys) {
                if (fields.contains(name)) object[name] = fields[name];
                else                       object.erase(name);
            }
            if (auto cpu = fields.find(pf::kCpuConfig); cpu != fields.end() && !cpu->empty())
                object[cfg::kCpuConfig] = *cpu;
            else
                object.erase(cfg::kCpuConfig);

            Json  board_scratch;
            Json& board = SubObject(object, cfg::kBoard, board_scratch);
            for (const ScreenFieldKey& screen : kScreenFieldKeys) {
                if (fields.contains(screen.field)) board[screen.config_key] = fields[screen.field];
                else                               board.erase(screen.config_key);
            }
            StoreSub(object, cfg::kBoard, board);
        },
        error);
}

#include "device_replica.h"

#include "byte_size_text.h"
#include "device_directory.h"
#include "device_form_rules.h"
#include "device_run_state.h"
#include "local_manifest_store.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/device_config_keys.h>
#include <cerfcore/platform/host_file.h>

#include <QDir>

#include <vector>

REGISTER_SERVICE(DeviceReplica);

namespace {

namespace cfg = cerfcore::config_key;

using cerfcore::DeviceFileSection;

Json Whitelisted(const Json& user) {
    Json out = Json::object();
    for (const char* key : {cfg::kMeta, cfg::kRom, cfg::kStorage})
        if (const auto it = user.find(key); it != user.end()) out[key] = *it;
    if (const auto board = user.find(cfg::kBoard); board != user.end() && board->is_object())
        if (const auto id = board->find(cfg::kId); id != board->end()) out[cfg::kBoard] = Json{{cfg::kId, *id}};
    return out;
}

Json& ObjectAt(Json& parent, const std::string& key) {
    Json& slot = parent[key];
    if (!slot.is_object()) slot = Json::object();
    return slot;
}

bool Relative(const QString& value) { return !cerfcore::IsAbsoluteHostPath(value.toStdString()); }

QString RelativeTo(const QString& dir, const QString& path) {
    return QDir::toNativeSeparators(QDir(dir).relativeFilePath(QDir::fromNativeSeparators(path)));
}

void AddSavedState(const DeviceDirectory& device, DeviceFileCopy& files) {
    for (const QString& name : DeviceDirectory::SavedStateNames()) {
        const QString path = device.FilePath(name);
        if (cerfcore::host_platform::HostFileExists(path.toStdString())) files.AddAs(path, name);
    }
}

void Put(DeviceReplicaPlan& plan, const DeviceFileRef& ref, const QString& value) {
    const std::string block = DeviceFormRules::BlockKey(ref.section).toStdString();
    if (ref.layer == DeviceFileRef::Layer::kDefault) {
        if (value != ref.value) ObjectAt(plan.user, block)[ref.key] = value.toStdString();
        return;
    }
    Json& slot = (ref.layer == DeviceFileRef::Layer::kBase ? plan.base : plan.user)[block][ref.key];
    (ref.index ? slot[*ref.index] : slot) = value.toStdString();
}

}

QVariantMap DeviceReplica::Choices(const QString& name) const {
    const DeviceDirectory device(LocalManifestStore::DevicePath(name));
    DeviceFileCopy        rom;
    DeviceFileCopy        storage;
    DeviceFileCopy        state;
    for (const DeviceFileRef& ref : emu_.Get<DeviceFormRules>().FileRefs(device, device.LoadBase(), device.LoadUser()))
        if (ref.present) (ref.section == DeviceFileSection::kRom ? rom : storage).Add(ref.resolved);
    const bool saved = ReadSavedState(device.Path()).has_value();
    if (saved) AddSavedState(device, state);
    return QVariantMap{{QStringLiteral("link"), device.ReadLink().has_value()},
                       {QStringLiteral("rom"), !rom.Files().empty()},
                       {QStringLiteral("storage"), !storage.Files().empty()},
                       {QStringLiteral("state"), saved},
                       {QStringLiteral("romSize"), FormatSize(rom.Bytes())},
                       {QStringLiteral("storageSize"), FormatSize(storage.Bytes())},
                       {QStringLiteral("stateSize"), FormatSize(state.Bytes())}};
}

DeviceReplicaPlan DeviceReplica::Plan(const QString& device_dir, const ReplicaOptions& options) const {
    const DeviceDirectory device(device_dir);
    const Json            base = device.LoadBase();
    const Json            user = device.LoadUser();
    DeviceReplicaPlan     plan{base, options.personal ? user : Whitelisted(user), DeviceFileCopy()};
    plan.user.erase(kManagerBlockKey);
    if (const auto link = user.find(kManagerBlockKey); options.link && link != user.end())
        plan.user[kManagerBlockKey] = *link;
    if (options.display_name) ObjectAt(plan.user, cfg::kMeta)[cfg::kName] = options.display_name->toStdString();

    const std::vector<DeviceFileRef>  refs = emu_.Get<DeviceFormRules>().FileRefs(device, base, user);
    std::vector<const DeviceFileRef*> copied;
    for (const DeviceFileRef& ref : refs) {
        const bool rom = ref.section == DeviceFileSection::kRom;
        if ((rom ? options.rom_files : options.storage_files) && ref.present)
            copied.push_back(&ref);
        else if (options.share_base && ref.present && Relative(ref.value))
            Put(plan, ref, RelativeTo(*options.share_base, ref.resolved));
        else if (Relative(ref.value))
            plan.files.Reserve(ref.value);
    }
    for (const DeviceFileRef* ref : copied) Put(plan, *ref, plan.files.Add(ref->resolved));
    if (options.saved_state) AddSavedState(device, plan.files);
    return plan;
}

bool DeviceReplica::WriteConfigs(const DeviceReplicaPlan& plan, const QString& dir, QString& error) {
    if (!WriteJsonFile(QDir(dir).filePath(DeviceDirectory::BaseConfigName()), plan.base, error)) return false;
    return plan.user.empty() || WriteJsonFile(QDir(dir).filePath(DeviceDirectory::UserConfigName()), plan.user, error);
}

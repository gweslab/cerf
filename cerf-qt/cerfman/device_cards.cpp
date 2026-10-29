#include "device_cards.h"

#include "../device_status_files.h"
#include "board_catalog.h"
#include "bundle_catalog.h"
#include "device_inventory.h"
#include "byte_size_text.h"
#include "device_run_state.h"
#include "device_texts.h"
#include "local_manifest_store.h"
#include "manager_operations.h"
#include "starting_devices.h"
#include "text_compare.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/state/state_image_format.h>

#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QSize>
#include <QUrl>
#include <QVariantList>

#include <utility>

REGISTER_SERVICE(DeviceCards);

namespace {

constexpr char kRunningState[] = "running";
constexpr char kSavedState[]   = "saved";
constexpr char kOffState[]     = "off";

QString RunStateName(RunStateKind kind) {
    switch (kind) {
        case RunStateKind::kRunning: return QString::fromLatin1(kRunningState);
        case RunStateKind::kSaved:   return QString::fromLatin1(kSavedState);
        case RunStateKind::kOff:     break;
    }
    return QString::fromLatin1(kOffState);
}

QString CardStatus(const RunState& state) {
    if (state.kind == RunStateKind::kRunning) return QStringLiteral("Running");
    if (state.saved) {
        const QString when  = QDateTime::fromMSecsSinceEpoch(state.saved->saved_at_msecs).toString(
            QStringLiteral("dd.MM HH:mm"));
        const QString size = FormatSize(state.saved->size);
        return size.isEmpty() ? QStringLiteral("Saved %1").arg(when) : QStringLiteral("Saved %1 · %2").arg(when, size);
    }
    return QStringLiteral("Powered off");
}

QString PreviewUrl(const QString& device_path, const RunState& state) {
    const char* name = state.kind == RunStateKind::kRunning ? cerffrontend::kLiveScreenshotFileName
                       : state.kind == RunStateKind::kSaved ? cerfcore::kSavedStateScreenshotFile
                                                            : nullptr;
    if (name == nullptr) return QString();
    const QFileInfo info(QDir(device_path).filePath(QString::fromLatin1(name)));
    if (!info.isFile()) return QString();
    QUrl url = QUrl::fromLocalFile(info.absoluteFilePath());
    url.setQuery(QString::number(info.lastModified().toMSecsSinceEpoch()));
    return url.toString();
}

}

QVariantMap DeviceCards::Rows(const QString& query) const {
    auto&                     texts   = emu_.Get<DeviceTexts>();
    std::vector<DeviceBundle> devices = emu_.Get<DeviceInventory>().List();
    texts.SortForCards(devices);

    std::vector<DeviceBundle> shown;
    int                       installed = 0;
    int                       updates   = 0;
    for (DeviceBundle& device : devices) {
        if (device.HasAnyUpdate()) ++updates;
        if (!device.IsInstalled()) continue;
        ++installed;
        if (MatchesQuery(texts.SearchFields(device), query)) shown.push_back(std::move(device));
    }

    auto&        starting_devices = emu_.Get<StartingDevices>();
    auto&        boards           = emu_.Get<BoardCatalog>();
    QVariantList out;
    for (const DeviceBundle& device : shown) {
        const QString  path     = LocalManifestStore::DevicePath(device.name);
        const RunState state    = ReadRunState(path);
        const bool     starting = state.kind != RunStateKind::kRunning && starting_devices.Pending(device.name);
        const bool     running  = starting || state.kind == RunStateKind::kRunning;
        out.append(QVariantMap{
            {QStringLiteral("key"), device.name},
            {QStringLiteral("name"), device.name},
            {QStringLiteral("deviceName"), device.DeviceName()},
            {QStringLiteral("board"), texts.GroupName(device)},
            {QStringLiteral("title"), texts.CardTitle(device)},
            {QStringLiteral("subtitle"), texts.CardSubtitle(device)},
            {QStringLiteral("detail"), texts.PanelDetail(device)},
            {QStringLiteral("arch"), boards.ArchName(device.meta.board_id)},
            {QStringLiteral("status"), starting ? QStringLiteral("Started") : CardStatus(state)},
            {QStringLiteral("state"), RunStateName(running ? RunStateKind::kRunning : state.kind)},
            {QStringLiteral("launchLabel"), running ? QStringLiteral("Show") : QStringLiteral("Run")},
            {QStringLiteral("saved"), !running && state.kind == RunStateKind::kSaved},
            {QStringLiteral("removable"), !running},
            {QStringLiteral("preview"), PreviewUrl(path, state)},
            {QStringLiteral("updatable"), device.Updatable()},
        });
    }
    const bool hide_updates = emu_.Get<BundleCatalog>().Loading() || emu_.Get<ManagerOperations>().Busy();
    return QVariantMap{{QStringLiteral("rows"), out},
                       {QStringLiteral("installed"), installed},
                       {QStringLiteral("bundleUpdates"), hide_updates ? 0 : updates}};
}

QString DeviceCards::UpdateRomsLabel(int count) const {
    return count == 1 ? QStringLiteral("Update 1 ROM") : QStringLiteral("Update %1 ROMs").arg(count);
}

QString DeviceCards::RunningState() const { return QString::fromLatin1(kRunningState); }

QString DeviceCards::SavedState() const { return QString::fromLatin1(kSavedState); }

QString DeviceCards::OffState() const { return QString::fromLatin1(kOffState); }

QVariantMap DeviceCards::Details(const QString& name) const {
    const auto details = [](const QString& device_name, const QString& description, const QVariantMap& source,
                            const QVariantList& unsupported, const QString& notes, const QVariantList& packages) {
        return QVariantMap{{QStringLiteral("name"), device_name},
                           {QStringLiteral("description"), description},
                           {QStringLiteral("source"), source},
                           {QStringLiteral("unsupportedFeatures"), unsupported},
                           {QStringLiteral("notes"), notes},
                           {QStringLiteral("packages"), packages}};
    };
    const auto source_of = [](const QString& caption, const QString& source_name, const QString& url) {
        return QVariantMap{{QStringLiteral("caption"), caption},
                           {QStringLiteral("name"), source_name},
                           {QStringLiteral("url"), url}};
    };
    const std::optional<DeviceBundle> found = emu_.Get<DeviceInventory>().Find(name);
    if (!found || !found->IsInstalled())
        return details(QString(), QString(), source_of(QString(), QString(), QString()), {}, {}, {});
    const DeviceBundle& device = *found;
    auto&               boards = emu_.Get<BoardCatalog>();

    QVariantMap source = source_of(QString(), QString(), QString());
    if (device.meta.source) {
        const DeviceSource& src = *device.meta.source;
        source = source_of(src.is_community_member ? QStringLiteral("Contributed by:") : QStringLiteral("Source:"),
                           src.name, !src.website.isEmpty() ? src.website : src.origin);
    }

    QVariantList unsupported_features;
    for (const cerfcore::DbDeviceFeature* feature : boards.UnsupportedFeatures(device.meta.board_id))
        unsupported_features.append(QVariantMap{
            {QStringLiteral("icon"), QString::fromStdString(feature->icon)},
            {QStringLiteral("tip"), QStringLiteral("CERF does not support this feature: %1")
                                        .arg(QString::fromStdString(feature->name))}});

    const QStringList note_lines = device.meta.notes + boards.Notes(device.meta.board_id);
    const QString     notes =
        note_lines.isEmpty() ? QString() : QStringLiteral("• ") + note_lines.join(QStringLiteral("\n• "));

    QVariantList packages;
    for (const PackageStatus& package : device.packages) {
        packages.append(QVariantMap{
            {QStringLiteral("category"), package.remote.category},
            {QStringLiteral("categoryLabel"), PackageCategoryLabel(package.remote.category)},
            {QStringLiteral("key"), package.remote.key},
            {QStringLiteral("name"), package.remote.name},
            {QStringLiteral("installs"), package.HasUpdate() || !package.installed},
            {QStringLiteral("actionLabel"), package.HasUpdate()  ? QStringLiteral("Update")
                                            : package.installed ? QStringLiteral("Delete")
                                                                : QStringLiteral("Get")}});
    }

    return details(device.name, device.meta.description.trimmed(), source, unsupported_features, notes, packages);
}

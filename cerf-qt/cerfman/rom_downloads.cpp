#include "rom_downloads.h"

#include "board_catalog.h"
#include "bundle_catalog.h"
#include "bundle_installer.h"
#include "bundle_repositories.h"
#include "device_actions.h"
#include "device_inventory.h"
#include "byte_size_text.h"
#include "device_texts.h"
#include "flow_reply.h"
#include "manager_operations.h"
#include "remote_manifest.h"
#include "text_compare.h"

#include <cerfcore/core/cerf_emulator.h>
#include "../product_links.h"

#include <QMap>
#include <QSet>

#include <algorithm>

REGISTER_SERVICE(RomDownloads);

namespace {

std::optional<int> PlaceOf(const DownloadPlaces& places, const DeviceBundle& device) {
    const auto it = places.constFind(qMakePair(device.remote->repo_url, device.remote->name));
    if (it == places.constEnd()) return std::nullopt;
    return *it;
}

QVariantMap RunningNotice(const QStringList& names) {
    if (names.size() == 1)
        return FlowMessage(QStringLiteral("Device is running"),
                           QStringLiteral("%1 was not updated because its ROM is running. Close it and try again.")
                               .arg(names.front()));
    return FlowMessage(QStringLiteral("Devices are running"),
                       QStringLiteral("These devices were not updated because their ROM is running:\n• %1")
                           .arg(names.join(QStringLiteral("\n• "))));
}

}

QString RomDownloads::RepositoriesUrl() const {
    return QString::fromUtf8(cerffrontend::kBundleRepositoriesUrl.text);
}

std::vector<DeviceBundle> RomDownloads::Candidates() const {
    auto&                     texts = emu_.Get<DeviceTexts>();
    std::vector<DeviceBundle> out;
    for (DeviceBundle& device : emu_.Get<DeviceInventory>().List())
        if (device.remote && !device.IsInstalled()) out.push_back(std::move(device));
    std::stable_sort(out.begin(), out.end(), [&texts](const DeviceBundle& a, const DeviceBundle& b) {
        return std::make_tuple(texts.DeviceGroupKey(a), texts.DeviceSortKey(a)) <
               std::make_tuple(texts.DeviceGroupKey(b), texts.DeviceSortKey(b));
    });
    return out;
}

QVariantMap RomDownloads::Catalog(bool hide_unsupported, const QString& query, bool by_downloads) const {
    auto&                         texts  = emu_.Get<DeviceTexts>();
    auto&                         boards = emu_.Get<BoardCatalog>();
    const std::optional<DownloadPlaces>& places = emu_.Get<BundleCatalog>().Places();

    std::vector<DeviceBundle> visible;
    for (DeviceBundle& device : Candidates()) {
        if (hide_unsupported && !boards.Runs(device.meta.board_id)) continue;
        if (!MatchesQuery(texts.SearchFields(device), query)) continue;
        visible.push_back(std::move(device));
    }
    if (by_downloads && places) {
        QMap<QString, int> group_rank;
        for (const DeviceBundle& device : visible) {
            const std::optional<int> place = PlaceOf(*places, device);
            const QString            group = texts.GroupName(device);
            if (place && (!group_rank.contains(group) || *place < group_rank.value(group)))
                group_rank.insert(group, *place);
        }
        const auto key = [&](const DeviceBundle& device) {
            const QString            group = texts.GroupName(device);
            const bool               ranked = group_rank.contains(group);
            const std::optional<int> place  = PlaceOf(*places, device);
            return std::make_tuple(!ranked, ranked ? group_rank.value(group) : 0, texts.DeviceGroupKey(device),
                                   !place.has_value(), place.value_or(0), texts.DeviceSortKey(device));
        };
        std::stable_sort(visible.begin(), visible.end(),
                         [&](const DeviceBundle& a, const DeviceBundle& b) { return key(a) < key(b); });
    }

    std::vector<std::pair<QString, QVariantList>> grouped;
    QMap<QString, size_t>                         group_index;
    for (const DeviceBundle& device : visible) {
        const QString name = texts.GroupName(device);
        if (!group_index.contains(name)) {
            group_index.insert(name, grouped.size());
            grouped.emplace_back(texts.DeviceLabel(device), QVariantList());
        }
        const QString soc  = boards.SocLabel(device.meta.board_id);
        const QString size = FormatSize(device.remote->archive_size);
        QStringList   detail{soc, size};
        detail.removeAll(QString());
        grouped[group_index.value(name)].second.append(
            QVariantMap{{QStringLiteral("key"), device.key},
                        {QStringLiteral("os"), texts.OsLabel(device)},
                        {QStringLiteral("soc"), soc},
                        {QStringLiteral("size"), size},
                        {QStringLiteral("detail"), detail.join(QStringLiteral(" · "))},
                        {QStringLiteral("notes"), device.meta.os_notes}});
    }
    QVariantList groups;
    for (const auto& [label, rows] : grouped)
        groups.append(QVariantMap{{QStringLiteral("label"), label}, {QStringLiteral("rows"), rows}});
    bool any_enabled = false;
    for (const BundleRepository& repo : emu_.Get<BundleRepositories>().Read()) any_enabled = any_enabled || repo.enabled;
    return QVariantMap{{QStringLiteral("groups"), groups},
                       {QStringLiteral("sortable"), places.has_value()},
                       {QStringLiteral("noSources"), !any_enabled}};
}

QString RomDownloads::Summary(const QStringList& keys) const {
    if (keys.isEmpty()) return QStringLiteral("Nothing selected");
    const QSet<QString> wanted(keys.begin(), keys.end());
    qint64              total = 0;
    for (const DeviceBundle& device : Candidates())
        if (wanted.contains(device.key)) total += device.remote->archive_size.value_or(0);
    const QString size = FormatSize(total);
    if (size.isEmpty()) return QStringLiteral("%1 selected").arg(keys.size());
    return QStringLiteral("%1 selected · %2").arg(QString::number(keys.size()), size);
}

QString RomDownloads::CopyrightRemovalTitle() const { return QStringLiteral("Copyright removal"); }

QString RomDownloads::CopyrightText() const {
    const std::vector<BundleCatalog::AbuseContact> contacts = emu_.Get<BundleCatalog>().AbuseContacts();
    if (contacts.empty())
        return QStringLiteral("The ROM bundle providers you added to your launcher have provided the following emails "
                              "to contact them:\n\nNo bundle repositories are configured.");
    QStringList lines;
    bool        missing = false;
    for (const auto& [url, email] : contacts) {
        lines.append(QStringLiteral("%1  %2").arg(url, email.value_or(QStringLiteral("-"))));
        missing = missing || !email;
    }
    QString text = QStringLiteral("The ROM bundle providers you added to your launcher have provided the following "
                                  "emails to contact them:\n\n%1")
                       .arg(lines.join(QLatin1Char('\n')));
    if (missing) text += QStringLiteral("\n\n- marks a repository that publishes no removal contact.");
    return text;
}

QVariantList RomDownloads::Thanks(const std::vector<const DeviceBundle*>& devices) const {
    QVariantList  out;
    QSet<QString> seen;
    for (const DeviceBundle* device : devices) {
        if (!device->meta.source) continue;
        const DeviceSource& source = *device->meta.source;
        if (source.website.isEmpty() || source.donate.isEmpty() || seen.contains(source.name)) continue;
        seen.insert(source.name);
        out.append(QVariantMap{
            {QStringLiteral("credit"),
             source.is_community_member
                 ? QStringLiteral("This ROM bundle was contributed by %1.").arg(source.name)
                 : QStringLiteral("This ROM bundle was preserved and provided by %1.").arg(source.name)},
            {QStringLiteral("website"), source.website},
            {QStringLiteral("donate"), source.donate}});
    }
    return out;
}

QVariantMap RomDownloads::Plan(const QStringList& keys) const {
    const std::vector<DeviceBundle>  candidates = Candidates();
    std::vector<const DeviceBundle*> targets;
    QStringList                      target_keys;
    QStringList                      skipped;
    for (const QString& key : keys) {
        const auto found = std::find_if(candidates.begin(), candidates.end(),
                                        [&key](const DeviceBundle& device) { return device.key == key; });
        if (found == candidates.end()) {
            const std::optional<DeviceBundle> device = emu_.Get<DeviceInventory>().FindByRemote(key);
            skipped.append(device ? device->DeviceName() : key);
            continue;
        }
        targets.push_back(&*found);
        target_keys.append(key);
    }
    QVariantMap plan = ThanksPlan(targets);
    if (!skipped.isEmpty()) {
        const QString message = QStringLiteral("These ROMs are installed or no longer offered:\n• %1")
                                    .arg(skipped.join(QStringLiteral("\n• ")));
        plan.insert(QStringLiteral("skipped"), FlowMessage(QStringLiteral("Not downloaded"), message));
    }
    if (!targets.empty()) plan.insert(QStringLiteral("keys"), target_keys);
    return plan;
}

QVariantMap RomDownloads::ThanksPlan(const std::vector<const DeviceBundle*>& devices) const {
    return QVariantMap{{QStringLiteral("thanks"), Thanks(devices)}};
}

void RomDownloads::Start(const QStringList& keys) {
    auto&                                 installer = emu_.Get<BundleInstaller>();
    std::vector<ManagerOperations::Step> steps;
    for (const QString& key : keys) {
        const DeviceBundle device = *emu_.Get<DeviceInventory>().Find(key);
        steps.push_back({device.name, installer.Install(*device.remote, std::nullopt)});
    }
    emu_.Get<ManagerOperations>().RunSequence(std::move(steps));
}

QVariantMap RomDownloads::DevicePlan(const QString& name) const {
    const std::optional<DeviceBundle> device = emu_.Get<DeviceInventory>().Find(name);
    if (!device) return FlowError(QStringLiteral("Update"), QStringLiteral("%1 was not found.").arg(name));
    if (emu_.Get<DeviceActions>().Running(name)) return FlowError(RunningNotice({device->DeviceName()}));
    if (device->HasUpdate()) {
        QVariantMap plan = ThanksPlan({&*device});
        plan.insert(QStringLiteral("download"), true);
        return plan;
    }
    if (device->cerf_json_pending) return QVariantMap{{QStringLiteral("download"), false}};
    return FlowError(QStringLiteral("Update"), QStringLiteral("%1 is up to date.").arg(device->DeviceName()));
}

void RomDownloads::UpdateDevice(const QString& name, bool download) {
    const DeviceBundle device     = *emu_.Get<DeviceInventory>().Find(name);
    auto&              operations = emu_.Get<ManagerOperations>();
    auto&              installer  = emu_.Get<BundleInstaller>();
    if (download) {
        operations.Run(QStringLiteral("Downloading %1…").arg(name), installer.Install(*device.remote, device.name),
                       QStringLiteral("Downloaded %1").arg(name));
        return;
    }
    operations.Run(QStringLiteral("Updating %1 config…").arg(name),
                   installer.RefreshCerfJson(name, *device.remote->cerf_json),
                   QStringLiteral("Updated %1 config").arg(name));
}

QVariantMap RomDownloads::PackagePlan(const QString& name, const QString& category, const QString& key) const {
    const std::optional<DeviceBundle> device = emu_.Get<DeviceInventory>().Find(name);
    if (!device)
        return FlowError(QStringLiteral("Cannot download package"), QStringLiteral("%1 was not found.").arg(name));
    if (device->FindPackage(category, key) == nullptr)
        return FlowError(QStringLiteral("Cannot download package"),
                         QStringLiteral("%1 no longer offers this package.").arg(device->DeviceName()));
    const QString problem = BundleInstaller::PackageTargetProblem(name);
    if (!problem.isEmpty()) return FlowError(QStringLiteral("Cannot download package"), problem);
    return ThanksPlan({&*device});
}

void RomDownloads::InstallPackage(const QString& name, const QString& category, const QString& key) {
    const RemotePackage package = emu_.Get<DeviceInventory>().FindPackage(name, category, key)->remote;
    emu_.Get<ManagerOperations>().Run(QStringLiteral("Downloading %1…").arg(package.name),
                                      emu_.Get<BundleInstaller>().InstallPackage(name, package),
                                      QStringLiteral("Installed %1 for %2").arg(package.name, name));
}

void RomDownloads::DeletePackage(const QString& name, const QString& category, const QString& key) {
    const std::optional<PackageStatus> status = emu_.Get<DeviceInventory>().FindPackage(name, category, key);
    const QString                      label  = status ? status->remote.name : key;
    emu_.Get<ManagerOperations>().RunDeletion(label, emu_.Get<BundleInstaller>().DeletePackage(name, category, key));
}

RomDownloads::UpdateSelection RomDownloads::SelectUpdates() const {
    auto&           actions = emu_.Get<DeviceActions>();
    UpdateSelection out{emu_.Get<DeviceInventory>().List(), {}, {}};
    for (size_t index = 0; index < out.devices.size(); ++index) {
        const DeviceBundle& device = out.devices[index];
        if (device.IsInstalled() && actions.Running(device.name)) {
            if (device.HasAnyUpdate()) out.running.append(device.DeviceName());
            continue;
        }
        if (device.HasUpdate()) out.items.push_back({UpdateItem::Kind::kRom, index, 0});
        for (size_t package = 0; package < device.packages.size(); ++package)
            if (device.packages[package].HasUpdate()) out.items.push_back({UpdateItem::Kind::kPackage, index, package});
        if (device.cerf_json_pending) out.items.push_back({UpdateItem::Kind::kConfig, index, 0});
    }
    return out;
}

QVariantMap RomDownloads::UpdateAllPlan() const {
    const UpdateSelection selection = SelectUpdates();
    QVariantMap           out;
    if (!selection.running.isEmpty()) out.insert(QStringLiteral("skipped"), RunningNotice(selection.running));
    out.insert(QStringLiteral("nothing"), selection.items.empty());
    out.insert(QStringLiteral("upToDate"), FlowMessage(QStringLiteral("Update all"),
                                                       QStringLiteral("All installed bundles and packages are up to date.")));
    return out;
}

void RomDownloads::UpdateAll() {
    auto&           installer = emu_.Get<BundleInstaller>();
    UpdateSelection selection = SelectUpdates();
    std::stable_sort(selection.items.begin(), selection.items.end(),
                     [](const UpdateItem& a, const UpdateItem& b) { return a.kind < b.kind; });
    std::vector<ManagerOperations::Step> steps;
    for (const UpdateItem& item : selection.items) {
        const DeviceBundle& device = selection.devices[item.device];
        switch (item.kind) {
        case UpdateItem::Kind::kRom:
            steps.push_back({device.name, installer.Install(*device.remote, device.name)});
            break;
        case UpdateItem::Kind::kPackage: {
            const RemotePackage& package = device.packages[item.package].remote;
            steps.push_back({QStringLiteral("%1: %2").arg(device.name, package.name),
                             installer.InstallPackage(device.name, package)});
            break;
        }
        case UpdateItem::Kind::kConfig:
            steps.push_back({QStringLiteral("%1 config").arg(device.name),
                             installer.RefreshCerfJson(device.name, *device.remote->cerf_json)});
            break;
        }
    }
    emu_.Get<ManagerOperations>().RunSequence(std::move(steps));
}

#include "remote_manifest.h"

#include "bundle_manifest_keys.h"
#include "bundle_name.h"
#include "bundle_repositories.h"
#include "package_identity.h"

#include <cerfcore/core/config_json.h>
#include <cerfcore/core/device_config_keys.h>

#include <QDateTime>
#include <QUrl>

namespace {

namespace mk = manifest_key;

constexpr char kPerRomKey[]    = "per_rom";
constexpr char kRomNameKey[]   = "name";
constexpr char kPlaceKey[]     = "place";
constexpr char kVersionQuery[] = "v";

QString Repr(const Json& value) {
    if (value.is_string()) return QStringLiteral("'%1'").arg(JsonString(value));
    return QString::fromStdString(value.dump());
}

QString ResolveUrl(const QString& base, const QString& path) {
    return QUrl(base).resolved(QUrl(path)).toString(QUrl::FullyEncoded);
}

bool ParsePackages(const QString& bundle, const Json* raw, const QString& manifest_url,
                   std::vector<RemotePackage>& out, QString& error) {
    if (raw == nullptr || raw->is_null()) return true;
    if (!raw->is_object()) {
        error = QStringLiteral("bundle %1: '%2' must be an object").arg(bundle, QLatin1String(mk::kAdditionalPackages));
        return false;
    }
    for (const auto& [category_key, entries] : raw->items()) {
        const QString category = QString::fromStdString(category_key);
        if (category.trimmed().isEmpty()) {
            error = QStringLiteral("bundle %1: malformed package category").arg(bundle);
            return false;
        }
        if (!entries.is_array()) {
            error = QStringLiteral("bundle %1: '%2' must be a list")
                        .arg(bundle, QString::fromStdString(cerfcore::CfgKeyPath({mk::kAdditionalPackages, category_key})));
            return false;
        }
        for (const Json& item : entries) {
            if (!item.is_object()) {
                error = QStringLiteral("bundle %1: malformed package entry in %2").arg(bundle, category);
                return false;
            }
            const std::optional<QString> file      = JsonOptionalText(item, mk::kFile);
            const std::optional<QString> directory = JsonOptionalText(item, mk::kDirectory);
            RemotePackage                package;
            if (file && !directory) {
                package.key = *file;
            } else if (directory && !file) {
                package.key          = *directory;
                package.is_directory = true;
            } else {
                error = QStringLiteral("bundle %1: package in %2 needs exactly one of '%3' and '%4'")
                            .arg(bundle, category, QLatin1String(mk::kFile), QLatin1String(mk::kDirectory));
                return false;
            }
            if (!IsSafeBundleName(package.key)) {
                error = QStringLiteral("bundle %1: unsafe package artifact name: '%2'").arg(bundle, package.key);
                return false;
            }
            package.archive_path = JsonText(item, mk::kArchivePath);
            if (package.archive_path.isEmpty()) {
                error = QStringLiteral("bundle %1: package %2/%3: '%4' is missing")
                            .arg(bundle, category, package.key, QLatin1String(mk::kArchivePath));
                return false;
            }
            const QString display  = JsonText(item, mk::kName);
            package.category       = category;
            package.name           = display.isEmpty() ? package.key : display;
            package.manifest_url   = manifest_url;
            package.archive_sha256 = JsonNonEmptyText(item, mk::kArchiveSha256);
            package.archive_size   = JsonInteger(item, mk::kArchiveSize);
            package.unpacked_size  = JsonInteger(item, mk::kUnpackedSize);
            out.push_back(std::move(package));
        }
    }
    return true;
}

}

QString RemotePackage::ArchiveUrl() const {
    const QString base = ResolveUrl(manifest_url, archive_path);
    return archive_sha256 ? AppendQuery(base, QString::fromLatin1(kVersionQuery), *archive_sha256) : base;
}

QString RemoteBundle::ArchiveUrl() const {
    return AppendQuery(ResolveUrl(manifest_url, archive_path), QString::fromLatin1(kVersionQuery), updated_at);
}

const RemotePackage* RemoteBundle::FindPackage(const QString& category, const QString& key) const {
    for (const RemotePackage& package : packages)
        if (IsPackage(package, category, key)) return &package;
    return nullptr;
}

QString AppendQuery(const QString& url, const QString& key, const QString& value) {
    const QChar sep = url.contains(QLatin1Char('?')) ? QLatin1Char('&') : QLatin1Char('?');
    return url + sep + key + QLatin1Char('=') + QString::fromLatin1(QUrl::toPercentEncoding(value));
}

QString CacheBustedUrl(const QUrl& url) {
    return AppendQuery(url.toString(QUrl::FullyEncoded), QStringLiteral("cb"),
                       QString::number(QDateTime::currentSecsSinceEpoch()));
}

QString PackageCategoryLabel(const QString& category) {
    if (category == QLatin1String("pdbs")) return QStringLiteral("PDBs");
    if (category == QLatin1String(cerfcore::config_key::kCompactFlashCards)) return QStringLiteral("Compact Flash Cards");
    if (category == QLatin1String(cerfcore::config_key::kSdCards)) return QStringLiteral("SD Cards");
    if (category == QLatin1String(cerfcore::config_key::kUsbDisks)) return QStringLiteral("USB Disks");
    return category;
}

bool ParseRemoteManifest(const QByteArray& body, const QString& repo_url, const QString& manifest_url,
                         RemoteManifest& out, std::optional<ManifestVersionMismatch>& mismatch, QString& error) {
    const std::optional<Json> parsed = ParseJsonObject(body, QStringLiteral("remote manifest"), error);
    if (!parsed) return false;
    const Json& manifest = *parsed;
    const std::optional<qint64> version = JsonInteger(manifest, mk::kVersion);
    if (!version) {
        error = QStringLiteral("remote manifest: '%1' must be an integer").arg(QLatin1String(mk::kVersion));
        return false;
    }
    const int remote_version = int(*version);
    if (remote_version != kSupportedManifestVersion) {
        mismatch = ManifestVersionMismatch{remote_version, remote_version > kSupportedManifestVersion};
        return false;
    }
    const auto bundles = manifest.find(mk::kBundles);
    if (bundles == manifest.end() || !bundles->is_array()) {
        error = QStringLiteral("remote manifest: '%1' must be a list").arg(QLatin1String(mk::kBundles));
        return false;
    }
    for (const Json& item : *bundles) {
        if (!item.is_object()) {
            error = QStringLiteral("remote manifest contains a malformed entry");
            return false;
        }
        const auto name = item.find(mk::kName);
        if (name == item.end() || !name->is_string() ||
            !IsSafeBundleName(JsonString(*name))) {
            error = QStringLiteral("remote manifest contains unsafe name: %1")
                        .arg(name == item.end() ? QStringLiteral("None") : Repr(*name));
            return false;
        }
        RemoteBundle bundle;
        bundle.name       = JsonString(*name);
        bundle.updated_at = JsonText(item, mk::kUpdatedAt);
        if (bundle.updated_at.isEmpty()) {
            error = QStringLiteral("bundle %1: '%2' is missing").arg(bundle.name, QLatin1String(mk::kUpdatedAt));
            return false;
        }
        bundle.archive_path = JsonText(item, mk::kArchivePath);
        if (bundle.archive_path.isEmpty()) {
            error = QStringLiteral("bundle %1: '%2' is missing").arg(bundle.name, QLatin1String(mk::kArchivePath));
            return false;
        }
        bundle.repo_url       = repo_url;
        bundle.manifest_url   = manifest_url;
        bundle.archive_sha256 = JsonNonEmptyText(item, mk::kArchiveSha256);
        bundle.archive_size   = JsonInteger(item, mk::kArchiveSize);
        bundle.unpacked_size  = JsonInteger(item, mk::kUnpackedSize);
        const auto cerf_json  = item.find(mk::kCerfJson);
        if (cerf_json != item.end() && cerf_json->is_object()) bundle.cerf_json = *cerf_json;
        const auto packages = item.find(mk::kAdditionalPackages);
        if (!ParsePackages(bundle.name, packages == item.end() ? nullptr : &*packages, manifest_url,
                           bundle.packages, error))
            return false;
        out.bundles.push_back(std::move(bundle));
    }
    const QString abuse = JsonText(manifest, mk::kAbuseEmail).trimmed();
    if (!abuse.isEmpty()) out.abuse_email = abuse;
    return true;
}

bool ParseAnalytics(const QByteArray& body, const QString& repo_url, DownloadPlaces& places, QString& error) {
    const QString             source = QString::fromLatin1(kRepositoryAnalyticsName);
    const std::optional<Json> parsed = ParseJsonObject(body, source, error);
    if (!parsed) return false;
    const Json& data    = *parsed;
    const auto  per_rom = data.find(kPerRomKey);
    if (per_rom == data.end() || !per_rom->is_array()) {
        error = QStringLiteral("%1: '%2' must be a list").arg(source, QLatin1String(kPerRomKey));
        return false;
    }
    const std::string entry_path = cerfcore::CfgElementPath(kPerRomKey);
    for (const Json& entry : *per_rom) {
        if (!entry.is_object()) {
            error = QStringLiteral("%1 contains a malformed entry").arg(source);
            return false;
        }
        const QString name = JsonText(entry, kRomNameKey);
        if (name.isEmpty()) {
            error = QStringLiteral("%1: '%2' is missing")
                        .arg(source, QString::fromStdString(cerfcore::CfgKeyPath({entry_path, kRomNameKey})));
            return false;
        }
        const std::optional<qint64> place = JsonInteger(entry, kPlaceKey);
        if (!place) {
            error = QStringLiteral("%1 entry %2: '%3' must be an integer").arg(source, name, QLatin1String(kPlaceKey));
            return false;
        }
        places.insert(qMakePair(repo_url, name), int(*place));
    }
    return true;
}

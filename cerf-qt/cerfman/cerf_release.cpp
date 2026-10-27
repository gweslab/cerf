#include "cerf_release.h"

#include "host_branch_table.h"
#include "installation_host_branch.h"
#include "json_file.h"
#include "object_url.h"

#include "../product_links.h"
#include "../version.h"

#include <algorithm>
#include <vector>

namespace {

constexpr char kGitHubSha256Prefix[] = "sha256:";
constexpr char kTagNameKey[]         = "tag_name";
constexpr const char* kObjectNameKey = host_branch_table::kEntryObjectNameKey;

std::vector<int> VersionParts(const QString& text) {
    std::vector<int> parts;
    for (const QString& part : text.trimmed().split(QLatin1Char('.'))) {
        const QString token   = part.trimmed();
        bool          numeric = false;
        const int     value   = token.toInt(&numeric);
        if (!numeric || token.startsWith(QLatin1Char('+')) || token.startsWith(QLatin1Char('-'))) break;
        parts.push_back(value);
    }
    return parts;
}

}

std::optional<CerfRelease> ParseStableRelease(const QByteArray& body, const QString& host_branch, QString& error) {
    const QString             marker  = ReleaseMarker(host_branch);
    const std::optional<Json> payload = ParseJsonObject(body, QStringLiteral("GitHub release API payload"), error);
    if (!payload) return std::nullopt;
    const QString tag = JsonText(*payload, kTagNameKey).trimmed();
    if (tag.isEmpty()) {
        error = QStringLiteral("GitHub release: '%1' is missing").arg(QLatin1String(kTagNameKey));
        return std::nullopt;
    }
    const auto assets = payload->find("assets");
    if (assets == payload->end() || !assets->is_array()) {
        error = QStringLiteral("GitHub release carries no asset list");
        return std::nullopt;
    }
    const QString suffix = QStringLiteral("-%1.zip").arg(marker);
    for (const Json& asset : *assets) {
        if (!asset.is_object()) continue;
        const QString name = JsonText(asset, "name");
        const QString url  = JsonText(asset, "browser_download_url");
        if (name.isEmpty() || url.isEmpty() || !name.endsWith(suffix)) continue;
        CerfRelease release;
        release.tag        = tag;
        release.body       = JsonText(*payload, "body");
        release.html_url   = JsonText(*payload, "html_url");
        if (release.html_url.isEmpty()) release.html_url = QString::fromLatin1(cerffrontend::kLatestReleaseUrl.text);
        release.asset_name = name;
        release.asset_url  = url;
        release.asset_size = JsonInteger(asset, "size");
        const QString digest = JsonText(asset, "digest");
        if (digest.startsWith(QLatin1String(kGitHubSha256Prefix)))
            release.asset_sha256 = NonEmptyText(digest.mid(int(sizeof(kGitHubSha256Prefix) - 1)));
        return release;
    }
    error = QStringLiteral("GitHub release has no %1.zip asset").arg(marker);
    return std::nullopt;
}

std::optional<CerfRelease> ParseCiBuild(const QByteArray& body, const QString& host_branch, QString& error) {
    const QString             latest  = QString::fromLatin1(host_branch_table::kLatestName);
    const std::optional<Json> payload = ParseJsonObject(body, latest, error);
    if (!payload) return std::nullopt;
    const Json* entry    = nullptr;
    const auto  branches = payload->find(host_branch_table::kBranchesKey);
    if (branches != payload->end() && branches->is_object()) {
        const auto found = branches->find(host_branch.toStdString());
        if (found != branches->end() && found->is_object()) entry = &*found;
    }
    if (entry == nullptr && host_branch == QLatin1String(host_branch_table::kRootEntry)) entry = &*payload;
    if (entry == nullptr) {
        error = QStringLiteral("%1 has no %2 build").arg(latest, host_branch);
        return std::nullopt;
    }
    QStringList parts;
    for (const char* key : host_branch_table::kEntryVersionKeys) {
        const std::optional<qint64> value = JsonInteger(*entry, key);
        if (!value) {
            error = QStringLiteral("%1: '%2' must be an integer").arg(latest, QLatin1String(key));
            return std::nullopt;
        }
        parts.append(QString::number(*value));
    }
    const QString name = JsonText(*entry, kObjectNameKey);
    if (name.isEmpty()) {
        error = QStringLiteral("%1: '%2' is missing").arg(latest, QLatin1String(kObjectNameKey));
        return std::nullopt;
    }
    if (name.contains(QLatin1Char('/')) || name.contains(QLatin1Char('\\')) || name.startsWith(QLatin1Char('.'))) {
        error = QStringLiteral("%1: '%2' is not a plain name").arg(latest, QLatin1String(kObjectNameKey));
        return std::nullopt;
    }
    CerfRelease release;
    release.tag        = parts.join(QLatin1Char('.'));
    release.body       = JsonText(*entry, host_branch_table::kEntryChangelogKey);
    release.html_url   = QString::fromLatin1(cerffrontend::kCiRunsUrl.text);
    release.asset_name = name;
    release.asset_url  = ObjectUrl(QString::fromLatin1(host_branch_table::kCiBaseUrl), name);
    release.asset_size   = JsonInteger(*entry, host_branch_table::kEntryObjectSizeKey);
    release.asset_sha256 = JsonNonEmptyText(*entry, host_branch_table::kEntryObjectSha256Key);
    return release;
}

bool IsNewerVersion(const QString& tag) {
    const std::vector<int> current{CERF_VERSION_MAJOR, CERF_VERSION_MINOR, CERF_VERSION_PATCH, CERF_VERSION_BUILD};
    const std::vector<int> remote = VersionParts(tag);
    if (remote.empty()) return false;
    return std::lexicographical_compare(current.begin(), current.end(), remote.begin(), remote.end());
}

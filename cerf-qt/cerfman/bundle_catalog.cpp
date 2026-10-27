#include "bundle_catalog.h"

#include "bundle_repositories.h"
#include "device_inventory.h"
#include "http_client.h"
#include "local_manifest_store.h"
#include "manager_operations.h"
#include "text_compare.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>
#include "../product_links.h"

#include <QStringList>

#include <algorithm>

REGISTER_SERVICE(BundleCatalog);

namespace {

QString RepoErrorsStatus(size_t count) {
    if (count == 0) return QString();
    if (count == 1) return QStringLiteral("1 bundle repository unavailable");
    return QStringLiteral("%1 bundle repositories unavailable").arg(count);
}

}

QString BundleCatalog::LoadingLabel() const {
    return QStringLiteral("Fetching bundle catalog…");
}

const RemoteBundle* BundleCatalog::Find(const QString& repo_url, const QString& name) const {
    for (const RemoteBundle& bundle : bundles_)
        if (bundle.repo_url == repo_url && bundle.name == name) return &bundle;
    return nullptr;
}

std::vector<BundleCatalog::AbuseContact> BundleCatalog::AbuseContacts() const {
    std::vector<AbuseContact> contacts;
    for (const BundleRepository& repo : emu_.Get<BundleRepositories>().Read()) {
        const auto it = abuse_emails_.constFind(repo.url);
        contacts.push_back(qMakePair(repo.url, it == abuse_emails_.constEnd() ? std::nullopt
                                                                              : std::optional<QString>(*it)));
    }
    return contacts;
}

void BundleCatalog::SetLoading(bool loading) {
    loading_ = loading;
    emit loadingChanged();
}

void BundleCatalog::OnReady() {
    connect(&emu_.Get<ManagerOperations>(), &ManagerOperations::busyChanged, this, [this] { RunPendingRefresh(); });
}

bool BundleCatalog::RefuseWhileLoading() {
    if (!loading_) return false;
    emit message(QStringLiteral("Catalog is loading"),
                 QStringLiteral("Wait until the bundle catalog is loaded, then try again."));
    return true;
}

void BundleCatalog::RunPendingRefresh() {
    if (!pending_report_all_failed_ || loading_ || emu_.Get<ManagerOperations>().Busy()) return;
    const bool report_all_failed = *pending_report_all_failed_;
    pending_report_all_failed_.reset();
    Refresh(report_all_failed);
}

void BundleCatalog::Refresh(bool report_all_failed) {
    if (loading_ || emu_.Get<ManagerOperations>().Busy()) {
        pending_report_all_failed_ = pending_report_all_failed_.value_or(false) || report_all_failed;
        return;
    }
    SetLoading(true);
    emu_.Get<LocalManifestStore>().Reload();
    auto fetch               = std::make_shared<Fetch>();
    fetch->report_all_failed = report_all_failed;
    for (const BundleRepository& repo : emu_.Get<BundleRepositories>().Read()) {
        if (!repo.enabled) continue;
        RepoResult result;
        result.url = repo.url;
        fetch->repos.push_back(std::move(result));
    }
    fetch->pending = int(fetch->repos.size()) * 2;
    if (fetch->pending == 0) {
        Finish(*fetch);
        return;
    }
    for (size_t i = 0; i < fetch->repos.size(); ++i) FetchRepo(fetch, i);
}

void BundleCatalog::FetchRepo(const std::shared_ptr<Fetch>& fetch, size_t index) {
    auto&         http         = emu_.Get<HttpClient>();
    const QString url          = fetch->repos[index].url;
    const QString manifest_url = BundleRepositories::ManifestUrl(url).toString(QUrl::FullyEncoded);
    http.Get(QUrl(CacheBustedUrl(BundleRepositories::ManifestUrl(url))), {}, this,
             [this, fetch, index, url, manifest_url](const QByteArray& body, const QString& error) {
                 RepoResult& result = fetch->repos[index];
                 if (!error.isEmpty())
                     result.error = QStringLiteral("failed to download remote manifest: %1").arg(error);
                 else
                     result.ok = ParseRemoteManifest(body, url, manifest_url, result.manifest, result.mismatch,
                                                     result.error);
                 Settle(fetch);
             });
    http.Get(QUrl(CacheBustedUrl(BundleRepositories::AnalyticsUrl(url))), {}, this,
             [this, fetch, index, url](const QByteArray& body, const QString& error) {
                 RepoResult& result  = fetch->repos[index];
                 QString     failure = error;
                 result.places_ok    = failure.isEmpty() && ParseAnalytics(body, url, result.places, failure);
                 if (!result.places_ok)
                     LOG(Manager, "repository %s analytics failed: %s\n", qUtf8Printable(url),
                         qUtf8Printable(failure));
                 Settle(fetch);
             });
}

void BundleCatalog::Settle(const std::shared_ptr<Fetch>& fetch) {
    if (--fetch->pending == 0) Finish(*fetch);
}

void BundleCatalog::Finish(const Fetch& fetch) {
    SetLoading(false);
    Apply(fetch);
    RunPendingRefresh();
}

void BundleCatalog::Apply(const Fetch& fetch) {
    for (const RepoResult& result : fetch.repos) {
        if (!result.mismatch) continue;
        const int remote = result.mismatch->remote_version;
        if (result.mismatch->remote_is_newer)
            emit message(QStringLiteral("A newer CERF build is required"),
                         QStringLiteral("The bundle catalog uses a newer format (manifest version %1) than this build "
                                        "understands (%2).\n\nDownload a newer CERF build:\n%3\n\nYour installed "
                                        "devices remain available to launch.")
                             .arg(remote)
                             .arg(kSupportedManifestVersion)
                             .arg(QString::fromUtf8(cerffrontend::kDownloadUrl.text)));
        else
            emit message(QStringLiteral("Remote manifest outdated"),
                         QStringLiteral("The server's catalog (manifest version %1) is older than this build expects "
                                        "(%2). Usually temporary - try later.")
                             .arg(remote)
                             .arg(kSupportedManifestVersion));
        emit refreshed();
        return;
    }

    std::vector<RemoteBundle> bundles;
    std::vector<RepoError>    errors;
    QMap<QString, QString>    abuse;
    DownloadPlaces            places;
    bool                      places_ok = true;
    for (const RepoResult& result : fetch.repos) {
        if (result.ok) {
            bundles.insert(bundles.end(), result.manifest.bundles.begin(), result.manifest.bundles.end());
            if (result.manifest.abuse_email) abuse.insert(result.url, *result.manifest.abuse_email);
        } else {
            errors.push_back({result.url, result.error});
            LOG(Manager, "repository %s failed: %s\n", qUtf8Printable(result.url), qUtf8Printable(result.error));
        }
        places_ok = places_ok && result.places_ok;
        for (auto it = result.places.constBegin(); it != result.places.constEnd(); ++it)
            places.insert(it.key(), it.value());
    }
    std::stable_sort(bundles.begin(), bundles.end(), [](const RemoteBundle& a, const RemoteBundle& b) {
        return SortTextLess(a.name, b.name);
    });
    const bool all_failed = !fetch.repos.empty() && errors.size() == fetch.repos.size();
    bundles_              = std::move(bundles);
    repo_errors_          = std::move(errors);
    abuse_emails_         = std::move(abuse);
    places_               = places_ok ? std::optional<DownloadPlaces>(std::move(places)) : std::nullopt;
    emu_.Get<DeviceInventory>().BackfillInstalledSha256();

    if (fetch.report_all_failed && all_failed) {
        QStringList parts;
        for (const RepoError& error : repo_errors_)
            parts.append(QStringLiteral("Repository %1 failed to load\n\n%2").arg(error.url, error.error));
        const QString text = parts.join(QStringLiteral("\n\n"));
        emit message(QStringLiteral("Remote manifest unavailable"), text);
    }
    const QString errors_status = RepoErrorsStatus(repo_errors_.size());
    if (!errors_status.isEmpty()) emit status(errors_status);
    emit refreshed();
}

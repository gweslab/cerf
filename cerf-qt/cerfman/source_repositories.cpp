#include "source_repositories.h"

#include "bundle_repositories.h"
#include "flow_reply.h"
#include "http_client.h"
#include "remote_manifest.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>

#include <optional>

REGISTER_SERVICE(SourceRepositories);

QString SourceRepositories::Checking() const { return QStringLiteral("Checking…"); }

QVariantList SourceRepositories::List() const {
    QVariantList out;
    for (const BundleRepository& repo : emu_.Get<BundleRepositories>().Read())
        out.append(QVariantMap{{QStringLiteral("url"), repo.url}, {QStringLiteral("enabled"), repo.enabled}});
    return out;
}

void SourceRepositories::Probe(const QString& url) {
    const QUrl    manifest     = BundleRepositories::ManifestUrl(url);
    const QString manifest_url = manifest.toString(QUrl::FullyEncoded);
    const QString fresh        = CacheBustedUrl(manifest);
    emu_.Get<HttpClient>().Get(QUrl(fresh), {}, this,
                               [this, url, manifest_url](const QByteArray& body, const QString& error) {
                                   QString failure = error;
                                   bool    online  = false;
                                   if (failure.isEmpty()) {
                                       RemoteManifest                         manifest;
                                       std::optional<ManifestVersionMismatch> mismatch;
                                       online = ParseRemoteManifest(body, url, manifest_url, manifest, mismatch,
                                                                    failure);
                                       if (mismatch)
                                           failure = QStringLiteral("unsupported manifest version %1")
                                                         .arg(mismatch->remote_version);
                                   }
                                   if (!online)
                                       LOG(Manager, "repository %s probe failed: %s\n", qUtf8Printable(url),
                                           qUtf8Printable(failure));
                                   emit probed(url, online ? QStringLiteral("Online") : QStringLiteral("Dead"));
                               });
}

QVariantMap SourceRepositories::Check(const QString& url, const QStringList& existing) const {
    if (!url.startsWith(QLatin1String("http://")) && !url.startsWith(QLatin1String("https://")))
        return FlowError(QStringLiteral("Invalid URL"), QStringLiteral("Enter a full http:// or https:// repository URL."));
    if (existing.contains(url))
        return FlowError(QStringLiteral("Already added"), QStringLiteral("That repository URL is already in the list."));
    return {};
}

QString SourceRepositories::Apply(const QVariantList& repositories) {
    std::vector<BundleRepository> out;
    for (const QVariant& item : repositories) {
        const QVariantMap repo = item.toMap();
        out.push_back({repo.value(QStringLiteral("url")).toString(), repo.value(QStringLiteral("enabled")).toBool()});
    }
    std::string error;
    if (!emu_.Get<BundleRepositories>().Write(out, error)) return QString::fromStdString(error);
    return QString();
}

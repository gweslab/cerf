#include "bundle_repositories.h"

#include "object_url.h"

#include "../frontend_config.h"

#include <cerfcore/core/cerf_emulator.h>

REGISTER_SERVICE(BundleRepositories);

QUrl BundleRepositories::ManifestUrl(const QString& base_url) {
    return QUrl(ObjectUrl(base_url, QString::fromLatin1(kRepositoryManifestName)));
}

QUrl BundleRepositories::AnalyticsUrl(const QString& base_url) {
    return QUrl(ObjectUrl(base_url, QString::fromLatin1(kRepositoryAnalyticsName)));
}

std::vector<BundleRepository> BundleRepositories::Parse(const Json& root) {
    std::vector<BundleRepository> out;
    for (const Json& item : root.value(kBundleRepositoriesKey, Json::array()))
        out.push_back(
            BundleRepository{JsonString(item.at(kRepositoryUrlKey)), item.at(kRepositoryEnabledKey).get<bool>()});
    return out;
}

Json BundleRepositories::ToJson(const std::vector<BundleRepository>& repositories) {
    Json list = Json::array();
    for (const BundleRepository& repository : repositories)
        list.push_back(
            {{kRepositoryUrlKey, repository.url.toStdString()}, {kRepositoryEnabledKey, repository.enabled}});
    return list;
}

std::vector<BundleRepository> BundleRepositories::Read() const {
    return Parse(LoadJsonObject(QString::fromStdString(emu_.Get<cerffrontend::FrontendConfig>().Path())));
}

bool BundleRepositories::Write(const std::vector<BundleRepository>& repositories, std::string& error) const {
    return emu_.Get<cerffrontend::FrontendConfig>().Write(
        [&](Json& root) { root[kBundleRepositoriesKey] = ToJson(repositories); }, error);
}

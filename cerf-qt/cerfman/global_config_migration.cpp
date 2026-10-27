#include "global_config_migration.h"

#include "bundle_repositories.h"
#include "host_branch_table.h"

#include <cerfcore/core/config_json.h>

#include <QSet>

namespace {

Json MergeRepositories(const Json& installed, const Json& staged) {
    const QString                 suffix = QLatin1Char('/') + QString::fromLatin1(kRepositoryManifestName);
    std::vector<BundleRepository> merged = BundleRepositories::Parse(installed);
    QSet<QString>                 urls;
    for (BundleRepository& repository : merged) {
        if (repository.url.endsWith(suffix)) repository.url.chop(suffix.size());
        urls.insert(repository.url);
    }
    for (const BundleRepository& repository : BundleRepositories::Parse(staged))
        if (!urls.contains(repository.url)) merged.push_back(repository);
    return BundleRepositories::ToJson(merged);
}

}

bool MigrateGlobalConfig(const Json& staged, const QString& installed_path, QString& error) {
    std::string message;
    if (cerfcore::CfgUpdateJsonFile(
            installed_path.toStdString(),
            [&](Json& installed) {
                Json merged                     = FillMissingKeys(installed, staged);
                merged[kBundleRepositoriesKey]  = MergeRepositories(installed, staged);
                merged[host_branch_table::kKey] = staged[host_branch_table::kKey];
                installed = std::move(merged);
            },
            cerfcore::CfgEmptyObject::kWrite, message))
        return true;
    error = QString::fromStdString(message);
    return false;
}

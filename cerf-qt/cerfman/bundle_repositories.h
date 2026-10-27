#pragma once

#include "json_file.h"

#include <cerfcore/core/service.h>

#include <QString>
#include <QUrl>

#include <string>
#include <vector>

inline constexpr char kBundleRepositoriesKey[]   = "bundle_repositories";
inline constexpr char kRepositoryUrlKey[]        = "url";
inline constexpr char kRepositoryEnabledKey[]    = "enabled";
inline constexpr char kRepositoryManifestName[]  = "manifest.json";
inline constexpr char kRepositoryAnalyticsName[] = "analytics.json";

struct BundleRepository {
    QString url;
    bool    enabled = false;
};

class BundleRepositories : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    std::vector<BundleRepository> Read() const;
    bool                          Write(const std::vector<BundleRepository>& repositories, std::string& error) const;

    static std::vector<BundleRepository> Parse(const Json& root);
    static Json                          ToJson(const std::vector<BundleRepository>& repositories);
    static QUrl                          ManifestUrl(const QString& base_url);
    static QUrl                          AnalyticsUrl(const QString& base_url);
};

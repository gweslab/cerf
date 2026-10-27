#include "local_manifest.h"

#include "bundle_manifest_keys.h"
#include "json_file.h"
#include "package_identity.h"
#include "text_compare.h"

#include <algorithm>

namespace {

namespace mk = manifest_key;

std::vector<LocalPackageRecord> ParsePackages(const Json& item) {
    std::vector<LocalPackageRecord> out;
    const Json                      categories = item.value(mk::kAdditionalPackages, Json::object());
    for (const auto& [category, entries] : categories.items()) {
        for (const Json& entry : entries) {
            const bool directory = entry.contains(mk::kDirectory);
            out.push_back({QString::fromStdString(category),
                           JsonString(entry.at(directory ? mk::kDirectory : mk::kFile)), directory,
                           JsonPresentText(entry, mk::kSha256)});
        }
    }
    return out;
}

}

const LocalPackageRecord* LocalBundleRecord::FindPackage(const QString& category, const QString& key) const {
    for (const LocalPackageRecord& record : packages)
        if (IsPackage(record, category, key)) return &record;
    return nullptr;
}

void LocalBundleRecord::DropPackage(const QString& category, const QString& key) {
    packages.erase(std::remove_if(packages.begin(), packages.end(),
                                  [&](const LocalPackageRecord& r) { return IsPackage(r, category, key); }),
                   packages.end());
}

bool LoadLocalManifest(const QString& path, LocalManifest& out, QString& error) {
    out.clear();
    const std::optional<Json> manifest = ReadJsonObjectIfPresent(path, error);
    if (!manifest) {
        error = QStringLiteral("local manifest: %1").arg(error);
        return false;
    }
    const Json bundles = manifest->value(mk::kBundles, Json::array());
    if (bundles.is_array()) {
        for (const Json& item : bundles) {
            LocalBundleRecord record;
            record.updated_at = JsonPresentText(item, mk::kUpdatedAt);
            record.sha256     = JsonPresentText(item, mk::kSha256);
            record.packages   = ParsePackages(item);
            out.insert(JsonString(item.at(mk::kName)), std::move(record));
        }
        return true;
    }
    for (const auto& [name, value] : bundles.items()) {
        LocalBundleRecord record;
        record.updated_at =
            value.is_object() ? JsonPresentText(value, mk::kUpdatedAt) : std::optional(JsonString(value));
        out.insert(QString::fromStdString(name), std::move(record));
    }
    return true;
}

bool SaveLocalManifest(const QString& path, const LocalManifest& manifest, QString& error) {
    QStringList names = manifest.keys();
    std::sort(names.begin(), names.end(), SortTextLess);
    Json bundles = Json::array();
    for (const QString& name : names) {
        const LocalBundleRecord& record = manifest.value(name);
        Json                     entry  = {{mk::kName, name.toStdString()}};
        if (record.updated_at) entry[mk::kUpdatedAt] = record.updated_at->toStdString();
        if (record.sha256) entry[mk::kSha256] = record.sha256->toStdString();
        if (!record.packages.empty()) {
            Json categories = Json::object();
            for (const LocalPackageRecord& package : record.packages) {
                const char* identity = package.is_directory ? mk::kDirectory : mk::kFile;
                Json        item     = {{identity, package.key.toStdString()}};
                if (package.sha256) item[mk::kSha256] = package.sha256->toStdString();
                categories[package.category.toStdString()].push_back(std::move(item));
            }
            entry[mk::kAdditionalPackages] = std::move(categories);
        }
        bundles.push_back(std::move(entry));
    }
    return WriteJsonFile(path, Json{{mk::kBundles, std::move(bundles)}}, error);
}

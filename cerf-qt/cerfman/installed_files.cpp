#include "installed_files.h"

#include "filesystem_path.h"

#include "../install_root_files.h"

#include <QDir>

#include <system_error>

namespace fs = std::filesystem;

std::optional<QStringList> InstalledFileList(const Json& record) {
    const auto list = record.find(cerffrontend::kInstalledFilesKey);
    if (list == record.end() || !list->is_array()) return std::nullopt;
    QStringList files;
    for (const Json& entry : *list)
        if (entry.is_string()) files.append(JsonString(entry));
    return files;
}

Json InstalledFileRecord(const QStringList& files) {
    Json list = Json::array();
    for (const QString& file : files) list.push_back(file.toStdString());
    return Json{{cerffrontend::kInstalledFilesKey, list}};
}

QStringList DroppedFiles(const QStringList& before, const QStringList& now) {
    QStringList dropped;
    for (const QString& file : before)
        if (!now.contains(file, Qt::CaseInsensitive) && !dropped.contains(file, Qt::CaseInsensitive))
            dropped.append(file);
    return dropped;
}

std::optional<fs::path> InstalledFileEntry(const QString& relative) {
    const fs::path entry = PathOf(relative);
    if (entry.empty() || entry.has_root_name() || entry.has_root_directory()) return std::nullopt;
    for (const fs::path& part : entry)
        if (part.empty() || part == "." || part == "..") return std::nullopt;
    return entry;
}

namespace {

std::optional<fs::file_type> EntryType(const fs::path& path, QString& error) {
    std::error_code       ec;
    const fs::file_status status = fs::symlink_status(path, ec);
    if (status.type() == fs::file_type::not_found) return fs::file_type::not_found;
    if (ec) {
        error = QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(PathText(path)), ErrorCodeText(ec));
        return std::nullopt;
    }
    return status.type();
}

}

bool AdoptInstalledName(const fs::path& root, const fs::path& entry, QString& error) {
    fs::path folder = root;
    for (const fs::path& part : entry) {
        const fs::path exact = folder / part;
        folder               = exact;
        std::error_code ec;
        if (fs::symlink_status(exact, ec).type() != fs::file_type::not_found) continue;
        const QString name = PathText(part);
        fs::path      variant;
        for (auto it = fs::directory_iterator(exact.parent_path(), ec); !ec && it != fs::directory_iterator();
             it.increment(ec)) {
            if (PathText(it->path().filename()).compare(name, Qt::CaseInsensitive) == 0) {
                variant = it->path();
                break;
            }
        }
        if (variant.empty()) return true;
        fs::rename(variant, exact, ec);
        if (ec) {
            error = QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(PathText(variant)), ErrorCodeText(ec));
            return false;
        }
    }
    return true;
}

InstalledFileRemoval RemoveInstalledFile(const fs::path& root, const fs::path& entry, QString& error) {
    fs::path folder;
    for (const fs::path& part : entry.parent_path()) {
        folder /= part;
        const std::optional<fs::file_type> type = EntryType(root / folder, error);
        if (!type) return InstalledFileRemoval::kFailed;
        if (*type != fs::file_type::directory) return InstalledFileRemoval::kSkipped;
    }
    const std::optional<fs::file_type> type = EntryType(root / entry, error);
    if (!type) return InstalledFileRemoval::kFailed;
    if (*type == fs::file_type::not_found || *type == fs::file_type::directory) return InstalledFileRemoval::kSkipped;
    if (!RemoveEntry(root / entry, error)) return InstalledFileRemoval::kFailed;
    for (folder = entry.parent_path(); !folder.empty(); folder = folder.parent_path()) {
        std::error_code folder_ec;
        if (!fs::remove(root / folder, folder_ec)) break;
    }
    return InstalledFileRemoval::kRemoved;
}

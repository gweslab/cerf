#include "filesystem_path.h"

#include "host_error_text.h"
#include "path_removal.h"

#include <cerfcore/platform/host_path_name.h>

#include <QDir>

namespace fs = std::filesystem;

fs::path PathOf(const QString& text) { return fs::path(text.toStdU16String()); }

QString PathText(const fs::path& path) { return QString::fromStdU16String(path.generic_u16string()); }

QString ErrorCodeText(const std::error_code& ec) {
    if (ec.category() == std::system_category()) return HostErrorText(static_cast<uint32_t>(ec.value()));
    return QString::fromStdString(ec.message());
}

bool RemoveEntry(const fs::path& path, QString& error) {
    const std::error_code ec = RemovePathTree(path);
    if (!ec) return true;
    error = QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(PathText(path)), ErrorCodeText(ec));
    return false;
}

bool EntryExists(const fs::path& path) {
    std::error_code ec;
    return fs::exists(fs::symlink_status(path, ec));
}

QString PathDisplayName(const QString& path) {
    return QString::fromStdString(cerfcore::host_platform::HostPathDisplayName(path.toStdString()));
}

QString LocationName(const QString& path) {
    return QString::fromStdString(cerfcore::host_platform::HostLocationName(path.toStdString()));
}

bool MakeDirectory(const QString& path, QString& error) {
    std::error_code ec;
    fs::create_directories(PathOf(path), ec);
    if (!ec) return true;
    error = QStringLiteral("cannot create %1 (%2)").arg(QDir::toNativeSeparators(path), ErrorCodeText(ec));
    return false;
}

bool CopyFileTo(const fs::path& from, const fs::path& to, QString& error) {
    if (!MakeDirectory(PathText(to.parent_path()), error)) return false;
    std::error_code ec;
    fs::copy_file(from, to, fs::copy_options::overwrite_existing, ec);
    if (!ec) return true;
    error = QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(PathText(to)), ErrorCodeText(ec));
    return false;
}

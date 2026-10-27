#include "zip_extract_host.h"

#include "filesystem_path.h"
#include "host_error_text.h"
#include "path_containment.h"

#include <cerfcore/core/path_split.h>

#include <QFile>
#include <QFileInfo>
#include <QSet>

#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <optional>

namespace {

QString ParentOf(const QString& path) {
    return path.left(qsizetype(cerfcore::PathParentLength(QStringView(path).utf16(), size_t(path.size()),
                                                          cerfcore::kPosixPathSeparators<char16_t>)));
}

std::optional<QString> ResolvedPath(const QString& path) {
    QStringList   pending = path.split(QLatin1Char('/'), Qt::SkipEmptyParts);
    QString       current = QStringLiteral("/");
    QSet<QString> followed;
    while (!pending.isEmpty()) {
        const QString part = pending.takeFirst();
        if (part == QLatin1String(".")) continue;
        if (part == QLatin1String("..")) {
            current = ParentOf(current);
            continue;
        }
        const QString next = current == QLatin1String("/") ? QLatin1Char('/') + part : current + QLatin1Char('/') + part;
        struct stat   info {};
        if (lstat(QFile::encodeName(next).constData(), &info) != 0 || !S_ISLNK(info.st_mode)) {
            current = next;
            continue;
        }
        if (followed.contains(next)) return std::nullopt;
        followed.insert(next);
        QByteArray    raw(qsizetype(info.st_size) + 1, Qt::Uninitialized);
        const ssize_t size = readlink(QFile::encodeName(next).constData(), raw.data(), size_t(raw.size()));
        if (size < 0 || size > info.st_size) return std::nullopt;
        raw.truncate(size);
        const QString link_text = QFile::decodeName(raw);
        if (link_text.startsWith(QLatin1Char('/'))) current = QStringLiteral("/");
        pending = link_text.split(QLatin1Char('/'), Qt::SkipEmptyParts) + pending;
    }
    return current;
}

bool ResolvesInside(const QString& real_root, const QString& path) {
    const std::optional<QString> resolved = ResolvedPath(path);
    return resolved && PathInside(real_root, *resolved);
}

void RemoveLinks(const std::vector<ZipLinkEntry>& links, size_t count, QString& error) {
    for (size_t i = 0; i < count; ++i)
        if (unlink(QFile::encodeName(links[i].path).constData()) != 0)
            error += QStringLiteral("\n%1: %2").arg(links[i].path, HostErrorText(uint32_t(errno)));
}

QString LinkEscapeError(const ZipLinkEntry& link) {
    return QStringLiteral("link in archive leaves the destination: %1").arg(link.path);
}

}

zip_t* OpenZipArchive(const QString& path, QString& error) {
    int          code    = 0;
    zip_t*       archive = zip_open(QFile::encodeName(path).constData(), ZIP_RDONLY, &code);
    if (archive != nullptr) return archive;
    zip_error_t failure;
    zip_error_init_with_code(&failure, code);
    error = QStringLiteral("%1: %2").arg(path, QString::fromUtf8(zip_error_strerror(&failure)));
    zip_error_fini(&failure);
    return nullptr;
}

QString HostEntryName(const QString& name) { return name; }

bool HostExtractsLinks() { return true; }

bool FinishUnixEntries(const QString& destination, const std::vector<ZipModeEntry>& modes,
                       const std::vector<ZipLinkEntry>& links, QString& error) {
    for (const ZipModeEntry& entry : modes) {
        if (chmod(QFile::encodeName(entry.path).constData(), mode_t(entry.mode)) != 0) {
            error = QStringLiteral("%1: %2").arg(entry.path, HostErrorText(uint32_t(errno)));
            return false;
        }
    }
    const QString real_root = QFileInfo(destination).canonicalFilePath();
    for (size_t i = 0; i < links.size(); ++i) {
        const ZipLinkEntry& link   = links[i];
        const QString       folder = QFileInfo(link.path).absolutePath();
        if (!ResolvesInside(real_root, folder)) {
            error = LinkEscapeError(link);
            RemoveLinks(links, i, error);
            return false;
        }
        if (!MakeDirectory(folder, error)) {
            RemoveLinks(links, i, error);
            return false;
        }
        if (symlink(QFile::encodeName(link.target).constData(), QFile::encodeName(link.path).constData()) != 0) {
            error = QStringLiteral("%1: %2").arg(link.path, HostErrorText(uint32_t(errno)));
            RemoveLinks(links, i, error);
            return false;
        }
    }
    for (const ZipLinkEntry& link : links) {
        if (ResolvesInside(real_root, link.path)) continue;
        error = LinkEscapeError(link);
        RemoveLinks(links, links.size(), error);
        return false;
    }
    return true;
}

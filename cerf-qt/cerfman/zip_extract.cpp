#include "zip_extract.h"

#include "file_writer.h"
#include "filesystem_path.h"
#include "path_containment.h"
#include "zip_extract_host.h"

#include <QDir>
#include <QFileInfo>

#include <functional>
#include <memory>
#include <vector>

namespace {

constexpr uint32_t kFileTypeMask = 0170000;
constexpr uint32_t kSymlinkType  = 0120000;

struct ArchiveCloser {
    void operator()(zip_t* archive) const { zip_discard(archive); }
};

struct Entry {
    zip_uint64_t index = 0;
    QString      name;
    QString      path;
    bool         directory = false;
    bool         link      = false;
    bool         unix_mode = false;
    uint32_t     mode      = 0;
};

QString Candidate(const QString& root, const QString& relative) {
    return QDir::isAbsolutePath(relative) ? QDir::cleanPath(relative) : QDir::cleanPath(root + QLatin1Char('/') + relative);
}

bool ReadEntry(zip_t* archive, const Entry& entry, const std::function<bool(const char*, qint64)>& sink,
               QString& error) {
    zip_file_t* file = zip_fopen_index(archive, entry.index, 0);
    if (file == nullptr) {
        error = QStringLiteral("%1: %2").arg(entry.name, QString::fromUtf8(zip_strerror(archive)));
        return false;
    }
    std::vector<char> buffer(static_cast<size_t>(FileWriter::kChunkBytes));
    bool              ok = true;
    for (;;) {
        const zip_int64_t got = zip_fread(file, buffer.data(), zip_uint64_t(buffer.size()));
        if (got < 0) {
            error = QStringLiteral("%1: %2").arg(entry.name, QString::fromUtf8(zip_file_strerror(file)));
            ok    = false;
            break;
        }
        if (got == 0) break;
        if (!sink(buffer.data(), qint64(got))) {
            ok = false;
            break;
        }
    }
    zip_fclose(file);
    return ok;
}

bool ExtractFile(zip_t* archive, const Entry& entry, QString& error) {
    if (!MakeDirectory(QFileInfo(entry.path).absolutePath(), error)) return false;
    FileWriter out(entry.path);
    if (!out.Open(error)) return false;
    return ReadEntry(archive, entry, [&](const char* data, qint64 size) { return out.Write(data, size, error); },
                     error) &&
           out.Close(error);
}

}

bool SafeExtract(const QString& zip_path, const QString& destination, QString& error) {
    std::unique_ptr<zip_t, ArchiveCloser> archive(OpenZipArchive(zip_path, error));
    if (!archive) return false;
    const QString     root  = QDir::cleanPath(QDir(destination).absolutePath());
    const zip_int64_t count = zip_get_num_entries(archive.get(), 0);
    if (count < 0) {
        error = QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(zip_path),
                                             QString::fromUtf8(zip_strerror(archive.get())));
        return false;
    }

    std::vector<Entry> entries;
    for (zip_int64_t i = 0; i < count; ++i) {
        Entry       entry;
        const char* name = zip_get_name(archive.get(), zip_uint64_t(i), ZIP_FL_ENC_GUESS);
        if (name == nullptr) {
            error = QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(zip_path),
                                                 QString::fromUtf8(zip_strerror(archive.get())));
            return false;
        }
        entry.index     = zip_uint64_t(i);
        entry.name      = QString::fromUtf8(name);
        const QString relative = HostEntryName(entry.name);
        entry.path      = Candidate(root, relative);
        entry.directory = relative.endsWith(QLatin1Char('/'));
        if (!PathInside(root, entry.path)) {
            error = QStringLiteral("unsafe path in archive: %1").arg(entry.name);
            return false;
        }
        zip_uint8_t  opsys      = 0;
        zip_uint32_t attributes = 0;
        if (zip_file_get_external_attributes(archive.get(), entry.index, 0, &opsys, &attributes) == 0 &&
            opsys == ZIP_OPSYS_UNIX) {
            entry.unix_mode = true;
            entry.mode      = attributes >> 16;
        }
        entry.link = HostExtractsLinks() && entry.unix_mode && (entry.mode & kFileTypeMask) == kSymlinkType;
        entries.push_back(std::move(entry));
    }

    std::vector<ZipLinkEntry> links;
    for (const Entry& entry : entries) {
        if (!entry.link) continue;
        QByteArray target;
        if (!ReadEntry(archive.get(), entry,
                       [&](const char* data, qint64 size) {
                           target.append(data, size);
                           return true;
                       },
                       error))
            return false;
        links.push_back({QDir::cleanPath(entry.path), QString::fromUtf8(target)});
    }

    std::vector<ZipModeEntry> modes;
    for (const Entry& entry : entries) {
        if (entry.link) continue;
        if (entry.directory) {
            if (!MakeDirectory(entry.path, error)) return false;
        } else if (!ExtractFile(archive.get(), entry, error)) {
            return false;
        }
        if (entry.unix_mode && (entry.mode & 0777) != 0) modes.push_back({entry.path, entry.mode & 0777});
    }
    return FinishUnixEntries(root, modes, links, error);
}

QString PreparedBundleRoot(const QString& extract_dir) {
    const QFileInfoList entries =
        QDir(extract_dir).entryInfoList(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System);
    if (entries.size() == 1 && entries.first().isDir())
        return entries.first().absoluteFilePath();
    return extract_dir;
}

#include "device_file_copy.h"

#include "device_directory.h"
#include "device_file_value.h"
#include "filesystem_path.h"
#include "host_file_copy.h"

#include <cerfcore/platform/host_file.h>

#include <QDir>
#include <QFileInfo>
#include <QLatin1StringView>

#include <filesystem>
#include <system_error>

namespace {

constexpr QLatin1StringView kNonPortableNameChars("<>:\"/\\|?*");

bool SameSource(const QString& a, const QString& b) {
    if (a == b) return true;
    if (IsDocumentFileValue(a) || IsDocumentFileValue(b)) return false;
    std::error_code ec;
    return std::filesystem::equivalent(PathOf(a), PathOf(b), ec);
}

qint64 SizeOf(const QString& source) {
    uint64_t size = 0;
    return cerfcore::host_platform::HostRegularFileSize(source.toStdString(), size) ? qint64(size) : 0;
}

QString PortableName(const QString& name) {
    QString out;
    for (const QChar c : name) out.append(c.unicode() < 0x20 || kNonPortableNameChars.contains(c) ? QLatin1Char('_') : c);
    while (out.endsWith(QLatin1Char('.')) || out.endsWith(QLatin1Char(' '))) out.chop(1);
    return out.isEmpty() ? QStringLiteral("file") : out;
}

}

DeviceFileCopy::DeviceFileCopy() {
    Reserve(DeviceDirectory::BaseConfigName());
    Reserve(DeviceDirectory::UserConfigName());
}

void DeviceFileCopy::Reserve(const QString& name) { taken_.push_back(name.toCaseFolded()); }

bool DeviceFileCopy::Taken(const QString& name) const {
    const QString folded = name.toCaseFolded();
    for (const QString& taken : taken_)
        if (taken == folded) return true;
    return false;
}

QString DeviceFileCopy::FreeName(const QString& wanted) const {
    const QString name = PortableName(wanted);
    if (!Taken(name)) return name;
    const QFileInfo info(name);
    const QString   stem   = info.completeBaseName();
    const QString   suffix = info.suffix();
    for (int n = 2;; ++n) {
        QString candidate = QStringLiteral("%1 (%2)").arg(stem, QString::number(n));
        if (!suffix.isEmpty()) candidate += QLatin1Char('.') + suffix;
        if (!Taken(candidate)) return candidate;
    }
}

QString DeviceFileCopy::Claim(const QString& wanted) {
    const QString name = FreeName(wanted);
    Reserve(name);
    return name;
}

QString DeviceFileCopy::Add(const QString& source) {
    for (const File& file : files_)
        if (SameSource(file.source, source)) return file.name;
    files_.push_back(File{source, Claim(PathDisplayName(source)), SizeOf(source)});
    return files_.back().name;
}

void DeviceFileCopy::AddAs(const QString& source, const QString& name) {
    files_.push_back(File{source, name, SizeOf(source)});
}

qint64 DeviceFileCopy::Bytes() const {
    qint64 total = 0;
    for (const File& file : files_) total += file.bytes;
    return total;
}

OperationResult DeviceFileCopy::Run(const QString& target_dir, const OperationProgress& progress,
                                    QString& error) const {
    for (const File& file : files_) {
        const OperationResult result = CopyHostFile(file.source, QDir(target_dir).filePath(file.name), progress, error);
        if (result != OperationResult::kDone) return result;
    }
    return OperationResult::kDone;
}

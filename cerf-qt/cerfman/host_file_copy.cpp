#include "host_file_copy.h"

#include "file_writer.h"
#include "filesystem_path.h"
#include "host_error_text.h"

#include <cerfcore/platform/host_error.h>
#include <cerfcore/platform/host_file.h>

#include <QDir>

#include <vector>

namespace hp = cerfcore::host_platform;

namespace {

QString HostFailure(const QString& path) {
    return QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(path), HostErrorText(hp::LastErrorCode()));
}

}

OperationResult CopyHostFile(const QString& source, const QString& destination, const OperationProgress& progress,
                             QString& error) {
    hp::HostFile in;
    hp::HostFile out;
    uint64_t     total = 0;
    if (!in.Open(source.toStdString(), hp::FileMode::kReadExisting) || !in.Size(total)) {
        error = HostFailure(source);
        return OperationResult::kFailed;
    }
    if (!out.Open(destination.toStdString(), hp::FileMode::kWriteNew)) {
        error = HostFailure(destination);
        return OperationResult::kFailed;
    }
    const QString     name  = PathDisplayName(source);
    const QString     label = QStringLiteral("Copying %1…").arg(name);
    qint64            done  = 0;
    std::vector<char> buffer(static_cast<size_t>(FileWriter::kChunkBytes));
    progress.Report(label, 0, qint64(total));
    for (;;) {
        if (progress.Cancelled()) {
            error = QStringLiteral("Copying %1: cancelled").arg(name);
            return OperationResult::kCancelled;
        }
        uint32_t got = 0;
        if (!in.Read(buffer.data(), uint32_t(buffer.size()), got)) {
            error = HostFailure(source);
            return OperationResult::kFailed;
        }
        if (got == 0) break;
        uint32_t written = 0;
        if (!out.Write(buffer.data(), got, written) || written != got) {
            error = HostFailure(destination);
            return OperationResult::kFailed;
        }
        done += got;
        progress.Report(label, done, qint64(total));
    }
    if (!out.Close()) {
        error = HostFailure(destination);
        return OperationResult::kFailed;
    }
    return OperationResult::kDone;
}

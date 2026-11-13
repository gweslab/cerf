#include "host_file_copy.h"

#include "file_writer.h"
#include "filesystem_path.h"
#include "host_error_text.h"

#include <cerfcore/platform/host_error.h>
#include <cerfcore/platform/host_file.h>

#include <QDir>

#include <vector>

namespace hp = cerfcore::host_platform;

OperationResult CopyHostFile(const QString& source, const QString& destination, const OperationProgress& progress,
                             QString& error) {
    hp::HostFile in;
    FileWriter   out(destination);
    uint64_t     total = 0;
    if (!in.Open(source.toStdString(), hp::FileMode::kReadExisting) || !in.Size(total)) {
        error = QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(source), HostErrorText(hp::LastErrorCode()));
        return OperationResult::kFailed;
    }
    if (!out.Open(error)) return OperationResult::kFailed;
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
            error = QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(source), HostErrorText(hp::LastErrorCode()));
            return OperationResult::kFailed;
        }
        if (got == 0) break;
        if (!out.Write(buffer.data(), got, error)) return OperationResult::kFailed;
        done += got;
        progress.Report(label, done, qint64(total));
    }
    return out.Close(error) ? OperationResult::kDone : OperationResult::kFailed;
}

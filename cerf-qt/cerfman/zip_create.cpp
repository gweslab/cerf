#include "zip_create.h"

#include "host_error_text.h"
#include "zip_create_host.h"

#include <cerfcore/platform/host_error.h>
#include <cerfcore/platform/host_file.h>

#include <QDir>

#include <algorithm>
#include <cstdint>

namespace {

namespace hp = cerfcore::host_platform;

constexpr double       kProgressPrecision = 0.001;
constexpr zip_uint64_t kMaxRead           = 1u << 30;

struct HostFileSource {
    QString      path;
    uint64_t     size    = 0;
    QString*     failure = nullptr;
    hp::HostFile file;
    zip_error_t  error;
};

struct CloseContext {
    const OperationProgress* progress;
    QString                  label;
    qint64                   total;
};

zip_int64_t Fail(HostFileSource& source, int code) {
    *source.failure = QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(source.path), HostErrorText(hp::LastErrorCode()));
    zip_error_set(&source.error, code, 0);
    return -1;
}

zip_int64_t HostFileCommand(void* state, void* data, zip_uint64_t length, zip_source_cmd_t command) {
    auto& source = *static_cast<HostFileSource*>(state);
    switch (command) {
        case ZIP_SOURCE_OPEN:
            return source.file.Open(source.path.toStdString(), hp::FileMode::kReadExisting) ? 0 : Fail(source, ZIP_ER_OPEN);
        case ZIP_SOURCE_READ: {
            uint32_t got = 0;
            if (!source.file.Read(data, uint32_t(std::min(length, kMaxRead)), got)) return Fail(source, ZIP_ER_READ);
            return zip_int64_t(got);
        }
        case ZIP_SOURCE_CLOSE:
            source.file.Close();
            return 0;
        case ZIP_SOURCE_STAT: {
            zip_stat_t* stat = ZIP_SOURCE_GET_ARGS(zip_stat_t, data, length, &source.error);
            if (stat == nullptr) return -1;
            zip_stat_init(stat);
            stat->size = source.size;
            stat->valid |= ZIP_STAT_SIZE;
            return zip_int64_t(sizeof(*stat));
        }
        case ZIP_SOURCE_ERROR:
            return zip_error_to_data(&source.error, data, length);
        case ZIP_SOURCE_FREE:
            zip_error_fini(&source.error);
            delete &source;
            return 0;
        case ZIP_SOURCE_SUPPORTS:
            return zip_source_make_command_bitmap(ZIP_SOURCE_OPEN, ZIP_SOURCE_READ, ZIP_SOURCE_CLOSE, ZIP_SOURCE_STAT,
                                                  ZIP_SOURCE_ERROR, ZIP_SOURCE_FREE, ZIP_SOURCE_SUPPORTS, -1);
        default:
            zip_error_set(&source.error, ZIP_ER_OPNOTSUPP, 0);
            return -1;
    }
}

void ReportProgress(zip_t*, double fraction, void* state) {
    const auto& context = *static_cast<const CloseContext*>(state);
    context.progress->Report(context.label, qint64(fraction * double(context.total)), context.total);
}

int CancelRequested(zip_t*, void* state) {
    return static_cast<const CloseContext*>(state)->progress->Cancelled() ? 1 : 0;
}

}

ZipCreator::~ZipCreator() {
    if (archive_ != nullptr) zip_discard(archive_);
}

QString ZipCreator::ArchiveFailure() const {
    return QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(path_), QString::fromUtf8(zip_strerror(archive_)));
}

bool ZipCreator::Open(QString& error) {
    archive_ = CreateZipArchive(path_, error);
    return archive_ != nullptr;
}

bool ZipCreator::AddFile(const QString& entry, const QString& source, QString& error) {
    uint64_t size = 0;
    if (!hp::HostRegularFileSize(source.toStdString(), size)) {
        error = QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(source), HostErrorText(hp::LastErrorCode()));
        return false;
    }
    auto* state    = new HostFileSource();
    state->path    = source;
    state->size    = size;
    state->failure = &source_failure_;
    zip_error_init(&state->error);
    zip_source_t* zip_source = zip_source_function(archive_, HostFileCommand, state);
    if (zip_source == nullptr) {
        zip_error_fini(&state->error);
        delete state;
        error = ArchiveFailure();
        return false;
    }
    if (zip_file_add(archive_, entry.toUtf8().constData(), zip_source, ZIP_FL_ENC_UTF_8 | ZIP_FL_OVERWRITE) < 0) {
        zip_source_free(zip_source);
        error = ArchiveFailure();
        return false;
    }
    total_ += qint64(size);
    return true;
}

OperationResult ZipCreator::Close(const QString& label, const OperationProgress& progress, QString& error) {
    CloseContext context{&progress, label, total_};
    zip_register_progress_callback_with_state(archive_, kProgressPrecision, ReportProgress, nullptr, &context);
    zip_register_cancel_callback_with_state(archive_, CancelRequested, nullptr, &context);
    progress.Report(label, 0, total_);
    if (zip_close(archive_) == 0) {
        archive_ = nullptr;
        return OperationResult::kDone;
    }
    const bool cancelled = zip_error_code_zip(zip_get_error(archive_)) == ZIP_ER_CANCELLED;
    error                = source_failure_.isEmpty() ? ArchiveFailure() : source_failure_;
    zip_discard(archive_);
    archive_ = nullptr;
    return cancelled ? OperationResult::kCancelled : OperationResult::kFailed;
}

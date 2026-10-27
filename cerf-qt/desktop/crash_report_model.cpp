#include "crash_report_model.h"

#include "../cerfman/byte_size_text.h"
#include "../cerfman/filesystem_path.h"
#include "../cerfman/manager_engine.h"
#include "../process_mode.h"
#include "file_manager_reveal.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/cli_option.h>

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>

#include <cstring>

REGISTER_SERVICE(CrashReportModel);

namespace {

constexpr qint64 kDumpViewLimit = 512 * 1024;

}

int CrashReportModel::Run(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        const char* log_path = nullptr;
        if (cerfcore::ReadCliOption(argv[i], kCrashReportArg, log_path)) log_path_ = QString::fromUtf8(log_path);
    }
    emu_.Get<ManagerEngine>().Open(QStringLiteral("CrashWindow"), {{QStringLiteral("visible"), true}});
    return QCoreApplication::exec();
}

QString CrashReportModel::LogPath() const {
    if (!log_path_.isEmpty()) return log_path_;
    return QString::fromStdString(cerfcore::GetCerfDir() + cerfcore::kLogFileName);
}

QString CrashReportModel::CrashLogPath() const {
    return QString::fromStdString(cerfcore::GetCerfDir() + cerfcore::kCrashLogFileName);
}

bool CrashReportModel::Exists(const QString& path) const { return QFileInfo(path).isFile(); }

QString CrashReportModel::ShowFile(const QString& path) const {
    const QString target = QFileInfo(path).absoluteFilePath();
    return RevealInFileManager(target) ? QString()
                                       : QStringLiteral("%1 cannot be opened.").arg(QDir::toNativeSeparators(target));
}

QString CrashReportModel::SizeLabel(const QString& path) const {
    const QFileInfo info(path);
    if (!info.isFile()) return QStringLiteral("missing");
    const QString size = FormatSize(info.size());
    return size.isEmpty() ? QStringLiteral("empty") : size;
}

QString CrashReportModel::DumpText() const {
    QFile file(CrashLogPath());
    if (!file.open(QIODevice::ReadOnly))
        return QStringLiteral("%1 cannot be read: %2").arg(PathDisplayName(file.fileName()), file.errorString());
    const QByteArray blob = file.read(kDumpViewLimit + 1);
    const QString    text = QString::fromUtf8(blob.left(kDumpViewLimit));
    if (blob.size() <= kDumpViewLimit) return text;
    return text + QStringLiteral("\n\n[… truncated for display …]");
}

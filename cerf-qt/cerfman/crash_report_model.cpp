#include "crash_report_model.h"

#include "../CerfStyle/touch_frontend.h"
#include "byte_size_text.h"
#include "file_offer.h"
#include "filesystem_path.h"
#include "manager_engine.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/fatal.h>
#include <cerfcore/core/log.h>

#include <QDir>
#include <QFile>
#include <QFileInfo>

REGISTER_SERVICE(CrashReportModel);

namespace {

constexpr qint64 kDumpViewLimit = 512 * 1024;

}

void CrashReportModel::Open(const std::string& crash_log_path) {
    emu_.Get<cerfcore::Fatal>().Guard([this, &crash_log_path] {
        emu_.Get<ManagerEngine>().Open(QStringLiteral("CrashWindow"),
                                       {{QStringLiteral("visible"), true},
                                        {QStringLiteral("mobile"), TouchFrontend::Active()},
                                        {QStringLiteral("crashLogPath"), QString::fromStdString(crash_log_path)}});
    });
}

QString CrashReportModel::LogPath() const { return QString::fromUtf8(cerfcore::Log::FilePath()); }

bool CrashReportModel::Exists(const QString& path) const { return QFileInfo(path).isFile(); }

QString CrashReportModel::ShowFile(const QString& path) const {
    const QString target = QFileInfo(path).absoluteFilePath();
    return OfferFile(target) ? QString()
                             : QStringLiteral("%1 cannot be opened.").arg(QDir::toNativeSeparators(target));
}

QString CrashReportModel::SizeLabel(const QString& path) const {
    const QFileInfo info(path);
    if (!info.isFile()) return QStringLiteral("missing");
    const QString size = FormatSize(info.size());
    return size.isEmpty() ? QStringLiteral("empty") : size;
}

QString CrashReportModel::DumpText(const QString& crash_log_path) const {
    QFile file(crash_log_path);
    if (!file.open(QIODevice::ReadOnly))
        return QStringLiteral("%1 cannot be read: %2").arg(PathDisplayName(file.fileName()), file.errorString());
    const QByteArray blob = file.read(kDumpViewLimit + 1);
    const QString    text = QString::fromUtf8(blob.left(kDumpViewLimit));
    if (blob.size() <= kDumpViewLimit) return text;
    return text + QStringLiteral("\n\n[… truncated for display …]");
}

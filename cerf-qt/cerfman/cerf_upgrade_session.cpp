#include "cerf_upgrade_session.h"

#include "byte_size_text.h"
#include "filesystem_path.h"
#include "http_download.h"
#include "install_options.h"
#include "manager_operations.h"
#include "install_directories.h"
#include "zip_extract.h"

#include <cerfcore/platform/host_process.h>
#include "../product_links.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QMetaObject>

namespace {

constexpr char kStagingZipName[] = "upgrade.zip";

}

CerfUpgradeSession::CerfUpgradeSession(CerfRelease release, QByteArray user_agent, QObject* parent)
    : UpgradeSession(parent), release_(std::move(release)), user_agent_(std::move(user_agent)) {
    SetHeading(QStringLiteral("Upgrading %1 to %2…").arg(QString::fromUtf8(cerffrontend::kProductName), release_.tag));
}

CerfUpgradeSession::~CerfUpgradeSession() {
    cancelled_.store(true, std::memory_order_release);
    StopWaiting();
    if (worker_.joinable()) worker_.join();
}

void CerfUpgradeSession::Start() { worker_ = std::thread([this] { Work(); }); }

bool CerfUpgradeSession::Stage(QString& staged_frontend, QString& error) {
    const QString install_dir = InstallRoot();
    const QString upgrade_dir = StagingDirectory(install_dir);
    const QString zip_path   = QDir(install_dir).filePath(QString::fromLatin1(kStagingZipName));

    PostLog(QStringLiteral("Preparing %1").arg(QDir::toNativeSeparators(upgrade_dir)));
    if (!RemoveEntry(PathOf(upgrade_dir), error) || !RemoveEntry(PathOf(zip_path), error)) return false;

    const QString asset = QStringLiteral("%1 %2").arg(release_.asset_name, FormatSize(release_.asset_size));
    PostLog(QStringLiteral("Downloading %1").arg(asset));
    const OperationProgress progress(
        [this](const QString&, qint64 done, std::optional<qint64> total) { PostProgress(done, total.value_or(0)); },
        cancelled_);
    const DownloadRequest request{release_.asset_url, zip_path, release_.asset_name, release_.asset_size,
                                  release_.asset_sha256, user_agent_};
    QString failure;
    if (DownloadVerified(request, progress, failure) != OperationResult::kDone) {
        error = QStringLiteral("Downloading %1: %2").arg(asset, failure);
        return false;
    }

    PostLog(QStringLiteral("Extracting the archive"));
    PostProgress(0, 0);
    if (!MakeDirectory(upgrade_dir, failure) || !SafeExtract(zip_path, upgrade_dir, failure)) {
        error = QStringLiteral("Extracting the archive: %1").arg(failure);
        return false;
    }
    if (!RemoveEntry(PathOf(zip_path), error)) return false;

    const QString self     = QString::fromStdString(cerfcore::host_platform::ExecutablePath());
    const QString relative = QDir(install_dir).relativeFilePath(self);
    staged_frontend        = QDir(upgrade_dir).filePath(relative);
    if (!QFileInfo(staged_frontend).isFile()) {
        error = QStringLiteral("%1 contains no %2").arg(release_.asset_name, relative);
        return false;
    }
    PostLog(QStringLiteral("Staged the new build in %1").arg(QDir::toNativeSeparators(upgrade_dir)));
    return true;
}

void CerfUpgradeSession::Work() {
    QString staged;
    QString error;
    if (Stage(staged, error) &&
        StartStage(staged, StagingDirectory(InstallRoot()), {QString::fromLatin1(kUpgradeArg)}, error)) {
        QMetaObject::invokeMethod(QCoreApplication::instance(), [] { QCoreApplication::quit(); },
                                  Qt::QueuedConnection);
        return;
    }
    PostFailure(QStringLiteral("Upgrade failed"), error, QStringLiteral("Your installation is untouched."));
}

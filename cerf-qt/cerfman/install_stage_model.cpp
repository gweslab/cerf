#include "install_stage_model.h"

#include "filesystem_path.h"
#include "install_copier.h"
#include "install_finalize.h"
#include "install_retry_gate.h"
#include "manager_engine.h"
#include "process_watch.h"
#include "install_directories.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/instance_threads.h>
#include <cerfcore/host/user_alert.h>
#include <cerfcore/platform/host_process.h>
#include "../product_links.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QMetaObject>

REGISTER_SERVICE(InstallStageModel);

void InstallStageModel::OnShutdown() {
    StopWaiting();
    if (worker_.joinable()) worker_.join();
}

int InstallStageModel::RunInstall(const InstallOptions& options) {
    options_ = options;
    SetHeading(options_.Heading());
    emu_.Get<ManagerEngine>().Open(QString::fromLatin1(kWindowType), WindowProperties());
    worker_ = emu_.Get<cerfcore::InstanceThreads>().Start([this] { Work(); });
    return QCoreApplication::exec();
}

std::optional<int> InstallStageModel::RunPostUpgrade(const InstallOptions& options) {
    options_ = options;
    QString error;
    if (options.wait_pid && !WaitForPid(error)) {
        Fail(options.FailedTitle(), error);
        return 1;
    }
    QString failure;
    if (!RemoveEntry(PathOf(StagingDirectory(InstallRoot())), failure))
        Fail(options.FailedTitle(),
             QStringLiteral("CERF was installed, but its staging folder could not be removed:\n%1\n\nDelete it by hand.")
                 .arg(failure));
    if (!options.launch_after) return 0;
    return std::nullopt;
}

void InstallStageModel::Close() { QCoreApplication::exit(exit_code_); }

void InstallStageModel::Work() {
    QString         error;
    InstallProgress progress = InstallProgress::kNothingChanged;
    if (Install(error, progress)) {
        QMetaObject::invokeMethod(this, [] { QCoreApplication::exit(0); }, Qt::QueuedConnection);
        return;
    }
    exit_code_ = 1;
    QString consequence;
    switch (progress) {
        case InstallProgress::kNothingChanged:
            consequence = QStringLiteral("Your installation is untouched.");
            break;
        case InstallProgress::kCopying:
            consequence = QStringLiteral("Your installation of CERF may now be corrupted: some files were replaced "
                                         "and some were not. Re-download CERF from %1")
                              .arg(QString::fromUtf8(cerffrontend::kDownloadUrl.text));
            break;
        case InstallProgress::kCopied:
            consequence = QStringLiteral("The new files of CERF are installed. Start CERF again.");
            break;
    }
    PostFailure(options_.FailedTitle(), error, consequence);
}

bool InstallStageModel::Install(QString& error, InstallProgress& progress) {
    const QString upgrade_dir = InstallRoot();
    const QString install_dir = QFileInfo(upgrade_dir).absolutePath();
    const QString self        = QString::fromStdString(cerfcore::host_platform::ExecutablePath());
    const QString frontend    = QDir(install_dir).filePath(QDir(upgrade_dir).relativeFilePath(self));

    if (options_.wait_pid) {
        PostLog(QStringLiteral("Waiting for the previous CERF process (pid %1)").arg(*options_.wait_pid));
        if (!WaitForPid(error)) return false;
    }
    std::vector<QString> images{frontend};
    for (const char* name : kRetiredExecutables) images.push_back(QDir(install_dir).filePath(QString::fromUtf8(name)));
    for (const QString& image : images) {
        for (;;) {
            std::vector<uint32_t> pids;
            if (!ProcessesRunningImage(image, pids, error)) return false;
            if (pids.empty()) break;
            if (!AskRetry(QStringLiteral("The emulator is running"),
                          QStringLiteral("%1 is running and its files cannot be replaced while it is.\n\nClose every "
                                         "emulator window, then retry.")
                              .arg(QString::fromUtf8(cerffrontend::kProductName)))) {
                error = QStringLiteral("cancelled while %1 was running").arg(PathDisplayName(image));
                return false;
            }
        }
    }

    const InstallRetryGate gate([this](const QString& line) { PostLog(line); },
                                [this](const QString& title, const QString& message) {
                                    return AskRetry(title, message);
                                });
    InstallCopier copier(gate);
    if (!copier.Prepare(upgrade_dir, install_dir, error)) return false;
    progress = InstallProgress::kCopying;
    if (!copier.Apply(error)) return false;
    progress = InstallProgress::kCopied;
    FinalizeInstall(install_dir, frontend, options_, gate);

    PostLog(QStringLiteral("Starting the installed %1").arg(QString::fromUtf8(cerffrontend::kProductName)));
    QStringList args{QString::fromLatin1(kPostUpgradeArg)};
    args.append(options_.CarriedArguments());
    return StartStage(frontend, install_dir, args, error);
}

bool InstallStageModel::WaitForPid(QString& error) const {
    const uint32_t pid = *options_.wait_pid;
    if (WaitForProcessExit(pid, int(kWaitForPidTimeoutMs), error)) return true;
    if (error.isEmpty())
        error = QStringLiteral("the previous CERF process (pid %1) is still running after %2 s; its files cannot "
                               "be replaced")
                    .arg(pid)
                    .arg(kWaitForPidTimeoutMs / 1000);
    return false;
}

void InstallStageModel::Fail(const QString& title, const QString& message) const {
    LogFailure(title, message);
    emu_.Get<cerfcore::UserAlert>().Show(cerfcore::AlertLevel::kError, cerfcore::AlertPlacement::kStandalone,
                                         title.toStdString(), message.toStdString());
}

#include <cerffrontend/launcher_process.h>

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>

#include "qt_launcher_path.h"

#include <QEventLoop>
#include <QProcess>
#include <QStringList>
#include <QWidget>

namespace {

class QtLauncherProcess : public cerffrontend::LauncherProcess {
public:
    using cerffrontend::LauncherProcess::LauncherProcess;

    std::string ExecutablePath() const override {
        return cerfcore::GetCerfDir() + LauncherPathInInstallation();
    }

    bool RunAndWait(uint64_t owner, const std::vector<std::string>& args, uint32_t& exit_code,
                    std::string& error) override {
        QStringList arguments;
        for (const std::string& arg : args) arguments << QString::fromStdString(arg);

        QProcess process;
        process.setProgram(QString::fromStdString(ExecutablePath()));
        process.setArguments(arguments);
        process.setWorkingDirectory(QString::fromStdString(cerfcore::GetCerfDir()));
        process.setProcessChannelMode(QProcess::ForwardedChannels);

        QEventLoop loop;
        QObject::connect(&process, &QProcess::finished, &loop, &QEventLoop::quit);
        QObject::connect(&process, &QProcess::errorOccurred, &loop, [&loop](QProcess::ProcessError e) {
            if (e == QProcess::FailedToStart) loop.quit();
        });
        process.start();
        if (process.state() != QProcess::NotRunning) loop.exec();

        if (process.error() == QProcess::FailedToStart) {
            error = "launcher error: " + process.errorString().toStdString();
            return false;
        }
        if (QWidget* window = QWidget::find(static_cast<WId>(owner))) window->activateWindow();
        exit_code = process.exitStatus() == QProcess::NormalExit
                        ? static_cast<uint32_t>(process.exitCode())
                        : static_cast<uint32_t>(128 + process.exitCode());
        return true;
    }
};

}

REGISTER_SERVICE_AS(QtLauncherProcess, cerffrontend::LauncherProcess);

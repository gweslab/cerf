#include "../frontend_launch.h"
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/log.h>
#include "../cerfman/manager_app.h"
#include "../install_root_files.h"
#include "../process_mode.h"
#include "../qt_app_defaults.h"
#include "../qt_back_gesture.h"
#include "../qt_emulator_run.h"
#include "../qt_message_log.h"
#include "crash_report.h"
#include "crash_report_model.h"
#include "host_diagnostics.h"
#include "host_timer_resolution.h"
#include "qt_arguments.h"
#include "qt_window_erase.h"

#include <QApplication>

namespace {

int RunEmulator(int argc, char** argv) {
    cerfcore::CerfConfig cfg;
    if (const std::optional<int> exit_code = cerffrontend::FrontendLaunch::ParseArgs(argc, argv, cfg))
        return *exit_code;
    const HostTimerResolution timer_resolution;
    cerffrontend::FrontendLaunch::OpenLog(cerfcore::Log::Cat::Cerf, cerfcore::kLogFileName);
    HostDiagnostics::LogReport();
    {
        QtEmulatorRun run(cfg, argc, argv, [] { QCoreApplication::exit(0); });
        run.Boot();
        QCoreApplication::exec();
    }
    cerfcore::Log::Close();
    return 0;
}

int RunManagerMode(ProcessMode mode, int argc, char** argv) {
    cerffrontend::FrontendLaunch::OpenLog(cerfcore::Log::Cat::Manager, cerffrontend::kManagerLogFileName);
    return ManagerApp::Run(argc, argv, [mode, argc, argv](cerfcore::CerfEmulator& manager) {
        switch (mode) {
            case ProcessMode::kCrashReport:  return manager.Get<CrashReportModel>().Run(argc, argv);
            case ProcessMode::kInstallStage: return manager.Get<ManagerApp>().RunInstallStage(argc, argv);
            case ProcessMode::kManager:
            case ProcessMode::kEmulator:     break;
        }
        return manager.Get<ManagerApp>().RunManager(false);
    });
}

}

int main(int argc, char* argv[]) {
    RouteQtMessagesToLog();
    QtArguments       args(argc, argv);
    const ProcessMode mode = DetectProcessMode(args.Count(), args.Values());
    if (mode != ProcessMode::kCrashReport) {
        QtCrashReport::Prepare();
        cerfcore::Log::SetCrashPresenter(&QtCrashReport::Present);
    }
    ApplyPlatformAppDefaults();
    QApplication   app(args.QtCount(), args.QtValues());
    args.KeepWhatQtLeft();
    QtBackGesture  back_gesture(app);
    QtWindowErase  window_erase(app);
    if (mode == ProcessMode::kEmulator) return RunEmulator(args.Count(), args.Values());
    return RunManagerMode(mode, args.Count(), args.Values());
}

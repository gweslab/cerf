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
#include "host_diagnostics.h"
#include "host_timer_resolution.h"
#include "qt_arguments.h"
#include "qt_main_window.h"
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
    std::optional<int> halt;
    std::string        crash_log_path;
    {
        QtEmulatorRun run(cfg, argc, argv, [] { QCoreApplication::exit(0); },
                          [](cerfcore::CerfEmulator& emu) { emu.Get<QtMainWindow>().OnTeardownWedged(); });
        if (run.Boot()) QCoreApplication::exec();
        halt = run.Halt();
        if (halt) crash_log_path = run.CrashLogPath();
    }
#if !CERF_DEV_MODE
    if (halt == cerfcore::CERF_FATAL_RUNTIME_ERROR) {
        return ManagerApp::Run(argc, argv, [&crash_log_path](cerfcore::CerfEmulator& manager) {
            return manager.Get<ManagerApp>().RunCrashWindow(cerfcore::CERF_FATAL_RUNTIME_ERROR, crash_log_path);
        });
    }
#endif
    cerfcore::Log::Close();
    return halt.value_or(0);
}

int RunManagerMode(ProcessMode mode, int argc, char** argv) {
    cerffrontend::FrontendLaunch::OpenLog(cerfcore::Log::Cat::Manager, cerffrontend::kManagerLogFileName);
    return ManagerApp::Run(argc, argv, [mode, argc, argv](cerfcore::CerfEmulator& manager) {
        if (mode == ProcessMode::kInstallStage) return manager.Get<ManagerApp>().RunInstallStage(argc, argv);
        return manager.Get<ManagerApp>().RunManager(false);
    });
}

}

int main(int argc, char* argv[]) {
    RouteQtMessagesToLog();
    QtArguments       args(argc, argv);
    const ProcessMode mode = DetectProcessMode(args.Count(), args.Values());
    ApplyPlatformAppDefaults();
    QApplication   app(args.QtCount(), args.QtValues());
    args.KeepWhatQtLeft();
    QtBackGesture  back_gesture(app);
    QtWindowErase  window_erase(app);
    if (mode == ProcessMode::kEmulator) return RunEmulator(args.Count(), args.Values());
    return RunManagerMode(mode, args.Count(), args.Values());
}

#include <cerffrontend/frontend_launch.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>
#include <cerfcore/execution/jit_runner.h>
#include "crash_report.h"
#include "qt_app_defaults.h"

#include <QApplication>
#include <QMetaObject>

#include <thread>

int main(int argc, char* argv[]) {
    cerfcore::Log::SetCrashPresenter(&QtCrashReport::Present);
    ApplyPlatformAppDefaults();
    QApplication app(argc, argv);
    cerfcore::CerfConfig cfg;
    if (const std::optional<int> exit_code =
            cerffrontend::FrontendLaunch::ParseArgs(argc, argv, cfg))
        return *exit_code;
    cerffrontend::FrontendLaunch::OpenLog();
    return cerffrontend::FrontendLaunch::RunEmulator(
        cfg, argc, argv, [&app](cerfcore::CerfEmulator& emu) {
            std::thread waiter([&emu, &app] {
                emu.WaitForExit();
                QMetaObject::invokeMethod(&app, [] { QCoreApplication::exit(0); },
                                          Qt::QueuedConnection);
            });
            app.exec();
            emu.Get<cerfcore::JitRunner>().RequestStop();
            waiter.join();
        });
}

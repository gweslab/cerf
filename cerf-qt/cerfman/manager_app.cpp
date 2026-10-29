#include "manager_app.h"

#include "crash_report_model.h"
#include "install_options.h"
#include "install_stage_model.h"
#include "manager_engine.h"

#include <cerfcore/core/cerf_config.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/fatal.h>
#include <cerfcore/core/log.h>

#include <QCoreApplication>
#include <QMetaObject>
#include <QObject>

REGISTER_SERVICE(ManagerApp);

int ManagerApp::Run(int argc, char** argv, const std::function<int(cerfcore::CerfEmulator&)>& body) {
    int         exit_code    = 0;
    bool        crash_window = false;
    std::string crash_log_path;
    for (;;) {
        QObject                loop_context;
        cerfcore::CerfConfig   cfg;
        cerfcore::CerfEmulator manager(cfg, argc, argv);
        manager.CreateAllServices();
        cerfcore::Fatal& fatal = manager.Get<cerfcore::Fatal>();
        fatal.RegisterHaltListener([&loop_context](int code) {
            QMetaObject::invokeMethod(&loop_context, [code] { QCoreApplication::exit(code); }, Qt::QueuedConnection);
        });
        ManagerApp& app       = manager.Get<ManagerApp>();
        const int   halt_code = exit_code;
        fatal.Guard([&] {
            exit_code = crash_window ? app.RunCrashWindow(halt_code, crash_log_path) : body(manager);
        });
        if (!fatal.Halted()) break;
        exit_code = fatal.HaltCode();
        if (app.crash_window_only_ || exit_code != cerfcore::CERF_FATAL_RUNTIME_ERROR) break;
        crash_window   = true;
        crash_log_path = fatal.CrashLogPath();
    }
    cerfcore::Log::Close();
    return exit_code;
}

int ManagerApp::RunManager(bool upgraded) {
    emu_.Get<ManagerEngine>().Open(QStringLiteral("Main"), {{QStringLiteral("upgraded"), upgraded}});
    return QCoreApplication::exec();
}

int ManagerApp::RunCrashWindow(int halt_code, const std::string& crash_log_path) {
    crash_window_only_ = true;
    emu_.Get<CrashReportModel>().Open(crash_log_path);
    cerfcore::Fatal& fatal = emu_.Get<cerfcore::Fatal>();
    if (fatal.Halted()) return fatal.HaltCode();
    QCoreApplication::exec();
    return halt_code;
}

int ManagerApp::RunInstallStage(int argc, char** argv) {
    const InstallOptions options = InstallOptions::Parse(argc, argv);
    auto&                stage   = emu_.Get<InstallStageModel>();
    if (options.stage == InstallStage::kInstall) return stage.RunInstall(options);
    if (const std::optional<int> code = stage.RunPostUpgrade(options)) return *code;
    return RunManager(!options.fresh);
}

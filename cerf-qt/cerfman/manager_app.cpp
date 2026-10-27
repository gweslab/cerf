#include "manager_app.h"

#include "install_options.h"
#include "install_stage_model.h"
#include "manager_engine.h"

#include <cerfcore/core/cerf_config.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>

#include <QCoreApplication>

REGISTER_SERVICE(ManagerApp);

int ManagerApp::Run(int argc, char** argv, const std::function<int(cerfcore::CerfEmulator&)>& body) {
    int exit_code = 0;
    {
        cerfcore::CerfConfig   cfg;
        cerfcore::CerfEmulator manager(cfg, argc, argv);
        manager.CreateAllServices();
        exit_code = body(manager);
    }
    cerfcore::Log::Close();
    return exit_code;
}

int ManagerApp::RunManager(bool upgraded) {
    emu_.Get<ManagerEngine>().Open(QStringLiteral("Main"), {{QStringLiteral("upgraded"), upgraded}});
    return QCoreApplication::exec();
}

int ManagerApp::RunInstallStage(int argc, char** argv) {
    const InstallOptions options = InstallOptions::Parse(argc, argv);
    auto&                stage   = emu_.Get<InstallStageModel>();
    if (options.stage == InstallStage::kInstall) return stage.RunInstall(options);
    if (const std::optional<int> code = stage.RunPostUpgrade(options)) return *code;
    return RunManager(!options.fresh);
}

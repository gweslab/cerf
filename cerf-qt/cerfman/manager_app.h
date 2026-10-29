#pragma once

#include <cerfcore/core/service.h>

#include <functional>
#include <string>

class ManagerApp : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static int  Run(int argc, char** argv, const std::function<int(cerfcore::CerfEmulator&)>& body);

    int RunManager(bool upgraded);
    int RunInstallStage(int argc, char** argv);
    int RunCrashWindow(int halt_code, const std::string& crash_log_path);

private:
    bool crash_window_only_ = false;
};

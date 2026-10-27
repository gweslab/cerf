#pragma once

#include <cerfcore/core/service.h>

#include <functional>

class ManagerApp : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static int  Run(int argc, char** argv, const std::function<int(cerfcore::CerfEmulator&)>& body);

    int RunManager(bool upgraded);
    int RunInstallStage(int argc, char** argv);
};

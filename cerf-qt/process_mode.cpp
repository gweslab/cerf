#include "process_mode.h"

#include "cerfman/install_options.h"

#include <cstring>

namespace {

constexpr const char* kInstallStageArgs[] = {kInstallArg, kUpgradeArg, kPostUpgradeArg};

}

ProcessMode DetectProcessMode(int argc, char** argv) {
    if (argc <= 1) return ProcessMode::kManager;
    for (int i = 1; i < argc; ++i) {
        std::optional<uint32_t> pid;
        if (ParseWaitForPidArg(argv[i], pid)) return ProcessMode::kInstallStage;
        for (const char* stage : kInstallStageArgs)
            if (std::strcmp(argv[i], stage) == 0) return ProcessMode::kInstallStage;
    }
    return ProcessMode::kEmulator;
}

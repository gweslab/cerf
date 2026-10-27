#pragma once

#include <cerfcore/core/cerf_config.h>
#include <cerfcore/core/log.h>

#include <optional>

namespace cerffrontend {

class FrontendLaunch {
public:
    static std::optional<int> ParseArgs(int argc, char** argv, cerfcore::CerfConfig& cfg);
    static void               OpenLog(cerfcore::Log::Cat channel, const char* file_name);
};

}

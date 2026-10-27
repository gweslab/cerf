#pragma once

#include <cerfcore/core/cerf_config.h>

namespace cerffrontend {

inline constexpr char kArgDevice[] = "--device=";
inline constexpr char kArgLog[]    = "--log=";

enum class ArgParseResult {
    Run,
    HelpShown,
    BadArgument,
};

ArgParseResult ParseCerfArgs(int argc, char* argv[], cerfcore::CerfConfig& cfg);

}

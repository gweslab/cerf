#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

struct ShaderChainSpec {
    uint64_t                                   generation           = 0;
    uint64_t                                   parameter_generation = 0;
    std::vector<std::string>                   presets;
    std::vector<std::pair<std::string, float>> parameters;
};

struct ShaderChainResult {
    uint64_t    generation = 0;
    bool        applied    = false;
    std::string error;
};

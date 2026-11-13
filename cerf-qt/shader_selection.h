#pragma once

#include "shader_chain_spec.h"

#include <cerfcore/core/service.h>

#include <string>
#include <utility>
#include <vector>

namespace cerffrontend {

class ShaderSelection : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override;

    const ShaderChainSpec& Spec() const { return spec_; }
    void Preview(const std::vector<std::string>& chain, const std::vector<std::pair<std::string, float>>& parameters);
    void EndPreview(bool apply_config);
    void Report(const ShaderChainResult& result);

    static std::string Directory();

private:
    void ApplyConfig();
    void Apply(const std::vector<std::string>& chain, const std::vector<std::pair<std::string, float>>& parameters);

    ShaderChainSpec spec_;
    bool            previewing_ = false;
};

}

#include "shader_selection.h"

#include "install_root_files.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/device_config_refresh.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/notification_stack.h>

#include <utility>

namespace cerffrontend {

REGISTER_SERVICE(ShaderSelection);

void ShaderSelection::OnReady() {
    emu_.Get<cerfcore::DeviceConfigRefresh>().RegisterListener([this] {
        if (!previewing_) ApplyConfig();
    });
    ApplyConfig();
}

std::string ShaderSelection::Directory() { return cerfcore::GetCerfDir() + kShadersDirName + "/"; }

void ShaderSelection::Preview(const std::vector<std::string>&                  chain,
                              const std::vector<std::pair<std::string, float>>& parameters) {
    previewing_ = true;
    Apply(chain, parameters);
}

void ShaderSelection::EndPreview(bool apply_config) {
    previewing_ = false;
    if (apply_config) ApplyConfig();
}

void ShaderSelection::Report(const ShaderChainResult& result) {
    if (result.applied) {
        LOG(Lcd, "ShaderSelection: chain %llu applied\n", static_cast<unsigned long long>(result.generation));
        return;
    }
    LOG(Lcd, "ShaderSelection: chain %llu failed: %s\n", static_cast<unsigned long long>(result.generation),
        result.error.c_str());
    emu_.Get<cerfcore::NotificationStack>().PostError("Shaders are off: " +
                                                      result.error.substr(0, result.error.find('\n')));
}

void ShaderSelection::ApplyConfig() {
    const auto& config = emu_.Get<cerfcore::DeviceConfig>();
    Apply(cerfcore::EnabledShaderPresets(config.shader_presets), config.shader_parameters);
}

void ShaderSelection::Apply(const std::vector<std::string>&                  chain,
                            const std::vector<std::pair<std::string, float>>& parameters) {
    const std::string        directory = Directory();
    std::vector<std::string> presets;
    for (const std::string& preset : chain) presets.push_back(directory + preset);
    if (presets == spec_.presets && parameters == spec_.parameters) return;
    ++spec_.parameter_generation;
    spec_.parameters = parameters;
    if (presets == spec_.presets) return;
    ++spec_.generation;
    spec_.presets = std::move(presets);
    LOG(Lcd, "ShaderSelection: chain %llu has %zu presets, %zu parameters\n",
        static_cast<unsigned long long>(spec_.generation), spec_.presets.size(), spec_.parameters.size());
}

}

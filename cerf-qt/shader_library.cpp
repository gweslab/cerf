#include "shader_library.h"

#include "shader_library_path.h"

#include <vector>

bool ShaderLibrary::Load(const char* runtime, std::string& error) {
    library_.setFileName(ShaderLibraryPath(runtime));
    if (!library_.load()) {
        error = library_.errorString().toStdString();
        return false;
    }
    if (!Bind(abi_version_, "libra_instance_abi_version", error) || !Bind(error_write_, "libra_error_write", error) ||
        !Bind(error_free_string_, "libra_error_free_string", error) || !Bind(error_free_, "libra_error_free", error) ||
        !Bind(error_errno_, "libra_error_errno", error) ||
        !Bind(preset_create_chain_, "libra_preset_create_chain", error) ||
        !Bind(preset_free_, "libra_preset_free", error) ||
        !Bind(get_runtime_params_, "libra_preset_get_runtime_params", error) ||
        !Bind(get_ordered_params_, "libra_preset_get_runtime_params_ordered", error) ||
        !Bind(free_runtime_params_, "libra_preset_free_runtime_params", error))
        return false;
    if (abi_version_() != LIBRASHADER_CURRENT_ABI) {
        error = library_.fileName().toStdString() + " has librashader ABI " + std::to_string(abi_version_()) +
                ", CERF needs ABI " + std::to_string(LIBRASHADER_CURRENT_ABI);
        return false;
    }
    ready_ = true;
    return true;
}

bool ShaderLibrary::Check(libra_error_t result, const char* what, std::string& error) {
    if (result == nullptr) return true;
    char* text = nullptr;
    if (error_write_(result, &text) == 0) {
        error = std::string(what) + ": " + text;
        error_free_string_(&text);
    } else {
        error = std::string(what) + ": librashader error " + std::to_string(static_cast<int>(error_errno_(result)));
    }
    error_free_(&result);
    return false;
}

bool ShaderLibrary::CreatePreset(const std::vector<std::string>& presets, libra_shader_preset_t& out,
                                 std::string& error) {
    std::vector<const char*> names;
    names.reserve(presets.size());
    for (const std::string& preset : presets) names.push_back(preset.c_str());
    return Check(preset_create_chain_(names.data(), names.size(), &out), "Load the shader presets", error);
}

void ShaderLibrary::FreePreset(libra_shader_preset_t& preset) { preset_free_(&preset); }

bool ShaderLibrary::Declared(libra_shader_preset_t& preset, bool ordered, std::vector<ShaderParameter>& out,
                             std::string& error) {
    alignas(alignof(libra_preset_param_list_t)) libra_preset_param_list_t list{};
    const libra_error_t result = ordered ? get_ordered_params_(&preset, &list) : get_runtime_params_(&preset, &list);
    if (!Check(result, "Read the shader parameters", error)) return false;
    for (uint64_t i = 0; i < list.length; ++i) {
        const libra_preset_param_t& p = list.parameters[i];
        out.push_back(ShaderParameter{p.name, p.description, p.initial, p.minimum, p.maximum, p.step});
    }
    free_runtime_params_(list);
    return true;
}

bool ShaderLibrary::Parameters(const std::vector<std::string>& presets, std::vector<ShaderParameter>& out,
                               std::string& error) {
    libra_shader_preset_t preset = nullptr;
    if (!CreatePreset(presets, preset, error)) return false;
    const bool read = Declared(preset, true, out, error);
    FreePreset(preset);
    return read;
}

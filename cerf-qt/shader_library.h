#pragma once

#include <librashader.h>

#include <QLibrary>

#include <string>
#include <vector>

struct ShaderParameter {
    std::string name;
    std::string description;
    float       initial = 0.0f;
    float       minimum = 0.0f;
    float       maximum = 0.0f;
    float       step    = 0.0f;
};

class ShaderLibrary {
public:
    bool Load(const char* runtime, std::string& error);
    bool Loaded() const { return ready_; }
    bool CreatePreset(const std::vector<std::string>& presets, libra_shader_preset_t& out, std::string& error);
    bool Declared(libra_shader_preset_t& preset, bool ordered, std::vector<ShaderParameter>& out, std::string& error);
    bool Parameters(const std::vector<std::string>& presets, std::vector<ShaderParameter>& out, std::string& error);
    void FreePreset(libra_shader_preset_t& preset);
    bool Check(libra_error_t result, const char* what, std::string& error);

    template <typename Fn>
    bool Bind(Fn& out, const char* name, std::string& error) {
        out = reinterpret_cast<Fn>(library_.resolve(name));
        if (out == nullptr) error = std::string(name) + " is missing from " + library_.fileName().toStdString();
        return out != nullptr;
    }

private:
    using PresetCreateChainFn = libra_error_t (*)(const char* const* filenames, size_t count,
                                                  libra_shader_preset_t* out);
    using OrderedParamsFn     = libra_error_t (*)(const libra_shader_preset_t* preset, libra_preset_param_list_t* out);

    QLibrary                             library_;
    bool                                  ready_ = false;
    PFN_libra_instance_abi_version        abi_version_        = nullptr;
    PFN_libra_error_write                 error_write_        = nullptr;
    PFN_libra_error_free_string           error_free_string_  = nullptr;
    PFN_libra_error_free                  error_free_         = nullptr;
    PFN_libra_error_errno                 error_errno_        = nullptr;
    PresetCreateChainFn                   preset_create_chain_ = nullptr;
    PFN_libra_preset_free                 preset_free_        = nullptr;
    PFN_libra_preset_get_runtime_params   get_runtime_params_ = nullptr;
    OrderedParamsFn                       get_ordered_params_ = nullptr;
    PFN_libra_preset_free_runtime_params  free_runtime_params_ = nullptr;
};

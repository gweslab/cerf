#include "shader_runtime.h"

#include <QQuickWindow>
#include <QRgb>
#include <QSGRendererInterface>

#include <utility>

namespace {

const char* ApiName(QSGRendererInterface::GraphicsApi api) {
    switch (api) {
        case QSGRendererInterface::Software:   return "software";
        case QSGRendererInterface::OpenGL:     return "OpenGL";
        case QSGRendererInterface::Direct3D11: return "Direct3D 11";
        case QSGRendererInterface::Direct3D12: return "Direct3D 12";
        case QSGRendererInterface::Vulkan:     return "Vulkan";
        case QSGRendererInterface::Metal:      return "Metal";
        default:                               return "unknown";
    }
}

}

std::unique_ptr<ShaderRuntime> ShaderRuntime::Create(QQuickWindow* window, std::string& error) {
    std::unique_ptr<ShaderRuntime> runtime = ForWindow(window);
    if (!runtime) {
        error = std::string("Shaders do not work with the ") + ApiName(window->rendererInterface()->graphicsApi()) +
                " renderer.";
        return nullptr;
    }
    if (!runtime->Init(error)) return nullptr;
    return runtime;
}

void ShaderRuntime::FrameFromRgba(const uint8_t* rows, size_t pitch, QSize size, ShadedFrame& frame) {
    frame.width  = static_cast<uint32_t>(size.width());
    frame.height = static_cast<uint32_t>(size.height());
    frame.pixels.resize(static_cast<size_t>(frame.width) * frame.height);
    for (uint32_t y = 0; y < frame.height; ++y) {
        const uint8_t* rgba = rows + static_cast<size_t>(y) * pitch;
        uint32_t*      out  = &frame.pixels[static_cast<size_t>(y) * frame.width];
        for (uint32_t x = 0; x < frame.width; ++x, rgba += 4) out[x] = qRgb(rgba[0], rgba[1], rgba[2]);
    }
}

bool ShaderRuntime::Build(const ShaderChainSpec& spec, std::string& error) {
    libra_shader_preset_t preset = nullptr;
    if (!library_.CreatePreset(spec.presets, preset, error)) return false;
    std::vector<ShaderParameter> declared;
    if (!library_.Declared(preset, false, declared, error)) {
        library_.FreePreset(preset);
        return false;
    }
    FreeChain();
    if (!CreateChain(preset, error)) return false;
    declared_ = std::move(declared);
    return ApplyParameters(spec.parameters, error);
}

bool ShaderRuntime::ApplyParameters(const std::vector<std::pair<std::string, float>>& values, std::string& error) {
    for (const ShaderParameter& parameter : declared_) {
        float value = parameter.initial;
        for (const auto& [name, set] : values)
            if (name == parameter.name) value = set;
        if (!SetParameter(parameter.name.c_str(), value, error)) return false;
    }
    return true;
}

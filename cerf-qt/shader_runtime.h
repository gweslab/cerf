#pragma once

#include "shader_capture.h"
#include "shader_chain_spec.h"
#include "shader_library.h"

#include <QImage>
#include <QSize>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

class QQuickWindow;
class QSGTexture;

class ShaderRuntime {
public:
    virtual ~ShaderRuntime() = default;

    static std::unique_ptr<ShaderRuntime> Create(QQuickWindow* window, std::string& error);

    bool                Build(const ShaderChainSpec& spec, std::string& error);
    bool                ApplyParameters(const std::vector<std::pair<std::string, float>>& values, std::string& error);
    virtual QImage::Format InputFormat() const                                                 = 0;
    virtual QSGTexture*    Output(QSize size, std::string& error)                              = 0;
    virtual bool           Render(const QImage& frame, uint64_t frame_count, std::string& error) = 0;
    virtual bool           ReadOutput(ShadedFrame& frame, std::string& error)                  = 0;
    virtual int            MaxTextureSize() const                                              = 0;

protected:
    explicit ShaderRuntime(QQuickWindow* window) : window_(window) {}

    static void FrameFromRgba(const uint8_t* rows, size_t pitch, QSize size, ShadedFrame& frame);

    virtual bool Init(std::string& error)                                         = 0;
    virtual bool CreateChain(libra_shader_preset_t& preset, std::string& error) = 0;
    virtual void FreeChain()                                                    = 0;
    virtual bool SetParameter(const char* name, float value, std::string& error) = 0;

    QQuickWindow*                window_;
    ShaderLibrary                library_;
    std::vector<ShaderParameter> declared_;

private:
    static std::unique_ptr<ShaderRuntime> ForWindow(QQuickWindow* window);
};

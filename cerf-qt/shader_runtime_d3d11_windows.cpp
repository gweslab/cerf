#define NOMINMAX
#define LIBRA_RUNTIME_D3D11

#include "shader_runtime_d3d11.h"

#include "fresh_sampler_texture.h"

#include <QQuickWindow>
#include <QSGRendererInterface>
#include <QSGTexture>
#include <QtQuick/qsgtexture_platform.h>

#include <d3d11.h>
#include <wrl/client.h>

#include <cstdio>
#include <memory>

namespace {

using Microsoft::WRL::ComPtr;

class ShaderRuntimeD3d11 final : public ShaderRuntime {
public:
    explicit ShaderRuntimeD3d11(QQuickWindow* window) : ShaderRuntime(window) {}
    ~ShaderRuntimeD3d11() override;

    QImage::Format InputFormat() const override { return QImage::Format_RGBX8888; }
    QSGTexture*    Output(QSize size, std::string& error) override;
    bool           Render(const QImage& frame, uint64_t frame_count, std::string& error) override;
    bool           ReadOutput(ShadedFrame& frame, std::string& error) override;
    int            MaxTextureSize() const override;

protected:
    bool Init(std::string& error) override;
    bool CreateChain(libra_shader_preset_t& preset, std::string& error) override;
    void FreeChain() override;
    bool SetParameter(const char* name, float value, std::string& error) override;

private:
    bool Created(HRESULT result, const char* what, std::string& error) const;

    ID3D11Device*                       device_  = nullptr;
    ID3D11DeviceContext*                context_ = nullptr;
    PFN_libra_d3d11_filter_chain_create create_  = nullptr;
    PFN_libra_d3d11_filter_chain_frame  frame_   = nullptr;
    PFN_libra_d3d11_filter_chain_free   free_    = nullptr;
    PFN_libra_d3d11_filter_chain_set_param set_param_ = nullptr;
    libra_d3d11_filter_chain_t          chain_   = nullptr;
    ComPtr<ID3D11Texture2D>             input_;
    ComPtr<ID3D11ShaderResourceView>    input_view_;
    QSize                               input_size_;
    ComPtr<ID3D11Texture2D>             output_;
    ComPtr<ID3D11RenderTargetView>      output_view_;
    QSize                               output_size_;
    std::unique_ptr<QSGTexture>         wrapper_;
};

ShaderRuntimeD3d11::~ShaderRuntimeD3d11() {
    FreeChain();
    wrapper_.reset();
}

bool ShaderRuntimeD3d11::Init(std::string& error) {
    QSGRendererInterface* renderer = window_->rendererInterface();
    device_  = static_cast<ID3D11Device*>(renderer->getResource(window_, QSGRendererInterface::DeviceResource));
    context_ = static_cast<ID3D11DeviceContext*>(
        renderer->getResource(window_, QSGRendererInterface::DeviceContextResource));
    if (device_ == nullptr || context_ == nullptr) {
        error = "The Direct3D 11 renderer has no device.";
        return false;
    }
    return library_.Load("d3d11", error) && library_.Bind(create_, "libra_d3d11_filter_chain_create", error) &&
           library_.Bind(frame_, "libra_d3d11_filter_chain_frame", error) &&
           library_.Bind(free_, "libra_d3d11_filter_chain_free", error) &&
           library_.Bind(set_param_, "libra_d3d11_filter_chain_set_param", error);
}

bool ShaderRuntimeD3d11::SetParameter(const char* name, float value, std::string& error) {
    return library_.Check(set_param_(&chain_, name, value), "Set a shader parameter", error);
}

int ShaderRuntimeD3d11::MaxTextureSize() const {
    const D3D_FEATURE_LEVEL level = device_->GetFeatureLevel();
    if (level >= D3D_FEATURE_LEVEL_11_0) return D3D11_REQ_TEXTURE2D_U_OR_V_DIMENSION;
    if (level >= D3D_FEATURE_LEVEL_10_0) return D3D10_REQ_TEXTURE2D_U_OR_V_DIMENSION;
    if (level >= D3D_FEATURE_LEVEL_9_3) return D3D_FL9_3_REQ_TEXTURE2D_U_OR_V_DIMENSION;
    return D3D_FL9_1_REQ_TEXTURE2D_U_OR_V_DIMENSION;
}

bool ShaderRuntimeD3d11::CreateChain(libra_shader_preset_t& preset, std::string& error) {
    return library_.Check(create_(&preset, device_, nullptr, &chain_), "Create the Direct3D 11 shader chain", error);
}

void ShaderRuntimeD3d11::FreeChain() {
    if (chain_ != nullptr) free_(&chain_);
    chain_ = nullptr;
}

bool ShaderRuntimeD3d11::Created(HRESULT result, const char* what, std::string& error) const {
    if (SUCCEEDED(result)) return true;
    char code[16];
    std::snprintf(code, sizeof(code), "0x%08lX", static_cast<unsigned long>(result));
    error = std::string("Create the ") + what + ": HRESULT " + code;
    return false;
}

QSGTexture* ShaderRuntimeD3d11::Output(QSize size, std::string& error) {
    if (wrapper_ && size == output_size_) return wrapper_.get();
    wrapper_.reset();
    output_view_.Reset();
    output_.Reset();
    output_size_ = QSize();
    const D3D11_TEXTURE2D_DESC desc{static_cast<UINT>(size.width()), static_cast<UINT>(size.height()), 1, 1,
                                    DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0}, D3D11_USAGE_DEFAULT,
                                    D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE, 0, 0};
    if (!Created(device_->CreateTexture2D(&desc, nullptr, &output_), "shader output texture", error) ||
        !Created(device_->CreateRenderTargetView(output_.Get(), nullptr, &output_view_), "shader output view", error))
        return nullptr;
    output_size_ = size;
    wrapper_.reset(FreshSampler(QNativeInterface::QSGD3D11Texture::fromNative(output_.Get(), window_, size)));
    return wrapper_.get();
}

bool ShaderRuntimeD3d11::Render(const QImage& frame, uint64_t frame_count, std::string& error) {
    if (input_size_ != frame.size()) {
        input_view_.Reset();
        input_.Reset();
        input_size_ = QSize();
        const D3D11_TEXTURE2D_DESC desc{static_cast<UINT>(frame.width()), static_cast<UINT>(frame.height()), 1, 1,
                                        DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0}, D3D11_USAGE_DEFAULT,
                                        D3D11_BIND_SHADER_RESOURCE, 0, 0};
        if (!Created(device_->CreateTexture2D(&desc, nullptr, &input_), "shader input texture", error) ||
            !Created(device_->CreateShaderResourceView(input_.Get(), nullptr, &input_view_), "shader input view",
                     error))
            return false;
        input_size_ = frame.size();
    }
    context_->UpdateSubresource(input_.Get(), 0, nullptr, frame.constBits(), static_cast<UINT>(frame.bytesPerLine()),
                                0);
    const libra_viewport_t viewport{0.0f, 0.0f, static_cast<uint32_t>(output_size_.width()),
                                    static_cast<uint32_t>(output_size_.height())};
    return library_.Check(frame_(&chain_, context_, frame_count, input_view_.Get(), output_view_.Get(), &viewport,
                                 nullptr, nullptr),
                          "Render the Direct3D 11 shader chain", error);
}

bool ShaderRuntimeD3d11::ReadOutput(ShadedFrame& frame, std::string& error) {
    const D3D11_TEXTURE2D_DESC desc{static_cast<UINT>(output_size_.width()), static_cast<UINT>(output_size_.height()),
                                    1, 1, DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0}, D3D11_USAGE_STAGING, 0,
                                    D3D11_CPU_ACCESS_READ, 0};
    ComPtr<ID3D11Texture2D> staging;
    if (!Created(device_->CreateTexture2D(&desc, nullptr, &staging), "shader read-back texture", error)) return false;
    context_->CopyResource(staging.Get(), output_.Get());
    D3D11_MAPPED_SUBRESOURCE mapped{};
    if (!Created(context_->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &mapped), "shader read-back mapping", error))
        return false;
    FrameFromRgba(static_cast<const uint8_t*>(mapped.pData), mapped.RowPitch, output_size_, frame);
    context_->Unmap(staging.Get(), 0);
    return true;
}

}

std::unique_ptr<ShaderRuntime> CreateShaderRuntimeD3d11(QQuickWindow* window) {
    return std::make_unique<ShaderRuntimeD3d11>(window);
}

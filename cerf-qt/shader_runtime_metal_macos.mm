#define LIBRA_RUNTIME_METAL

#include "shader_runtime_metal.h"

#include "fresh_sampler_texture.h"

#import <Metal/Metal.h>

#include <QQuickWindow>
#include <QSGRendererInterface>
#include <QSGTexture>
#include <QtQuick/qsgtexture_platform.h>

#include <memory>

namespace {

constexpr int kMacMaxTextureSize = 16384;

class ShaderRuntimeMetal final : public ShaderRuntime {
public:
    explicit ShaderRuntimeMetal(QQuickWindow* window) : ShaderRuntime(window) {}
    ~ShaderRuntimeMetal() override;

    QImage::Format InputFormat() const override { return QImage::Format_RGB32; }
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
    id<MTLTexture> NewTexture(QSize size, MTLPixelFormat format, MTLTextureUsage usage);

    id<MTLDevice>                     device_  = nil;
    id<MTLCommandQueue>               queue_   = nil;
    PFN_libra_mtl_filter_chain_create create_  = nullptr;
    PFN_libra_mtl_filter_chain_frame  frame_   = nullptr;
    PFN_libra_mtl_filter_chain_free   free_    = nullptr;
    PFN_libra_mtl_filter_chain_set_param set_param_ = nullptr;
    libra_mtl_filter_chain_t          chain_   = nullptr;
    id<MTLTexture>                    input_   = nil;
    QSize                             input_size_;
    id<MTLTexture>                    output_  = nil;
    QSize                             output_size_;
    std::unique_ptr<QSGTexture>       wrapper_;
};

ShaderRuntimeMetal::~ShaderRuntimeMetal() {
    FreeChain();
    wrapper_.reset();
    [input_ release];
    [output_ release];
}

bool ShaderRuntimeMetal::Init(std::string& error) {
    QSGRendererInterface* renderer = window_->rendererInterface();
    device_ = (id<MTLDevice>)renderer->getResource(window_, QSGRendererInterface::DeviceResource);
    queue_  = (id<MTLCommandQueue>)renderer->getResource(window_, QSGRendererInterface::CommandQueueResource);
    if (device_ == nil || queue_ == nil) {
        error = "The Metal renderer has no device.";
        return false;
    }
    return library_.Load("metal", error) && library_.Bind(create_, "libra_mtl_filter_chain_create", error) &&
           library_.Bind(frame_, "libra_mtl_filter_chain_frame", error) &&
           library_.Bind(free_, "libra_mtl_filter_chain_free", error) &&
           library_.Bind(set_param_, "libra_mtl_filter_chain_set_param", error);
}

bool ShaderRuntimeMetal::SetParameter(const char* name, float value, std::string& error) {
    return library_.Check(set_param_(&chain_, name, value), "Set a shader parameter", error);
}

int ShaderRuntimeMetal::MaxTextureSize() const { return kMacMaxTextureSize; }

bool ShaderRuntimeMetal::CreateChain(libra_shader_preset_t& preset, std::string& error) {
    return library_.Check(create_(&preset, queue_, nullptr, &chain_), "Create the Metal shader chain", error);
}

void ShaderRuntimeMetal::FreeChain() {
    if (chain_ != nullptr) free_(&chain_);
    chain_ = nullptr;
}

id<MTLTexture> ShaderRuntimeMetal::NewTexture(QSize size, MTLPixelFormat format, MTLTextureUsage usage) {
    MTLTextureDescriptor* desc = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:format
                                                                                    width:size.width()
                                                                                   height:size.height()
                                                                                mipmapped:NO];
    desc.usage       = usage;
    desc.storageMode = MTLStorageModePrivate;
    return [device_ newTextureWithDescriptor:desc];
}

QSGTexture* ShaderRuntimeMetal::Output(QSize size, std::string& error) {
    if (wrapper_ && size == output_size_) return wrapper_.get();
    @autoreleasepool {
        wrapper_.reset();
        [output_ release];
        output_ = NewTexture(size, MTLPixelFormatRGBA8Unorm,
                             MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead);
        output_size_ = QSize();
        if (output_ == nil) {
            error = "Create the shader output texture: the Metal device returned no texture.";
            return nullptr;
        }
        output_size_ = size;
        wrapper_.reset(FreshSampler(QNativeInterface::QSGMetalTexture::fromNative(output_, window_, size)));
    }
    return wrapper_.get();
}

bool ShaderRuntimeMetal::Render(const QImage& frame, uint64_t frame_count, std::string& error) {
    @autoreleasepool {
        if (input_size_ != frame.size()) {
            [input_ release];
            input_      = NewTexture(frame.size(), MTLPixelFormatBGRA8Unorm, MTLTextureUsageShaderRead);
            input_size_ = QSize();
            if (input_ == nil) {
                error = "Create the shader input texture: the Metal device returned no texture.";
                return false;
            }
            input_size_ = frame.size();
        }
        const NSUInteger width   = static_cast<NSUInteger>(frame.width());
        const NSUInteger height  = static_cast<NSUInteger>(frame.height());
        const NSUInteger row     = static_cast<NSUInteger>(frame.bytesPerLine());
        id<MTLBuffer>    staging = [device_ newBufferWithBytes:frame.constBits()
                                                     length:row * height
                                                    options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer>      upload = [queue_ commandBuffer];
        id<MTLBlitCommandEncoder> blit   = [upload blitCommandEncoder];
        [blit copyFromBuffer:staging
                 sourceOffset:0
            sourceBytesPerRow:row
          sourceBytesPerImage:row * height
                   sourceSize:MTLSizeMake(width, height, 1)
                    toTexture:input_
             destinationSlice:0
             destinationLevel:0
            destinationOrigin:MTLOriginMake(0, 0, 0)];
        [blit endEncoding];
        [upload commit];
        [staging release];
        id<MTLCommandBuffer>   commands = [queue_ commandBuffer];
        const libra_viewport_t viewport{0.0f, 0.0f, static_cast<uint32_t>(output_size_.width()),
                                        static_cast<uint32_t>(output_size_.height())};
        if (!library_.Check(frame_(&chain_, commands, frame_count, input_, output_, &viewport, nullptr, nullptr),
                            "Render the Metal shader chain", error))
            return false;
        [commands commit];
    }
    return true;
}

bool ShaderRuntimeMetal::ReadOutput(ShadedFrame& frame, std::string& error) {
    @autoreleasepool {
        const NSUInteger width  = static_cast<NSUInteger>(output_size_.width());
        const NSUInteger height = static_cast<NSUInteger>(output_size_.height());
        const NSUInteger row    = width * 4u;
        id<MTLBuffer>    buffer = [device_ newBufferWithLength:row * height options:MTLResourceStorageModeShared];
        if (buffer == nil) {
            error = "Create the shader read-back buffer: the Metal device returned no buffer.";
            return false;
        }
        id<MTLCommandBuffer>      commands = [queue_ commandBuffer];
        id<MTLBlitCommandEncoder> blit     = [commands blitCommandEncoder];
        [blit copyFromTexture:output_
                     sourceSlice:0
                     sourceLevel:0
                    sourceOrigin:MTLOriginMake(0, 0, 0)
                      sourceSize:MTLSizeMake(width, height, 1)
                        toBuffer:buffer
               destinationOffset:0
          destinationBytesPerRow:row
        destinationBytesPerImage:row * height];
        [blit endEncoding];
        [commands commit];
        [commands waitUntilCompleted];
        const bool completed = [commands status] == MTLCommandBufferStatusCompleted;
        if (completed)
            FrameFromRgba(static_cast<const uint8_t*>([buffer contents]), row, output_size_, frame);
        else
            error = std::string("Read the shader output: ") + [[[commands error] localizedDescription] UTF8String];
        [buffer release];
        return completed;
    }
}

}

std::unique_ptr<ShaderRuntime> CreateShaderRuntimeMetal(QQuickWindow* window) {
    return std::make_unique<ShaderRuntimeMetal>(window);
}

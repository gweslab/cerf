#define LIBRA_RUNTIME_OPENGL

#include "shader_runtime_gl.h"

#include "fresh_sampler_texture.h"

#include <QOpenGLContext>
#include <QOpenGLExtraFunctions>
#include <QQuickWindow>
#include <QSGTexture>
#include <QtQuick/qsgtexture_platform.h>

#if QT_CONFIG(opengles2)
#include <GLES3/gl3.h>
#endif

#include <memory>
#include <string>
#include <vector>

namespace {

const void* QOPENGLF_APIENTRY GlProcAddress(const char* name) {
    return reinterpret_cast<const void*>(QOpenGLContext::currentContext()->getProcAddress(name));
}

class ShaderRuntimeGl final : public ShaderRuntime {
public:
    explicit ShaderRuntimeGl(QQuickWindow* window) : ShaderRuntime(window) {}
    ~ShaderRuntimeGl() override;

    QImage::Format InputFormat() const override { return QImage::Format_RGBX8888; }
    QSGTexture*    Output(QSize size, std::string& error) override;
    bool           Render(const QImage& frame, uint64_t frame_count, std::string& error) override;
    bool           ReadOutput(ShadedFrame& frame, std::string& error) override;
    int            MaxTextureSize() const override { return max_texture_; }

protected:
    bool Init(std::string& error) override;
    bool CreateChain(libra_shader_preset_t& preset, std::string& error) override;
    void FreeChain() override;
    bool SetParameter(const char* name, float value, std::string& error) override;

private:
    GLuint NewTexture(QSize size);

    QOpenGLExtraFunctions*            gl_     = nullptr;
    PFN_libra_gl_filter_chain_create  create_ = nullptr;
    PFN_libra_gl_filter_chain_frame   frame_  = nullptr;
    PFN_libra_gl_filter_chain_free    free_   = nullptr;
    PFN_libra_gl_filter_chain_set_param set_param_ = nullptr;
    libra_gl_filter_chain_t           chain_  = nullptr;
    GLuint                            input_  = 0;
    QSize                             input_size_;
    GLuint                            output_ = 0;
    QSize                             output_size_;
    std::unique_ptr<QSGTexture>       wrapper_;
    int                               max_texture_ = 0;
};

ShaderRuntimeGl::~ShaderRuntimeGl() {
    FreeChain();
    wrapper_.reset();
    if (gl_ == nullptr) return;
    const GLuint textures[] = {input_, output_};
    gl_->glDeleteTextures(2, textures);
}

bool ShaderRuntimeGl::Init(std::string& error) {
    QOpenGLContext* context = QOpenGLContext::currentContext();
    if (context == nullptr) {
        error = "The OpenGL renderer has no current context.";
        return false;
    }
    const QSurfaceFormat format = context->format();
    const bool           usable = context->isOpenGLES() ? format.majorVersion() >= 3
                                                        : format.version() >= qMakePair(3, 3);
    if (!usable) {
        error = std::string("Shaders need OpenGL 3.3 or OpenGL ES 3.0; this window has ") +
                (context->isOpenGLES() ? "OpenGL ES " : "OpenGL ") + std::to_string(format.majorVersion()) + "." +
                std::to_string(format.minorVersion()) + ".";
        return false;
    }
    gl_ = context->extraFunctions();
    GLint max_texture = 0;
    gl_->glGetIntegerv(GL_MAX_TEXTURE_SIZE, &max_texture);
    max_texture_ = max_texture;
    return library_.Load("gl", error) && library_.Bind(create_, "libra_gl_filter_chain_create", error) &&
           library_.Bind(frame_, "libra_gl_filter_chain_frame", error) &&
           library_.Bind(free_, "libra_gl_filter_chain_free", error) &&
           library_.Bind(set_param_, "libra_gl_filter_chain_set_param", error);
}

bool ShaderRuntimeGl::SetParameter(const char* name, float value, std::string& error) {
    return library_.Check(set_param_(&chain_, name, value), "Set a shader parameter", error);
}

bool ShaderRuntimeGl::CreateChain(libra_shader_preset_t& preset, std::string& error) {
    const auto loader = reinterpret_cast<libra_gl_loader_t>(&GlProcAddress);
    return library_.Check(create_(&preset, loader, nullptr, &chain_), "Create the OpenGL shader chain", error);
}

void ShaderRuntimeGl::FreeChain() {
    if (chain_ != nullptr) free_(&chain_);
    chain_ = nullptr;
}

GLuint ShaderRuntimeGl::NewTexture(QSize size) {
    GLuint texture = 0;
    gl_->glGenTextures(1, &texture);
    gl_->glBindTexture(GL_TEXTURE_2D, texture);
    gl_->glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, size.width(), size.height(), 0, GL_RGBA, GL_UNSIGNED_BYTE, nullptr);
    gl_->glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_LEVEL, 0);
    gl_->glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    gl_->glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    gl_->glBindTexture(GL_TEXTURE_2D, 0);
    return texture;
}

QSGTexture* ShaderRuntimeGl::Output(QSize size, std::string&) {
    if (wrapper_ && size == output_size_) return wrapper_.get();
    wrapper_.reset();
    gl_->glDeleteTextures(1, &output_);
    output_      = NewTexture(size);
    output_size_ = size;
    wrapper_.reset(FreshSampler(QNativeInterface::QSGOpenGLTexture::fromNative(output_, window_, size)));
    return wrapper_.get();
}

bool ShaderRuntimeGl::Render(const QImage& frame, uint64_t frame_count, std::string& error) {
    if (input_size_ != frame.size()) {
        gl_->glDeleteTextures(1, &input_);
        input_      = NewTexture(frame.size());
        input_size_ = frame.size();
    }
    gl_->glBindTexture(GL_TEXTURE_2D, input_);
    gl_->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, frame.width(), frame.height(), GL_RGBA, GL_UNSIGNED_BYTE,
                         frame.constBits());
    gl_->glBindTexture(GL_TEXTURE_2D, 0);
    const libra_image_gl_t image{input_, GL_RGBA8, static_cast<uint32_t>(frame.width()),
                                 static_cast<uint32_t>(frame.height())};
    const libra_image_gl_t out{output_, GL_RGBA8, static_cast<uint32_t>(output_size_.width()),
                               static_cast<uint32_t>(output_size_.height())};
    const libra_viewport_t viewport{0.0f, 0.0f, out.width, out.height};
    return library_.Check(frame_(&chain_, frame_count, image, out, &viewport, nullptr, nullptr),
                          "Render the OpenGL shader chain", error);
}

bool ShaderRuntimeGl::ReadOutput(ShadedFrame& frame, std::string& error) {
    GLint previous = 0;
    gl_->glGetIntegerv(GL_READ_FRAMEBUFFER_BINDING, &previous);
    GLuint framebuffer = 0;
    gl_->glGenFramebuffers(1, &framebuffer);
    gl_->glBindFramebuffer(GL_READ_FRAMEBUFFER, framebuffer);
    gl_->glFramebufferTexture2D(GL_READ_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, output_, 0);
    const GLenum         status = gl_->glCheckFramebufferStatus(GL_READ_FRAMEBUFFER);
    std::vector<uint8_t> rgba;
    if (status == GL_FRAMEBUFFER_COMPLETE) {
        rgba.resize(static_cast<size_t>(output_size_.width()) * output_size_.height() * 4u);
        gl_->glReadPixels(0, 0, output_size_.width(), output_size_.height(), GL_RGBA, GL_UNSIGNED_BYTE, rgba.data());
    }
    gl_->glBindFramebuffer(GL_READ_FRAMEBUFFER, static_cast<GLuint>(previous));
    gl_->glDeleteFramebuffers(1, &framebuffer);
    if (status != GL_FRAMEBUFFER_COMPLETE) {
        error = "The shader output framebuffer is incomplete, status " + std::to_string(status);
        return false;
    }
    FrameFromRgba(rgba.data(), static_cast<size_t>(output_size_.width()) * 4u, output_size_, frame);
    return true;
}

}

std::unique_ptr<ShaderRuntime> CreateShaderRuntimeGl(QQuickWindow* window) {
    return std::make_unique<ShaderRuntimeGl>(window);
}

#pragma once

#include "shader_capture.h"
#include "shader_runtime.h"

#include <QImage>
#include <QSGRenderNode>

#include <cstdint>
#include <memory>
#include <string>

class QQuickWindow;

class ShaderChainNode : public QSGRenderNode {
public:
    ShaderChainNode(QQuickWindow* window, std::unique_ptr<ShaderRuntime> runtime);

    ShaderRuntime&     Runtime() { return *runtime_; }
    void               SetFrame(const QImage& guest);
    void               Suspend() { active_ = false; }
    void               RequestCapture(std::shared_ptr<ShaderCapture> capture) { capture_ = std::move(capture); }
    bool               Freeze(const QImage& guest, ShadedFrame& output, std::string& error);
    const std::string& RenderError() const { return render_error_; }

    void prepare() override;
    void render(const RenderState* state) override;

private:
    void Capture(bool rendered);

    QQuickWindow*                  window_;
    std::unique_ptr<ShaderRuntime> runtime_;
    QImage                         frame_;
    bool                           active_      = false;
    uint64_t                       frame_count_ = 0;
    std::string                    render_error_;
    std::shared_ptr<ShaderCapture> capture_;
};

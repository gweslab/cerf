#include "shader_chain_node.h"

#include <cerfcore/core/log.h>

#include <QQuickWindow>

#include <utility>

ShaderChainNode::ShaderChainNode(QQuickWindow* window, std::unique_ptr<ShaderRuntime> runtime)
    : window_(window), runtime_(std::move(runtime)) {}

void ShaderChainNode::SetFrame(const QImage& guest) {
    frame_  = guest.convertToFormat(runtime_->InputFormat());
    active_ = true;
}

bool ShaderChainNode::Freeze(const QImage& guest, ShadedFrame& output, std::string& error) {
    SetFrame(guest);
    active_ = false;
    return runtime_->Render(frame_, frame_count_++, error) && runtime_->ReadOutput(output, error);
}

void ShaderChainNode::prepare() {
    if (!active_ || !render_error_.empty()) return;
    window_->beginExternalCommands();
    const bool rendered = runtime_->Render(frame_, frame_count_++, render_error_);
    if (capture_) Capture(rendered);
    window_->endExternalCommands();
}

void ShaderChainNode::Capture(bool rendered) {
    ShadedFrame frame;
    std::string error;
    const bool  read = rendered && runtime_->ReadOutput(frame, error);
    if (rendered && !read) LOG(Lcd, "ShaderChainNode: reading the shader output failed: %s\n", error.c_str());
    capture_->Finish(read ? ShaderCapture::State::kCaptured : ShaderCapture::State::kUnshaded, std::move(frame));
    capture_.reset();
}

void ShaderChainNode::render(const RenderState*) {}

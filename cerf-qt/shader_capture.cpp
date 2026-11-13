#include "shader_capture.h"

#include <utility>

bool ShaderCapture::Pending() {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_ == State::kPending;
}

void ShaderCapture::Finish(State state, ShadedFrame frame) {
    std::lock_guard<std::mutex> lock(mutex_);
    state_ = state;
    frame_ = std::move(frame);
}

ShaderCapture::State ShaderCapture::Take(ShadedFrame& frame) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == State::kCaptured) frame = std::move(frame_);
    return state_;
}

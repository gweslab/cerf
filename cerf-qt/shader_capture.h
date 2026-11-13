#pragma once

#include <cstdint>
#include <mutex>
#include <vector>

struct ShadedFrame {
    std::vector<uint32_t> pixels;
    uint32_t              width  = 0;
    uint32_t              height = 0;
};

class ShaderCapture {
public:
    enum class State : uint8_t { kPending, kCaptured, kUnshaded };

    bool  Pending();
    void  Finish(State state, ShadedFrame frame);
    State Take(ShadedFrame& frame);

private:
    std::mutex  mutex_;
    State       state_ = State::kPending;
    ShadedFrame frame_;
};

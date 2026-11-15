#pragma once

#include <cerfcore/core/service.h>

#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>
#include <vector>

namespace cerfcore {
class FrameRenderer;
}

namespace cerffrontend {

class GuestContentLatch : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override;

    bool Probe();

private:
    struct Sample {
        bool     lit = false;
        uint64_t sig = 0;
    };

    std::optional<Sample> RenderSampleLocked();
    void                  ApplyRearmLocked();
    void                  CaptureBaseline();

    cerfcore::FrameRenderer* renderer_ = nullptr;
    std::atomic<bool>        rearm_{false};
    std::mutex               mtx_;
    std::vector<uint32_t>    pixels_;
    bool                     latched_          = false;
    bool                     awaiting_release_ = false;
    bool                     rearmed_          = false;
    uint64_t                 baseline_         = 0;
};

}

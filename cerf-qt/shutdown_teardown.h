#pragma once

#include <cerfcore/core/service.h>

#include <chrono>
#include <cstdint>

namespace cerffrontend {

class ShutdownTeardown : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    enum class Step { kWaiting, kStopped, kWedged };

    static constexpr uint32_t kPollMs  = 100u;
    static constexpr uint32_t kGraceMs = 5000u;

    bool Active() const { return active_; }
    bool Begin();
    Step Poll();

private:
    bool                                  active_ = false;
    std::chrono::steady_clock::time_point start_{};
};

}

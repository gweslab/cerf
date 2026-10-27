#pragma once

#include <cerfcore/core/service.h>

#include <atomic>

namespace cerffrontend {

class PointerStylusSimulation : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool Enabled() const { return enabled_.load(std::memory_order_acquire); }
    void SetEnabled(bool on) { enabled_.store(on, std::memory_order_release); }

private:
    std::atomic<bool> enabled_{false};
};

}

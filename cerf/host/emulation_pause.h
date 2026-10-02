#pragma once

#include "../core/service.h"

#include <atomic>
#include <cstdint>
#include <mutex>

class EmulationPause : public Service {
public:
    using Service::Service;

    void Toggle();
    bool IsPaused() const {
        return user_.load(std::memory_order_acquire) ||
               state_operation_.load(std::memory_order_acquire);
    }
    bool IsUserPaused() const { return user_.load(std::memory_order_acquire); }
    bool UserCanToggle() const;

    void BeginStateOperation();
    void EndStateOperation(bool release_user_pause);

    uint64_t AnimationTickMs() const;

private:
    void Apply(bool user, bool state_operation);
    void ShowUserCard(bool shown);

    std::mutex            mtx_;
    std::atomic<bool>     user_{false};
    std::atomic<bool>     state_operation_{false};
    std::atomic<uint64_t> pause_tick_ms_{0};
};
